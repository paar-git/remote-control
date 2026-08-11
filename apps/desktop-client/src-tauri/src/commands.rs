//! Commands exposed to the webview.
//!
//! # Rules every command here follows
//!
//! * **No secret crosses this boundary.** No private key, password, password hash,
//!   pairing code verifier, or raw database row is ever returned. The DTOs below are
//!   hand-written for exactly that reason: returning a row type directly would leak a
//!   column the moment someone added one.
//! * **Errors are strings, not error chains.** A Rust error chain can carry local file
//!   paths and OS messages; the webview gets a short, safe sentence instead, and the
//!   detail goes to the log.
//! * **Every response is `camelCase`** to match the Zod schemas in `api.ts`, which
//!   parse rather than trust what arrives.

use std::sync::Arc;

use rc_security::Permission;
use serde::Serialize;

use crate::AppState;

/// A safe, operator-facing error.
///
/// Constructed from a message that has already been vetted; the underlying error is
/// logged separately.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    /// Stable machine-readable code the UI can branch on.
    pub code: &'static str,
    /// Short sentence safe to show the user.
    pub message: String,
}

impl CommandError {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// This installation has no device identity, so it cannot connect.
    pub(crate) fn no_identity() -> Self {
        Self::new(
            "no_identity",
            "This device has no identity yet. Restart the application to create one.",
        )
    }

    /// Turn a transport failure into something the operator can act on.
    ///
    /// Each arm names the next step, because "something went wrong" is not an answer
    /// anyone can do anything with.
    pub(crate) fn from_transport(err: &rc_transport::TransportError) -> Self {
        use rc_transport::TransportError as T;

        match err {
            T::FingerprintMismatch => Self::new(
                "identity_changed",
                "This server presented a different identity than the one saved for it. \
                 It has been refused. If you reinstalled the server, remove the saved \
                 entry; otherwise investigate before retrying.",
            ),
            T::NotTrusted | T::Revoked => {
                Self::new("not_authorized", "The server did not accept this device.")
            }
            T::IncompatibleVersion => Self::new(
                "protocol_mismatch",
                "This client and that server speak different protocol versions. Update \
                 both to the same release.",
            ),
            T::Throttled { retry_after_secs } => Self::new(
                "throttled",
                format!(
                    "The server is rate-limiting this device. Try again in {retry_after_secs} seconds."
                ),
            ),
            T::Connect { .. } | T::ConnectionLost { .. } | T::HandshakeTimeout => Self::new(
                "unreachable",
                "Could not reach the server. Check that it is on and on the same network.",
            ),
            other => {
                tracing::warn!(%other, "transport failure");
                Self::new(
                    "connection_failed",
                    "The connection failed. Check the application log for details.",
                )
            }
        }
    }

    /// The application is locked and no session is active.
    pub(crate) fn locked() -> Self {
        Self::new("locked", "Sign in to continue.")
    }

    /// The session exists but lacks the required permission.
    pub(crate) fn permission_denied(permission: Permission) -> Self {
        Self::new(
            "permission_denied",
            format!(
                "This account is not permitted to {}.",
                permission.name().replace('_', " ")
            ),
        )
    }
}

type CommandResult<T> = Result<T, CommandError>;

/// This client's own cryptographic identity.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalIdentityDto {
    /// Stable device identifier.
    pub device_id: String,
    /// Identity fingerprint, lowercase hex. The value a peer pins.
    pub identity_fingerprint: String,
    /// Certificate fingerprint, lowercase hex. Changes on renewal.
    pub certificate_fingerprint: String,
    /// Certificate generation counter.
    pub certificate_version: u32,
    /// When the certificate becomes valid.
    pub certificate_not_before_ms: i64,
    /// When the certificate expires.
    pub certificate_not_after_ms: i64,
    /// Whether the certificate is due for renewal.
    pub needs_renewal: bool,
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Report this client's cryptographic identity.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn local_identity(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<LocalIdentityDto> {
    let identity = state
        .identity
        .as_ref()
        .ok_or_else(|| CommandError::new("no_identity", "This device has no identity yet."))?;

    let public = identity.public();
    Ok(LocalIdentityDto {
        device_id: public.device_id.to_canonical_string(),
        identity_fingerprint: public.identity_fingerprint.to_hex(),
        certificate_fingerprint: public.certificate_fingerprint.to_hex(),
        certificate_version: public.certificate_version,
        certificate_not_before_ms: public.certificate_not_before_ms,
        certificate_not_after_ms: public.certificate_not_after_ms,
        needs_renewal: public.needs_renewal_at(state.clock.now_ms()),
    })
}
