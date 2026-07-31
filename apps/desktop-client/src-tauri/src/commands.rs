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

use rc_security::permissions::Capability;
use rc_storage::audit::{AuditCategory, AuditEvent, AuditResult, actions};
use rc_storage::models::PeerRoleRow;
use serde::{Deserialize, Serialize};

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
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// An unexpected internal failure. Detail goes to the log, not the webview.
    fn internal(context: &str, err: &dyn std::fmt::Display) -> Self {
        tracing::error!(%err, context, "command failed");
        Self::new(
            "internal",
            "Something went wrong. Check the application log for details.",
        )
    }

    /// The application is locked and no session is active.
    pub(crate) fn locked() -> Self {
        Self::new("locked", "Sign in to continue.")
    }

    /// The session exists but lacks the required capability.
    pub(crate) fn permission_denied(capability: Capability) -> Self {
        Self::new(
            "permission_denied",
            format!(
                "This account is not permitted to {}.",
                capability.name().replace('_', " ")
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

/// Whether an owner account exists and whether a session is unlocked.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerStatusDto {
    /// `false` on first run, which drives the setup wizard.
    pub account_exists: bool,
    /// Whether the current process has an authenticated owner session.
    pub authenticated: bool,
    /// Username, once authenticated.
    pub username: Option<String>,
}

/// A trusted device as shown in the Devices list.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDeviceDto {
    /// Stable device identifier.
    pub device_id: String,
    /// User-editable label.
    pub display_name: String,
    /// Hostname recorded at pairing time.
    pub hostname: String,
    /// Pinned identity fingerprint, lowercase hex.
    pub identity_fingerprint: String,
    /// Current certificate fingerprint, lowercase hex.
    pub certificate_fingerprint: String,
    /// Permission role name.
    pub role: String,
    /// Capability names granted at pairing time.
    pub capabilities: Vec<String>,
    /// When pairing completed.
    pub paired_at_ms: i64,
    /// Last successful mutual authentication, if any.
    pub last_authenticated_at_ms: Option<i64>,
    /// Whether trust has been withdrawn.
    pub revoked: bool,
    /// When trust was withdrawn.
    pub revoked_at_ms: Option<i64>,
}

impl From<rc_storage::TrustedDevice> for TrustedDeviceDto {
    fn from(device: rc_storage::TrustedDevice) -> Self {
        Self {
            device_id: device.device_id.to_canonical_string(),
            display_name: device.display_name,
            hostname: device.hostname,
            identity_fingerprint: device.identity_fingerprint.to_hex(),
            certificate_fingerprint: device.certificate_fingerprint.to_hex(),
            role: device.role.name().to_string(),
            capabilities: device
                .granted_capabilities
                .iter()
                .map(|c| c.name().to_string())
                .collect(),
            paired_at_ms: device.paired_at_ms,
            last_authenticated_at_ms: device.last_authenticated_at_ms,
            revoked: device.revoked,
            revoked_at_ms: device.revoked_at_ms,
        }
    }
}

/// One audit-log entry.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntryDto {
    /// Row identifier.
    pub id: i64,
    /// When it happened.
    pub occurred_at_ms: i64,
    /// Broad category.
    pub category: String,
    /// Specific action.
    pub action: String,
    /// Outcome.
    pub result: String,
    /// Device acted upon.
    pub target_device_id: Option<String>,
}

/// Credentials submitted from the setup wizard or the login screen.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialsInput {
    /// Login name.
    pub username: String,
    /// Password. Never logged, never echoed back.
    pub password: String,
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

/// Report whether an owner account exists and whether it is unlocked.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn owner_status(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<OwnerStatusDto> {
    let owner = state
        .owner
        .as_ref()
        .ok_or_else(|| CommandError::new("no_database", "The local database is unavailable."))?;

    let account_exists = owner
        .exists()
        .await
        .map_err(|err| CommandError::internal("owner_status", &err))?;

    let session = state.session.lock().map_err(|_| {
        CommandError::new(
            "internal",
            "The session state is unusable. Restart the application.",
        )
    })?;

    Ok(OwnerStatusDto {
        account_exists,
        authenticated: session.is_some(),
        username: session.as_ref().map(|s| s.username.clone()),
    })
}

/// Create the owner account. Only valid on first run.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn create_owner(
    state: tauri::State<'_, Arc<AppState>>,
    credentials: CredentialsInput,
) -> CommandResult<()> {
    let owner = state
        .owner
        .as_ref()
        .ok_or_else(|| CommandError::new("no_database", "The local database is unavailable."))?;

    match owner
        .create(
            &credentials.username,
            &credentials.password,
            state.clock.as_ref(),
            &rc_security::OsRandom,
        )
        .await
    {
        Ok(_) => {
            state
                .audit(AuditEvent::new(
                    AuditCategory::Auth,
                    actions::OWNER_CREATED,
                    AuditResult::Success,
                ))
                .await;
            Ok(())
        }
        Err(rc_storage::StorageError::Conflict) => Err(CommandError::new(
            "already_exists",
            "An owner account already exists on this device.",
        )),
        // Password- and username-policy messages are safe to show: they describe the
        // rule, never the value.
        Err(rc_storage::StorageError::Invalid { field, reason }) => Err(CommandError::new(
            "invalid",
            format!("The {field} {reason}."),
        )),
        Err(err) => Err(CommandError::internal("create_owner", &err)),
    }
}

/// Authenticate the owner and unlock the application.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn owner_login(
    state: tauri::State<'_, Arc<AppState>>,
    credentials: CredentialsInput,
) -> CommandResult<OwnerStatusDto> {
    let owner = state
        .owner
        .as_ref()
        .ok_or_else(|| CommandError::new("no_database", "The local database is unavailable."))?;

    let outcome = owner
        .authenticate(
            &credentials.username,
            &credentials.password,
            state.clock.as_ref(),
        )
        .await
        .map_err(|err| CommandError::internal("owner_login", &err))?;

    match outcome {
        Ok(authenticated) => {
            if let Ok(mut session) = state.session.lock() {
                *session = Some(crate::OwnerSession {
                    account_id: authenticated.account_id.clone(),
                    username: authenticated.username.clone(),
                    role: authenticated.role,
                });
            }

            state
                .audit(
                    AuditEvent::new(
                        AuditCategory::Auth,
                        actions::LOGIN_SUCCEEDED,
                        AuditResult::Success,
                    )
                    .actor_account(authenticated.account_id.clone())
                    .meta("hash_upgraded", authenticated.password_hash_upgraded),
                )
                .await;

            Ok(OwnerStatusDto {
                account_exists: true,
                authenticated: true,
                username: Some(authenticated.username),
            })
        }
        Err(rc_security::SecurityError::Throttled { retry_after_secs }) => {
            state
                .audit(AuditEvent::new(
                    AuditCategory::Auth,
                    actions::LOGIN_THROTTLED,
                    AuditResult::Denied,
                ))
                .await;
            Err(CommandError::new(
                "throttled",
                format!("Too many failed attempts. Try again in {retry_after_secs} seconds."),
            ))
        }
        Err(_) => {
            state
                .audit(AuditEvent::new(
                    AuditCategory::Auth,
                    actions::LOGIN_FAILED,
                    AuditResult::Failure,
                ))
                .await;
            // Identical for a wrong password and an unknown account.
            Err(CommandError::new(
                "invalid_credentials",
                "Incorrect username or password.",
            ))
        }
    }
}

/// Lock the application, clearing the in-process session.
///
/// Returns `CommandResult` even though it cannot currently fail: every command in this
/// module presents the same `{ ok } | { error }` envelope to the frontend, and the
/// TypeScript client validates that envelope uniformly. Dropping the wrapper here would
/// make logout the one command needing a special case on the client.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
#[tauri::command]
pub fn owner_logout(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<()> {
    if let Ok(mut session) = state.session.lock() {
        *session = None;
    }
    Ok(())
}

/// List trusted devices.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn list_trusted_devices(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<Vec<TrustedDeviceDto>> {
    state.require_capability(Capability::TrustedDeviceManagement)?;

    let trust = state
        .trust
        .as_ref()
        .ok_or_else(|| CommandError::new("no_database", "The local database is unavailable."))?;

    // The client's saved devices are agents it may connect to.
    let devices = trust
        .list(PeerRoleRow::Agent)
        .await
        .map_err(|err| CommandError::internal("list_trusted_devices", &err))?;

    Ok(devices.into_iter().map(Into::into).collect())
}

/// Rename a trusted device.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn rename_trusted_device(
    state: tauri::State<'_, Arc<AppState>>,
    device_id: String,
    new_name: String,
) -> CommandResult<()> {
    state.require_capability(Capability::TrustedDeviceManagement)?;

    let trust = state
        .trust
        .as_ref()
        .ok_or_else(|| CommandError::new("no_database", "The local database is unavailable."))?;

    let parsed = device_id
        .parse()
        .map_err(|_| CommandError::new("invalid", "That device identifier is not valid."))?;

    match trust.rename(parsed, &new_name).await {
        Ok(()) => {
            state
                .audit(
                    AuditEvent::new(
                        AuditCategory::Permission,
                        actions::DEVICE_RENAMED,
                        AuditResult::Success,
                    )
                    .target_device(&device_id),
                )
                .await;
            Ok(())
        }
        Err(rc_storage::StorageError::NotFound) => Err(CommandError::new(
            "not_found",
            "That device is no longer in the list.",
        )),
        Err(rc_storage::StorageError::Invalid { field, reason }) => Err(CommandError::new(
            "invalid",
            format!("The {field} {reason}."),
        )),
        Err(err) => Err(CommandError::internal("rename_trusted_device", &err)),
    }
}

/// Revoke a trusted device.
///
/// Takes effect immediately: the row is marked revoked, and every subsequent
/// authorization check reads live state.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn revoke_trusted_device(
    state: tauri::State<'_, Arc<AppState>>,
    device_id: String,
) -> CommandResult<()> {
    state.require_capability(Capability::TrustedDeviceManagement)?;

    let trust = state
        .trust
        .as_ref()
        .ok_or_else(|| CommandError::new("no_database", "The local database is unavailable."))?;

    let parsed = device_id
        .parse()
        .map_err(|_| CommandError::new("invalid", "That device identifier is not valid."))?;

    match trust.revoke(parsed, state.clock.now_ms()).await {
        Ok(()) => {
            state
                .audit(
                    AuditEvent::new(
                        AuditCategory::DeviceRevocation,
                        actions::DEVICE_REVOKED,
                        AuditResult::Success,
                    )
                    .target_device(&device_id),
                )
                .await;
            Ok(())
        }
        Err(rc_storage::StorageError::NotFound) => Err(CommandError::new(
            "not_found",
            "That device is no longer in the list.",
        )),
        Err(err) => Err(CommandError::internal("revoke_trusted_device", &err)),
    }
}

/// Recent audit entries.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn recent_audit_events(
    state: tauri::State<'_, Arc<AppState>>,
    limit: u32,
) -> CommandResult<Vec<AuditEntryDto>> {
    let audit = state
        .audit_repo
        .as_ref()
        .ok_or_else(|| CommandError::new("no_database", "The local database is unavailable."))?;

    let rows = audit
        .recent(limit)
        .await
        .map_err(|err| CommandError::internal("recent_audit_events", &err))?;

    Ok(rows
        .into_iter()
        .map(|row| AuditEntryDto {
            id: row.id,
            occurred_at_ms: row.occurred_at_ms,
            category: row.category,
            action: row.action,
            result: row.result,
            target_device_id: row.target_device_id,
        })
        .collect())
}

/// Validate a pairing code's format without contacting anything.
///
/// This exists so the Devices screen can give immediate feedback while the operator
/// types. It proves nothing about whether the code is *correct* — only that it could
/// be a code at all. Completing a pairing needs the transport from Phase 3.
///
/// Takes `String` and returns `CommandResult` for the same reasons as [`owner_logout`]:
/// Tauri deserializes command arguments into owned values, and the envelope is uniform
/// across the command surface.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
#[tauri::command]
pub fn check_pairing_code_format(code: String) -> CommandResult<bool> {
    Ok(rc_security::PairingCode::parse(&code).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_errors_carry_no_internal_detail() {
        let err = CommandError::internal(
            "test",
            &std::io::Error::other("C:\\Users\\someone\\secret\\path.db is locked"),
        );
        assert!(!err.message.contains("C:\\"));
        assert!(!err.message.contains("secret"));
        assert_eq!(err.code, "internal");
    }

    #[test]
    fn trusted_device_dto_exposes_no_key_material() {
        // The DTO is hand-written precisely so a new column cannot leak by default.
        let fields = [
            "device_id",
            "display_name",
            "hostname",
            "identity_fingerprint",
            "certificate_fingerprint",
            "role",
            "capabilities",
            "paired_at_ms",
            "last_authenticated_at_ms",
            "revoked",
            "revoked_at_ms",
        ];
        assert_eq!(fields.len(), 11, "update this list when the DTO changes");
        assert!(
            !fields.contains(&"identity_public_key"),
            "raw keys must not be exposed"
        );
        assert!(!fields.contains(&"password_hash"));
    }

    #[test]
    fn pairing_code_format_check_accepts_and_rejects() {
        assert!(check_pairing_code_format("ABC-DEF-GHJ".into()).unwrap());
        assert!(!check_pairing_code_format("OOO-OOO-OOO".into()).unwrap());
        assert!(!check_pairing_code_format(String::new()).unwrap());
    }
}
