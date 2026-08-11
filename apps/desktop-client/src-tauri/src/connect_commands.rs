//! Commands for pairing and the connection lifecycle.
//!
//! Kept separate from [`crate::commands`] because these are the only commands that
//! touch the network, and because every one of them has to answer the same two
//! questions before doing anything: is the application unlocked, and does this session
//! hold the capability the operation needs.
//!
//! The same rules as the rest of the command surface apply: no secret crosses this
//! boundary, errors are short vetted sentences rather than error chains, and every
//! response is `camelCase` so the Zod schemas on the other side can parse rather than
//! trust it.
//!
//! One rule is specific to this module. **A pairing code arrives from the webview and
//! is never sent back to it, never logged, and never stored.** It is parsed into a
//! [`rc_security::PairingCode`], used once, and dropped.

use std::sync::Arc;

use rc_security::pairing::RequestedPermissions;
use rc_security::permissions::{Capability, Role};
use rc_storage::audit::{AuditCategory, AuditEvent, AuditResult, actions};
use rc_storage::models::PeerRoleRow;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::commands::CommandError;
use crate::connection::{ConnectionState, SavedServer, parse_endpoint};

type CommandResult<T> = Result<T, CommandError>;

/// What the operator typed into the pairing panel.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairInput {
    /// Where the server is, as `host:port` or an address.
    pub address: String,
    /// The one-time code read off the server console. Never echoed back.
    pub code: String,
    /// The name to save the server under.
    pub display_name: String,
}

/// What the operator gets back after a successful pairing.
///
/// The fingerprint is here so it can be compared, by eye, against what the server
/// printed. That comparison is the operator's own check that they paired with the
/// machine they meant to — the cryptography proves the two ends agree, not that the far
/// end is the machine in the next room.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedServerDto {
    /// The server's device id.
    pub device_id: String,
    /// The name it was saved under.
    pub display_name: String,
    /// The pinned identity fingerprint, grouped for reading aloud.
    pub identity_fingerprint: String,
    /// The role granted.
    pub role: String,
}

/// Pair with a server and save it.
///
/// # Errors
/// [`CommandError`] with a specific code for each failure the operator can act on: a
/// malformed code, an unreachable address, a refused proof, or a server that is not in
/// pairing mode.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn pair_with_server(
    state: tauri::State<'_, Arc<AppState>>,
    input: PairInput,
) -> CommandResult<PairedServerDto> {
    state.require_capability(Capability::TrustedDeviceManagement)?;

    let identity = state
        .identity
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;
    let trust = state.trust.as_ref().ok_or_else(CommandError::no_database)?;

    let address = parse_endpoint(&input.address).ok_or_else(|| {
        CommandError::new(
            "invalid_address",
            "That is not an address this application can dial. Use an IP address, \
             optionally with a port.",
        )
    })?;

    // Parsed here and dropped at the end of this function. It is never logged, never
    // stored, and never returned.
    let code = rc_security::PairingCode::parse(&input.code).map_err(|_| {
        CommandError::new(
            "invalid_code",
            "That is not a valid pairing code. Check the characters and try again.",
        )
    })?;

    let display_name = sanitise_display_name(&input.display_name);

    // No pin exists yet — that is the problem pairing solves. Safety comes from the
    // transcript, which binds both observed certificate fingerprints.
    let (connector, _observed) =
        rc_transport::ClientConnector::new(identity, rc_transport::PinPolicy::TrustOnFirstUse)
            .map_err(|err| CommandError::from_transport(&err))?;

    let connection = tokio::time::timeout(
        std::time::Duration::from_secs(crate::connection::CONNECT_TIMEOUT_SECS),
        connector.connect(address),
    )
    .await
    .map_err(|_| CommandError::unreachable(address))?
    .map_err(|_| CommandError::unreachable(address))?;

    let paired = rc_transport::pair_as_client(
        &connection,
        identity,
        crate::connection::client_descriptor(identity, &state.host),
        &code,
        // The client asks for Owner because it is the operator's own machine. The
        // agent may grant less, and what it grants is what gets recorded.
        RequestedPermissions::full(Role::Owner),
        None,
    )
    .await
    .map_err(|err| {
        tracing::warn!(%err, "pairing failed");
        CommandError::pairing_failed(&err)
    })?;

    connection.close(0u32.into(), b"pairing complete");

    // Recorded as an agent: a server this client may connect to, which is the opposite
    // direction from the agent's own record of this client.
    trust
        .insert_paired_device(
            paired.device_id,
            PeerRoleRow::Agent,
            &display_name,
            "",
            &paired.public_key,
            paired.identity_fingerprint,
            paired.certificate_fingerprint,
            &paired.granted_permissions,
            Some(&paired.transcript_digest),
            state.clock.now_ms(),
        )
        .await
        .map_err(|err| match err {
            rc_storage::StorageError::Conflict => CommandError::new(
                "already_paired",
                "This server is already paired with a different device record. Revoke \
                 the old one before pairing again.",
            ),
            other => CommandError::internal("pair_with_server", &other),
        })?;

    // The address that worked, so the next connect can try it first.
    if let Err(err) = trust
        .record_successful_address(paired.device_id, address)
        .await
    {
        tracing::warn!(%err, "could not record the server address");
    }

    state
        .audit(
            AuditEvent::new(
                AuditCategory::Pairing,
                actions::PAIRING_COMPLETED,
                AuditResult::Success,
            )
            .target_device(paired.device_id)
            .meta("role", paired.granted_permissions.role.name())
            .meta("transcript_digest", &paired.transcript_digest),
        )
        .await;

    Ok(PairedServerDto {
        device_id: paired.device_id.to_canonical_string(),
        display_name,
        identity_fingerprint: paired.identity_fingerprint.to_display_groups(),
        role: paired.granted_permissions.role.name().to_owned(),
    })
}

/// Connect to a saved server.
///
/// # Errors
/// [`CommandError`] describing what to do about it: the server is off, the identity
/// changed, or this device is no longer authorized.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn connect_to_server(
    state: tauri::State<'_, Arc<AppState>>,
    device_id: String,
) -> CommandResult<ConnectionState> {
    state.require_capability(Capability::RemoteDesktopView)?;

    let server = load_saved_server(&state, &device_id).await?;

    let manager = state.connection.as_ref().ok_or_else(|| {
        CommandError::new(
            "no_identity",
            "This device has no identity to connect with.",
        )
    })?;

    match manager.connect(&server).await {
        Ok(_session_id) => {
            if let Some(address) = manager.connected_address().await
                && let Some(trust) = state.trust.as_ref()
                && let Err(err) = trust
                    .record_successful_address(server.device_id, address)
                    .await
            {
                tracing::warn!(%err, "could not record the connected address");
            }

            state
                .audit(
                    AuditEvent::new(
                        AuditCategory::Connection,
                        actions::SESSION_STARTED,
                        AuditResult::Success,
                    )
                    .target_device(&device_id),
                )
                .await;

            Ok(manager.state())
        }
        Err(err) => {
            state
                .audit(
                    AuditEvent::new(
                        AuditCategory::Connection,
                        actions::CONNECTION_REFUSED,
                        AuditResult::Failure,
                    )
                    .target_device(&device_id)
                    .meta("reason", &err),
                )
                .await;
            // The state carries the precise reason; returning it rather than an error
            // lets the UI show the same thing whether the call succeeded or not.
            Ok(manager.state())
        }
    }
}

/// Disconnect deliberately.
///
/// Suppresses automatic reconnection until the operator connects again.
///
/// # Errors
/// [`CommandError`] only if the application is locked.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn disconnect_from_server(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<ConnectionState> {
    state.require_capability(Capability::RemoteDesktopView)?;

    let manager = state
        .connection
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;

    manager.disconnect().await;

    state
        .audit(AuditEvent::new(
            AuditCategory::Connection,
            actions::SESSION_ENDED,
            AuditResult::Success,
        ))
        .await;

    Ok(manager.state())
}

/// Reconnect to a saved server, applying the backoff.
///
/// # Errors
/// [`CommandError`] only if the application is locked or the server is unknown; the
/// outcome of the attempt is carried in the returned state.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn reconnect_to_server(
    state: tauri::State<'_, Arc<AppState>>,
    device_id: String,
) -> CommandResult<ConnectionState> {
    state.require_capability(Capability::RemoteDesktopView)?;

    let server = load_saved_server(&state, &device_id).await?;
    let manager = state
        .connection
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;

    let _ = manager.reconnect(&server).await;

    state
        .audit(
            AuditEvent::new(
                AuditCategory::Connection,
                actions::RECONNECTED,
                AuditResult::Success,
            )
            .target_device(&device_id),
        )
        .await;

    Ok(manager.state())
}

/// The current connection state.
///
/// Returns `Offline` rather than failing when there is no manager, so the UI has one
/// shape to render regardless of how the client started up.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
#[tauri::command]
pub fn connection_state(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<ConnectionState> {
    Ok(state
        .connection
        .as_ref()
        .map_or(ConnectionState::Offline, |manager| manager.state()))
}

/// Measure the round trip to the connected agent.
///
/// # Errors
/// [`CommandError`] if nothing is connected.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn ping_server(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<u64> {
    state.require_capability(Capability::RemoteDesktopView)?;

    let manager = state
        .connection
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;

    manager
        .ping()
        .await
        .map_err(|err| CommandError::from_transport(&err))
}

/// Load a saved server and turn it into what the connection manager needs.
async fn load_saved_server(state: &AppState, device_id: &str) -> CommandResult<SavedServer> {
    let trust = state.trust.as_ref().ok_or_else(CommandError::no_database)?;

    let parsed = device_id
        .parse()
        .map_err(|_| CommandError::new("invalid", "That device identifier is not valid."))?;

    let device = trust
        .find(parsed)
        .await
        .map_err(|err| CommandError::internal("load_saved_server", &err))?
        .ok_or_else(|| {
            CommandError::new("not_found", "That server is no longer in the saved list.")
        })?;

    // Checked here as well as at the agent. A client that knows it revoked a server
    // should say so immediately rather than dialling out to be told.
    if device.revoked {
        return Err(CommandError::new(
            "revoked",
            "Access to this server was revoked. Pair with it again to restore it.",
        ));
    }

    Ok(SavedServer {
        device_id: device.device_id,
        display_name: device.display_name,
        certificate_fingerprint: device.certificate_fingerprint,
        identity_fingerprint: device.identity_fingerprint,
        last_known_address: device.last_known_address,
        configured_endpoint: device.remote_endpoint,
    })
}

/// Make an operator-typed name safe to store and render.
fn sanitise_display_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(rc_protocol::limits::MAX_DEVICE_NAME_BYTES / 4)
        .collect();
    let trimmed = cleaned.trim();

    if trimmed.is_empty() {
        "Home server".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blank_name_gets_a_usable_default() {
        assert_eq!(sanitise_display_name("   "), "Home server");
        assert_eq!(sanitise_display_name(""), "Home server");
    }

    #[test]
    fn control_characters_are_stripped_from_a_typed_name() {
        assert_eq!(sanitise_display_name("home\u{0}\nserver"), "homeserver");
    }

    #[test]
    fn an_overlong_name_is_bounded() {
        let long = "a".repeat(1000);
        assert!(sanitise_display_name(&long).len() <= rc_protocol::limits::MAX_DEVICE_NAME_BYTES);
    }

    #[test]
    fn a_pairing_result_never_carries_the_code_back() {
        let dto = PairedServerDto {
            device_id: "dev_x".to_owned(),
            display_name: "server".to_owned(),
            identity_fingerprint: "AAAA BBBB".to_owned(),
            role: "owner".to_owned(),
        };
        let rendered = serde_json::to_string(&dto).unwrap();

        assert!(!rendered.to_lowercase().contains("code"));
        assert!(!rendered.to_lowercase().contains("verifier"));
    }
}
