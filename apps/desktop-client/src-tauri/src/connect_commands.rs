//! Commands for the connection lifecycle.
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

use std::sync::Arc;

use rc_security::permissions::Capability;
use rc_storage::audit::{AuditCategory, AuditEvent, AuditResult, actions};

use crate::AppState;
use crate::commands::CommandError;
use crate::connection::{ConnectionState, SavedServer};

type CommandResult<T> = Result<T, CommandError>;

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
            "Access to this server was revoked.",
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
