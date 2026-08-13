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

use rc_security::Permission;
use rc_transport::PeerAddress;

use crate::AppState;
use crate::commands::CommandError;
use crate::connection::{ConnectionState, Target};

type CommandResult<T> = Result<T, CommandError>;

/// Connect to a machine by the address the user typed.
///
/// The address is parsed here as well as in the interface. The interface's parser
/// exists so a typo is reported under the field; this one is the boundary, and it does
/// not trust what arrives over IPC.
///
/// `unattended_password` is offered to the other machine, which decides. It is never
/// stored, never logged and never returned.
///
/// On success the machine is recorded in the recent list under the address as typed —
/// the same key the responder pins on — so it can be reconnected to with one click.
///
/// # Errors
/// [`CommandError`] if the address is unusable, if this installation has no identity,
/// or if the other machine refused or could not be reached.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn connect_to_address(
    address: String,
    unattended_password: Option<String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<ConnectionState> {
    let parsed = address.parse::<PeerAddress>().map_err(|err| {
        tracing::debug!(%err, "an address typed in the interface could not be parsed");
        CommandError::new(
            "invalid_address",
            "That is not an address this application can use. Try something like              192.168.1.77.",
        )
    })?;

    let manager = state
        .connection
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;

    let target = Target {
        address: parsed,
        unattended_password,
    };

    manager
        .connect(&target)
        .await
        .map_err(|err| CommandError::from_transport(&err))?;

    // Recorded only after admission. A machine that refused is not one this list should
    // offer to reconnect to with one click, and the name comes from the descriptor that
    // only an admitted session receives.
    if let Some(database) = state.database.as_ref() {
        let name = manager
            .peer()
            .await
            .map_or_else(|| target.address.host.clone(), |peer| peer.display_name);
        let recent = rc_storage::RecentRepository::new(database);
        if let Err(err) = recent
            .record(&target.address.to_string(), &name, state.clock.now_ms())
            .await
        {
            // The connection is up; failing to write history must not tear it down.
            tracing::warn!(%err, "could not record a connection in the recent list");
        }
    }

    Ok(manager.state())
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
    state.require_permission(Permission::ControlInput)?;

    let manager = state
        .connection
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;

    manager.disconnect().await;

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
    state.require_permission(Permission::ControlInput)?;

    let manager = state
        .connection
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;

    manager
        .ping()
        .await
        .map_err(|err| CommandError::from_transport(&err))
}
