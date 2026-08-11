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

use crate::AppState;
use crate::commands::CommandError;
use crate::connection::ConnectionState;

type CommandResult<T> = Result<T, CommandError>;

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
