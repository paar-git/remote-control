//! Commands for the connection lifecycle.
//!
//! Kept separate from [`crate::commands`] because these are the only commands that
//! touch the network, and because every one of them has to answer the same two
//! questions before doing anything: is there a connection, and does this session
//! hold the capability the operation needs.
//!
//! The same rules as the rest of the command surface apply: no secret crosses this
//! boundary, errors are short vetted sentences rather than error chains, and every
//! response is `camelCase` so the Zod schemas on the other side can parse rather than
//! trust it.

use std::sync::Arc;

use rc_security::Clock;
use rc_storage::{NewSessionRecord, SessionDirection, SessionHistoryRepository, SessionOutcome};
use rc_transport::PeerAddress;

use crate::AppState;
use crate::commands::CommandError;
use crate::connection::{ConnectionManager, ConnectionState, RefusalReason, Target};

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

    let pinned_identity = match state.database.as_ref() {
        Some(database) => rc_storage::RecentRepository::new(database)
            .find(&parsed.to_string())
            .await
            .ok()
            .flatten()
            .and_then(|row| row.known_identity),
        None => None,
    };

    let target = Target {
        address: parsed,
        unattended_password,
        pinned_identity,
    };

    if let Err(err) = manager.connect(&target).await {
        // A refusal is a decision, not a dropped packet. Write it so Sessions shows
        // that this machine tried and was turned away.
        if RefusalReason::classify(&err).is_some() {
            record_outgoing(
                manager.as_ref(),
                state.database.as_ref(),
                state.clock.now_ms(),
                &target,
                SessionOutcome::Refused,
            )
            .await;
        }
        return Err(CommandError::from_transport(&err));
    }

    // Recorded only after admission. A machine that refused is not one this list should
    // offer to reconnect to with one click, and the name comes from the descriptor that
    // only an admitted session receives.
    if let Some(database) = state.database.as_ref() {
        let name = manager
            .peer()
            .await
            .map_or_else(|| target.address.host.clone(), |peer| peer.display_name);
        let recent = rc_storage::RecentRepository::new(database);
        let address = target.address.to_string();
        if let Err(err) = recent.record(&address, &name, state.clock.now_ms()).await {
            // The connection is up; failing to write history must not tear it down.
            tracing::warn!(%err, "could not record a connection in the recent list");
        }
        if let Some(identity) = manager.peer_identity().await
            && let Err(err) = recent.set_known_identity(&address, identity).await
        {
            tracing::warn!(%err, "could not pin the identity seen at this address");
        }
    }

    record_outgoing(
        manager.as_ref(),
        state.database.as_ref(),
        state.clock.now_ms(),
        &target,
        SessionOutcome::Completed,
    )
    .await;

    spawn_outgoing_watch(
        Arc::clone(manager),
        target,
        state.database.clone(),
        Arc::clone(&state.clock),
    );

    Ok(manager.state())
}

/// Disconnect deliberately.
///
/// Suppresses automatic reconnection until the operator connects again.
///
/// # Errors
/// [`CommandError`] if this client has no identity.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn disconnect_from_server(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<ConnectionState> {
    let manager = state
        .connection
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;

    manager.disconnect().await;
    finish_outgoing(
        manager.as_ref(),
        state.database.as_ref(),
        state.clock.now_ms(),
        SessionOutcome::Completed,
        "user_requested",
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
    let manager = state
        .connection
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;

    manager
        .ping()
        .await
        .map_err(|err| CommandError::from_transport(&err))
}

/// Finish the current outgoing history row when the link drops, then reconnect
/// unless the operator ended it. A new admitted session gets a new row.
fn spawn_outgoing_watch(
    manager: Arc<ConnectionManager>,
    target: Target,
    database: Option<rc_storage::Database>,
    clock: Arc<dyn Clock>,
) {
    tokio::spawn(async move {
        loop {
            manager.wait_until_closed().await;
            let intentional = manager.was_intentional();
            finish_outgoing(
                manager.as_ref(),
                database.as_ref(),
                clock.now_ms(),
                if intentional {
                    SessionOutcome::Completed
                } else {
                    SessionOutcome::Failed
                },
                if intentional {
                    "user_requested"
                } else {
                    "transport_failure"
                },
            )
            .await;
            if intentional {
                return;
            }
            match manager.reconnect(&target).await {
                Ok(_) => {
                    record_outgoing(
                        manager.as_ref(),
                        database.as_ref(),
                        clock.now_ms(),
                        &target,
                        SessionOutcome::Completed,
                    )
                    .await;
                }
                Err(err) => {
                    tracing::warn!(%err, "automatic reconnect ended");
                    return;
                }
            }
        }
    });
}

/// Write an outgoing history row. The connection stays up even if the write fails.
async fn record_outgoing(
    manager: &ConnectionManager,
    database: Option<&rc_storage::Database>,
    now_ms: i64,
    target: &Target,
    outcome: SessionOutcome,
) {
    let Some(database) = database else {
        return;
    };

    let (session_id, device_name) = match manager.state() {
        ConnectionState::Connected {
            session_id,
            device_name,
            ..
        } => (Some(session_id), device_name),
        _ => (
            None,
            manager
                .peer()
                .await
                .map_or_else(|| target.address.to_string(), |peer| peer.display_name),
        ),
    };

    match SessionHistoryRepository::new(database)
        .record(&NewSessionRecord {
            session_id,
            identity_fingerprint: manager.peer_identity().await,
            device_name,
            direction: SessionDirection::Outgoing,
            address: target.address.to_string(),
            started_ms: now_ms,
            permissions: manager.granted(),
            outcome,
            end_reason: None,
        })
        .await
    {
        Ok(id) => {
            if outcome == SessionOutcome::Completed {
                manager.set_outgoing_history_id(id).await;
            }
        }
        Err(err) => {
            tracing::warn!(%err, "could not record an outgoing session");
        }
    }
}

/// Close the current outgoing history row exactly once.
async fn finish_outgoing(
    manager: &ConnectionManager,
    database: Option<&rc_storage::Database>,
    now_ms: i64,
    outcome: SessionOutcome,
    end_reason: &'static str,
) {
    let Some(id) = manager.take_outgoing_history_id().await else {
        return;
    };
    let Some(database) = database else {
        return;
    };
    if let Err(err) = SessionHistoryRepository::new(database)
        .finish(id, now_ms, outcome, Some(end_reason))
        .await
    {
        tracing::warn!(%err, "could not record how the outgoing session ended");
    }
}
