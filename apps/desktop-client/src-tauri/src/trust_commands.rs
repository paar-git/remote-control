//! Commands for My Devices: trusted devices, session history and live sessions.
//!
//! These are actions by the person sitting at this keyboard deciding what their own
//! machine allows, so — like the rest of [`crate::host_commands`] — none of them is
//! gated on a remote session's permissions. The remote equivalent is
//! `rc_host_agent::trust_service`, which *is* gated, on `Administer`.
//!
//! # Nothing here carries a secret
//!
//! A device is authenticated by holding its identity private key, not by presenting a
//! stored token, so a trust relationship has no credential attached to leak. The
//! fingerprints that do cross this boundary are public values whose whole purpose is to
//! be compared by eye across two screens.
//!
//! # The presence probe never knocks
//!
//! [`probe_device`] opens a QUIC connection and drops it **before sending
//! `Authenticate`**. The far side therefore never reaches an admission decision: no
//! Accept dialog is raised on it, no session is recorded, and no unattended-password
//! attempt is counted against its lockout. A "check if it is online" button that raised
//! a prompt on someone's screen would be worse than no button.

use std::sync::Arc;

use rc_security::Fingerprint;
use serde::Serialize;

use crate::AppState;
use crate::commands::CommandError;
use crate::host::{permission_names, permissions_from_names};

type CommandResult<T> = Result<T, CommandError>;

/// How long a reachability probe waits before calling a device offline.
///
/// Long enough for a busy machine on a real network, short enough that a page of
/// offline devices settles rather than hanging. Probes run concurrently, so this is the
/// wait for the whole page, not per device.
const PROBE_TIMEOUT_SECS: u64 = 3;

/// A device this machine trusts.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDeviceDto {
    /// The trust key, as lowercase hex. A public value.
    pub identity_fingerprint: String,
    /// The device id it reported. Display only.
    pub device_id: String,
    /// The name it reported. Untrusted; the interface sanitises it again.
    pub display_name: String,
    /// The operating-system family it reported. Untrusted.
    pub os_family: String,
    /// Where it last connected from, if it has.
    pub last_address: Option<String>,
    /// When a human first trusted it.
    pub added_ms: i64,
    /// When it was last admitted.
    pub last_connected_ms: Option<i64>,
    /// Whether it may reconnect without anyone approving.
    pub unattended: bool,
    /// Whether it is temporarily refused.
    pub suspended: bool,
    /// What an admitted session from it receives.
    pub permissions: Vec<String>,
}

/// One recorded session.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecordDto {
    /// Row identifier.
    pub id: i64,
    /// The session id, absent for a connection that was never admitted.
    pub session_id: Option<String>,
    /// The device's identity, absent for a device that was never trusted.
    pub identity_fingerprint: Option<String>,
    /// The name displayed at the time. Untrusted.
    pub device_name: String,
    /// `incoming` or `outgoing`.
    pub direction: String,
    /// The address involved.
    pub address: String,
    /// When it started.
    pub started_ms: i64,
    /// When it ended, absent while it is still running.
    pub ended_ms: Option<i64>,
    /// What it held.
    pub permissions: Vec<String>,
    /// `completed`, `refused` or `failed`.
    pub outcome: String,
    /// Why it ended, when that is known.
    pub end_reason: Option<String>,
}

/// A session controlling this machine right now.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InboundSessionDto {
    /// The identifier assigned at admission.
    pub session_id: String,
    /// The identity the controlling device proved.
    pub identity_fingerprint: String,
    /// The name it reported. Untrusted.
    pub device_name: String,
    /// Where it connected from.
    pub address: String,
    /// What it is permitted to do.
    pub permissions: Vec<String>,
    /// When it was admitted.
    pub started_ms: i64,
}

/// The database, or a refusal the user can act on.
fn database(state: &AppState) -> CommandResult<&rc_storage::Database> {
    state
        .database
        .as_ref()
        .ok_or_else(CommandError::no_database)
}

/// Turn a storage failure into something safe to show.
fn storage_failed(err: &rc_storage::StorageError) -> CommandError {
    tracing::warn!(%err, "a trust storage operation failed");
    CommandError::new(
        "storage_failed",
        "That could not be saved. Check the application log for details.",
    )
}

/// A device that is no longer in the list.
fn not_trusted() -> CommandError {
    CommandError::new(
        "not_found",
        "That device is not in your trusted list any more. Refresh and try again.",
    )
}

/// Parse an identity, refusing anything that is not one.
///
/// A malformed value is refused rather than matched loosely: it could not name a real
/// device, and coercing it would mean acting on a device the caller did not name.
fn identity_of(value: &str) -> CommandResult<Fingerprint> {
    value.parse::<Fingerprint>().map_err(|_| {
        CommandError::new(
            "invalid_identity",
            "That is not a device identity this version understands.",
        )
    })
}

/// The trusted devices on this machine, most recently connected first.
///
/// # Errors
/// [`CommandError`] if the local database is not available.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn list_trusted_devices(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<Vec<TrustedDeviceDto>> {
    let devices = rc_storage::TrustRepository::new(database(&state)?)
        .list()
        .await
        .map_err(|err| storage_failed(&err))?;

    Ok(devices
        .into_iter()
        .map(|device| TrustedDeviceDto {
            identity_fingerprint: device.identity_fingerprint.to_hex(),
            device_id: device.device_id,
            display_name: device.display_name,
            os_family: device.os_family,
            last_address: device.last_address,
            added_ms: device.added_ms,
            last_connected_ms: device.last_connected_ms,
            unattended: device.unattended,
            suspended: device.suspended,
            permissions: permission_names(device.permissions),
        })
        .collect())
}

/// Change what a trusted device may do.
///
/// This is the only way `administer` is ever granted. It is not reachable from the
/// Accept dialog, which strips the bit from whatever it returns.
///
/// # Errors
/// [`CommandError`] if the identity is malformed, names no trusted device, or if
/// `permissions` contains a name this build does not know.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn set_device_permissions(
    identity: String,
    permissions: Vec<String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<()> {
    let identity = identity_of(&identity)?;
    let permissions = permissions_from_names(&permissions).ok_or_else(|| {
        CommandError::new(
            "unknown_permission",
            "That permission is not one this version understands.",
        )
    })?;

    write(
        rc_storage::TrustRepository::new(database(&state)?)
            .set_permissions(identity, permissions)
            .await,
    )
}

/// Turn a trusted device's unattended reconnection on or off.
///
/// Deliberately separate from [`set_device_permissions`]: granting a laptop unattended
/// access to a desktop must not widen a single permission bit, and the two commands
/// writing different columns is what makes that structural rather than careful.
///
/// # Errors
/// [`CommandError`] if the identity is malformed or names no trusted device.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn set_device_unattended(
    identity: String,
    enabled: bool,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<()> {
    let identity = identity_of(&identity)?;
    write(
        rc_storage::TrustRepository::new(database(&state)?)
            .set_unattended(identity, enabled)
            .await,
    )
}

/// Temporarily refuse a device without forgetting it.
///
/// # Errors
/// [`CommandError`] if the identity is malformed or names no trusted device.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn set_device_suspended(
    identity: String,
    suspended: bool,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<()> {
    let parsed = identity_of(&identity)?;
    write(
        rc_storage::TrustRepository::new(database(&state)?)
            .set_suspended(parsed, suspended)
            .await,
    )?;

    if suspended {
        for session in state.host_runtime.inbound_sessions().await {
            if session.identity_fingerprint.ct_eq(&parsed) {
                state
                    .host_runtime
                    .disconnect_inbound(session.session_id)
                    .await;
            }
        }
    }

    Ok(())
}

/// Forget a device entirely.
///
/// This is the whole of revocation. There is no stored token to invalidate, because
/// there is none to begin with: the next connection from that device finds no row and
/// is treated as the stranger it now is.
///
/// Any session it currently holds is ended too. Leaving one running would mean a device
/// whose access had just been revoked kept it until it happened to disconnect.
///
/// # Errors
/// [`CommandError`] if the identity is malformed. Revoking a device that is already
/// gone succeeds: the caller wanted it gone, and it is.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn revoke_device(
    identity: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<()> {
    let parsed = identity_of(&identity)?;

    rc_storage::TrustRepository::new(database(&state)?)
        .revoke(parsed)
        .await
        .map_err(|err| storage_failed(&err))?;

    for session in state.host_runtime.inbound_sessions().await {
        if session.identity_fingerprint.ct_eq(&parsed) {
            state
                .host_runtime
                .disconnect_inbound(session.session_id)
                .await;
        }
    }

    Ok(())
}

/// Whether a device answers at an address.
///
/// Three honest states, never a fabricated one: `online` if a TLS connection completes,
/// `offline` if it does not within [`PROBE_TIMEOUT_SECS`]. The interface shows
/// `checking` while this is in flight; it is not a value this command returns.
///
/// The connection is dropped before `Authenticate` is sent — see the module
/// documentation for why that matters.
///
/// # Errors
/// [`CommandError`] if this installation has no identity to present, or if the address
/// cannot be parsed.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn probe_device(
    address: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<String> {
    let identity = state
        .identity
        .as_ref()
        .ok_or_else(CommandError::no_identity)?;

    let parsed = address
        .parse::<rc_transport::PeerAddress>()
        .map_err(|_| CommandError::new("invalid_address", "That is not an address."))?;

    // A name that resolves to nothing is offline, not an error: the operator asked
    // whether the device is reachable, and it is not.
    let Ok(sockets) = parsed.to_socket_addrs() else {
        return Ok("offline".to_owned());
    };
    let Some(socket) = sockets.into_iter().next() else {
        return Ok("offline".to_owned());
    };

    // Trust-on-first-use, because this proves nothing and admits nobody: it is asking
    // whether anything answers, not who. Whether the identity is the expected one is
    // decided by a real connection, which pins it.
    let Ok((connector, _observed)) =
        rc_transport::ClientConnector::new(identity, rc_transport::PinPolicy::TrustOnFirstUse)
    else {
        return Ok("offline".to_owned());
    };

    let reached = tokio::time::timeout(
        std::time::Duration::from_secs(PROBE_TIMEOUT_SECS),
        connector.connect(socket),
    )
    .await;

    // Dropped here, before any stream is opened and before `Authenticate`. The far side
    // sees a connection that went away and never reaches an admission decision.
    let online = matches!(reached, Ok(Ok(_)));
    connector.close();

    Ok(if online { "online" } else { "offline" }.to_owned())
}

/// Sessions and refusals recorded on this machine, most recent first.
///
/// # Errors
/// [`CommandError`] if the local database is not available.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn list_session_history(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<Vec<SessionRecordDto>> {
    let records = rc_storage::SessionHistoryRepository::new(database(&state)?)
        .list(rc_storage::HISTORY_LIMIT)
        .await
        .map_err(|err| storage_failed(&err))?;

    Ok(records
        .into_iter()
        .map(|record| SessionRecordDto {
            id: record.id,
            session_id: record.session_id,
            identity_fingerprint: record.identity_fingerprint.map(|f| f.to_hex()),
            device_name: record.device_name,
            direction: record.direction.as_str().to_owned(),
            address: record.address,
            started_ms: record.started_ms,
            ended_ms: record.ended_ms,
            permissions: permission_names(record.permissions),
            outcome: record.outcome.as_str().to_owned(),
            end_reason: record.end_reason,
        })
        .collect())
}

/// Sessions controlling this machine right now.
///
/// # Errors
/// Never fails. The registry is in memory and always answerable — an operator must be
/// able to find out who is connected even when the database has gone away.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
#[tauri::command]
pub async fn inbound_sessions(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<Vec<InboundSessionDto>> {
    Ok(state
        .host_runtime
        .inbound_sessions()
        .await
        .into_iter()
        .map(|session| InboundSessionDto {
            session_id: session.session_id.to_canonical_string(),
            identity_fingerprint: session.identity_fingerprint.to_hex(),
            device_name: session.display_name,
            address: session.source,
            permissions: permission_names(session.permissions),
            started_ms: session.started_at_ms,
        })
        .collect())
}

/// End one session controlling this machine.
///
/// Returns whether it was there to end, rather than always reporting success: a button
/// that claims to have disconnected something already gone teaches the operator that
/// the button is decorative.
///
/// # Errors
/// Never fails.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
#[tauri::command]
pub async fn disconnect_inbound(
    session_id: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<bool> {
    // A malformed id names no session, which is exactly what `false` says.
    let Ok(parsed) = session_id.parse::<rc_protocol::SessionId>() else {
        return Ok(false);
    };
    Ok(state.host_runtime.disconnect_inbound(parsed).await)
}

/// End every session and stop accepting new ones.
///
/// The emergency stop. It closes the door as well as the sessions: ending them while
/// still accepting would let an unattended device reconnect immediately, which is not
/// what anybody reaching for this means.
///
/// Returns how many sessions were ended.
///
/// # Errors
/// Never fails on the session half. If `accepting` cannot be written the sessions are
/// still ended, and the failure is logged — ending them is the urgent part.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
#[tauri::command]
pub async fn emergency_disconnect(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<u32> {
    let ended = state.host_runtime.disconnect_all_inbound().await;

    if let Ok(db) = database(&state)
        && let Err(err) = rc_storage::SettingsRepository::new(db)
            .set_accepting(false)
            .await
    {
        tracing::error!(%err, "sessions were ended but this machine is still accepting");
    }
    state.host_runtime.stop().await;

    Ok(u32::try_from(ended).unwrap_or(u32::MAX))
}

/// Translate a single-row write, so "that device is gone" reads as itself.
fn write(outcome: rc_storage::Result<()>) -> CommandResult<()> {
    outcome.map_err(|err| match err {
        rc_storage::StorageError::NotFound => not_trusted(),
        other => storage_failed(&other),
    })
}

#[cfg(test)]
mod tests {
    use rc_security::{Permission, PermissionSet};

    use super::*;

    #[test]
    fn a_malformed_identity_is_refused_rather_than_matched_loosely() {
        for bad in ["", "not-hex", &"A".repeat(64), &"a".repeat(63)] {
            assert!(identity_of(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn a_well_formed_identity_is_accepted() {
        let identity = Fingerprint::from_bytes([7u8; 32]);
        assert_eq!(identity_of(&identity.to_hex()).unwrap(), identity);
    }

    #[test]
    fn a_missing_device_reads_as_a_missing_device_rather_than_a_save_failure() {
        // The two need different sentences: one is "refresh", the other is "check the
        // log", and showing the wrong one sends the operator to the wrong place.
        let missing = write(Err(rc_storage::StorageError::NotFound)).unwrap_err();
        assert_eq!(missing.code, "not_found");
    }

    #[test]
    fn a_trusted_device_dto_carries_no_credential() {
        // There is no secret attached to a trust relationship, and this type must not
        // acquire one. A guard against a future field that would send one to a webview.
        let dto = TrustedDeviceDto {
            identity_fingerprint: "a".repeat(64),
            device_id: "dev-1".to_owned(),
            display_name: "Gaming PC".to_owned(),
            os_family: "windows".to_owned(),
            last_address: Some("10.0.0.1:7443".to_owned()),
            added_ms: 1,
            last_connected_ms: Some(2),
            unattended: true,
            suspended: false,
            permissions: permission_names(PermissionSet::NONE.with(Permission::Administer)),
        };

        let json = serde_json::to_string(&dto).unwrap().to_lowercase();
        for forbidden in ["password", "secret", "token", "phc", "argon"] {
            assert!(!json.contains(forbidden), "must not carry {forbidden}");
        }
        assert!(json.contains("identityfingerprint"), "camelCase: {json}");
    }
}
