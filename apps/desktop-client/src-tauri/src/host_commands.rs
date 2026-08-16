//! Commands for the host side: this machine's own door.
//!
//! Kept apart from [`crate::connect_commands`], which is about reaching *out*. Nothing
//! here is gated on a session's permissions, and that is deliberate rather than an
//! omission: these are actions by the person sitting at this keyboard, deciding what
//! their own machine does. The permissions in this application describe what a *remote*
//! peer may do here; applying them to the local user would be asking the door whether
//! it may be locked.
//!
//! The same rules as the rest of the command surface apply: no secret crosses this
//! boundary — in particular the unattended password and its hash never do — errors are
//! short vetted sentences, and every response is `camelCase` for the Zod schemas that
//! parse rather than trust it.

use std::sync::Arc;

use rc_host_agent::{AcceptDecision, TrustChoice};
use rc_security::{HashingPolicy, OsRandom, PasswordCredential, PermissionSet};
use serde::Serialize;

use crate::AppState;
use crate::commands::CommandError;
use crate::host::{AcceptRequestDto, permission_names, permissions_from_names};

type CommandResult<T> = Result<T, CommandError>;

/// Whether this machine is accepting connections, and where it can be reached.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostStatusDto {
    /// Whether incoming connections are being accepted.
    pub accepting: bool,
    /// Every address a peer could dial, `host:port`.
    ///
    /// Empty on a machine with no usable network address, which is reported honestly
    /// rather than padded with a loopback address that would not work from elsewhere.
    pub addresses: Vec<String>,
    /// The name a peer sees when connecting here.
    pub machine_name: String,
    /// The port being listened on.
    pub listen_port: u16,
}

/// This machine's settings.
///
/// Note what is missing: the unattended password and its hash. `unattended_configured`
/// says only whether one exists. The hash never leaves the database, and this type is
/// hand-written rather than derived from the storage row precisely so that adding a
/// column cannot start sending one.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SettingsDto {
    /// Whether incoming connections are being accepted.
    pub accepting: bool,
    /// The port being listened on.
    pub listen_port: u16,
    /// The name a peer sees when connecting here.
    pub machine_name: String,
    /// Whether an unattended-access password is set.
    pub unattended_configured: bool,
    /// What an unattended-password connection receives. Empty unless configured.
    pub unattended_permissions: Vec<String>,
}

/// A machine this installation has connected to before.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecentDto {
    /// The address the user typed to reach it.
    pub address: String,
    /// The name it reported. Untrusted; the interface sanitises it again.
    pub machine_name: String,
    /// When a connection to it was last recorded.
    pub last_connected_ms: i64,
    /// Whether a pinned identity lets it in without asking.
    /// The identity that answered here, once one has. Compared on every later
    /// connection; a mismatch is reported rather than silently connected to.
    pub known_identity: Option<String>,
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
    // The error can name a column, a file path or a SQL fragment; the operator gets a
    // sentence and the detail goes to the log.
    tracing::warn!(%err, "a host storage operation failed");
    CommandError::new(
        "storage_failed",
        "That could not be saved. Check the application log for details.",
    )
}

/// Build the status from settings plus what is actually bound.
async fn status_of(state: &AppState) -> CommandResult<HostStatusDto> {
    let settings = rc_storage::SettingsRepository::new(database(state)?)
        .load()
        .await
        .map_err(|err| storage_failed(&err))?;

    // The port a peer must dial is the one actually bound, which can differ from the
    // configured one if a change has been saved but not applied. Reporting the
    // configured port while listening on another would have the user typing an address
    // that cannot connect.
    let port = state
        .host_runtime
        .listening_port()
        .await
        .unwrap_or(settings.listen_port);

    Ok(HostStatusDto {
        accepting: settings.accepting && state.host_runtime.is_listening().await,
        addresses: rc_platform::reachable_addresses()
            .into_iter()
            .map(|address| match address {
                // Bracketed so the port is unambiguous: `fe80::1:7443` is
                // indistinguishable from an address whose last group is 7443, and what
                // is shown here is what the user types on the other machine.
                std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
                std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
            })
            .collect(),
        machine_name: settings.machine_name,
        listen_port: port,
    })
}

/// Whether this machine is accepting, and where it can be reached.
///
/// # Errors
/// [`CommandError`] if the local database is not available.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn host_status(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<HostStatusDto> {
    status_of(&state).await
}

/// Start or stop accepting incoming connections.
///
/// The setting is written first and the listener started second, so a listener can
/// never be running while the stored answer says it should not be. The decision layer
/// reads that same setting and refuses independently, so the two together fail closed.
///
/// # Errors
/// [`CommandError`] if the database is unavailable, if this installation has no
/// identity to present, or if the port cannot be bound.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn set_accepting(
    accepting: bool,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<HostStatusDto> {
    let db = database(&state)?;
    let settings_repo = rc_storage::SettingsRepository::new(db);

    settings_repo
        .set_accepting(accepting)
        .await
        .map_err(|err| storage_failed(&err))?;

    if accepting {
        let identity = state
            .identity
            .as_ref()
            .ok_or_else(CommandError::no_identity)?;
        let settings = settings_repo
            .load()
            .await
            .map_err(|err| storage_failed(&err))?;

        if let Err(err) = state
            .host_runtime
            .start(Arc::clone(identity), db, settings.listen_port)
            .await
        {
            // The stored answer said yes and the socket said no. Put the setting back
            // rather than leaving the interface claiming to accept connections that
            // nothing is listening for.
            tracing::error!(%err, "could not start accepting connections");
            let _ = settings_repo.set_accepting(false).await;
            return Err(CommandError::host(format!(
                "Could not listen on port {}. Another program may be using it.",
                settings.listen_port
            )));
        }
    } else {
        state.host_runtime.stop().await;
    }

    status_of(&state).await
}

/// The connection waiting on a decision, if one is waiting.
///
/// Polled by the window on startup as well as driven by the `rc://accept-request`
/// event: an event emitted before the webview was listening reaches nobody, and a
/// request that raised no dialog would sit until it timed out.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
#[tauri::command]
pub async fn pending_accept_request(
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<Option<AcceptRequestDto>> {
    Ok(state.host_runtime.prompt().pending().await)
}

/// Answer a pending accept request.
///
/// An empty `granted` is passed through as an accept of nothing rather than being
/// turned into a dismissal here. The decision layer already treats an empty grant as a
/// refusal, in one place that every door funnels through; deciding it a second time
/// here would be a second rule that could disagree with that one.
///
/// `trust` says how much of the answer outlives the connection. Persisting it is the
/// decision layer's job, not this command's: writing the trust row here would mean a
/// second place that could remember a device the rule had actually refused.
///
/// # Errors
/// [`CommandError`] if `granted` names a permission this build does not know, or if
/// `trust` is not one of the three choices.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn answer_accept_request(
    request_id: String,
    granted: Vec<String>,
    trust: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<()> {
    let permissions = permissions_from_names(&granted).ok_or_else(|| {
        CommandError::new(
            "unknown_permission",
            "That permission is not one this version understands. Update both machines.",
        )
    })?;

    let trust = trust_choice_from_name(&trust).ok_or_else(|| {
        CommandError::new(
            "unknown_trust_choice",
            "That is not a trust choice this version understands.",
        )
    })?;

    state
        .host_runtime
        .prompt()
        .answer(&request_id, AcceptDecision::Accept { permissions, trust })
        .await;

    Ok(())
}

/// The wire name of a trust choice, as the interface sends it.
///
/// A closed set: an unrecognised value is refused rather than falling back to the most
/// permissive -- or, worse, to the most permissive-looking. `remember_unattended` is
/// the only value that grants access without a human, and it must never be reachable by
/// a typo.
fn trust_choice_from_name(name: &str) -> Option<TrustChoice> {
    match name {
        "once" => Some(TrustChoice::Once),
        "remember" => Some(TrustChoice::Remember),
        "remember_unattended" => Some(TrustChoice::RememberUnattended),
        _ => None,
    }
}

/// Dismiss a pending accept request.
///
/// A separate command from [`answer_accept_request`] with an empty grant, so that
/// "No" is an explicit act in the interface rather than an accept that happens to
/// carry nothing.
///
/// # Errors
/// Never fails: a dismissal of a request that has already gone changes nothing, which
/// is the outcome the user asked for.
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)]
#[tauri::command]
pub async fn dismiss_accept_request(
    request_id: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<()> {
    state
        .host_runtime
        .prompt()
        .answer(&request_id, AcceptDecision::Dismiss)
        .await;
    Ok(())
}

/// Machines connected to before, most recent first.
///
/// # Errors
/// [`CommandError`] if the local database is not available.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn list_recent(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<Vec<RecentDto>> {
    let entries = rc_storage::RecentRepository::new(database(&state)?)
        .list()
        .await
        .map_err(|err| storage_failed(&err))?;

    Ok(entries
        .into_iter()
        .map(|entry| RecentDto {
            address: entry.address,
            machine_name: entry.machine_name,
            last_connected_ms: entry.last_connected_ms,
            known_identity: entry.known_identity.map(|identity| identity.to_hex()),
        })
        .collect())
}

/// Forget a machine from the dial history.
///
/// This is the *outgoing* list. It does not revoke anything: incoming trust lives in
/// My Devices, keyed on a device identity, and is revoked there. Removing an address
/// here forgets where this machine dialled, nothing more.
///
/// # Errors
/// [`CommandError`] if the local database is not available.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn remove_recent(
    address: String,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<()> {
    rc_storage::RecentRepository::new(database(&state)?)
        .remove(&address)
        .await
        .map_err(|err| storage_failed(&err))
}

/// This machine's settings.
///
/// # Errors
/// [`CommandError`] if the local database is not available.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn host_settings(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<SettingsDto> {
    let repo = rc_storage::SettingsRepository::new(database(&state)?);
    let settings = repo.load().await.map_err(|err| storage_failed(&err))?;

    // Asked separately rather than inferred from the permissions: a configured password
    // granting nothing is a real state, and reading "has permissions" as "has a
    // password" would report it as unconfigured.
    let configured = repo
        .unattended_credential()
        .await
        .map_err(|err| storage_failed(&err))?
        .is_some();

    Ok(SettingsDto {
        accepting: settings.accepting,
        listen_port: settings.listen_port,
        machine_name: settings.machine_name,
        unattended_configured: configured,
        unattended_permissions: permission_names(settings.unattended_permissions),
    })
}

/// Set or clear the unattended-access password.
///
/// The password is hashed here and the plaintext is dropped; nothing stores it and
/// nothing sends it back. Passing `null` clears both the password and what it granted,
/// in one write, so a cleared password can never leave permissions behind for whatever
/// is set next.
///
/// # Errors
/// [`CommandError`] if the password is too short, if `permissions` names something this
/// build does not know, or if the database is unavailable.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn set_unattended_password(
    password: Option<String>,
    permissions: Vec<String>,
    state: tauri::State<'_, Arc<AppState>>,
) -> CommandResult<()> {
    let repo = rc_storage::SettingsRepository::new(database(&state)?);

    let Some(password) = password else {
        return repo
            .set_unattended(None, PermissionSet::NONE)
            .await
            .map_err(|err| storage_failed(&err));
    };

    let granted = permissions_from_names(&permissions).ok_or_else(|| {
        CommandError::new(
            "unknown_permission",
            "That permission is not one this version understands.",
        )
    })?;

    if granted.is_empty() {
        return Err(CommandError::new(
            "empty_grant",
            "Choose at least one thing an unattended connection may do, or clear the \
             password instead.",
        ));
    }

    // Hashing is deliberately slow, so it runs off the async worker rather than
    // stalling every other task on this runtime for the duration.
    let credential = tokio::task::spawn_blocking(move || {
        PasswordCredential::create(&password, HashingPolicy::PRODUCTION, &OsRandom)
    })
    .await
    .map_err(|err| {
        tracing::error!(%err, "the password hashing task failed");
        CommandError::new(
            "storage_failed",
            "The password could not be set. Check the application log for details.",
        )
    })?
    .map_err(|err| {
        // The message names the rule that was broken — a length floor — and carries
        // nothing derived from the password itself.
        tracing::info!(%err, "an unattended password was refused");
        CommandError::new(
            "weak_password",
            "That password is too short. Use at least 12 characters.",
        )
    })?;

    repo.set_unattended(Some(&credential), granted)
        .await
        .map_err(|err| storage_failed(&err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settings_dto_cannot_carry_a_password_or_a_hash() {
        // The one thing this type exists to keep on this side of the boundary. A field
        // added to the storage row must not reach the webview, so the serialised shape
        // is pinned rather than trusted.
        let dto = SettingsDto {
            accepting: true,
            listen_port: 7443,
            machine_name: "KOREN-PC".to_owned(),
            unattended_configured: true,
            unattended_permissions: vec!["view_metrics".to_owned()],
        };
        let json = serde_json::to_value(&dto).unwrap();
        let object = json.as_object().unwrap();

        assert_eq!(
            object.len(),
            5,
            "exactly five fields cross the boundary, got {json}"
        );
        for key in [
            "accepting",
            "listenPort",
            "machineName",
            "unattendedConfigured",
            "unattendedPermissions",
        ] {
            assert!(object.contains_key(key), "missing key {key}");
        }

        let text = json.to_string();
        assert!(!text.contains("argon2"), "no hash may appear: {text}");
        assert!(!text.contains('$'), "no PHC string may appear: {text}");
    }

    #[test]
    fn the_dtos_are_serialised_in_camel_case() {
        // A mismatch here would only surface at runtime, as a Zod validation error.
        let status = serde_json::to_value(&HostStatusDto {
            accepting: true,
            addresses: vec!["192.168.1.42:7443".to_owned()],
            machine_name: "KOREN-PC".to_owned(),
            listen_port: 7443,
        })
        .unwrap();
        for key in ["accepting", "addresses", "machineName", "listenPort"] {
            assert!(status.get(key).is_some(), "missing key {key}");
        }

        let recent = serde_json::to_value(&RecentDto {
            address: "192.168.1.77:7443".to_owned(),
            machine_name: "WORK-LAPTOP".to_owned(),
            last_connected_ms: 1,
            known_identity: Some("a".repeat(64)),
        })
        .unwrap();
        for key in ["address", "machineName", "lastConnectedMs", "knownIdentity"] {
            assert!(recent.get(key).is_some(), "missing key {key}");
        }
    }

    #[test]
    fn an_ipv6_address_is_bracketed_so_the_port_is_unambiguous() {
        // `fe80::1:7443` is indistinguishable from an address whose last group is 7443.
        // Whatever is shown here is what the user types on the other machine, and
        // `PeerAddress` requires the brackets to read the port.
        let formatted = |address: std::net::IpAddr, port: u16| match address {
            std::net::IpAddr::V6(v6) => format!("[{v6}]:{port}"),
            std::net::IpAddr::V4(v4) => format!("{v4}:{port}"),
        };

        assert_eq!(
            formatted("192.168.1.42".parse().unwrap(), 7443),
            "192.168.1.42:7443"
        );
        assert_eq!(
            formatted("2001:db8::1".parse().unwrap(), 7443),
            "[2001:db8::1]:7443"
        );
    }
}
