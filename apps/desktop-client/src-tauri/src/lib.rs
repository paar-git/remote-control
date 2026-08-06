//! Desktop client backend.
//!
//! The client process runs **unelevated**, by design. It never performs privileged
//! operating-system work itself; anything requiring Administrator or root is sent to
//! the host agent over an authenticated session and executed there through the
//! allowlist in `rc-platform::privileged`.
//!
//! Commands exposed to the webview are declared in [`run`]. Each one returns a typed
//! error string rather than a Rust error, because the webview must never receive an
//! internal error chain that could disclose local paths.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod commands;
mod connect_commands;
mod connection;
mod file_commands;
mod session_commands;

use std::sync::{Arc, Mutex};

use rc_platform::{AppPaths, HostInfo};
use rc_security::permissions::{AuthorizationContext, Capability, Role};
use rc_security::{Clock, DeviceIdentity, SystemClock};
use rc_storage::audit::AuditEvent;
use serde::Serialize;

/// An authenticated owner session, held in memory only.
///
/// Deliberately not persisted: unlocking the application is a per-run action, so
/// closing the app relocks it.
#[derive(Debug, Clone)]
pub struct OwnerSession {
    /// Account identifier.
    pub account_id: String,
    /// Login name.
    pub username: String,
    /// Role. Always [`Role::Owner`] in v1.
    pub role: Role,
}

/// Shared backend state, created once during setup.
pub struct AppState {
    /// Facts about this machine, gathered at startup.
    pub host: HostInfo,
    /// Where the client keeps its config, data and logs.
    pub paths: AppPaths,
    /// The client's local database, if it opened successfully.
    ///
    /// A failure here is not fatal: the UI must still start so it can *tell* the user
    /// what went wrong, rather than showing a window that never appears.
    pub database: Option<rc_storage::Database>,
    /// This client's cryptographic identity, loaded from the keystore.
    ///
    /// Shared rather than owned because the connection manager holds it for the life
    /// of every connection it makes; a `DeviceIdentity` is deliberately not `Clone`,
    /// since duplicating a private key is not something that should be easy to do by
    /// accident.
    pub identity: Option<Arc<DeviceIdentity>>,
    /// Owner account repository.
    pub owner: Option<rc_storage::OwnerRepository>,
    /// Trusted-device repository.
    pub trust: Option<rc_storage::TrustRepository>,
    /// Audit repository.
    pub audit_repo: Option<rc_storage::AuditRepository>,
    /// The authenticated session, if the application is unlocked.
    pub session: Mutex<Option<OwnerSession>>,
    /// The connection to a saved server, when this client has an identity to use.
    ///
    /// `None` only when the keystore could not be loaded, in which case the window
    /// still opens so the user can be told why rather than watching nothing happen.
    pub connection: Option<Arc<connection::ConnectionManager>>,
    /// Time source. Injected so tests can control it.
    pub clock: Arc<dyn Clock>,
}

impl AppState {
    /// The authorization context for the current session.
    ///
    /// Returns `None` when the application is locked. Note that this is *application*
    /// authorization only: it never implies operating-system privilege, which stays
    /// behind the agent's allowlist.
    #[must_use]
    pub fn authorization(&self) -> Option<AuthorizationContext> {
        let session = self.session.lock().ok()?;
        session.as_ref().map(|s| AuthorizationContext::new(s.role))
    }

    /// Enforce that the current session holds `capability`.
    ///
    /// Every capability check goes through here rather than through scattered
    /// `is_owner` tests, so adding a role means changing the permission table and
    /// nothing else.
    fn require_capability(&self, capability: Capability) -> Result<(), commands::CommandError> {
        match self.authorization() {
            None => Err(commands::CommandError::locked()),
            Some(context) => context
                .require(capability)
                .map_err(|_| commands::CommandError::permission_denied(capability)),
        }
    }

    /// Append an audit record, logging rather than failing if the write does not work.
    ///
    /// Losing an audit row is bad; aborting a completed security action because the
    /// log write failed would be worse.
    async fn audit(&self, event: AuditEvent) {
        let Some(repo) = self.audit_repo.as_ref() else {
            return;
        };
        if let Err(err) = repo.record(&event, self.clock.now_ms()).await {
            tracing::error!(%err, action = event.action, "could not write an audit record");
        }
    }
}

/// Protocol version, in the shape the frontend schema expects.
#[derive(Debug, Serialize)]
pub struct ProtocolVersionDto {
    /// Breaking-change component.
    pub major: u16,
    /// Additive-change component.
    pub minor: u16,
}

/// Response of the `client_info` command.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientInfo {
    /// Version of this client build.
    pub app_version: String,
    /// Wire protocol version implemented.
    pub protocol_version: ProtocolVersionDto,
    /// Machine hostname.
    pub hostname: String,
    /// OS family.
    pub os_family: String,
    /// Human-readable OS version.
    pub os_version: String,
    /// CPU architecture.
    pub architecture: String,
    /// Whether this process is elevated. Expected to be `false`.
    pub elevated: bool,
    /// Whether the local database opened and migrated.
    pub database_ready: bool,
}

/// Report information about the client and the machine it runs on.
///
/// Deliberately excludes filesystem paths: the webview has no need for them, and
/// leaking them would widen the impact of any future rendering bug.
// `tauri::State` must be taken by value: it is a cheap handle, and the command macro
// requires this signature to perform its extraction.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
fn client_info(state: tauri::State<'_, Arc<AppState>>) -> ClientInfo {
    let host = &state.host;
    ClientInfo {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: ProtocolVersionDto {
            major: rc_protocol::CURRENT_VERSION.major,
            minor: rc_protocol::CURRENT_VERSION.minor,
        },
        hostname: host.hostname.clone(),
        os_family: os_family_str(host.os_family).to_string(),
        os_version: host.os_version.clone(),
        architecture: host.architecture.clone(),
        elevated: rc_platform::is_elevated(),
        database_ready: state.database.is_some(),
    }
}

/// Serialise an [`rc_protocol::control::OsFamily`] the way the frontend schema expects.
fn os_family_str(family: rc_protocol::control::OsFamily) -> &'static str {
    use rc_protocol::control::OsFamily;
    match family {
        OsFamily::Windows => "windows",
        OsFamily::Linux => "linux",
        OsFamily::MacOs => "macos",
        _ => "unknown",
    }
}

/// Build the backend state: directories, keystore, database and repositories.
///
/// Every step degrades rather than aborting. A client that cannot open its database
/// still opens its window, so the user is *told* what is wrong instead of watching
/// nothing happen.
async fn initialise() -> Arc<AppState> {
    let host = HostInfo::detect();
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);

    let empty = |paths: AppPaths| AppState {
        host: host.clone(),
        paths,
        database: None,
        identity: None,
        owner: None,
        trust: None,
        audit_repo: None,
        session: Mutex::new(None),
        connection: None,
        clock: Arc::clone(&clock),
    };

    let paths = match AppPaths::for_client() {
        Ok(paths) => paths,
        Err(err) => {
            tracing::error!(%err, "could not resolve client directories");
            // Nothing further can be persisted, but the window must still open so the
            // user sees the failure instead of nothing happening.
            return Arc::new(empty(AppPaths::with_root(
                std::env::temp_dir().join("remote-control"),
            )));
        }
    };

    if let Err(err) = paths.create_all() {
        tracing::error!(%err, "could not create client directories");
        return Arc::new(empty(paths));
    }

    // The keystore is loaded before the database: without an identity the client
    // cannot pair or connect, so a failure here is worth reporting prominently.
    let keystore = rc_security::Keystore::in_data_dir(paths.data_dir());
    let identity = match keystore.load_or_create(&host.hostname, clock.as_ref()) {
        Ok(identity) => {
            tracing::info!(
                device_id = %identity.device_id(),
                identity_fingerprint = %identity.public().identity_fingerprint,
                certificate_version = identity.public().certificate_version,
                "client identity ready"
            );
            Some(Arc::new(identity))
        }
        Err(err) => {
            tracing::error!(%err, "could not load or create the client identity");
            None
        }
    };

    let database = match rc_storage::Database::open(paths.database_file()).await {
        Ok(db) => {
            tracing::info!(path = %paths.database_file().display(), "client database ready");
            Some(db)
        }
        Err(err) => {
            tracing::error!(%err, "could not open the client database");
            None
        }
    };

    let (owner, trust, audit_repo) = database.as_ref().map_or((None, None, None), |db| {
        (
            Some(rc_storage::OwnerRepository::new(db)),
            Some(rc_storage::TrustRepository::new(db)),
            Some(rc_storage::AuditRepository::new(db)),
        )
    });

    // The connection manager needs an identity: without one this client cannot
    // authenticate to anything, and offering a Connect button that could only fail
    // would be worse than not offering it.
    let connection = identity.as_ref().map(|identity| {
        let descriptor = connection::client_descriptor(identity, &host);
        Arc::new(connection::ConnectionManager::new(
            Arc::clone(identity),
            descriptor,
            connection::client_capabilities(),
        ))
    });

    Arc::new(AppState {
        host,
        paths,
        database,
        identity,
        owner,
        trust,
        audit_repo,
        session: Mutex::new(None),
        connection,
        clock,
    })
}

/// Start the desktop client.
///
/// Returns only when the application exits. If the webview runtime cannot start there
/// is no window in which to show an error, so the failure is logged and the process
/// exits non-zero rather than panicking with an unhelpful backtrace.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        protocol = %rc_protocol::CURRENT_VERSION,
        "starting desktop client"
    );

    let state = tauri::async_runtime::block_on(initialise());

    if rc_platform::is_elevated() {
        tracing::warn!(
            "the desktop client is running elevated; this is unnecessary and reduces \
             the isolation between the UI and privileged operations"
        );
    }

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            client_info,
            commands::local_identity,
            commands::owner_status,
            commands::create_owner,
            commands::owner_login,
            commands::owner_logout,
            commands::list_trusted_devices,
            commands::rename_trusted_device,
            commands::revoke_trusted_device,
            commands::recent_audit_events,
            commands::check_pairing_code_format,
            connect_commands::discover_agents,
            connect_commands::pair_with_server,
            connect_commands::connect_to_server,
            connect_commands::disconnect_from_server,
            connect_commands::reconnect_to_server,
            connect_commands::connection_state,
            connect_commands::ping_server,
            session_commands::system_snapshot,
            session_commands::server_facts,
            session_commands::open_terminal,
            session_commands::send_terminal_input,
            session_commands::resize_terminal,
            session_commands::close_terminal,
            file_commands::list_remote_directory,
            file_commands::list_local_directory,
            file_commands::default_local_directory,
            file_commands::create_remote_directory,
            file_commands::delete_remote_path,
            file_commands::rename_remote_path,
            file_commands::upload_file,
            file_commands::download_file,
        ])
        .run(tauri::generate_context!());

    if let Err(err) = result {
        tracing::error!(%err, "the webview runtime failed to start");
        eprintln!("Remote Control could not start its window: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rc_protocol::control::OsFamily;

    #[test]
    fn os_family_strings_match_the_frontend_schema() {
        // These exact strings are what `clientInfoSchema` in api.ts accepts.
        assert_eq!(os_family_str(OsFamily::Windows), "windows");
        assert_eq!(os_family_str(OsFamily::Linux), "linux");
        assert_eq!(os_family_str(OsFamily::MacOs), "macos");
        assert_eq!(os_family_str(OsFamily::Unknown), "unknown");
    }

    #[tokio::test]
    async fn initialise_produces_usable_state() {
        let state = initialise().await;
        assert!(!state.host.hostname.is_empty());
        assert!(state.host.logical_cores >= 1);
    }

    #[test]
    fn client_info_is_serialised_in_camel_case() {
        // The frontend schema uses camelCase keys; a mismatch here would only surface
        // at runtime as a validation error, so it is pinned by a test.
        let info = ClientInfo {
            app_version: "0.1.0".into(),
            protocol_version: ProtocolVersionDto { major: 1, minor: 0 },
            hostname: "h".into(),
            os_family: "linux".into(),
            os_version: "v".into(),
            architecture: "x86_64".into(),
            elevated: false,
            database_ready: true,
        };
        let json = serde_json::to_value(&info).unwrap();

        for key in [
            "appVersion",
            "protocolVersion",
            "hostname",
            "osFamily",
            "osVersion",
            "architecture",
            "elevated",
            "databaseReady",
        ] {
            assert!(json.get(key).is_some(), "missing key {key}");
        }
    }

    #[test]
    fn client_info_does_not_leak_local_paths() {
        // The webview has no need for filesystem paths and must not receive them.
        let info = ClientInfo {
            app_version: "0.1.0".into(),
            protocol_version: ProtocolVersionDto { major: 1, minor: 0 },
            hostname: "h".into(),
            os_family: "windows".into(),
            os_version: "v".into(),
            architecture: "x86_64".into(),
            elevated: false,
            database_ready: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("C:\\"), "no Windows paths");
        assert!(!json.contains("/home/"), "no Unix home paths");
        assert!(!json.to_lowercase().contains(".db"), "no database path");
    }
}
