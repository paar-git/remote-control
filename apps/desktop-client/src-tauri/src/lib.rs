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

use std::sync::Arc;

use rc_platform::{AppPaths, HostInfo};
use serde::Serialize;

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

/// Build the backend state: directories, logging and the local database.
async fn initialise() -> Arc<AppState> {
    let host = HostInfo::detect();

    let paths = match AppPaths::for_client() {
        Ok(paths) => paths,
        Err(err) => {
            tracing::error!(%err, "could not resolve client directories");
            // Nothing further can be persisted, but the window must still open so the
            // user sees the failure instead of nothing happening.
            return Arc::new(AppState {
                host,
                paths: AppPaths::with_root(std::env::temp_dir().join("remote-control")),
                database: None,
            });
        }
    };

    if let Err(err) = paths.create_all() {
        tracing::error!(%err, "could not create client directories");
        return Arc::new(AppState {
            host,
            paths,
            database: None,
        });
    }

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

    Arc::new(AppState {
        host,
        paths,
        database,
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
        .invoke_handler(tauri::generate_handler![client_info])
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
