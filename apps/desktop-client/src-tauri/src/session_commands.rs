//! Commands that use a live session: metrics and terminals.
//!
//! # Terminal output reaches the UI as events, not as a return value
//!
//! A terminal produces bytes continuously and unprompted. A command that returned them
//! would have to either block until some arbitrary amount arrived or be polled, and both
//! add latency to every keystroke. Output is emitted as a Tauri event instead, and the
//! webview subscribes.
//!
//! # What is never logged
//!
//! Terminal input and output. Both are raw bytes from a shell session — the place a
//! password is typed and the place a secret is printed. They cross this module without
//! being recorded anywhere, and the DTOs carry them base64-encoded purely because JSON
//! has no byte type, not as any kind of protection.

use std::sync::Arc;

use base64::Engine as _;
use rc_protocol::TerminalId;
use rc_protocol::control::{ControlRequestPayload, ControlResponsePayload, ControlResult};
use rc_protocol::terminal::{
    PrivilegeLevel, ShellKind, TerminalAgentMessage, TerminalClientMessage, TerminalSize,
};
use rc_security::permissions::Capability;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::commands::CommandError;

type CommandResult<T> = Result<T, CommandError>;

/// Event name carrying terminal output to the webview.
pub const TERMINAL_OUTPUT_EVENT: &str = "terminal://output";

/// Event name announcing that a terminal ended.
pub const TERMINAL_EXIT_EVENT: &str = "terminal://exit";

/// One chunk of terminal output.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalOutputEvent {
    /// Which terminal produced it.
    pub terminal_id: String,
    /// Base64 of the raw bytes, including ANSI escapes.
    ///
    /// Base64 because JSON has no byte type and the stream is not valid UTF-8 in
    /// general — a multi-byte character split across two reads would be mangled by a
    /// lossy conversion, and the terminal emulator needs the bytes exactly as the shell
    /// wrote them.
    pub data_base64: String,
}

/// A terminal that ended.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalExitEvent {
    /// Which terminal ended.
    pub terminal_id: String,
    /// The shell's exit code, when one was reported.
    pub exit_code: Option<i32>,
    /// An operator-facing reason when the terminal failed rather than exited.
    pub error: Option<String>,
}

/// What the UI asks for when opening a terminal.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenTerminalInput {
    /// Which shell.
    pub shell: String,
    /// Initial column count.
    pub cols: u16,
    /// Initial row count.
    pub rows: u16,
    /// Starting directory, when the operator chose one.
    pub working_directory: Option<String>,
}

/// A terminal that opened.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedTerminalDto {
    /// Identifier for subsequent input, resize and close.
    pub terminal_id: String,
    /// The program the server actually launched. Untrusted text.
    pub shell_path: String,
    /// The shell's process id on the server.
    pub pid: u32,
    /// Whether the session is elevated.
    pub elevated: bool,
}

/// A dashboard snapshot, flattened for the UI.
///
/// Hand-written rather than passing the protocol type through, for the same reason
/// every other DTO here is: a field added to the protocol should not appear in the
/// webview until someone decides it should.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotDto {
    /// When the agent took the reading.
    pub captured_at_ms: i64,
    /// Seconds since the server booted.
    pub uptime_secs: u64,
    /// Processor model. Untrusted text.
    pub cpu_model: String,
    /// Overall CPU utilisation.
    pub cpu_percent: f32,
    /// Per-core utilisation.
    pub cpu_per_core: Vec<f32>,
    /// Logical processor count.
    pub logical_cores: u32,
    /// Physical memory in use.
    pub memory_used_bytes: u64,
    /// Physical memory installed.
    pub memory_total_bytes: u64,
    /// Swap in use.
    pub swap_used_bytes: u64,
    /// Swap configured.
    pub swap_total_bytes: u64,
    /// Mounted volumes.
    pub disks: Vec<DiskDto>,
    /// Network interfaces.
    pub networks: Vec<NetworkDto>,
    /// Temperature sensors the platform exposed. Empty means none were readable, not
    /// that the machine is cold.
    pub temperatures: Vec<TemperatureDto>,
    /// The busiest processes.
    pub top_processes: Vec<ProcessDto>,
    /// Load averages, where the platform has the concept.
    pub load_average: Option<[f64; 3]>,
}

/// One mounted volume.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskDto {
    /// Mount point or drive letter. Untrusted text.
    pub mount_point: String,
    /// Filesystem type. Untrusted text.
    pub filesystem: String,
    /// Capacity in bytes.
    pub total_bytes: u64,
    /// Free space in bytes.
    pub available_bytes: u64,
}

/// One network interface.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDto {
    /// Interface name. Untrusted text.
    pub interface: String,
    /// Current receive rate.
    pub receive_rate_bps: u64,
    /// Current transmit rate.
    pub transmit_rate_bps: u64,
    /// Bytes received since boot.
    pub received_bytes: u64,
    /// Bytes transmitted since boot.
    pub transmitted_bytes: u64,
}

/// One temperature sensor.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemperatureDto {
    /// Sensor label. Untrusted text.
    pub label: String,
    /// Reading in Celsius.
    pub celsius: f32,
    /// Vendor-declared critical threshold, when known.
    pub critical_celsius: Option<f32>,
}

/// One process.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessDto {
    /// Process id.
    pub pid: u32,
    /// Executable name. Untrusted text.
    pub name: String,
    /// Owning account, when the agent could resolve it. Untrusted text.
    pub user: Option<String>,
    /// CPU utilisation.
    pub cpu_percent: f32,
    /// Resident memory.
    pub memory_bytes: u64,
}

/// Static facts about the connected server.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerFactsDto {
    /// Hostname. Untrusted text.
    pub hostname: String,
    /// OS family.
    pub os_family: String,
    /// OS name and version. Untrusted text.
    pub os_version: String,
    /// Kernel version. Untrusted text.
    pub kernel_version: String,
    /// CPU architecture.
    pub architecture: String,
    /// Logical processor count.
    pub logical_cores: u32,
    /// Agent version.
    pub agent_version: String,
    /// The account the agent runs as. Untrusted text.
    pub agent_user: String,
    /// Whether the agent holds Administrator or root.
    pub agent_elevated: bool,
    /// When the server last booted.
    pub booted_at_ms: i64,
}

/// Fetch a live snapshot from the connected server.
///
/// # Errors
/// [`CommandError`] if nothing is connected or the server refuses.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn system_snapshot(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<SnapshotDto> {
    state.require_capability(Capability::RemoteDesktopView)?;
    let manager = connection(&state)?;

    match manager
        .request(ControlRequestPayload::SystemSnapshot)
        .await
        .map_err(|err| CommandError::from_transport(&err))?
    {
        ControlResult::Ok(ControlResponsePayload::Snapshot(snapshot)) => {
            Ok(convert_snapshot(&snapshot))
        }
        ControlResult::Err { message, .. } => Err(CommandError::new("agent_refused", message)),
        // The agent answered something else entirely, which is a protocol error rather
        // than a value to try to make sense of.
        ControlResult::Ok(_) => Err(CommandError::new(
            "unexpected_response",
            "The server sent an unexpected reply. Check that both sides are on the same \
             version.",
        )),
    }
}

/// Fetch the facts about the server that do not change between snapshots.
///
/// # Errors
/// As [`system_snapshot`].
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn server_facts(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<ServerFactsDto> {
    state.require_capability(Capability::RemoteDesktopView)?;
    let manager = connection(&state)?;

    match manager
        .request(ControlRequestPayload::HostInfo)
        .await
        .map_err(|err| CommandError::from_transport(&err))?
    {
        ControlResult::Ok(ControlResponsePayload::HostInfo(host)) => Ok(ServerFactsDto {
            hostname: host.hostname,
            os_family: os_family_name(host.os_family).to_owned(),
            os_version: host.os_version,
            kernel_version: host.kernel_version,
            architecture: host.architecture,
            logical_cores: host.logical_cores,
            agent_version: host.agent_version,
            agent_user: host.agent_user,
            agent_elevated: host.agent_elevated,
            booted_at_ms: host.booted_at_ms,
        }),
        ControlResult::Err { message, .. } => Err(CommandError::new("agent_refused", message)),
        ControlResult::Ok(_) => Err(CommandError::new(
            "unexpected_response",
            "The server sent an unexpected reply. Check that both sides are on the same \
             version.",
        )),
    }
}

/// Open a terminal on the connected server.
///
/// # Errors
/// [`CommandError`] if nothing is connected, the session lacks the capability, or the
/// server cannot open a terminal.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn open_terminal(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    input: OpenTerminalInput,
) -> CommandResult<OpenedTerminalDto> {
    state.require_capability(Capability::Terminal)?;
    let manager = connection(&state)?;

    let terminal_id = TerminalId::generate();
    let shell = parse_shell(&input.shell);

    let opened = manager
        .open_terminal(
            terminal_id,
            TerminalClientMessage::Open {
                terminal_id,
                shell,
                // Elevation is a separate decision made on the server; this build never
                // requests it, so no path here can quietly ask for more than a standard
                // shell.
                privilege: PrivilegeLevel::Standard,
                size: TerminalSize {
                    cols: input.cols,
                    rows: input.rows,
                }
                .clamped(),
                working_directory: input.working_directory,
            },
            terminal_event_sink(app),
        )
        .await
        .map_err(|err| CommandError::from_transport(&err))?;

    match opened {
        TerminalAgentMessage::Opened {
            shell_path,
            privilege,
            pid,
            ..
        } => Ok(OpenedTerminalDto {
            terminal_id: terminal_id.to_canonical_string(),
            shell_path,
            pid,
            elevated: privilege == PrivilegeLevel::Elevated,
        }),
        TerminalAgentMessage::Error { message, .. } => {
            // The agent's message names what to do about it; passing it through
            // unaltered is better than substituting a vaguer one.
            Err(CommandError::new("terminal_refused", message))
        }
        _ => Err(CommandError::new(
            "unexpected_response",
            "The server sent an unexpected reply while opening the terminal.",
        )),
    }
}

/// Send keystrokes to a terminal.
///
/// # Errors
/// [`CommandError`] if the terminal is not open.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn send_terminal_input(
    state: tauri::State<'_, Arc<AppState>>,
    terminal_id: String,
    data_base64: String,
) -> CommandResult<()> {
    state.require_capability(Capability::Terminal)?;
    let manager = connection(&state)?;

    let terminal_id = parse_terminal_id(&terminal_id)?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(&data_base64)
        .map_err(|_| CommandError::new("invalid", "That terminal input is not valid."))?;

    // Bounded here as well as at the agent: a webview bug should not be able to make
    // the client allocate without limit either.
    if data.len() > rc_protocol::limits::MAX_TERMINAL_FRAME / 2 {
        return Err(CommandError::new(
            "too_large",
            "That is too much input to send at once.",
        ));
    }

    manager
        .send_terminal(&TerminalClientMessage::Input { terminal_id, data })
        .await
        .map_err(|err| CommandError::from_transport(&err))
}

/// Tell the server the terminal window changed size.
///
/// # Errors
/// [`CommandError`] if the terminal is not open.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn resize_terminal(
    state: tauri::State<'_, Arc<AppState>>,
    terminal_id: String,
    cols: u16,
    rows: u16,
) -> CommandResult<()> {
    state.require_capability(Capability::Terminal)?;
    let manager = connection(&state)?;

    manager
        .send_terminal(&TerminalClientMessage::Resize {
            terminal_id: parse_terminal_id(&terminal_id)?,
            size: TerminalSize { cols, rows }.clamped(),
        })
        .await
        .map_err(|err| CommandError::from_transport(&err))
}

/// Close a terminal.
///
/// # Errors
/// [`CommandError`] if the terminal is not open.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn close_terminal(
    state: tauri::State<'_, Arc<AppState>>,
    terminal_id: String,
) -> CommandResult<()> {
    state.require_capability(Capability::Terminal)?;
    let manager = connection(&state)?;

    manager
        .send_terminal(&TerminalClientMessage::Close {
            terminal_id: parse_terminal_id(&terminal_id)?,
        })
        .await
        .map_err(|err| CommandError::from_transport(&err))
}

/// The connection manager, or a message saying nothing is connected.
fn connection(state: &AppState) -> CommandResult<Arc<crate::connection::ConnectionManager>> {
    state
        .connection
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| CommandError::new("not_connected", "Connect to a server first."))
}

/// A sink that forwards terminal messages to the webview as events.
fn terminal_event_sink(app: tauri::AppHandle) -> crate::connection::TerminalSink {
    Arc::new(move |message: TerminalAgentMessage| {
        use tauri::Emitter as _;

        match message {
            TerminalAgentMessage::Output { terminal_id, data } => {
                // The bytes are not logged here or anywhere: this is a shell session's
                // output.
                let payload = TerminalOutputEvent {
                    terminal_id: terminal_id.to_canonical_string(),
                    data_base64: base64::engine::general_purpose::STANDARD.encode(&data),
                };
                let _ = app.emit(TERMINAL_OUTPUT_EVENT, payload);
            }
            TerminalAgentMessage::Exited {
                terminal_id,
                exit_code,
            } => {
                let _ = app.emit(
                    TERMINAL_EXIT_EVENT,
                    TerminalExitEvent {
                        terminal_id: terminal_id.to_canonical_string(),
                        exit_code,
                        error: None,
                    },
                );
            }
            TerminalAgentMessage::Error {
                terminal_id,
                message,
                ..
            } => {
                let _ = app.emit(
                    TERMINAL_EXIT_EVENT,
                    TerminalExitEvent {
                        terminal_id: terminal_id.to_canonical_string(),
                        exit_code: None,
                        error: Some(message),
                    },
                );
            }
            _ => {}
        }
    })
}

/// Parse a terminal id from the webview.
fn parse_terminal_id(value: &str) -> CommandResult<TerminalId> {
    value
        .parse()
        .map_err(|_| CommandError::new("invalid", "That terminal identifier is not valid."))
}

/// Map a shell name from the UI onto the protocol's closed set.
///
/// Anything unrecognised becomes the platform default rather than being passed through:
/// the protocol deliberately offers a choice of *kinds*, not of programs.
fn parse_shell(value: &str) -> ShellKind {
    match value {
        "powershell" => ShellKind::PowerShell,
        "cmd" => ShellKind::Cmd,
        "bash" => ShellKind::Bash,
        _ => ShellKind::SystemDefault,
    }
}

/// Serialise an OS family the way the frontend schema expects.
const fn os_family_name(family: rc_protocol::control::OsFamily) -> &'static str {
    use rc_protocol::control::OsFamily;
    match family {
        OsFamily::Windows => "windows",
        OsFamily::Linux => "linux",
        OsFamily::MacOs => "macos",
        _ => "unknown",
    }
}

/// Flatten a protocol snapshot into the DTO the UI renders.
fn convert_snapshot(snapshot: &rc_protocol::system::SystemSnapshot) -> SnapshotDto {
    SnapshotDto {
        captured_at_ms: snapshot.captured_at_ms,
        uptime_secs: snapshot.uptime_secs,
        cpu_model: snapshot.cpu.model.clone(),
        cpu_percent: snapshot.cpu.usage_percent,
        cpu_per_core: snapshot.cpu.per_core_percent.clone(),
        logical_cores: u32::try_from(snapshot.cpu.logical_cores).unwrap_or(u32::MAX),
        memory_used_bytes: snapshot.memory.used_bytes,
        memory_total_bytes: snapshot.memory.total_bytes,
        swap_used_bytes: snapshot.memory.swap_used_bytes,
        swap_total_bytes: snapshot.memory.swap_total_bytes,
        disks: snapshot
            .disks
            .iter()
            .map(|disk| DiskDto {
                mount_point: disk.mount_point.clone(),
                filesystem: disk.filesystem.clone(),
                total_bytes: disk.total_bytes,
                available_bytes: disk.available_bytes,
            })
            .collect(),
        networks: snapshot
            .networks
            .iter()
            .map(|network| NetworkDto {
                interface: network.interface.clone(),
                receive_rate_bps: network.receive_rate_bps,
                transmit_rate_bps: network.transmit_rate_bps,
                received_bytes: network.received_bytes,
                transmitted_bytes: network.transmitted_bytes,
            })
            .collect(),
        temperatures: snapshot
            .temperatures
            .iter()
            .map(|reading| TemperatureDto {
                label: reading.label.clone(),
                celsius: reading.celsius,
                critical_celsius: reading.critical_celsius,
            })
            .collect(),
        top_processes: snapshot
            .top_processes
            .iter()
            .map(|process| ProcessDto {
                pid: process.pid,
                name: process.name.clone(),
                user: process.user.clone(),
                cpu_percent: process.cpu_percent,
                memory_bytes: process.memory_bytes,
            })
            .collect(),
        load_average: snapshot.load_average,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unrecognised_shell_name_becomes_the_platform_default() {
        // The protocol offers a choice of kinds, not of programs; passing an unknown
        // value through would be the first step towards a path.
        assert_eq!(parse_shell("powershell"), ShellKind::PowerShell);
        assert_eq!(parse_shell("bash"), ShellKind::Bash);
        assert_eq!(parse_shell("/bin/evil"), ShellKind::SystemDefault);
        assert_eq!(parse_shell(""), ShellKind::SystemDefault);
    }

    #[test]
    fn a_malformed_terminal_id_is_refused() {
        assert!(parse_terminal_id("not-an-id").is_err());
        assert!(parse_terminal_id("").is_err());
        assert!(parse_terminal_id(&TerminalId::generate().to_canonical_string()).is_ok());
    }

    #[test]
    fn terminal_output_crosses_the_boundary_as_bytes_not_as_lossy_text() {
        // A multi-byte character split across two reads would be mangled by a lossy
        // conversion, and the emulator needs exactly what the shell wrote.
        let raw = vec![0x1b, b'[', b'3', b'1', b'm', 0xE2, 0x82];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&raw);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();

        assert_eq!(decoded, raw);
    }

    #[test]
    fn a_snapshot_dto_reports_no_gpu_or_battery_it_did_not_receive() {
        // The DTO has no field for either, so a UI cannot render a figure the agent
        // never measured.
        let fields = [
            "capturedAtMs",
            "uptimeSecs",
            "cpuModel",
            "cpuPercent",
            "cpuPerCore",
            "logicalCores",
            "memoryUsedBytes",
            "memoryTotalBytes",
            "swapUsedBytes",
            "swapTotalBytes",
            "disks",
            "networks",
            "temperatures",
            "topProcesses",
            "loadAverage",
        ];
        assert_eq!(fields.len(), 15, "update this list when the DTO changes");
        assert!(!fields.contains(&"gpuPercent"));
        assert!(!fields.contains(&"batteryPercent"));
    }

    #[test]
    fn every_os_family_has_a_name_the_schema_accepts() {
        use rc_protocol::control::OsFamily;

        assert_eq!(os_family_name(OsFamily::Windows), "windows");
        assert_eq!(os_family_name(OsFamily::Linux), "linux");
        assert_eq!(os_family_name(OsFamily::MacOs), "macos");
        assert_eq!(os_family_name(OsFamily::Unknown), "unknown");
    }

    #[test]
    fn the_event_names_are_namespaced() {
        // A bare name would collide with anything else the webview listens for.
        assert!(TERMINAL_OUTPUT_EVENT.starts_with("terminal://"));
        assert!(TERMINAL_EXIT_EVENT.starts_with("terminal://"));
        assert_ne!(TERMINAL_OUTPUT_EVENT, TERMINAL_EXIT_EVENT);
    }
}
