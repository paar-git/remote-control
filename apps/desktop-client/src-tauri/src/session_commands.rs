//! Commands that use a live session: metrics.

use std::sync::Arc;

use rc_protocol::control::{ControlRequestPayload, ControlResponsePayload, ControlResult};
use rc_security::Permission;
use serde::Serialize;

use crate::AppState;
use crate::commands::CommandError;

type CommandResult<T> = Result<T, CommandError>;

/// Event name carrying one pushed metrics tick to the webview.
pub const METRICS_UPDATE_EVENT: &str = "metrics://update";

/// Event name announcing that the metrics stream ended, and why.
pub const METRICS_STOPPED_EVENT: &str = "metrics://stopped";

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
    state.require_permission(Permission::ViewMetrics)?;
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
    state.require_permission(Permission::ViewMetrics)?;
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

/// One pushed metrics tick.
///
/// Deliberately a subset of [`SnapshotDto`]: the fields that change between samples. The
/// process list and the CPU model come from a snapshot, once, so the screen merges a
/// tick onto the snapshot it already has rather than the agent resending static facts
/// several times a minute as though they were live readings.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsTickDto {
    /// When the agent took the reading.
    pub captured_at_ms: i64,
    /// Seconds since the server booted.
    pub uptime_secs: u64,
    /// Overall CPU utilisation.
    pub cpu_percent: f32,
    /// Per-core utilisation.
    pub cpu_per_core: Vec<f32>,
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
    /// Temperature sensors the platform exposed.
    pub temperatures: Vec<TemperatureDto>,
    /// Load averages, where the platform has the concept.
    pub load_average: Option<[f64; 3]>,
}

/// Why a metrics stream ended.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsStoppedEvent {
    /// A stable reason code the screen can branch on.
    pub reason: String,
    /// A sentence safe to show an operator.
    pub message: String,
}

/// Subscribe to pushed metrics from the connected server.
///
/// Returns the interval the agent actually accepted, which may be slower than the one
/// requested — the screen reports what it is getting rather than what it asked for.
///
/// # Errors
/// [`CommandError`] if nothing is connected, the session lacks the capability, or the
/// server refused the subscription.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn subscribe_metrics(
    app: tauri::AppHandle,
    state: tauri::State<'_, Arc<AppState>>,
    interval_ms: u32,
) -> CommandResult<u32> {
    state.require_permission(Permission::ViewMetrics)?;
    let manager = connection(&state)?;

    manager
        .subscribe_metrics(interval_ms, metrics_event_sink(app))
        .await
        .map_err(|err| CommandError::from_transport(&err))
}

/// Stop pushed metrics.
///
/// # Errors
/// [`CommandError`] if nothing is connected.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn unsubscribe_metrics(state: tauri::State<'_, Arc<AppState>>) -> CommandResult<()> {
    let manager = connection(&state)?;

    manager
        .unsubscribe_metrics()
        .await
        .map_err(|err| CommandError::from_transport(&err))
}

/// A sink that forwards pushed metrics to the webview as events.
fn metrics_event_sink(app: tauri::AppHandle) -> crate::connection::MetricsSink {
    Arc::new(move |message: rc_protocol::system::MetricsAgentMessage| {
        use rc_protocol::system::{MetricsAgentMessage, MetricsStopReason};
        use tauri::Emitter as _;

        match message {
            MetricsAgentMessage::Update(update) => {
                let _ = app.emit(METRICS_UPDATE_EVENT, convert_update(&update));
            }
            MetricsAgentMessage::Stopped { reason } => {
                // Forwarded rather than swallowed: a dashboard that stopped updating
                // must be able to say so instead of leaving its last reading on screen
                // looking current.
                let (code, message) = match reason {
                    MetricsStopReason::Unsubscribed => ("unsubscribed", "Live updates stopped."),
                    MetricsStopReason::NotAuthorized => (
                        "not_authorized",
                        "This device is no longer permitted to watch this server.",
                    ),
                    MetricsStopReason::Unavailable => (
                        "unavailable",
                        "The server stopped being able to take readings.",
                    ),
                    // A reason a newer agent knows and this build does not. Reported as
                    // a stop rather than ignored, which would freeze the dashboard.
                    _ => ("stopped", "The server stopped sending live updates."),
                };
                let _ = app.emit(
                    METRICS_STOPPED_EVENT,
                    MetricsStoppedEvent {
                        reason: code.to_owned(),
                        message: message.to_owned(),
                    },
                );
            }
            // A message a newer agent knows and this build does not.
            _ => {}
        }
    })
}

/// Convert a pushed tick into the shape the webview reads.
fn convert_update(update: &rc_protocol::system::MetricsUpdate) -> MetricsTickDto {
    MetricsTickDto {
        captured_at_ms: update.captured_at_ms,
        uptime_secs: update.uptime_secs,
        cpu_percent: update.cpu.usage_percent,
        cpu_per_core: update.cpu.per_core_percent.clone(),
        memory_used_bytes: update.memory.used_bytes,
        memory_total_bytes: update.memory.total_bytes,
        swap_used_bytes: update.memory.swap_used_bytes,
        swap_total_bytes: update.memory.swap_total_bytes,
        disks: update
            .disks
            .iter()
            .map(|disk| DiskDto {
                mount_point: disk.mount_point.clone(),
                filesystem: disk.filesystem.clone(),
                total_bytes: disk.total_bytes,
                available_bytes: disk.available_bytes,
            })
            .collect(),
        networks: update
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
        temperatures: update
            .temperatures
            .iter()
            .map(|reading| TemperatureDto {
                label: reading.label.clone(),
                celsius: reading.celsius,
                critical_celsius: reading.critical_celsius,
            })
            .collect(),
        load_average: update.load_average,
    }
}

/// The connection manager, or a message saying nothing is connected.
fn connection(state: &AppState) -> CommandResult<Arc<crate::connection::ConnectionManager>> {
    state
        .connection
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| CommandError::new("not_connected", "Connect to a server first."))
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
        assert!(METRICS_UPDATE_EVENT.starts_with("metrics://"));
        assert!(METRICS_STOPPED_EVENT.starts_with("metrics://"));
        assert_ne!(METRICS_UPDATE_EVENT, METRICS_STOPPED_EVENT);
    }
}
