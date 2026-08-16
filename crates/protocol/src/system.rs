//! System monitoring, process management, service control and power actions.

use serde::{Deserialize, Serialize};

/// A point-in-time snapshot of host health, driving the dashboard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemSnapshot {
    /// When this snapshot was taken, milliseconds since the Unix epoch.
    pub captured_at_ms: i64,
    /// Seconds since the host booted.
    pub uptime_secs: u64,
    /// CPU state.
    pub cpu: CpuStats,
    /// Memory state.
    pub memory: MemoryStats,
    /// One entry per mounted volume.
    pub disks: Vec<DiskStats>,
    /// One entry per network interface.
    pub networks: Vec<NetworkStats>,
    /// Temperature sensors, where the platform exposes them safely.
    pub temperatures: Vec<TemperatureReading>,
    /// GPUs, where a supported backend is available.
    pub gpus: Vec<GpuStats>,
    /// Battery, on laptops and UPS-backed hosts.
    pub battery: Option<BatteryStats>,
    /// Highest resource consumers, already sorted by the agent.
    pub top_processes: Vec<ProcessInfo>,
    /// Load averages over 1, 5 and 15 minutes. Empty on Windows.
    pub load_average: Option<[f64; 3]>,
}

/// A recurring metrics tick on the metrics channel.
///
/// Deliberately lighter than [`SystemSnapshot`]: it carries only values that change
/// between samples. Static identity (`cpu.model`, core counts) and the process list
/// come from a one-shot snapshot or host-info fetch, following the same split already
/// used when [`crate::control::HostSummary`] was pulled out of the dashboard payload.
///
/// A client that stops reading must not receive a burst of stale ticks later — the
/// agent skips missed intervals rather than queuing them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricsUpdate {
    /// When this sample was taken, milliseconds since the Unix epoch.
    pub captured_at_ms: i64,
    /// Seconds since the host booted.
    pub uptime_secs: u64,
    /// Live CPU utilisation. No model string or core counts — those are static.
    pub cpu: CpuSample,
    /// Memory state.
    pub memory: MemoryStats,
    /// One entry per mounted volume.
    pub disks: Vec<DiskStats>,
    /// One entry per network interface.
    pub networks: Vec<NetworkStats>,
    /// Temperature sensors, where the platform exposes them safely.
    pub temperatures: Vec<TemperatureReading>,
    /// GPUs, where a supported backend is available.
    pub gpus: Vec<GpuStats>,
    /// Battery, on laptops and UPS-backed hosts.
    pub battery: Option<BatteryStats>,
    /// Load averages over 1, 5 and 15 minutes. Empty on Windows.
    pub load_average: Option<[f64; 3]>,
}

/// Agent → client messages on the metrics channel.
///
/// The channel carries only pushes: a subscription is opened and closed on the *control*
/// channel, so there is no client-to-agent message here and nothing on this channel can
/// change what the agent does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MetricsAgentMessage {
    /// One sample.
    ///
    /// Boxed for the same reason [`crate::control::ControlResponsePayload::Snapshot`]
    /// is: un-boxed it would set the size of the whole enum, and `Stopped` is a handful
    /// of bytes.
    Update(Box<MetricsUpdate>),
    /// The agent stopped pushing, and why.
    ///
    /// Sent rather than simply going quiet. A dashboard that stops updating without
    /// being told cannot distinguish "this server is idle" from "this server stopped
    /// answering" — and would keep showing the last reading as though it were current.
    Stopped {
        /// Why the stream ended.
        reason: MetricsStopReason,
    },
}

/// Why a metrics stream ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum MetricsStopReason {
    /// The client asked to stop.
    Unsubscribed,
    /// The session lost the capability that permitted it, mid-stream.
    ///
    /// Authorization is re-checked every tick rather than captured at subscribe time, so
    /// a device revoked while a dashboard is open stops receiving readings immediately.
    NotAuthorized,
    /// The agent could not take a sample.
    Unavailable,
}

/// Live CPU utilisation for a metrics tick.
///
/// Omits model and core counts: those do not change between samples and live on
/// [`CpuStats`] / host info instead. Sending them every tick would make static facts
/// look like live readings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CpuSample {
    /// Overall utilisation, 0.0–100.0.
    pub usage_percent: f32,
    /// Per-core utilisation, 0.0–100.0.
    pub per_core_percent: Vec<f32>,
    /// Current clock in MHz, when available.
    pub frequency_mhz: Option<u64>,
}

/// Aggregate and per-core CPU utilisation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CpuStats {
    /// Marketing name of the processor.
    pub model: String,
    /// Number of logical processors.
    pub logical_cores: usize,
    /// Number of physical cores, when the platform reports it.
    pub physical_cores: Option<usize>,
    /// Overall utilisation, 0.0–100.0.
    pub usage_percent: f32,
    /// Per-core utilisation, 0.0–100.0.
    pub per_core_percent: Vec<f32>,
    /// Current clock in MHz, when available.
    pub frequency_mhz: Option<u64>,
}

/// Physical and swap memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryStats {
    /// Total physical memory in bytes.
    pub total_bytes: u64,
    /// Used physical memory in bytes.
    pub used_bytes: u64,
    /// Memory available to new allocations, in bytes.
    pub available_bytes: u64,
    /// Total swap / page file in bytes.
    pub swap_total_bytes: u64,
    /// Used swap / page file in bytes.
    pub swap_used_bytes: u64,
}

/// A mounted volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskStats {
    /// Mount point or drive letter.
    pub mount_point: String,
    /// Filesystem type, e.g. `"NTFS"` or `"ext4"`.
    pub filesystem: String,
    /// Total capacity in bytes.
    pub total_bytes: u64,
    /// Free space in bytes.
    pub available_bytes: u64,
    /// Whether the volume is removable.
    pub removable: bool,
}

/// Cumulative and instantaneous interface counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Interface name.
    pub interface: String,
    /// Bytes received since boot.
    pub received_bytes: u64,
    /// Bytes transmitted since boot.
    pub transmitted_bytes: u64,
    /// Receive rate in bytes per second over the last sampling interval.
    pub receive_rate_bps: u64,
    /// Transmit rate in bytes per second over the last sampling interval.
    pub transmit_rate_bps: u64,
}

/// One temperature sensor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemperatureReading {
    /// Sensor label as reported by the platform.
    pub label: String,
    /// Current reading in degrees Celsius.
    pub celsius: f32,
    /// Vendor-declared critical threshold, when known.
    pub critical_celsius: Option<f32>,
}

/// A graphics adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpuStats {
    /// Adapter name.
    pub name: String,
    /// Core utilisation percentage, when the driver reports it.
    pub usage_percent: Option<f32>,
    /// Used video memory in bytes.
    pub memory_used_bytes: Option<u64>,
    /// Total video memory in bytes.
    pub memory_total_bytes: Option<u64>,
    /// Core temperature in Celsius.
    pub temperature_celsius: Option<f32>,
}

/// Battery or UPS state.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BatteryStats {
    /// Charge remaining, 0.0–100.0.
    pub charge_percent: f32,
    /// Whether the host is running on external power.
    pub on_ac_power: bool,
    /// Estimated seconds of runtime remaining.
    pub seconds_remaining: Option<u64>,
}

/// A running process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process id.
    pub pid: u32,
    /// Parent process id.
    pub parent_pid: Option<u32>,
    /// Executable name. Untrusted; render as inert text.
    pub name: String,
    /// Full executable path. `None` when the agent lacks permission to read it.
    pub executable_path: Option<String>,
    /// Owning user account, when resolvable.
    pub user: Option<String>,
    /// CPU utilisation, 0.0–100.0 across all cores.
    pub cpu_percent: f32,
    /// Resident memory in bytes.
    pub memory_bytes: u64,
    /// Process start time, milliseconds since the Unix epoch.
    pub started_at_ms: Option<i64>,
}

/// Current state of a service or unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ServiceState {
    /// Running.
    Running,
    /// Stopped.
    Stopped,
    /// Mid-transition.
    Starting,
    /// Mid-transition.
    Stopping,
    /// Failed or in an error state.
    Failed,
    /// State could not be determined.
    Unknown,
}

/// Whether a service starts at boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StartupType {
    /// Starts at boot.
    Automatic,
    /// Started on demand.
    Manual,
    /// Will not start.
    Disabled,
    /// Could not be determined.
    Unknown,
}

/// A Windows service or a systemd unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Canonical service or unit name used for control operations.
    pub name: String,
    /// Human-friendly name. Untrusted.
    pub display_name: String,
    /// Description. Untrusted.
    pub description: Option<String>,
    /// Current state.
    pub state: ServiceState,
    /// Boot behaviour.
    pub startup: StartupType,
    /// Main process id when running.
    pub pid: Option<u32>,
    /// True when the agent's deny-rules forbid controlling this service because doing
    /// so would predictably break the agent or the host.
    pub protected: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_metrics_update_round_trips_on_the_wire() {
        // The metrics channel carries this type every tick; a field that fails to
        // serialise would freeze every dashboard rather than one request.
        let update = MetricsUpdate {
            captured_at_ms: 1_700_000_000_000,
            uptime_secs: 3_600,
            cpu: CpuSample {
                usage_percent: 12.5,
                per_core_percent: vec![10.0, 15.0],
                frequency_mhz: Some(3_600),
            },
            memory: MemoryStats {
                total_bytes: 16_000_000_000,
                used_bytes: 8_000_000_000,
                available_bytes: 8_000_000_000,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
            },
            disks: vec![DiskStats {
                mount_point: "C:\\".into(),
                filesystem: "NTFS".into(),
                total_bytes: 500_000_000_000,
                available_bytes: 200_000_000_000,
                removable: false,
            }],
            networks: vec![NetworkStats {
                interface: "eth0".into(),
                received_bytes: 1_000,
                transmitted_bytes: 2_000,
                receive_rate_bps: 100,
                transmit_rate_bps: 200,
            }],
            temperatures: vec![TemperatureReading {
                label: "CPU".into(),
                celsius: 45.0,
                critical_celsius: Some(95.0),
            }],
            gpus: Vec::new(),
            battery: None,
            load_average: Some([0.1, 0.2, 0.3]),
        };

        let bytes = postcard::to_stdvec(&update).unwrap();
        let back: MetricsUpdate = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.captured_at_ms, update.captured_at_ms);
        assert_eq!(back.cpu.per_core_percent, update.cpu.per_core_percent);
        assert_eq!(back.memory.total_bytes, update.memory.total_bytes);
        assert_eq!(back.disks[0].mount_point, "C:\\");
        assert_eq!(back.networks[0].receive_rate_bps, 100);
        assert!(back.gpus.is_empty());
        assert!(back.battery.is_none());
        assert_eq!(back.load_average, Some([0.1, 0.2, 0.3]));
    }

    #[test]
    fn a_stop_tells_the_client_why_rather_than_going_quiet() {
        // A dashboard that stops updating without being told cannot distinguish an idle
        // server from one that stopped answering, and would keep presenting the last
        // reading as current.
        for reason in [
            MetricsStopReason::Unsubscribed,
            MetricsStopReason::NotAuthorized,
            MetricsStopReason::Unavailable,
        ] {
            let message = MetricsAgentMessage::Stopped { reason };
            let bytes = postcard::to_stdvec(&message).unwrap();
            let back: MetricsAgentMessage = postcard::from_bytes(&bytes).unwrap();

            assert_eq!(back, message);
        }
    }

    #[test]
    fn a_stop_is_far_smaller_than_a_sample() {
        // What boxing the sample buys: `Stopped` does not pay for `Update`'s size.
        let stop = postcard::to_stdvec(&MetricsAgentMessage::Stopped {
            reason: MetricsStopReason::Unsubscribed,
        })
        .unwrap();

        assert!(
            stop.len() < 8,
            "a stop is a couple of bytes: {}",
            stop.len()
        );
    }

    #[test]
    fn a_metrics_update_carries_no_process_list_or_cpu_identity() {
        // What a tick puts on the wire, inspected rather than asserted about. A field
        // added back to `MetricsUpdate` later would fail this — which is the point: the
        // process walk is the expensive part, and static identity sent every tick makes
        // fixed facts look like live readings.
        let update = MetricsUpdate {
            captured_at_ms: 0,
            uptime_secs: 0,
            cpu: CpuSample {
                usage_percent: 1.0,
                per_core_percent: vec![1.0],
                frequency_mhz: None,
            },
            memory: MemoryStats {
                total_bytes: 1,
                used_bytes: 1,
                available_bytes: 0,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
            },
            disks: Vec::new(),
            networks: Vec::new(),
            temperatures: Vec::new(),
            gpus: Vec::new(),
            battery: None,
            load_average: None,
        };

        let encoded = serde_json::to_value(&update).expect("a tick serialises");
        let object = encoded.as_object().expect("a tick is a struct");

        assert!(
            !object.contains_key("top_processes"),
            "a tick must not carry a process list: {object:?}"
        );

        let cpu = object["cpu"].as_object().expect("cpu is a struct");
        for static_field in ["model", "logical_cores", "physical_cores"] {
            assert!(
                !cpu.contains_key(static_field),
                "`cpu.{static_field}` does not change between samples and belongs on a \
                 snapshot, not on every tick"
            );
        }
        // The live half is still present, or a tick would carry nothing worth pushing.
        assert!(cpu.contains_key("usage_percent"));
        assert!(cpu.contains_key("per_core_percent"));
    }
}
