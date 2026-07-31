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

/// An operation to perform on a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ServiceAction {
    /// Start it now.
    Start,
    /// Stop it now.
    Stop,
    /// Stop then start.
    Restart,
    /// Set to start at boot.
    EnableAtBoot,
    /// Set to not start at boot.
    DisableAtBoot,
}

/// A power operation on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PowerAction {
    /// Lock the console session.
    Lock,
    /// Sign the interactive user out.
    SignOut,
    /// Reboot.
    Restart,
    /// Power off.
    Shutdown,
    /// Suspend to RAM.
    Sleep,
    /// Suspend to disk.
    Hibernate,
    /// Restart only the agent process, leaving the host up.
    RestartAgent,
    /// Reboot into the platform's recovery / advanced startup environment.
    RestartToRecovery,
}

impl PowerAction {
    /// Whether this action interrupts the host badly enough to demand the strongest
    /// confirmation flow in the UI.
    #[must_use]
    pub const fn is_high_impact(self) -> bool {
        matches!(
            self,
            Self::Restart
                | Self::Shutdown
                | Self::SignOut
                | Self::Hibernate
                | Self::Sleep
                | Self::RestartToRecovery
        )
    }

    /// Whether this action would drop the current remote session.
    #[must_use]
    pub const fn ends_session(self) -> bool {
        !matches!(self, Self::Lock)
    }
}

/// A pending power action the operator can still cancel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledPowerAction {
    /// What will happen.
    pub action: PowerAction,
    /// When it fires, milliseconds since the Unix epoch.
    pub execute_at_ms: i64,
    /// Token required to cancel it.
    pub cancel_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_power_actions_are_high_impact() {
        for action in [
            PowerAction::Restart,
            PowerAction::Shutdown,
            PowerAction::SignOut,
        ] {
            assert!(
                action.is_high_impact(),
                "{action:?} must require strong confirmation"
            );
        }
    }

    #[test]
    fn lock_is_low_impact_and_keeps_the_session() {
        assert!(!PowerAction::Lock.is_high_impact());
        assert!(!PowerAction::Lock.ends_session());
    }

    #[test]
    fn restarting_the_agent_ends_the_session_but_is_not_high_impact() {
        assert!(PowerAction::RestartAgent.ends_session());
        assert!(!PowerAction::RestartAgent.is_high_impact());
    }
}
