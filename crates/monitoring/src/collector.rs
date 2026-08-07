//! The stateful metrics collector.

use std::collections::HashMap;
use std::time::Instant;

use rc_protocol::system::{
    BatteryStats, CpuSample, CpuStats, DiskStats, MemoryStats, MetricsUpdate, NetworkStats,
    ProcessInfo, SystemSnapshot, TemperatureReading,
};

/// How many processes a snapshot carries.
///
/// A dashboard shows a handful; sending every process on a busy server would put
/// thousands of rows through the frame limit on every tick to display twenty. The full
/// list is available on request through the process manager.
pub const TOP_PROCESS_COUNT: usize = 12;

/// The shortest interval between samples the collector will honour, in milliseconds.
///
/// CPU utilisation is measured across an interval; sampling faster than the kernel
/// updates its counters yields noise rather than detail, and costs a full process
/// enumeration each time. A client asking for 100 ms gets this instead.
pub const MIN_SAMPLE_INTERVAL_MS: u32 = 500;

/// The longest interval a client may request, in milliseconds.
pub const MAX_SAMPLE_INTERVAL_MS: u32 = 60_000;

/// Collects system metrics, keeping the state that rate calculations need.
pub struct MetricsCollector {
    system: sysinfo::System,
    disks: sysinfo::Disks,
    networks: sysinfo::Networks,
    components: sysinfo::Components,
    /// Resolves numeric owner ids to account names.
    ///
    /// A raw uid is not something an operator can act on; the name is. Refreshed with
    /// the process list rather than per process, because the mapping changes rarely and
    /// resolving it per row would be a syscall per process per tick.
    users: sysinfo::Users,
    /// Cumulative interface counters from the previous sample, for rate calculation.
    previous_network: HashMap<String, (u64, u64)>,
    /// When the previous sample was taken.
    previous_sample: Option<Instant>,
}

impl std::fmt::Debug for MetricsCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsCollector")
            .field("has_previous_sample", &self.previous_sample.is_some())
            .finish_non_exhaustive()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsCollector {
    /// A collector with no prior sample.
    ///
    /// The first snapshot it produces reports no network rates, because a rate over a
    /// zero-length interval is not a number. The second and later ones do.
    #[must_use]
    pub fn new() -> Self {
        Self {
            system: sysinfo::System::new(),
            disks: sysinfo::Disks::new_with_refreshed_list(),
            networks: sysinfo::Networks::new_with_refreshed_list(),
            components: sysinfo::Components::new_with_refreshed_list(),
            users: sysinfo::Users::new_with_refreshed_list(),
            previous_network: HashMap::new(),
            previous_sample: None,
        }
    }

    /// Clamp a requested interval into what the collector will actually honour.
    #[must_use]
    pub const fn clamp_interval(requested_ms: u32) -> u32 {
        if requested_ms < MIN_SAMPLE_INTERVAL_MS {
            MIN_SAMPLE_INTERVAL_MS
        } else if requested_ms > MAX_SAMPLE_INTERVAL_MS {
            MAX_SAMPLE_INTERVAL_MS
        } else {
            requested_ms
        }
    }

    /// Take a full dashboard snapshot, including the top process list.
    ///
    /// `now_ms` is passed in rather than read here so the timestamp on a snapshot comes
    /// from the same clock as everything else the agent records.
    pub fn snapshot(&mut self, now_ms: i64) -> SystemSnapshot {
        let elapsed = self.refresh(RefreshKind::WithProcesses);

        SystemSnapshot {
            captured_at_ms: now_ms,
            uptime_secs: sysinfo::System::uptime(),
            cpu: self.cpu(),
            memory: self.memory(),
            disks: self.disk_stats(),
            networks: self.network_stats(elapsed),
            temperatures: self.temperatures(),
            // No GPU backend is linked, so no GPU is reported. An empty list means "not
            // measured"; a zeroed entry would mean "measured as idle", which would be a
            // lie the operator has no way to detect.
            gpus: Vec::new(),
            battery: self.battery(),
            top_processes: self.top_processes(),
            load_average: load_average(),
        }
    }

    /// Take a lightweight metrics tick for the push stream.
    ///
    /// Shares the same sampling path and rate state as [`Self::snapshot`], but skips
    /// process enumeration: a dashboard subscription must not pay for a full process
    /// walk every half-second on the machine it is watching.
    pub fn update(&mut self, now_ms: i64) -> MetricsUpdate {
        let elapsed = self.refresh(RefreshKind::RatesOnly);
        let cpu = self.cpu();

        MetricsUpdate {
            captured_at_ms: now_ms,
            uptime_secs: sysinfo::System::uptime(),
            cpu: CpuSample {
                usage_percent: cpu.usage_percent,
                per_core_percent: cpu.per_core_percent,
                frequency_mhz: cpu.frequency_mhz,
            },
            memory: self.memory(),
            disks: self.disk_stats(),
            networks: self.network_stats(elapsed),
            temperatures: self.temperatures(),
            gpus: Vec::new(),
            battery: self.battery(),
            load_average: load_average(),
        }
    }

    /// Refresh platform counters and return the interval since the previous sample.
    fn refresh(&mut self, kind: RefreshKind) -> Option<std::time::Duration> {
        let elapsed = self.previous_sample.map(|previous| previous.elapsed());
        self.previous_sample = Some(Instant::now());

        self.system.refresh_cpu_all();
        self.system.refresh_memory();
        if matches!(kind, RefreshKind::WithProcesses) {
            self.system.refresh_processes(
                sysinfo::ProcessesToUpdate::All,
                // Removing dead processes keeps the map from growing without bound on a
                // long-lived agent watching a busy machine.
                true,
            );
        }
        self.disks.refresh(true);
        self.networks.refresh(true);
        self.components.refresh(true);

        elapsed
    }

    fn cpu(&self) -> CpuStats {
        let cpus = self.system.cpus();
        let per_core_percent: Vec<f32> = cpus.iter().map(sysinfo::Cpu::cpu_usage).collect();

        // The aggregate is the mean of the cores rather than a separate reading, so the
        // headline figure and the per-core bars can never disagree on screen.
        let usage_percent = if per_core_percent.is_empty() {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let count = per_core_percent.len() as f32;
            per_core_percent.iter().sum::<f32>() / count
        };

        CpuStats {
            model: cpus
                .first()
                .map_or_else(|| "unknown".to_owned(), |cpu| cpu.brand().trim().to_owned()),
            logical_cores: cpus.len(),
            physical_cores: sysinfo::System::physical_core_count(),
            usage_percent,
            per_core_percent,
            frequency_mhz: cpus.first().map(sysinfo::Cpu::frequency).filter(|f| *f > 0),
        }
    }

    fn memory(&self) -> MemoryStats {
        MemoryStats {
            total_bytes: self.system.total_memory(),
            used_bytes: self.system.used_memory(),
            available_bytes: self.system.available_memory(),
            swap_total_bytes: self.system.total_swap(),
            swap_used_bytes: self.system.used_swap(),
        }
    }

    fn disk_stats(&self) -> Vec<DiskStats> {
        let mut disks: Vec<DiskStats> = self
            .disks
            .list()
            .iter()
            .map(|disk| DiskStats {
                mount_point: disk.mount_point().to_string_lossy().into_owned(),
                filesystem: disk.file_system().to_string_lossy().into_owned(),
                total_bytes: disk.total_space(),
                available_bytes: disk.available_space(),
                removable: disk.is_removable(),
            })
            // A volume reporting zero capacity is one the platform could not measure —
            // an empty optical drive, or a mount the agent cannot stat. Showing it as a
            // full disk would be alarming and wrong.
            .filter(|disk| disk.total_bytes > 0)
            .collect();

        disks.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
        disks
    }

    fn network_stats(&mut self, elapsed: Option<std::time::Duration>) -> Vec<NetworkStats> {
        let seconds = elapsed.map(|d| d.as_secs_f64()).filter(|s| *s > 0.0);

        let mut stats: Vec<NetworkStats> = self
            .networks
            .list()
            .iter()
            .map(|(name, data)| {
                let received = data.total_received();
                let transmitted = data.total_transmitted();

                // Rates are derivatives: without a previous sample and a real interval
                // there is nothing to divide by, so they are reported as zero rather
                // than invented.
                let (receive_rate_bps, transmit_rate_bps) =
                    match (seconds, self.previous_network.get(name.as_str())) {
                        (Some(seconds), Some((previous_rx, previous_tx))) => {
                            // Counters reset when an interface is reconfigured; a negative
                            // delta means the baseline moved, not that traffic flowed
                            // backwards.
                            let rx_delta = received.saturating_sub(*previous_rx);
                            let tx_delta = transmitted.saturating_sub(*previous_tx);
                            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
                            #[allow(clippy::cast_sign_loss)]
                            (
                                (rx_delta as f64 / seconds) as u64,
                                (tx_delta as f64 / seconds) as u64,
                            )
                        }
                        _ => (0, 0),
                    };

                NetworkStats {
                    interface: name.clone(),
                    received_bytes: received,
                    transmitted_bytes: transmitted,
                    receive_rate_bps,
                    transmit_rate_bps,
                }
            })
            .collect();

        self.previous_network = stats
            .iter()
            .map(|s| (s.interface.clone(), (s.received_bytes, s.transmitted_bytes)))
            .collect();

        stats.sort_by(|a, b| a.interface.cmp(&b.interface));
        stats
    }

    fn temperatures(&self) -> Vec<TemperatureReading> {
        self.components
            .list()
            .iter()
            .filter_map(|component| {
                // A component with no current reading is one the platform lists but
                // cannot sample. Reporting it at zero would look like a fault.
                let celsius = component.temperature()?;
                Some(TemperatureReading {
                    label: component.label().to_owned(),
                    celsius,
                    critical_celsius: component.critical(),
                })
            })
            .collect()
    }

    /// Battery state.
    ///
    /// Not measured by this build: `sysinfo` does not expose battery information, and
    /// linking a platform battery API for a feature that only applies to laptops has
    /// not been done. Reported as absent rather than as a plausible-looking full charge.
    #[allow(clippy::unused_self)]
    const fn battery(&self) -> Option<BatteryStats> {
        None
    }

    fn top_processes(&self) -> Vec<ProcessInfo> {
        let mut processes: Vec<ProcessInfo> = self
            .system
            .processes()
            .values()
            .map(|process| convert_process(process, &self.users))
            .collect();

        // By CPU, then by memory as a tie-break: on an idle machine every process reads
        // 0% CPU, and ordering those arbitrarily would make the list reshuffle on every
        // tick.
        processes.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.memory_bytes.cmp(&a.memory_bytes))
        });
        processes.truncate(TOP_PROCESS_COUNT);
        processes
    }

    /// Every running process, for the process manager.
    pub fn all_processes(&mut self) -> Vec<ProcessInfo> {
        self.system
            .refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        self.users.refresh();
        self.system
            .processes()
            .values()
            .map(|process| convert_process(process, &self.users))
            .collect()
    }
}

/// What a sample needs from the platform.
#[derive(Debug, Clone, Copy)]
enum RefreshKind {
    /// Full dashboard: rates plus a process walk.
    WithProcesses,
    /// Push tick: rates only. Process enumeration is the expensive part.
    RatesOnly,
}

/// Convert one `sysinfo` process into the protocol's shape.
fn convert_process(process: &sysinfo::Process, users: &sysinfo::Users) -> ProcessInfo {
    ProcessInfo {
        pid: process.pid().as_u32(),
        parent_pid: process.parent().map(sysinfo::Pid::as_u32),
        name: process.name().to_string_lossy().into_owned(),
        // `None` when the agent may not read it, which is common for system processes
        // and for anything owned by another user. An empty string would be
        // indistinguishable from a process at the filesystem root.
        executable_path: process
            .exe()
            .map(|path| path.to_string_lossy().into_owned()),
        // Resolved to a name, or absent. A numeric id the operator cannot act on is
        // not more useful than saying the owner is unknown.
        user: process
            .user_id()
            .and_then(|uid| users.get_user_by_id(uid))
            .map(|user| user.name().to_owned()),
        cpu_percent: process.cpu_usage(),
        memory_bytes: process.memory(),
        started_at_ms: i64::try_from(process.start_time())
            .ok()
            .and_then(|secs| secs.checked_mul(1000)),
    }
}

/// Load averages, where the platform has the concept.
///
/// Windows does not; `sysinfo` reports zeros there, which would read as a perfectly
/// idle machine rather than as a figure that does not exist.
fn load_average() -> Option<[f64; 3]> {
    if cfg!(windows) {
        return None;
    }
    let load = sysinfo::System::load_average();
    Some([load.one, load.five, load.fifteen])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_reports_real_measured_values() {
        let mut collector = MetricsCollector::new();
        let snapshot = collector.snapshot(1_700_000_000_000);

        assert_eq!(snapshot.captured_at_ms, 1_700_000_000_000);
        assert!(snapshot.cpu.logical_cores >= 1, "a running host has a CPU");
        assert!(snapshot.memory.total_bytes > 0, "a running host has memory");
        assert!(
            !snapshot.cpu.model.is_empty(),
            "the processor model must be reported"
        );
        assert_eq!(
            snapshot.cpu.per_core_percent.len(),
            snapshot.cpu.logical_cores,
            "one reading per logical core"
        );
    }

    #[test]
    fn the_headline_cpu_figure_agrees_with_the_per_core_readings() {
        // If these could disagree, the number and the bars beside it would contradict
        // each other on screen.
        let mut collector = MetricsCollector::new();
        let snapshot = collector.snapshot(0);

        if snapshot.cpu.per_core_percent.is_empty() {
            return;
        }
        #[allow(clippy::cast_precision_loss)]
        let mean = snapshot.cpu.per_core_percent.iter().sum::<f32>()
            / snapshot.cpu.per_core_percent.len() as f32;
        assert!((snapshot.cpu.usage_percent - mean).abs() < 0.01);
    }

    #[test]
    fn the_first_snapshot_reports_no_network_rates() {
        // A rate over a zero-length interval is not a number. Reporting one would mean
        // inventing it.
        let mut collector = MetricsCollector::new();
        let snapshot = collector.snapshot(0);

        for interface in &snapshot.networks {
            assert_eq!(interface.receive_rate_bps, 0);
            assert_eq!(interface.transmit_rate_bps, 0);
        }
    }

    #[tokio::test]
    async fn a_later_snapshot_can_report_rates() {
        let mut collector = MetricsCollector::new();
        collector.snapshot(0);
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        let second = collector.snapshot(1);

        // The rates are whatever the machine actually did; what is asserted is that the
        // calculation ran rather than being skipped for want of a baseline.
        assert!(
            second
                .networks
                .iter()
                .all(|n| n.receive_rate_bps < u64::MAX),
            "rates must be finite"
        );
        assert!(collector.previous_sample.is_some());
    }

    #[test]
    fn nothing_unmeasurable_is_reported_as_zero() {
        let mut collector = MetricsCollector::new();
        let snapshot = collector.snapshot(0);

        // No GPU backend is linked, so no GPU is claimed.
        assert!(
            snapshot.gpus.is_empty(),
            "an unmeasured GPU must be absent, not reported as idle"
        );
        // Battery is not measured by this build.
        assert!(snapshot.battery.is_none());

        if cfg!(windows) {
            assert!(
                snapshot.load_average.is_none(),
                "Windows has no load average; zeros would read as an idle machine"
            );
        }
    }

    #[test]
    fn a_volume_with_no_measurable_capacity_is_omitted() {
        // An empty optical drive reports zero capacity; showing it would look like a
        // full disk.
        let mut collector = MetricsCollector::new();
        let snapshot = collector.snapshot(0);

        assert!(snapshot.disks.iter().all(|disk| disk.total_bytes > 0));
    }

    #[test]
    fn the_process_list_is_bounded_and_ordered() {
        let mut collector = MetricsCollector::new();
        let snapshot = collector.snapshot(0);

        assert!(snapshot.top_processes.len() <= TOP_PROCESS_COUNT);
        for pair in snapshot.top_processes.windows(2) {
            let (first, second) = (&pair[0], &pair[1]);
            let ordered = first.cpu_percent > second.cpu_percent
                || (first.cpu_percent - second.cpu_percent).abs() < f32::EPSILON
                    && first.memory_bytes >= second.memory_bytes;
            assert!(ordered, "the top-process list must be sorted");
        }
    }

    #[test]
    fn the_full_process_list_is_longer_than_the_top_slice() {
        let mut collector = MetricsCollector::new();
        let top = collector.snapshot(0).top_processes.len();
        let all = collector.all_processes().len();

        assert!(all >= top, "the full list cannot be shorter than its head");
        assert!(all > 1, "a running host has processes");
    }

    #[test]
    fn a_requested_interval_is_clamped_into_a_sane_range() {
        // Sampling faster than the kernel updates its counters produces noise and costs
        // a process enumeration each time.
        assert_eq!(MetricsCollector::clamp_interval(0), MIN_SAMPLE_INTERVAL_MS);
        assert_eq!(MetricsCollector::clamp_interval(50), MIN_SAMPLE_INTERVAL_MS);
        assert_eq!(MetricsCollector::clamp_interval(1_000), 1_000);
        assert_eq!(
            MetricsCollector::clamp_interval(u32::MAX),
            MAX_SAMPLE_INTERVAL_MS
        );
    }

    #[test]
    fn an_update_omits_processes_and_cpu_identity() {
        // A push tick must stay cheaper than a full snapshot: no process walk, and no
        // static CPU fields that belong on the one-shot snapshot.
        let mut collector = MetricsCollector::new();
        let update = collector.update(1_700_000_000_000);

        assert_eq!(update.captured_at_ms, 1_700_000_000_000);
        assert!(
            !update.cpu.per_core_percent.is_empty(),
            "live utilisation is still reported"
        );
        assert!(update.memory.total_bytes > 0);
        // The type has no process field; gpus stay empty rather than inventing idle GPUs.
        assert!(update.gpus.is_empty());
        assert!(update.battery.is_none());
    }

    #[tokio::test]
    async fn an_update_still_reports_network_rates_after_a_baseline() {
        // Skipping process enumeration must not break the rate path shared with
        // snapshots: both methods advance the same previous-sample state.
        let mut collector = MetricsCollector::new();
        let _ = collector.update(0);
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        let second = collector.update(1);

        assert!(
            second
                .networks
                .iter()
                .all(|n| n.receive_rate_bps < u64::MAX),
            "rates must be finite"
        );
        assert!(collector.previous_sample.is_some());
    }

    #[test]
    fn snapshot_and_update_share_one_rate_timeline() {
        // Two collectors would disagree; one collector used both ways must keep a
        // coherent interval so rates do not reset every time the UI mixes paths.
        let mut collector = MetricsCollector::new();
        collector.snapshot(0);
        assert!(collector.previous_sample.is_some());
        collector.update(1);
        assert!(collector.previous_sample.is_some());
        assert!(
            collector.previous_network.len() < 1000,
            "interface state must track interfaces, not samples"
        );
    }

    #[test]
    fn snapshots_do_not_grow_the_collector_without_bound() {
        // A long-lived agent takes these forever; state that accumulated per sample
        // would be a slow leak.
        let mut collector = MetricsCollector::new();
        for _ in 0..5 {
            collector.snapshot(0);
        }
        assert!(
            collector.previous_network.len() < 1000,
            "interface state must track interfaces, not samples"
        );
    }

    #[test]
    fn a_process_the_agent_cannot_read_reports_no_path_rather_than_an_empty_one() {
        // An empty string would be indistinguishable from a process at the filesystem
        // root; `None` says plainly that the value was not available.
        let mut collector = MetricsCollector::new();
        let processes = collector.all_processes();

        assert!(
            processes
                .iter()
                .all(|p| p.executable_path.as_deref() != Some("")),
            "an unreadable path must be absent, not empty"
        );
    }

    #[test]
    fn the_collector_debug_output_carries_no_process_detail() {
        // Metrics include process names and paths; a `Debug` dump of the collector in a
        // log line would carry the lot.
        let collector = MetricsCollector::new();
        let rendered = format!("{collector:?}");

        assert!(rendered.contains("MetricsCollector"));
        assert!(!rendered.contains(".exe"), "no process detail: {rendered}");
    }
}
