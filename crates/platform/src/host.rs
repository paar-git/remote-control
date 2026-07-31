//! Facts about the machine the agent is running on.

use rc_protocol::control::OsFamily;

/// Static-ish description of the host, gathered once at startup and refreshed rarely.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HostInfo {
    /// Machine hostname.
    pub hostname: String,
    /// OS family this build is running on.
    pub os_family: OsFamily,
    /// Human-readable OS name and version.
    pub os_version: String,
    /// Kernel version string.
    pub kernel_version: String,
    /// CPU architecture, e.g. `"x86_64"`.
    pub architecture: String,
    /// Number of logical processors.
    pub logical_cores: usize,
    /// Total physical memory in bytes.
    pub total_memory_bytes: u64,
}

impl HostInfo {
    /// Gather host facts from the operating system.
    ///
    /// Never fails: unavailable fields fall back to `"unknown"` rather than erroring,
    /// because a missing kernel version must not stop the agent from starting.
    #[must_use]
    pub fn detect() -> Self {
        let unknown = || "unknown".to_string();

        let mut system = sysinfo::System::new();
        system.refresh_memory();

        Self {
            hostname: sysinfo::System::host_name().unwrap_or_else(unknown),
            os_family: detect_os_family(),
            os_version: sysinfo::System::long_os_version().unwrap_or_else(unknown),
            kernel_version: sysinfo::System::kernel_version().unwrap_or_else(unknown),
            architecture: std::env::consts::ARCH.to_string(),
            logical_cores: std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
            total_memory_bytes: system.total_memory(),
        }
    }
}

/// The OS family this binary was compiled for.
#[must_use]
pub const fn detect_os_family() -> OsFamily {
    if cfg!(windows) {
        OsFamily::Windows
    } else if cfg!(target_os = "linux") {
        OsFamily::Linux
    } else if cfg!(target_os = "macos") {
        OsFamily::MacOs
    } else {
        OsFamily::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_a_known_os_family() {
        assert_ne!(
            detect_os_family(),
            OsFamily::Unknown,
            "this build targets a supported OS"
        );
    }

    #[test]
    fn host_info_is_populated() {
        let info = HostInfo::detect();
        assert!(!info.hostname.is_empty());
        assert!(!info.architecture.is_empty());
        assert!(info.logical_cores >= 1);
        assert!(info.total_memory_bytes > 0, "a running host has memory");
    }

    #[test]
    fn host_info_matches_the_compiled_target() {
        assert_eq!(HostInfo::detect().os_family, detect_os_family());
        assert_eq!(HostInfo::detect().architecture, std::env::consts::ARCH);
    }

    #[test]
    fn detection_is_stable_across_calls() {
        assert_eq!(HostInfo::detect().hostname, HostInfo::detect().hostname);
    }
}
