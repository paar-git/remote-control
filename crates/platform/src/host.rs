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

/// Every address on this machine a peer on the same network could dial.
///
/// Loopback is excluded: an address only this machine can reach is not one to show
/// someone who is being asked to type it in elsewhere. Link-local IPv4 (`169.254/16`)
/// is excluded for the same reason — it means DHCP failed, so the address will not
/// route. IPv6 link-local (`fe80::/10`) is excluded because it is unusable without a
/// zone index this does not carry.
///
/// Returns them sorted, IPv4 first, so the list a user reads off the screen does not
/// reorder itself between calls. May be empty on a machine with no network at all,
/// which is reported as empty rather than padded with a loopback address that would
/// not work.
#[must_use]
pub fn reachable_addresses() -> Vec<std::net::IpAddr> {
    use std::net::IpAddr;

    let networks = sysinfo::Networks::new_with_refreshed_list();
    let mut found: Vec<IpAddr> = networks
        .values()
        .flat_map(sysinfo::NetworkData::ip_networks)
        .map(|network| network.addr)
        .filter(|address| match address {
            IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local(),
            // `is_unicast_link_local` is still unstable, so the prefix is checked
            // directly: fe80::/10 is the first ten bits being 1111111010.
            IpAddr::V6(v6) => !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80,
        })
        .collect();

    found.sort_unstable_by_key(|address| (address.is_ipv6(), address.to_string()));
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reachable_addresses_exclude_anything_a_peer_could_not_dial() {
        // The list is read off a screen and typed in on another machine. A loopback or
        // link-local address there is worse than a short list: it looks like an answer
        // and cannot work.
        for address in reachable_addresses() {
            assert!(!address.is_loopback(), "{address} is loopback");
            match address {
                std::net::IpAddr::V4(v4) => assert!(!v4.is_link_local(), "{v4} is link-local"),
                std::net::IpAddr::V6(v6) => {
                    assert_ne!(v6.segments()[0] & 0xffc0, 0xfe80, "{v6} is link-local");
                }
            }
        }
    }

    #[test]
    fn reachable_addresses_are_ordered_and_unique() {
        // Shown as a list a user picks from; it must not reshuffle between renders.
        let first = reachable_addresses();
        assert_eq!(first, reachable_addresses(), "the order must be stable");

        let mut deduped = first.clone();
        deduped.dedup();
        assert_eq!(deduped, first, "an address must not appear twice");

        assert!(
            first.windows(2).all(|w| !w[0].is_ipv6() || w[1].is_ipv6()),
            "IPv4 addresses come first, got {first:?}"
        );
    }

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
