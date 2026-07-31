//! Platform abstraction for the host agent.
//!
//! Operating-system differences are confined to this crate. Everything above it —
//! the connection layer, the file manager, the dashboard — is written once against
//! these types. Adding macOS support means adding implementations here, not editing
//! call sites throughout the tree.
//!
//! # Modules
//!
//! * [`paths`] — where configuration, data and logs live on each OS.
//! * [`host`] — facts about the machine.
//! * [`privileged`] — the closed allowlist of privileged commands. Read the module
//!   docs before adding anything: the injection-resistance argument depends on the
//!   rules described there.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod error;
pub mod host;
pub mod paths;
pub mod privileged;

pub use error::{PlatformError, Result};
pub use host::HostInfo;
pub use paths::AppPaths;
pub use privileged::PrivilegedCommand;

/// Whether the current process is running with Administrator / root privileges.
///
/// The desktop client is expected to return `false` here: it deliberately does not
/// run elevated, and routes privileged work through the agent service instead.
#[must_use]
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY-free alternative to libc: on Linux the effective UID is readable
        // from /proc without an unsafe call, and `unsafe_code` is forbidden here.
        std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .and_then(|uid| uid.split_whitespace().nth(1))
                .is_some_and(|effective| effective == "0")
        })
    }
    #[cfg(windows)]
    {
        // Probing a path that only Administrators may write is a reliable, allocation
        // -free check that needs no Win32 bindings and no unsafe code.
        let probe = std::path::Path::new("C:\\Windows\\System32\\config\\systemprofile");
        std::fs::read_dir(probe).is_ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn elevation_check_does_not_panic() {
        // The value depends on how the test runner was launched, so only the fact
        // that the probe completes safely is asserted.
        let _ = super::is_elevated();
    }
}
