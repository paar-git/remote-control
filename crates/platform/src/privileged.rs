//! The privileged-command allowlist.
//!
//! Every privileged operation the agent can perform is resolved here into a
//! *fixed program path plus an explicit argument vector*. Nothing in this module ever
//! builds a shell command line from a string, and no caller-supplied text is ever
//! concatenated into a command. That makes command injection structurally impossible
//! rather than something we try to filter for:
//!
//! * The program is chosen from a closed set of constants, never from input.
//! * Arguments are passed as a `Vec<String>` to `CreateProcess`/`execve`, so quoting,
//!   `&&`, `|`, `;`, `$(…)` and newlines in a caller-supplied value are inert data.
//! * The only caller-supplied values that reach an argument vector are service names,
//!   and those are validated against [`validate_service_name`] first.
//!
//! Resolution is a pure function so the entire allowlist is unit-testable without
//! running anything.

use rc_protocol::system::{PowerAction, ServiceAction};

use crate::error::{PlatformError, Result};

/// A resolved privileged command: exactly what will be executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedCommand {
    /// Absolute path (or bare name resolved via the system path) of the program.
    pub program: String,
    /// Arguments, passed verbatim as separate argv entries. Never shell-parsed.
    pub args: Vec<String>,
    /// Whether the operation needs Administrator / root.
    pub requires_elevation: bool,
    /// Stable name used in audit records.
    pub audit_name: &'static str,
}

/// Longest permitted service or unit name.
const MAX_SERVICE_NAME_LEN: usize = 256;

/// Services and units that must not be controlled remotely, because stopping them
/// would sever the agent's own connectivity or break the host badly enough that
/// nobody could reconnect to fix it.
///
/// The operator can still act on these locally at the console. This list is a
/// deny-rule, checked after the allowlist.
pub const PROTECTED_SERVICES: &[&str] = &[
    // The agent itself.
    "remote-control-agent",
    "remote-control-agent.service",
    // Windows networking and login.
    "dhcp",
    "dnscache",
    "lanmanworkstation",
    "netprofm",
    "nlasvc",
    "nsi",
    "rpcss",
    "termservice",
    "winlogon",
    // Linux networking, login and init.
    "dbus",
    "dbus.service",
    "networking",
    "networking.service",
    "networkmanager",
    "networkmanager.service",
    "systemd-logind",
    "systemd-logind.service",
    "systemd-networkd",
    "systemd-networkd.service",
    "systemd-resolved",
    "systemd-resolved.service",
    "ssh",
    "ssh.service",
    "sshd",
    "sshd.service",
];

/// Validate a caller-supplied service or unit name.
///
/// Accepts only characters that appear in real Windows service names and systemd unit
/// names: ASCII alphanumerics and `-`, `_`, `.`, `@`. Everything else — whitespace,
/// quotes, slashes, shell metacharacters, NUL, non-ASCII — is rejected.
///
/// This is defence in depth. Even a name that slipped through could not inject a
/// command, because it is passed as a single argv element.
///
/// # Errors
/// Returns [`PlatformError::InvalidArgument`] for empty, over-long or malformed names.
pub fn validate_service_name(name: &str) -> Result<()> {
    const OP: &str = "service control";

    if name.is_empty() {
        return Err(PlatformError::InvalidArgument {
            operation: OP,
            reason: "service name must not be empty",
        });
    }
    if name.len() > MAX_SERVICE_NAME_LEN {
        return Err(PlatformError::InvalidArgument {
            operation: OP,
            reason: "service name is too long",
        });
    }
    // A leading '-' would be parsed as a flag by the target program.
    if name.starts_with('-') {
        return Err(PlatformError::InvalidArgument {
            operation: OP,
            reason: "service name must not start with a dash",
        });
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
    {
        return Err(PlatformError::InvalidArgument {
            operation: OP,
            reason: "service name contains disallowed characters",
        });
    }
    Ok(())
}

/// Whether a service is on the protected deny-list.
///
/// Comparison is case-insensitive because Windows service names are, and a trailing
/// `.service` suffix is normalised away because systemd treats it as optional.
#[must_use]
pub fn is_protected_service(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    let bare = lowered.strip_suffix(".service").unwrap_or(&lowered);
    PROTECTED_SERVICES.iter().any(|protected| {
        let p = protected.strip_suffix(".service").unwrap_or(protected);
        p == bare
    })
}

/// Resolve a power action into an executable command for the current platform.
///
/// # Errors
/// Returns [`PlatformError::Unsupported`] when the platform has no safe equivalent.
pub fn resolve_power_action(action: PowerAction) -> Result<PrivilegedCommand> {
    #[cfg(windows)]
    {
        windows_power(action)
    }
    #[cfg(not(windows))]
    {
        unix_power(action)
    }
}

/// Resolve a service action into an executable command for the current platform.
///
/// # Errors
/// * [`PlatformError::InvalidArgument`] if the name fails validation.
/// * [`PlatformError::BlockedBySafetyRule`] if the service is protected.
/// * [`PlatformError::Unsupported`] if the platform cannot perform the action.
pub fn resolve_service_action(name: &str, action: ServiceAction) -> Result<PrivilegedCommand> {
    validate_service_name(name)?;

    if is_protected_service(name) {
        return Err(PlatformError::BlockedBySafetyRule {
            operation: "service control",
            reason: "this service is required for the agent or host to stay reachable",
        });
    }

    #[cfg(windows)]
    {
        windows_service(name, action)
    }
    #[cfg(not(windows))]
    {
        unix_service(name, action)
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// Resolve a power action to a Windows command. Exposed for cross-platform tests.
#[allow(dead_code)]
pub(crate) fn windows_power(action: PowerAction) -> Result<PrivilegedCommand> {
    let system32 = |exe: &str| format!("C:\\Windows\\System32\\{exe}");
    let cmd = |program: String, args: &[&str], elevate: bool, audit: &'static str| {
        Ok(PrivilegedCommand {
            program,
            args: args.iter().map(|s| (*s).to_string()).collect(),
            requires_elevation: elevate,
            audit_name: audit,
        })
    };

    match action {
        // LockWorkStation via rundll32 is the documented, supported mechanism.
        PowerAction::Lock => cmd(
            system32("rundll32.exe"),
            &["user32.dll,LockWorkStation"],
            false,
            "power.lock",
        ),
        PowerAction::SignOut => cmd(system32("shutdown.exe"), &["/l"], false, "power.sign_out"),
        // /t 0 is overridden by the scheduler, which supplies its own countdown.
        PowerAction::Restart => cmd(
            system32("shutdown.exe"),
            &["/r", "/t", "0"],
            true,
            "power.restart",
        ),
        PowerAction::Shutdown => cmd(
            system32("shutdown.exe"),
            &["/s", "/t", "0"],
            true,
            "power.shutdown",
        ),
        // Sleep requires hibernation to be off, otherwise this hibernates instead.
        PowerAction::Sleep => cmd(
            system32("rundll32.exe"),
            &["powrprof.dll,SetSuspendState", "0,1,0"],
            true,
            "power.sleep",
        ),
        PowerAction::Hibernate => cmd(system32("shutdown.exe"), &["/h"], true, "power.hibernate"),
        PowerAction::RestartToRecovery => cmd(
            system32("shutdown.exe"),
            &["/r", "/o", "/t", "0"],
            true,
            "power.recovery",
        ),
        // Handled in-process by the agent supervisor, not by spawning anything.
        PowerAction::RestartAgent => Err(PlatformError::Unsupported {
            operation: "restart agent via external command",
        }),
        // `PowerAction` is `#[non_exhaustive]`. An action added by a newer peer must
        // fail closed here rather than fall through to something approximate.
        _ => Err(PlatformError::NotAllowlisted {
            operation: "unrecognised power action",
        }),
    }
}

/// Resolve a service action to a Windows command. Exposed for cross-platform tests.
#[allow(dead_code)]
pub(crate) fn windows_service(name: &str, action: ServiceAction) -> Result<PrivilegedCommand> {
    let sc = "C:\\Windows\\System32\\sc.exe".to_string();
    let owned = name.to_string();

    let (args, audit) = match action {
        ServiceAction::Start => (vec!["start".to_string(), owned], "service.start"),
        ServiceAction::Stop => (vec!["stop".to_string(), owned], "service.stop"),
        // sc.exe has no restart verb; the caller sequences stop then start so it can
        // report which half failed.
        ServiceAction::Restart => (vec!["stop".to_string(), owned], "service.restart"),
        ServiceAction::EnableAtBoot => (
            vec![
                "config".to_string(),
                owned,
                "start=".to_string(),
                "auto".to_string(),
            ],
            "service.enable",
        ),
        ServiceAction::DisableAtBoot => (
            vec![
                "config".to_string(),
                owned,
                "start=".to_string(),
                "disabled".to_string(),
            ],
            "service.disable",
        ),
        // Fail closed on variants added by a newer peer.
        _ => {
            return Err(PlatformError::NotAllowlisted {
                operation: "unrecognised service action",
            });
        }
    };

    Ok(PrivilegedCommand {
        program: sc,
        args,
        requires_elevation: true,
        audit_name: audit,
    })
}

// ---------------------------------------------------------------------------
// Unix / Linux
// ---------------------------------------------------------------------------

/// Resolve a power action to a Linux command. Exposed for cross-platform tests.
#[allow(dead_code)]
pub(crate) fn unix_power(action: PowerAction) -> Result<PrivilegedCommand> {
    let systemctl = "/usr/bin/systemctl".to_string();
    let cmd = |args: &[&str], elevate: bool, audit: &'static str| {
        Ok(PrivilegedCommand {
            program: systemctl.clone(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            requires_elevation: elevate,
            audit_name: audit,
        })
    };

    match action {
        // Locks every active session rather than assuming a single seat.
        PowerAction::Lock => Ok(PrivilegedCommand {
            program: "/usr/bin/loginctl".to_string(),
            args: vec!["lock-sessions".to_string()],
            requires_elevation: true,
            audit_name: "power.lock",
        }),
        PowerAction::SignOut => Ok(PrivilegedCommand {
            program: "/usr/bin/loginctl".to_string(),
            args: vec!["terminate-user".to_string()],
            requires_elevation: true,
            audit_name: "power.sign_out",
        }),
        PowerAction::Restart => cmd(&["reboot"], true, "power.restart"),
        PowerAction::Shutdown => cmd(&["poweroff"], true, "power.shutdown"),
        PowerAction::Sleep => cmd(&["suspend"], true, "power.sleep"),
        PowerAction::Hibernate => cmd(&["hibernate"], true, "power.hibernate"),
        // Requires a bootloader entry the agent cannot assume exists.
        PowerAction::RestartToRecovery => Err(PlatformError::Unsupported {
            operation: "restart to recovery",
        }),
        PowerAction::RestartAgent => Err(PlatformError::Unsupported {
            operation: "restart agent via external command",
        }),
        // Fail closed on variants added by a newer peer.
        _ => Err(PlatformError::NotAllowlisted {
            operation: "unrecognised power action",
        }),
    }
}

/// Resolve a service action to a Linux command. Exposed for cross-platform tests.
#[allow(dead_code)]
pub(crate) fn unix_service(name: &str, action: ServiceAction) -> Result<PrivilegedCommand> {
    let (verb, audit) = match action {
        ServiceAction::Start => ("start", "service.start"),
        ServiceAction::Stop => ("stop", "service.stop"),
        ServiceAction::Restart => ("restart", "service.restart"),
        ServiceAction::EnableAtBoot => ("enable", "service.enable"),
        ServiceAction::DisableAtBoot => ("disable", "service.disable"),
        // Fail closed on variants added by a newer peer.
        _ => {
            return Err(PlatformError::NotAllowlisted {
                operation: "unrecognised service action",
            });
        }
    };

    Ok(PrivilegedCommand {
        program: "/usr/bin/systemctl".to_string(),
        // `--` stops systemctl parsing anything after it as an option, so even a name
        // that passed validation cannot become a flag.
        args: vec![verb.to_string(), "--".to_string(), name.to_string()],
        requires_elevation: true,
        audit_name: audit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Payloads that would matter if any of this were passed through a shell.
    const INJECTION_PAYLOADS: &[&str] = &[
        "nginx; rm -rf /",
        "nginx && shutdown -h now",
        "nginx | tee /etc/passwd",
        "nginx`whoami`",
        "nginx$(id)",
        "nginx\nshutdown",
        "nginx\r\nshutdown",
        "nginx&calc.exe",
        "nginx\"; sc delete x; \"",
        "nginx'",
        "../../../etc/systemd/system/evil.service",
        "..\\..\\windows\\system32\\evil",
        "nginx service",
        "nginx\0evil",
        "-f",
        "--force",
        "sérvice",
        "服务",
    ];

    #[test]
    fn service_name_validation_rejects_every_injection_payload() {
        for payload in INJECTION_PAYLOADS {
            assert!(
                validate_service_name(payload).is_err(),
                "must reject service name {payload:?}"
            );
        }
    }

    #[test]
    fn service_name_validation_accepts_real_names() {
        for name in [
            "nginx",
            "nginx.service",
            "ssh-agent",
            "systemd-timesyncd.service",
            "getty@tty1.service",
            "MSSQL_SERVER",
            "W32Time",
            "user_service.v2",
        ] {
            assert!(
                validate_service_name(name).is_ok(),
                "must accept service name {name:?}"
            );
        }
    }

    #[test]
    fn service_name_validation_rejects_empty_and_overlong() {
        assert!(validate_service_name("").is_err());
        assert!(validate_service_name(&"a".repeat(MAX_SERVICE_NAME_LEN + 1)).is_err());
        assert!(validate_service_name(&"a".repeat(MAX_SERVICE_NAME_LEN)).is_ok());
    }

    #[test]
    fn injection_payloads_never_reach_a_resolved_command() {
        for payload in INJECTION_PAYLOADS {
            let resolved = resolve_service_action(payload, ServiceAction::Stop);
            assert!(
                resolved.is_err(),
                "must not resolve a command for {payload:?}"
            );
        }
    }

    #[test]
    fn protected_services_cannot_be_controlled() {
        for name in [
            "sshd",
            "SSHD.service",
            "systemd-networkd",
            "remote-control-agent",
            "RpcSs",
        ] {
            let err = resolve_service_action(name, ServiceAction::Stop).unwrap_err();
            assert!(
                matches!(err, PlatformError::BlockedBySafetyRule { .. }),
                "{name} must be blocked, got {err:?}"
            );
        }
    }

    #[test]
    fn the_agents_own_service_is_protected() {
        assert!(is_protected_service("remote-control-agent"));
        assert!(is_protected_service("remote-control-agent.service"));
    }

    #[test]
    fn unprotected_services_resolve() {
        let cmd = resolve_service_action("nginx", ServiceAction::Restart).unwrap();
        assert!(cmd.requires_elevation);
        assert!(cmd.args.iter().any(|a| a == "nginx"));
    }

    #[test]
    fn a_service_name_is_always_a_single_argv_element() {
        // The property that makes injection impossible: whatever the name is, it
        // occupies exactly one slot and is never split or re-parsed.
        let cmd = unix_service("nginx.service", ServiceAction::Start).unwrap();
        assert_eq!(cmd.args.iter().filter(|a| a.contains("nginx")).count(), 1);

        let cmd = windows_service("W32Time", ServiceAction::Start).unwrap();
        assert_eq!(cmd.args.iter().filter(|a| a.contains("W32Time")).count(), 1);
    }

    #[test]
    fn systemctl_invocations_terminate_option_parsing() {
        for action in [
            ServiceAction::Start,
            ServiceAction::Stop,
            ServiceAction::Restart,
            ServiceAction::EnableAtBoot,
            ServiceAction::DisableAtBoot,
        ] {
            let cmd = unix_service("nginx", action).unwrap();
            let dash_dash = cmd
                .args
                .iter()
                .position(|a| a == "--")
                .expect("`--` guard present");
            let name = cmd
                .args
                .iter()
                .position(|a| a == "nginx")
                .expect("name present");
            assert!(dash_dash < name, "`--` must precede the service name");
        }
    }

    #[test]
    fn destructive_power_actions_require_elevation_on_both_platforms() {
        for action in [PowerAction::Restart, PowerAction::Shutdown] {
            assert!(windows_power(action).unwrap().requires_elevation);
            assert!(unix_power(action).unwrap().requires_elevation);
        }
    }

    #[test]
    fn locking_does_not_require_elevation_on_windows() {
        assert!(!windows_power(PowerAction::Lock).unwrap().requires_elevation);
    }

    #[test]
    fn agent_restart_is_never_an_external_command() {
        // It is handled by the supervisor in-process; spawning something to restart
        // ourselves would race with our own shutdown.
        assert!(windows_power(PowerAction::RestartAgent).is_err());
        assert!(unix_power(PowerAction::RestartAgent).is_err());
    }

    #[test]
    fn every_resolved_program_is_a_fixed_constant_path() {
        let mut commands = Vec::new();
        for action in [
            PowerAction::Lock,
            PowerAction::SignOut,
            PowerAction::Restart,
            PowerAction::Shutdown,
            PowerAction::Sleep,
            PowerAction::Hibernate,
        ] {
            if let Ok(c) = windows_power(action) {
                commands.push(c);
            }
            if let Ok(c) = unix_power(action) {
                commands.push(c);
            }
        }
        commands.push(unix_service("nginx", ServiceAction::Start).unwrap());
        commands.push(windows_service("nginx", ServiceAction::Start).unwrap());

        for cmd in commands {
            assert!(
                cmd.program.starts_with("C:\\Windows\\System32\\") || cmd.program.starts_with('/'),
                "program must be an absolute, known path: {}",
                cmd.program
            );
            assert!(
                !cmd.audit_name.is_empty(),
                "every command must be auditable"
            );
            // No shell is ever involved.
            assert!(!cmd.program.to_lowercase().contains("cmd.exe"));
            assert!(!cmd.program.contains("powershell"));
            assert!(!cmd.program.ends_with("/sh"));
            assert!(!cmd.program.ends_with("/bash"));
        }
    }
}
