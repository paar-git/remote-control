//! Resolving a requested shell to a program on this host.
//!
//! # Why this is a lookup rather than a string
//!
//! The client asks for a *kind* of shell — PowerShell, cmd, bash — and this module
//! finds a matching program. It never accepts a path from the client.
//!
//! That is deliberate. A "which shell" field that took an arbitrary path would be an
//! arbitrary-program-execution API wearing a terminal's clothes: the capability check
//! would say "may open a terminal" and the effect would be "may run anything". Keeping
//! the choice to a closed set means the worst a client can do with this API is get a
//! shell — which is what the capability grants, and no more.
//!
//! Once inside the shell the operator can of course run anything. The difference
//! matters because it is *auditable*: the session is recorded as a terminal session,
//! not as an opaque command.

use rc_protocol::terminal::ShellKind;

use crate::error::{Result, TerminalError};

/// A shell that exists on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedShell {
    /// Absolute path to the program.
    pub program: String,
    /// Arguments it is launched with.
    pub args: Vec<String>,
    /// What to call it in the UI.
    pub label: &'static str,
}

/// Candidate programs for each kind, in preference order.
///
/// PowerShell 7 before Windows PowerShell 5, because an operator who installed 7 wants
/// 7. Everything is an absolute path or a bare name resolved against `PATH` by the
/// platform — never a value from the client.
fn candidates(
    kind: ShellKind,
) -> (
    &'static [&'static str],
    &'static [&'static str],
    &'static str,
) {
    match kind {
        ShellKind::PowerShell => (
            &["pwsh.exe", "powershell.exe"],
            // `-NoLogo` because a banner on every session is noise, and
            // `-NoProfile` is deliberately *not* passed: an operator's profile is part
            // of the environment they expect on their own machine.
            &["-NoLogo"],
            "PowerShell",
        ),
        ShellKind::Cmd => (&["cmd.exe"], &[], "Command Prompt"),
        ShellKind::Bash => (
            &["/bin/bash", "/usr/bin/bash", "bash"],
            // A login shell, so the operator gets the environment they would get on the
            // console rather than a stripped one.
            &["-l"],
            "Bash",
        ),
        ShellKind::SystemDefault | _ => {
            if cfg!(windows) {
                (&["powershell.exe", "cmd.exe"], &["-NoLogo"], "PowerShell")
            } else {
                (&["/bin/bash", "/bin/sh"], &["-l"], "Shell")
            }
        }
    }
}

/// Find a program for `kind` on this host.
///
/// # Errors
/// [`TerminalError::ShellNotFound`] when no candidate exists, which is the honest
/// answer on a container image with no bash rather than falling back to something the
/// operator did not ask for.
pub fn resolve_shell(kind: ShellKind) -> Result<ResolvedShell> {
    let (programs, args, label) = candidates(kind);

    for program in programs {
        if let Some(found) = locate(program) {
            return Ok(ResolvedShell {
                program: found,
                // `cmd.exe` rejects the PowerShell arguments, so arguments belong to the
                // kind rather than to the fallback list.
                args: args.iter().map(|arg| (*arg).to_owned()).collect(),
                label,
            });
        }
    }

    Err(TerminalError::ShellNotFound {
        kind: kind_name(kind),
    })
}

/// Whether `program` exists, resolving a bare name against `PATH`.
fn locate(program: &str) -> Option<String> {
    let path = std::path::Path::new(program);

    if path.is_absolute() {
        return path.is_file().then(|| program.to_owned());
    }

    // A bare name is resolved by walking `PATH` rather than handed to the shell, so the
    // result is a concrete path that can be recorded in the audit trail.
    let separator = if cfg!(windows) { ';' } else { ':' };
    let paths = std::env::var("PATH").ok()?;

    paths
        .split(separator)
        .map(|dir| std::path::Path::new(dir).join(program))
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.to_string_lossy().into_owned())
}

/// Stable name for a shell kind, for errors and audit records.
#[must_use]
pub const fn kind_name(kind: ShellKind) -> &'static str {
    match kind {
        ShellKind::PowerShell => "PowerShell",
        ShellKind::Cmd => "Command Prompt",
        ShellKind::Bash => "bash",
        ShellKind::SystemDefault => "default",
        // `ShellKind` is `#[non_exhaustive]`.
        _ => "unknown",
    }
}

/// Validate a client-supplied working directory.
///
/// # Errors
/// [`TerminalError::BadWorkingDirectory`] if it is not an existing directory.
///
/// The value comes from the client, so it is checked rather than trusted. It is used
/// only as the child's starting directory — a shell can `cd` anywhere afterwards, so
/// this is a convenience, not a confinement, and is not presented as one.
pub fn validate_working_directory(directory: &str) -> Result<std::path::PathBuf> {
    let path = std::path::Path::new(directory);

    if !path.is_dir() {
        return Err(TerminalError::BadWorkingDirectory);
    }

    // Canonicalised so the audit record names one path rather than whichever of several
    // spellings the client happened to send.
    path.canonicalize()
        .map_err(|_| TerminalError::BadWorkingDirectory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_platforms_default_shell_resolves() {
        // Every supported platform has one; failing here means the agent could not open
        // a terminal at all.
        let shell = resolve_shell(ShellKind::SystemDefault).expect("a default shell must exist");

        assert!(!shell.program.is_empty());
        assert!(
            std::path::Path::new(&shell.program).is_file(),
            "the resolved program must actually exist: {}",
            shell.program
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_resolves_powershell_and_cmd() {
        let powershell = resolve_shell(ShellKind::PowerShell).unwrap();
        assert!(
            powershell.program.to_lowercase().contains("powershell")
                || powershell.program.to_lowercase().contains("pwsh")
        );

        let cmd = resolve_shell(ShellKind::Cmd).unwrap();
        assert!(cmd.program.to_lowercase().contains("cmd.exe"));
        assert!(
            cmd.args.is_empty(),
            "cmd.exe rejects PowerShell's arguments"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_resolves_bash_as_a_login_shell() {
        let bash = resolve_shell(ShellKind::Bash).unwrap();
        assert!(bash.program.contains("bash"));
        assert!(
            bash.args.contains(&"-l".to_owned()),
            "an operator expects their console environment"
        );
    }

    #[test]
    fn a_resolved_program_is_an_absolute_path() {
        // The audit trail records what actually ran, not a name that PATH might have
        // resolved differently.
        let shell = resolve_shell(ShellKind::SystemDefault).unwrap();
        assert!(
            std::path::Path::new(&shell.program).is_absolute(),
            "got {}",
            shell.program
        );
    }

    #[test]
    fn every_shell_kind_has_a_stable_name() {
        let names = [
            kind_name(ShellKind::PowerShell),
            kind_name(ShellKind::Cmd),
            kind_name(ShellKind::Bash),
            kind_name(ShellKind::SystemDefault),
        ];
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
    }

    #[test]
    fn a_missing_program_is_not_located() {
        assert_eq!(locate("definitely-not-a-real-program-xyz"), None);
        assert_eq!(locate("/definitely/not/a/real/path"), None);
    }

    #[test]
    fn an_existing_directory_is_accepted_and_canonicalised() {
        let dir = std::env::temp_dir();
        let validated = validate_working_directory(&dir.to_string_lossy()).unwrap();
        assert!(validated.is_dir());
    }

    #[test]
    fn a_working_directory_that_is_not_a_directory_is_refused() {
        assert!(validate_working_directory("/no/such/directory/anywhere").is_err());
        assert!(validate_working_directory("").is_err());
    }

    #[test]
    fn a_file_is_not_accepted_as_a_working_directory() {
        let file = std::env::current_exe().unwrap();
        assert!(validate_working_directory(&file.to_string_lossy()).is_err());
    }

    #[test]
    fn the_client_cannot_choose_the_program_only_the_kind() {
        // The property that keeps this from being an arbitrary-execution API: there is
        // no input to `resolve_shell` other than a closed enum.
        let shell = resolve_shell(ShellKind::SystemDefault).unwrap();
        let again = resolve_shell(ShellKind::SystemDefault).unwrap();
        assert_eq!(
            shell, again,
            "resolution depends only on the host, never on caller input"
        );
    }
}
