//! Terminal-channel messages backed by a real pseudo-terminal on the host.

use serde::{Deserialize, Serialize};

use crate::ids::TerminalId;

/// Which shell to spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ShellKind {
    /// Windows PowerShell or PowerShell 7, whichever the agent resolves.
    PowerShell,
    /// Windows `cmd.exe`.
    Cmd,
    /// The platform's default POSIX shell.
    Bash,
    /// The user's login shell as configured on the host.
    SystemDefault,
}

/// Privilege level a terminal session runs at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeLevel {
    /// Runs as the unprivileged agent user.
    Standard,
    /// Runs elevated (Administrator / root). Must be explicitly requested and
    /// separately authorized.
    Elevated,
}

/// Terminal grid size in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalSize {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
}

impl TerminalSize {
    /// Clamp to a range a PTY will actually accept.
    #[must_use]
    pub const fn clamped(self) -> Self {
        Self {
            cols: if self.cols < 2 {
                2
            } else if self.cols > 1000 {
                1000
            } else {
                self.cols
            },
            rows: if self.rows < 2 {
                2
            } else if self.rows > 1000 {
                1000
            } else {
                self.rows
            },
        }
    }
}

/// Client → agent terminal messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TerminalClientMessage {
    /// Open a new PTY.
    Open {
        /// Id the client assigns to this session.
        terminal_id: TerminalId,
        /// Shell to launch.
        shell: ShellKind,
        /// Requested privilege level.
        privilege: PrivilegeLevel,
        /// Initial grid size.
        size: TerminalSize,
        /// Working directory. `None` means the agent's configured default.
        working_directory: Option<String>,
    },
    /// Raw bytes for the PTY's standard input.
    Input {
        /// Target session.
        terminal_id: TerminalId,
        /// Bytes to write. Never logged.
        data: Vec<u8>,
    },
    /// The terminal window was resized.
    Resize {
        /// Target session.
        terminal_id: TerminalId,
        /// New grid size.
        size: TerminalSize,
    },
    /// Send a signal / control event to the foreground process.
    Signal {
        /// Target session.
        terminal_id: TerminalId,
        /// Which signal.
        signal: TerminalSignal,
    },
    /// Close the PTY and reap the child process.
    Close {
        /// Target session.
        terminal_id: TerminalId,
    },
}

/// Portable control events deliverable to a PTY's foreground process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TerminalSignal {
    /// Ctrl+C — interrupt.
    Interrupt,
    /// Ctrl+\ — quit (POSIX only; ignored on Windows).
    Quit,
    /// Forcibly terminate the process tree.
    Kill,
}

/// Agent → client terminal messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TerminalAgentMessage {
    /// The PTY was created successfully.
    Opened {
        /// Session that opened.
        terminal_id: TerminalId,
        /// Program actually launched, for display in the UI.
        shell_path: String,
        /// Privilege the session actually got, which may be lower than requested.
        privilege: PrivilegeLevel,
        /// Host process id of the shell.
        pid: u32,
    },
    /// Bytes read from the PTY. Combined stdout and stderr, as a PTY has one stream.
    Output {
        /// Source session.
        terminal_id: TerminalId,
        /// Raw bytes, including ANSI escapes. Never logged.
        data: Vec<u8>,
    },
    /// The shell exited.
    Exited {
        /// Session that ended.
        terminal_id: TerminalId,
        /// Process exit code, if one was reported.
        exit_code: Option<i32>,
    },
    /// The session could not be opened or an operation on it failed.
    Error {
        /// Session concerned.
        terminal_id: TerminalId,
        /// Machine-readable code.
        code: crate::control::ErrorCode,
        /// Operator-facing message.
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_size_is_clamped_to_a_usable_range() {
        assert_eq!(
            TerminalSize { cols: 0, rows: 0 }.clamped(),
            TerminalSize { cols: 2, rows: 2 }
        );
        assert_eq!(
            TerminalSize {
                cols: u16::MAX,
                rows: u16::MAX
            }
            .clamped(),
            TerminalSize {
                cols: 1000,
                rows: 1000
            }
        );
        let ok = TerminalSize {
            cols: 120,
            rows: 40,
        };
        assert_eq!(ok.clamped(), ok);
    }

    #[test]
    fn terminal_messages_roundtrip_on_the_wire() {
        let msg = TerminalClientMessage::Input {
            terminal_id: TerminalId::generate(),
            data: vec![3, 0, 255],
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();
        assert_eq!(
            postcard::from_bytes::<TerminalClientMessage>(&bytes).unwrap(),
            msg
        );
    }
}
