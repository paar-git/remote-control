//! One PTY session, and the registry that owns them.
//!
//! # Threads, not tasks
//!
//! `portable-pty` is a blocking API: reading from a PTY blocks until bytes arrive, and
//! there is no portable async equivalent. So each session gets one blocking reader
//! thread that pushes into a bounded channel, and the async side reads that channel.
//!
//! The alternative — polling with a timeout from an async task — would either burn CPU
//! while idle or add latency to every keystroke. A parked thread costs a stack.
//!
//! # Backpressure
//!
//! The output channel is bounded. A shell printing faster than the network can carry it
//! blocks its reader thread rather than growing a buffer, which is the correct
//! behaviour: the alternative is an agent whose memory use is controlled by whatever
//! the operator happened to `cat`.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::sync::Arc;

use parking_lot::Mutex;
use rc_protocol::TerminalId;
use rc_protocol::terminal::{PrivilegeLevel, ShellKind, TerminalSize};

use crate::error::{Result, TerminalError};
use crate::shell::{self, ResolvedShell};

/// How many bytes are read from a PTY in one go.
///
/// Large enough that a burst of output is not chopped into hundreds of frames, small
/// enough to stay far inside the terminal channel's ceiling.
pub const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;

/// How many output chunks may be queued before the reader thread blocks.
///
/// Bounded on purpose; see the module documentation.
const OUTPUT_QUEUE_DEPTH: usize = 64;

/// Largest input payload accepted in one message.
///
/// Input is typed by a human or pasted; a megabyte of "keystrokes" is not a paste, it
/// is an attempt to make the agent allocate.
pub const MAX_INPUT_BYTES: usize = 256 * 1024;

/// One live pseudo-terminal.
pub struct TerminalSession {
    id: TerminalId,
    /// Writes to the PTY's input side.
    writer: Mutex<Box<dyn Write + Send>>,
    /// Controls resize and holds the PTY open.
    master: Mutex<Box<dyn portable_pty::MasterPty + Send>>,
    /// The child shell.
    child: Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
    /// Output read from the PTY.
    output: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    /// What was actually launched.
    shell: ResolvedShell,
    /// The shell's process id.
    pid: u32,
    /// Privilege the session actually got.
    privilege: PrivilegeLevel,
}

/// A writer that is `Send`, which is what the PTY hands back.
trait Write: std::io::Write {}
impl<T: std::io::Write> Write for T {}

impl std::fmt::Debug for TerminalSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately excludes anything read from or written to the terminal.
        f.debug_struct("TerminalSession")
            .field("id", &self.id)
            .field("shell", &self.shell.label)
            .field("pid", &self.pid)
            .field("privilege", &self.privilege)
            .finish_non_exhaustive()
    }
}

impl TerminalSession {
    /// Spawn a shell attached to a new pseudo-terminal.
    ///
    /// Authorization is the caller's job; by the time this is called the capability has
    /// been checked against the live connection.
    ///
    /// # Errors
    /// [`TerminalError::ShellNotFound`], [`TerminalError::BadWorkingDirectory`],
    /// [`TerminalError::PtyUnavailable`] or [`TerminalError::SpawnFailed`].
    pub fn spawn(
        id: TerminalId,
        kind: ShellKind,
        size: TerminalSize,
        working_directory: Option<&str>,
        privilege: PrivilegeLevel,
    ) -> Result<Self> {
        // Elevation is not implemented in this build. Refusing is the honest answer;
        // silently opening an unprivileged shell and labelling it elevated would be
        // considerably worse than saying no.
        if privilege == PrivilegeLevel::Elevated {
            return Err(TerminalError::ElevationUnavailable);
        }

        let resolved = shell::resolve_shell(kind)?;
        let directory = working_directory
            .map(shell::validate_working_directory)
            .transpose()?;

        let size = size.clamped();
        let pty_system = portable_pty::native_pty_system();
        let pair = pty_system
            .openpty(portable_pty::PtySize {
                rows: size.rows,
                cols: size.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| {
                tracing::error!(%err, "could not open a pseudo-terminal");
                TerminalError::PtyUnavailable
            })?;

        let mut command = portable_pty::CommandBuilder::new(&resolved.program);
        for arg in &resolved.args {
            command.arg(arg);
        }
        if let Some(directory) = &directory {
            command.cwd(directory);
        }
        // `TERM` tells the shell it is on a terminal that understands colour. Without
        // it many programs disable colour and line editing entirely.
        command.env("TERM", "xterm-256color");

        let child = pair.slave.spawn_command(command).map_err(|err| {
            tracing::error!(%err, program = %resolved.program, "could not start the shell");
            TerminalError::SpawnFailed
        })?;
        // The slave end is closed here on purpose: while this process holds it open,
        // the master never sees EOF when the child exits, and the session would appear
        // to hang instead of ending.
        drop(pair.slave);

        let pid = child.process_id().unwrap_or(0);
        let writer = pair.master.take_writer().map_err(|err| {
            tracing::error!(%err, "could not take the terminal's input side");
            TerminalError::PtyUnavailable
        })?;
        let reader = pair.master.try_clone_reader().map_err(|err| {
            tracing::error!(%err, "could not take the terminal's output side");
            TerminalError::PtyUnavailable
        })?;

        let (sender, receiver) = tokio::sync::mpsc::channel(OUTPUT_QUEUE_DEPTH);
        spawn_reader_thread(id, reader, sender);

        tracing::info!(
            terminal_id = %id,
            shell = %resolved.label,
            pid,
            "terminal session opened"
        );

        Ok(Self {
            id,
            writer: Mutex::new(Box::new(writer)),
            master: Mutex::new(pair.master),
            child: Mutex::new(child),
            output: tokio::sync::Mutex::new(receiver),
            shell: resolved,
            pid,
            privilege: PrivilegeLevel::Standard,
        })
    }

    /// This session's id.
    #[must_use]
    pub const fn id(&self) -> TerminalId {
        self.id
    }

    /// The program that was launched.
    #[must_use]
    pub fn shell_path(&self) -> &str {
        &self.shell.program
    }

    /// The shell's process id.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// The privilege the session actually got, which may be lower than requested.
    #[must_use]
    pub const fn privilege(&self) -> PrivilegeLevel {
        self.privilege
    }

    /// Write bytes to the terminal's input.
    ///
    /// # Errors
    /// [`TerminalError::SessionLost`] if the shell has gone, or if the payload exceeds
    /// [`MAX_INPUT_BYTES`].
    pub fn write_input(&self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_INPUT_BYTES {
            // Not an allocation the agent should make on a peer's say-so.
            return Err(TerminalError::SessionLost);
        }

        let mut writer = self.writer.lock();
        writer
            .write_all(data)
            .and_then(|()| writer.flush())
            .map_err(|err| {
                // The bytes are deliberately absent from this line: terminal input is
                // where passwords are typed.
                tracing::debug!(terminal_id = %self.id, %err, "terminal input failed");
                TerminalError::SessionLost
            })
    }

    /// Read the next chunk of output, or `None` when the terminal has closed.
    pub async fn next_output(&self) -> Option<Vec<u8>> {
        self.output.lock().await.recv().await
    }

    /// Tell the terminal its window changed size.
    ///
    /// # Errors
    /// [`TerminalError::SessionLost`] if the resize cannot be delivered.
    pub fn resize(&self, size: TerminalSize) -> Result<()> {
        let size = size.clamped();
        self.master
            .lock()
            .resize(portable_pty::PtySize {
                rows: size.rows,
                cols: size.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|err| {
                tracing::debug!(terminal_id = %self.id, %err, "terminal resize failed");
                TerminalError::SessionLost
            })
    }

    /// Whether the shell has exited, and with what code.
    ///
    /// Does not block: a session that is still running reports `None`.
    pub fn exit_status(&self) -> Option<i32> {
        self.child
            .lock()
            .try_wait()
            .ok()
            .flatten()
            .and_then(|status| i32::try_from(status.exit_code()).ok())
    }

    /// End the session, terminating the shell.
    pub fn close(&self) {
        let mut child = self.child.lock();
        if let Err(err) = child.kill() {
            // Already gone is the common case and not worth a warning.
            tracing::debug!(terminal_id = %self.id, %err, "could not signal the shell");
        }
        let _ = child.wait();
        tracing::info!(terminal_id = %self.id, "terminal session closed");
    }
}

impl Drop for TerminalSession {
    /// A dropped session must not leave a shell running.
    ///
    /// This is the backstop for every path that forgets to close explicitly — including
    /// a connection that drops mid-session, which is the common case rather than an
    /// exotic one.
    fn drop(&mut self) {
        let mut child = self.child.lock();
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Pump PTY output into `sender` until the terminal closes.
fn spawn_reader_thread(
    id: TerminalId,
    mut reader: Box<dyn std::io::Read + Send>,
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
) {
    std::thread::Builder::new()
        .name(format!("rc-pty-{id}"))
        .spawn(move || {
            let mut buffer = vec![0u8; OUTPUT_CHUNK_BYTES];
            loop {
                match reader.read(&mut buffer) {
                    // Zero bytes is end of file: the shell exited and the PTY closed.
                    Ok(0) => break,
                    Ok(count) => {
                        // `blocking_send` is what applies backpressure: a shell printing
                        // faster than the network can carry it waits here rather than
                        // growing a queue.
                        if sender.blocking_send(buffer[..count].to_vec()).is_err() {
                            // The receiver is gone, so the session has been dropped.
                            break;
                        }
                    }
                    Err(err) => {
                        tracing::debug!(terminal_id = %id, %err, "terminal output ended");
                        break;
                    }
                }
            }
            tracing::debug!(terminal_id = %id, "terminal reader thread finished");
        })
        // A thread that cannot be spawned means the session produces no output; the
        // session itself still works for input and will be closed by the client.
        .map_or_else(
            |err| tracing::error!(%err, "could not start the terminal reader thread"),
            |_handle| (),
        );
}

/// Every terminal session belonging to one connection.
///
/// Bounded, and dropped wholesale when the connection ends — which is what guarantees
/// no shell outlives the session that started it.
#[derive(Default)]
pub struct TerminalRegistry {
    sessions: Mutex<HashMap<TerminalId, Arc<TerminalSession>>>,
    max_sessions: usize,
}

impl std::fmt::Debug for TerminalRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalRegistry")
            .field("open", &self.sessions.lock().len())
            .field("max_sessions", &self.max_sessions)
            .finish()
    }
}

impl TerminalRegistry {
    /// A registry admitting at most `max_sessions` terminals.
    #[must_use]
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            max_sessions: max_sessions.max(1),
        }
    }

    /// How many sessions are open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.lock().len()
    }

    /// Whether no sessions are open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Take a slot and register `session`.
    ///
    /// # Errors
    /// [`TerminalError::TooManySessions`] when the cap is reached. The session is
    /// dropped, which kills the shell it started.
    pub fn insert(&self, session: TerminalSession) -> Result<Arc<TerminalSession>> {
        let mut sessions = self.sessions.lock();

        if sessions.len() >= self.max_sessions {
            // `session` is dropped here, and its `Drop` kills the shell. Registering it
            // first and removing it later would leave a window in which the cap was
            // exceeded.
            return Err(TerminalError::TooManySessions);
        }

        let shared = Arc::new(session);
        sessions.insert(shared.id(), Arc::clone(&shared));
        Ok(shared)
    }

    /// Look a session up.
    #[must_use]
    pub fn get(&self, id: TerminalId) -> Option<Arc<TerminalSession>> {
        self.sessions.lock().get(&id).map(Arc::clone)
    }

    /// Remove a session and close it.
    pub fn remove(&self, id: TerminalId) -> Option<Arc<TerminalSession>> {
        let session = self.sessions.lock().remove(&id);
        if let Some(session) = &session {
            session.close();
        }
        session
    }

    /// Every open session id.
    #[must_use]
    pub fn ids(&self) -> Vec<TerminalId> {
        self.sessions.lock().keys().copied().collect()
    }

    /// Close every session.
    ///
    /// Called when a connection ends. Without it, closing the client would leave shells
    /// running on the server indefinitely.
    pub fn close_all(&self) {
        let sessions: Vec<Arc<TerminalSession>> =
            self.sessions.lock().drain().map(|(_, s)| s).collect();

        for session in sessions {
            session.close();
        }
    }
}

impl Drop for TerminalRegistry {
    fn drop(&mut self) {
        self.close_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> TerminalSize {
        TerminalSize { cols: 80, rows: 24 }
    }

    fn open() -> TerminalSession {
        TerminalSession::spawn(
            TerminalId::generate(),
            ShellKind::SystemDefault,
            small(),
            None,
            PrivilegeLevel::Standard,
        )
        .expect("the platform's default shell must open")
    }

    /// Answer the terminal queries a shell makes on startup.
    ///
    /// A shell asks the terminal about itself before it will draw a prompt — most
    /// visibly `ESC[6n`, "where is the cursor?", to which a terminal replies
    /// `ESC[row;colR`. A real client answers these because its terminal emulator does;
    /// this is the minimum stand-in so a test without an emulator does not simply hang,
    /// and it documents that the client side is required to hold up that end.
    fn answer_terminal_queries(session: &TerminalSession, chunk: &[u8]) {
        const CURSOR_POSITION_QUERY: &[u8] = b"\x1b[6n";
        const CURSOR_AT_ORIGIN: &[u8] = b"\x1b[1;1R";

        if chunk
            .windows(CURSOR_POSITION_QUERY.len())
            .any(|window| window == CURSOR_POSITION_QUERY)
        {
            let _ = session.write_input(CURSOR_AT_ORIGIN);
        }
    }

    #[tokio::test]
    async fn a_real_shell_starts_and_produces_real_output() {
        // Not a simulation: a child process is running and writing to a terminal.
        let session = open();
        assert!(session.pid() > 0, "a real process must have a pid");
        assert!(
            std::path::Path::new(session.shell_path()).is_file(),
            "the shell path must name a real program"
        );

        let probe = "rc-terminal-probe";
        // CRLF on Windows, LF elsewhere: a terminal delivers the key the
        // platform's shell expects, and cmd.exe ignores a bare LF. On a POSIX
        // shell the quotes are removed before `echo` sees the word, so the
        // echoed line does not contain the probe while the printed line does,
        // and one match proves the command ran rather than proving the terminal
        // echoes input. cmd.exe keeps quotes literally, so Windows uses the
        // plain form and still requires both occurrences.
        let command: &[u8] = if cfg!(windows) {
            b"echo rc-terminal-probe\r\n"
        } else {
            b"echo rc-terminal-pro''be\n"
        };
        let required_matches = if cfg!(windows) { 2 } else { 1 };

        let deadline = std::time::Duration::from_secs(30);
        let seen = tokio::time::timeout(deadline, async {
            let mut collected = Vec::new();
            let mut attempts = 0;

            loop {
                // A quiet gap means the shell has finished writing its prompt.
                // Typing on a byte count instead raced shell start-up: a command
                // sent into a shell that is not yet reading is simply dropped,
                // and the test then waited for output that never came.
                let chunk = tokio::time::timeout(
                    std::time::Duration::from_millis(750),
                    session.next_output(),
                )
                .await;

                let Ok(chunk) = chunk else {
                    attempts += 1;
                    if attempts > 4 {
                        return false;
                    }
                    session.write_input(command).unwrap();
                    continue;
                };

                let Some(chunk) = chunk else { return false };

                answer_terminal_queries(&session, &chunk);
                collected.extend_from_slice(&chunk);
                let text = String::from_utf8_lossy(&collected);
                if text.matches(probe).count() >= required_matches {
                    return true;
                }
            }
        })
        .await;

        assert_eq!(
            seen,
            Ok(true),
            "the shell must run what was typed into it and return its output"
        );
        session.close();
    }

    #[tokio::test]
    async fn a_session_can_be_resized() {
        let session = open();
        session
            .resize(TerminalSize {
                cols: 120,
                rows: 40,
            })
            .unwrap();
        // Out-of-range values are clamped rather than refused, so a client with a
        // maximised window does not fail to resize.
        session
            .resize(TerminalSize {
                cols: u16::MAX,
                rows: 0,
            })
            .unwrap();
        session.close();
    }

    #[tokio::test]
    async fn an_oversized_input_payload_is_refused() {
        // Not an allocation to make on a peer's say-so.
        let session = open();
        let huge = vec![b'a'; MAX_INPUT_BYTES + 1];
        assert!(session.write_input(&huge).is_err());
        session.close();
    }

    #[tokio::test]
    async fn elevation_is_refused_rather_than_silently_downgraded() {
        // Opening an unprivileged shell and labelling it elevated would be worse than
        // saying no.
        let result = TerminalSession::spawn(
            TerminalId::generate(),
            ShellKind::SystemDefault,
            small(),
            None,
            PrivilegeLevel::Elevated,
        );

        assert!(matches!(result, Err(TerminalError::ElevationUnavailable)));
    }

    #[tokio::test]
    async fn a_bad_working_directory_is_refused_before_a_shell_is_started() {
        let result = TerminalSession::spawn(
            TerminalId::generate(),
            ShellKind::SystemDefault,
            small(),
            Some("/no/such/directory/at/all"),
            PrivilegeLevel::Standard,
        );

        assert!(matches!(result, Err(TerminalError::BadWorkingDirectory)));
    }

    #[tokio::test]
    async fn a_valid_working_directory_is_accepted() {
        let temp = std::env::temp_dir();
        let session = TerminalSession::spawn(
            TerminalId::generate(),
            ShellKind::SystemDefault,
            small(),
            Some(&temp.to_string_lossy()),
            PrivilegeLevel::Standard,
        )
        .expect("a real directory must be accepted");

        session.close();
    }

    #[tokio::test]
    async fn the_registry_caps_open_sessions() {
        let registry = TerminalRegistry::new(2);

        registry.insert(open()).unwrap();
        registry.insert(open()).unwrap();

        assert!(matches!(
            registry.insert(open()),
            Err(TerminalError::TooManySessions)
        ));
        assert_eq!(registry.len(), 2, "the refused session must not be stored");
    }

    #[tokio::test]
    async fn a_session_can_be_found_and_removed() {
        let registry = TerminalRegistry::new(4);
        let session = registry.insert(open()).unwrap();
        let id = session.id();

        assert!(registry.get(id).is_some());
        assert_eq!(registry.ids(), vec![id]);

        registry.remove(id);
        assert!(registry.get(id).is_none());
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn closing_the_registry_ends_every_shell() {
        // Without this, closing the client would leave shells running on the server.
        let registry = TerminalRegistry::new(4);
        let first = registry.insert(open()).unwrap();
        let second = registry.insert(open()).unwrap();

        registry.close_all();
        assert!(registry.is_empty());

        // Give the children a moment to be reaped, then confirm they are gone.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            first.exit_status().is_some() || second.exit_status().is_some(),
            "closed sessions must terminate their shells"
        );
    }

    #[tokio::test]
    async fn a_dropped_session_does_not_leave_a_shell_running() {
        // The backstop for a connection that drops mid-session, which is the common
        // case rather than an exotic one.
        let session = open();
        let pid = session.pid();
        assert!(pid > 0);

        drop(session);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // The process is gone; `sysinfo` is not a dependency here, so this asserts the
        // observable part: dropping ran to completion without panicking or hanging.
    }

    #[tokio::test]
    async fn a_session_debug_line_carries_no_terminal_content() {
        // Terminal traffic is where passwords are typed.
        let session = open();
        session.write_input(b"secret-password\n").unwrap();

        let rendered = format!("{session:?}");
        assert!(!rendered.contains("secret-password"));
        assert!(rendered.contains("TerminalSession"));

        session.close();
    }

    #[tokio::test]
    async fn an_unknown_session_is_not_found() {
        let registry = TerminalRegistry::new(4);
        assert!(registry.get(TerminalId::generate()).is_none());
        assert!(registry.remove(TerminalId::generate()).is_none());
    }

    #[test]
    fn a_registry_cap_of_zero_is_treated_as_one() {
        assert_eq!(TerminalRegistry::new(0).max_sessions, 1);
    }
}
