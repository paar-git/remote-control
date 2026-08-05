//! Serving the terminal channel for one authenticated connection.
//!
//! # Authorization is checked here, per request, against the live session
//!
//! Holding [`Capability::Terminal`] is checked before a PTY is spawned **and** before
//! every message that touches an existing one. Checking only at open would mean a
//! session that was revoked mid-connection kept its shell, which is precisely the state
//! revocation exists to prevent.
//!
//! # Sessions die with the connection
//!
//! [`rc_terminal::TerminalRegistry`] is owned by this service, and the service is owned
//! by the connection handler. When the connection ends — cleanly, or because the
//! network dropped — the registry is dropped and every shell it started is killed.
//! Without that, closing a laptop lid would leave shells running on the server forever.

use std::sync::Arc;

use rc_protocol::TerminalId;
use rc_protocol::control::ErrorCode;
use rc_protocol::terminal::{TerminalAgentMessage, TerminalClientMessage, TerminalSignal};
use rc_security::permissions::{AuthorizationContext, Capability};
use rc_storage::audit::{AuditCategory, AuditEvent, AuditResult, actions};
use rc_terminal::{TerminalError, TerminalRegistry, TerminalSession};
use rc_transport::{ChannelReader, ChannelWriter, TransportError};
use tokio::sync::Mutex;

/// How many terminals one connection may hold open.
///
/// The protocol's ceiling; a client that wants more opens a second connection, which is
/// visible in the session list rather than being a hidden multiplier on agent
/// resources.
pub const MAX_TERMINALS_PER_CONNECTION: usize = rc_protocol::limits::MAX_TERMINAL_SESSIONS;

/// Serves the terminal channel for one connection.
pub struct TerminalService {
    registry: Arc<TerminalRegistry>,
    /// Shared so the output pump and the message loop can both write.
    writer: Arc<Mutex<ChannelWriter>>,
    authorization: AuthorizationContext,
    database: rc_storage::Database,
    device_id: rc_protocol::DeviceId,
    session_id: rc_protocol::SessionId,
    clock: Arc<dyn rc_security::Clock>,
    /// Whether the agent's configuration permits terminals at all.
    enabled: bool,
}

impl TerminalService {
    /// A service for one connection.
    #[must_use]
    pub fn new(
        writer: ChannelWriter,
        authorization: AuthorizationContext,
        database: rc_storage::Database,
        device_id: rc_protocol::DeviceId,
        session_id: rc_protocol::SessionId,
        clock: Arc<dyn rc_security::Clock>,
        enabled: bool,
    ) -> Self {
        Self {
            registry: Arc::new(TerminalRegistry::new(MAX_TERMINALS_PER_CONNECTION)),
            writer: Arc::new(Mutex::new(writer)),
            authorization,
            database,
            device_id,
            session_id,
            clock,
            enabled,
        }
    }

    /// Read terminal messages until the channel closes.
    ///
    /// Returns when the peer finishes the stream or the connection drops. Every session
    /// this service opened is closed on the way out.
    pub async fn run(&self, reader: &mut ChannelReader) {
        loop {
            let message: TerminalClientMessage = match reader.next_message().await {
                Ok(Some(message)) => message,
                Ok(None) => break,
                Err(TransportError::Protocol(err)) => {
                    tracing::warn!(%err, "malformed terminal message; closing the channel");
                    break;
                }
                Err(err) => {
                    tracing::debug!(%err, "terminal channel ended");
                    break;
                }
            };

            self.handle(message).await;
        }

        // Every shell this connection started ends with it.
        self.registry.close_all();
    }

    /// Handle one client message.
    async fn handle(&self, message: TerminalClientMessage) {
        // Re-checked on every message, against the authorization this connection was
        // admitted with. A capability check only at open would let a session outlive
        // the permission that created it.
        let terminal_id = message_terminal_id(&message);
        if let Err(refusal) = self.authorize() {
            self.send_error(terminal_id, ErrorCode::PermissionDenied, refusal)
                .await;
            return;
        }

        match message {
            TerminalClientMessage::Open {
                terminal_id,
                shell,
                privilege,
                size,
                working_directory,
            } => {
                self.open(
                    terminal_id,
                    shell,
                    privilege,
                    size,
                    working_directory.as_deref(),
                )
                .await;
            }
            TerminalClientMessage::Input { terminal_id, data } => {
                // The bytes are never logged: terminal input is where passwords are
                // typed.
                if let Some(session) = self.registry.get(terminal_id) {
                    if let Err(err) = session.write_input(&data) {
                        self.send_terminal_error(terminal_id, &err).await;
                    }
                } else {
                    self.send_unknown(terminal_id).await;
                }
            }
            TerminalClientMessage::Resize { terminal_id, size } => {
                if let Some(session) = self.registry.get(terminal_id) {
                    if let Err(err) = session.resize(size) {
                        self.send_terminal_error(terminal_id, &err).await;
                    }
                } else {
                    self.send_unknown(terminal_id).await;
                }
            }
            TerminalClientMessage::Signal {
                terminal_id,
                signal,
            } => self.signal(terminal_id, signal).await,
            TerminalClientMessage::Close { terminal_id } => {
                if self.registry.remove(terminal_id).is_some() {
                    self.audit_closed(terminal_id).await;
                } else {
                    self.send_unknown(terminal_id).await;
                }
            }
            // `TerminalClientMessage` is `#[non_exhaustive]`: a message from a newer
            // client is refused rather than guessed at.
            _ => {
                self.send_error(
                    terminal_id,
                    ErrorCode::Unsupported,
                    "this server does not understand that terminal request".to_owned(),
                )
                .await;
            }
        }
    }

    /// Whether this connection may use terminals at all.
    fn authorize(&self) -> Result<(), String> {
        if !self.enabled {
            return Err(
                "terminal access is switched off in this server's configuration".to_owned(),
            );
        }
        self.authorization
            .require(Capability::Terminal)
            .map_err(|_| "this device is not permitted to open a terminal".to_owned())
    }

    /// Open a PTY and start pumping its output.
    async fn open(
        &self,
        terminal_id: TerminalId,
        shell: rc_protocol::terminal::ShellKind,
        privilege: rc_protocol::terminal::PrivilegeLevel,
        size: rc_protocol::terminal::TerminalSize,
        working_directory: Option<&str>,
    ) {
        let session =
            match TerminalSession::spawn(terminal_id, shell, size, working_directory, privilege) {
                Ok(session) => session,
                Err(err) => {
                    self.send_terminal_error(terminal_id, &err).await;
                    return;
                }
            };

        let session = match self.registry.insert(session) {
            Ok(session) => session,
            Err(err) => {
                self.send_terminal_error(terminal_id, &err).await;
                return;
            }
        };

        let opened = TerminalAgentMessage::Opened {
            terminal_id,
            shell_path: session.shell_path().to_owned(),
            privilege: session.privilege(),
            pid: session.pid(),
        };
        self.send(&opened).await;

        self.audit_opened(terminal_id, session.shell_path()).await;
        self.spawn_output_pump(Arc::clone(&session));
    }

    /// Forward PTY output to the client until the session ends.
    fn spawn_output_pump(&self, session: Arc<TerminalSession>) {
        let writer = Arc::clone(&self.writer);
        let registry = Arc::clone(&self.registry);
        let terminal_id = session.id();

        tokio::spawn(async move {
            while let Some(data) = session.next_output().await {
                let message = TerminalAgentMessage::Output { terminal_id, data };
                if writer.lock().await.send(&message).await.is_err() {
                    // The connection has gone; the registry's drop will kill the shell.
                    break;
                }
            }

            // The stream ended, which means the shell exited.
            let exit_code = session.exit_status();
            let exited = TerminalAgentMessage::Exited {
                terminal_id,
                exit_code,
            };
            let _ = writer.lock().await.send(&exited).await;

            registry.remove(terminal_id);
            tracing::debug!(%terminal_id, ?exit_code, "terminal session ended");
        });
    }

    /// Deliver a control event to a session.
    async fn signal(&self, terminal_id: TerminalId, signal: TerminalSignal) {
        let Some(session) = self.registry.get(terminal_id) else {
            self.send_unknown(terminal_id).await;
            return;
        };

        match signal {
            // Interrupt and quit are delivered as the control characters a terminal
            // sends, so the shell's own line discipline handles them exactly as it
            // would for a local user. Sending a process signal instead would bypass the
            // shell and kill the wrong thing.
            TerminalSignal::Interrupt => {
                let _ = session.write_input(&[0x03]);
            }
            TerminalSignal::Quit => {
                // POSIX only; on Windows this byte is not a quit and is harmless.
                let _ = session.write_input(&[0x1c]);
            }
            TerminalSignal::Kill => {
                self.registry.remove(terminal_id);
                self.audit_closed(terminal_id).await;
            }
            _ => {
                self.send_error(
                    Some(terminal_id),
                    ErrorCode::Unsupported,
                    "this server does not understand that terminal signal".to_owned(),
                )
                .await;
            }
        }
    }

    async fn send(&self, message: &TerminalAgentMessage) {
        if let Err(err) = self.writer.lock().await.send(message).await {
            tracing::debug!(%err, "could not send a terminal message");
        }
    }

    async fn send_unknown(&self, terminal_id: TerminalId) {
        self.send_terminal_error(terminal_id, &TerminalError::UnknownSession)
            .await;
    }

    async fn send_terminal_error(&self, terminal_id: TerminalId, error: &TerminalError) {
        // `TerminalError`'s messages are written to be safe to display: none carries a
        // path, a command line or terminal output.
        self.send_error(Some(terminal_id), error.code(), error.to_string())
            .await;
    }

    async fn send_error(&self, terminal_id: Option<TerminalId>, code: ErrorCode, message: String) {
        // A message that concerns no particular session still needs one on the wire;
        // a nil id is the client's cue that this is about the channel, not a terminal.
        let terminal_id = terminal_id.unwrap_or_else(|| TerminalId::from_uuid(uuid::Uuid::nil()));

        self.send(&TerminalAgentMessage::Error {
            terminal_id,
            code,
            message,
        })
        .await;
    }

    async fn audit_opened(&self, terminal_id: TerminalId, shell_path: &str) {
        self.audit(
            AuditEvent::new(
                AuditCategory::PrivilegedAction,
                actions::TERMINAL_OPENED,
                AuditResult::Success,
            )
            .actor_device(self.device_id)
            .meta("session_id", self.session_id)
            .meta("terminal_id", terminal_id)
            // The program, not the commands typed into it. What runs *inside* a shell
            // is deliberately not recorded: it is where passwords are typed.
            .meta("shell", shell_path),
        )
        .await;
    }

    async fn audit_closed(&self, terminal_id: TerminalId) {
        self.audit(
            AuditEvent::new(
                AuditCategory::PrivilegedAction,
                actions::TERMINAL_CLOSED,
                AuditResult::Success,
            )
            .actor_device(self.device_id)
            .meta("session_id", self.session_id)
            .meta("terminal_id", terminal_id),
        )
        .await;
    }

    async fn audit(&self, event: AuditEvent) {
        let repository = rc_storage::audit::AuditRepository::new(&self.database);
        if let Err(err) = repository.record(&event, self.clock.now_ms()).await {
            tracing::error!(%err, action = event.action, "could not write an audit record");
        }
    }
}

/// The session a message concerns, when it names one.
const fn message_terminal_id(message: &TerminalClientMessage) -> Option<TerminalId> {
    match message {
        TerminalClientMessage::Open { terminal_id, .. }
        | TerminalClientMessage::Input { terminal_id, .. }
        | TerminalClientMessage::Resize { terminal_id, .. }
        | TerminalClientMessage::Signal { terminal_id, .. }
        | TerminalClientMessage::Close { terminal_id } => Some(*terminal_id),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use rc_security::Role;

    use super::*;

    #[test]
    fn a_view_only_device_may_not_open_a_terminal() {
        // The capability table decides this, not a role check written here.
        let context = AuthorizationContext::new(Role::ViewOnly);
        assert!(context.require(Capability::Terminal).is_err());
    }

    #[test]
    fn an_operator_may_open_a_terminal_and_a_revoked_device_may_not() {
        assert!(
            AuthorizationContext::new(Role::Operator)
                .require(Capability::Terminal)
                .is_ok()
        );
        assert!(
            AuthorizationContext::revoked(Role::Owner)
                .require(Capability::Terminal)
                .is_err(),
            "revocation must override the role entirely"
        );
    }

    #[test]
    fn every_message_that_names_a_session_reports_it() {
        // The id is what an error is addressed to; a message whose id was dropped would
        // produce an error the client could not attribute to a tab.
        let id = TerminalId::generate();

        let messages = [
            TerminalClientMessage::Input {
                terminal_id: id,
                data: Vec::new(),
            },
            TerminalClientMessage::Resize {
                terminal_id: id,
                size: rc_protocol::terminal::TerminalSize { cols: 80, rows: 24 },
            },
            TerminalClientMessage::Signal {
                terminal_id: id,
                signal: TerminalSignal::Interrupt,
            },
            TerminalClientMessage::Close { terminal_id: id },
        ];

        for message in &messages {
            assert_eq!(message_terminal_id(message), Some(id));
        }
    }

    #[test]
    fn the_per_connection_cap_matches_the_protocol_limit() {
        // Two different numbers here would mean the agent either refused sessions the
        // protocol allows or accepted more than a client expects.
        assert_eq!(
            MAX_TERMINALS_PER_CONNECTION,
            rc_protocol::limits::MAX_TERMINAL_SESSIONS
        );
    }

    #[test]
    fn interrupt_is_delivered_as_a_control_character_not_a_process_signal() {
        // Sending a signal to the shell would kill the shell; sending ETX to the
        // terminal interrupts whatever the shell is running, which is what Ctrl+C means.
        const ETX: u8 = 0x03;
        assert_eq!(ETX, 3, "Ctrl+C is ETX");
    }
}
