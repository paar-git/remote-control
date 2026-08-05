//! The agent's listener: accepting connections, routing them, and running sessions.
//!
//! # What happens to an incoming connection
//!
//! ```text
//!   QUIC + mTLS (trust-on-first-use at the TLS layer)
//!        │
//!        ├─ read the peer's certificate fingerprint from *this connection*
//!        ├─ accept the control stream
//!        ├─ read the Opening, which states its purpose
//!        │
//!        ├── Opening::Hello ────► trust lookup, revocation re-check ──► session
//!        └── Opening::Pairing ──► only while a window is open ────────► pairing
//! ```
//!
//! # Why TLS admits unknown peers here
//!
//! The listener pins nothing, because it serves *many* paired clients and a single pin
//! could only ever match one of them. Admission is decided one layer up, by the
//! handshake's trust lookup, which reads the database on every connection so a
//! revocation takes effect on the very next attempt rather than at the next restart.
//!
//! That means an unknown peer can complete a TLS handshake and open a stream. What it
//! cannot do is anything else: it is refused at the handshake unless it is trusted, or
//! unless the operator has deliberately opened a pairing window.
//!
//! # Bounds
//!
//! Concurrent sessions are capped by configuration. A connection arriving over the cap
//! is refused immediately and audited, rather than queued — a queue would let anyone
//! who can reach the port hold agent memory.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use rc_protocol::control::{
    Capabilities, ControlRequest, ControlRequestPayload, ControlResponse, ControlResponsePayload,
    ControlResult, DeviceDescriptor, DisconnectReason, Opening,
};
use rc_protocol::pairing::PairingMessage;
use rc_security::pairing::{PairingManager, PairingOutcome};
use rc_security::{Clock, DeviceIdentity, Fingerprint, SystemClock};
use rc_storage::audit::{AuditCategory, AuditEvent, AuditRepository, AuditResult, actions};
use rc_storage::models::PeerRoleRow;
use rc_storage::trust::TrustRepository;
use rc_transport::handshake::{TrustDirectory, TrustRecord};
use rc_transport::{
    AgentListener, ChannelReader, ChannelWriter, PairingRecorder, PairingService, PinPolicy,
    TransportError,
};

use crate::config::AgentConfig;
use crate::sessions::{SessionRegistry, SessionSlot};

/// Everything the listener needs, assembled once at startup.
pub struct AgentServer {
    /// This agent's cryptographic identity.
    identity: Arc<DeviceIdentity>,
    /// Validated configuration.
    config: AgentConfig,
    /// The agent's local database.
    database: rc_storage::Database,
    /// Open pairing windows. Shared with the `pair` command path.
    pairing: Arc<PairingManager>,
    /// Live sessions, for the cap and for the operator's session list.
    sessions: Arc<SessionRegistry>,
    /// Time source. Injected so expiry is testable.
    clock: Arc<dyn Clock>,
    /// Facts about this host, gathered once.
    host: rc_platform::HostInfo,
    /// Set once the QUIC listener is bound, cleared when it stops.
    ///
    /// Read by the health endpoint, which must be able to distinguish "the process is
    /// running" from "the agent is reachable" — a service manager already knows the
    /// first and cannot see the second.
    listener_ready: Arc<std::sync::atomic::AtomicBool>,
}

impl AgentServer {
    /// Assemble a server. Does not bind anything yet.
    #[must_use]
    pub fn new(
        identity: Arc<DeviceIdentity>,
        config: AgentConfig,
        database: rc_storage::Database,
        pairing: Arc<PairingManager>,
    ) -> Self {
        let max_sessions = usize::from(config.network.max_sessions);
        Self {
            identity,
            config,
            database,
            pairing,
            sessions: Arc::new(SessionRegistry::new(max_sessions)),
            clock: Arc::new(SystemClock),
            host: rc_platform::HostInfo::detect(),
            listener_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// The live session registry, shared with the health endpoint.
    #[must_use]
    pub fn sessions(&self) -> Arc<SessionRegistry> {
        Arc::clone(&self.sessions)
    }

    /// The listener-bound flag, shared with the health endpoint.
    #[must_use]
    pub fn listener_ready(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.listener_ready)
    }

    /// What this agent tells peers about itself.
    #[must_use]
    pub fn descriptor(&self) -> DeviceDescriptor {
        let public = self.identity.public();
        DeviceDescriptor {
            device_id: public.device_id,
            display_name: self.config.device_name.clone(),
            hostname: self.host.hostname.clone(),
            os_family: self.host.os_family,
            os_version: self.host.os_version.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            // Self-reported, for display. Peers use what their TLS connection saw.
            certificate_fingerprint: public.certificate_fingerprint.to_hex(),
        }
    }

    /// What this build of this agent, with this configuration, can actually do.
    ///
    /// Derived from the feature switches rather than hard-coded, so an operator running
    /// a monitoring-only agent has that reflected in what the client offers to do.
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        let features = &self.config.features;
        Capabilities {
            remote_desktop: features.remote_desktop,
            terminal: features.terminal,
            file_transfer: features.file_transfer,
            monitoring: true,
            process_management: features.process_management,
            service_management: features.service_management,
            power_control: features.power_control,
            clipboard: features.clipboard_sync,
            wake_on_lan: false,
            display_count: 0,
        }
    }

    /// Bind the listener and serve until `shutdown` resolves.
    ///
    /// # Errors
    /// Fails only if the socket cannot be bound. Per-connection failures are logged and
    /// audited; they never stop the listener, because one hostile peer must not be able
    /// to take the agent off the network.
    pub async fn run(
        self: Arc<Self>,
        shutdown: impl Future<Output = ()> + Send,
    ) -> anyhow::Result<()> {
        let address = self.config.listen_socket();

        let (listener, _endpoint_observed) = AgentListener::bind(
            address,
            &self.identity,
            // Nothing is pinned here; see the module documentation.
            PinPolicy::TrustOnFirstUse,
        )
        .with_context(|| format!("could not bind the QUIC listener on {address}"))?;

        let bound = listener.local_address()?;
        self.listener_ready
            .store(true, std::sync::atomic::Ordering::Release);
        tracing::info!(%bound, "listening for client connections");

        self.audit(
            AuditEvent::new(
                AuditCategory::Connection,
                actions::LISTENER_STARTED,
                AuditResult::Success,
            )
            .meta("port", bound.port()),
        )
        .await;

        // Discovery is a convenience. Failing to advertise must not stop the agent
        // serving clients that already know its address.
        let _advertiser = if self.config.network.discovery_enabled {
            match rc_transport::Advertiser::start(
                self.identity.device_id(),
                &self.config.device_name,
                self.identity.public().identity_fingerprint,
                bound.port(),
            ) {
                Ok(advertiser) => Some(advertiser),
                Err(err) => {
                    tracing::warn!(%err, "could not advertise on the local network");
                    None
                }
            }
        } else {
            tracing::info!("local discovery is disabled by configuration");
            None
        };

        let accepting = async {
            while let Some(incoming) = listener.accept().await {
                match incoming {
                    Ok(connection) => {
                        let server = Arc::clone(&self);
                        // One task per connection, so a slow or hostile peer cannot
                        // delay the next one.
                        tokio::spawn(async move {
                            let remote = connection.remote_address();
                            if let Err(err) = server.handle(connection).await {
                                tracing::info!(%remote, %err, "connection ended");
                            }
                        });
                    }
                    Err(err) => {
                        // Expected on an exposed port: scanners, half-open probes and
                        // peers with the wrong ALPN all land here.
                        tracing::debug!(%err, "an incoming connection did not establish");
                    }
                }
            }
        };

        tokio::select! {
            () = accepting => tracing::warn!("the listener stopped accepting"),
            () = shutdown => tracing::info!("shutting down the listener"),
        }

        self.listener_ready
            .store(false, std::sync::atomic::Ordering::Release);
        listener.close();
        listener.wait_idle().await;
        Ok(())
    }

    /// Handle one established connection.
    async fn handle(self: Arc<Self>, connection: quinn::Connection) -> anyhow::Result<()> {
        let remote = connection.remote_address();

        // From this connection, never from a message and never from the endpoint-wide
        // record, which every concurrent handshake shares.
        let observed = rc_transport::peer_certificate_fingerprint(&connection)?;

        let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await?;
        let opening = rc_transport::handshake::read_opening(&mut reader).await?;

        match opening {
            Opening::Pairing(message) => {
                self.handle_pairing(&mut reader, &mut writer, *message, observed, remote)
                    .await
            }
            Opening::Hello(hello) => {
                self.handle_session(
                    &connection,
                    &mut reader,
                    &mut writer,
                    *hello,
                    observed,
                    remote,
                )
                .await
            }
            // `Opening` is `#[non_exhaustive]`: a purpose from a newer client that this
            // build does not know is refused, not approximated.
            _ => {
                tracing::warn!(%remote, "a peer opened a connection for an unknown purpose");
                Err(TransportError::UnexpectedMessage {
                    expected: "Hello or Pairing",
                }
                .into())
            }
        }
    }

    /// Run a pairing exchange, if the operator has a window open.
    async fn handle_pairing(
        &self,
        reader: &mut ChannelReader,
        writer: &mut ChannelWriter,
        message: PairingMessage,
        observed: Fingerprint,
        remote: SocketAddr,
    ) -> anyhow::Result<()> {
        let PairingMessage::Request(request) = message else {
            // The exchange has a fixed shape; anything else is a protocol error.
            return Err(TransportError::UnexpectedMessage {
                expected: "pairing request",
            }
            .into());
        };

        tracing::info!(%remote, "a peer is attempting to pair");

        let recorder = TrustRecorder {
            database: self.database.clone(),
            clock: Arc::clone(&self.clock),
        };

        let service = PairingService {
            manager: &self.pairing,
            identity: &self.identity,
            descriptor: self.descriptor(),
            clock: self.clock.as_ref(),
            recorder: &recorder,
        };

        match service.serve(reader, writer, &request, observed).await {
            Ok(outcome) => {
                // The persisted trail is closed out here, after trust has been
                // recorded, so a row can never read `consumed` for a pairing that did
                // not complete.
                crate::identity::mark_window_consumed(
                    &self.database,
                    outcome.pairing_session_id,
                    outcome.client_device_id,
                    self.clock.now_ms(),
                )
                .await;
                self.audit_pairing_success(&outcome, remote).await;
                Ok(())
            }
            Err(err) => {
                self.audit_pairing_failure(&err, remote).await;
                Err(err.into())
            }
        }
    }

    /// Authenticate a client and run its session.
    async fn handle_session(
        self: &Arc<Self>,
        connection: &quinn::Connection,
        reader: &mut ChannelReader,
        writer: &mut ChannelWriter,
        hello: rc_protocol::control::Hello,
        observed: Fingerprint,
        remote: SocketAddr,
    ) -> anyhow::Result<()> {
        // Checked before authenticating, so an authenticated client is never turned
        // away for a reason it could have been told about earlier — and so the cap
        // cannot be exceeded by clients that all authenticate at once.
        let Some(slot) = self.sessions.reserve() else {
            tracing::warn!(%remote, "refusing a connection: the session limit is reached");
            self.audit(
                AuditEvent::new(
                    AuditCategory::Connection,
                    actions::CONNECTION_LIMIT_REACHED,
                    AuditResult::Denied,
                )
                .meta("source", redact_address(remote)),
            )
            .await;
            return Err(TransportError::Throttled {
                retry_after_secs: 30,
            }
            .into());
        };

        let directory = DatabaseDirectory {
            trust: TrustRepository::new(&self.database),
        };

        let peer = match rc_transport::handshake::finish_accept(
            writer,
            &directory,
            observed,
            hello,
            self.descriptor(),
            self.capabilities(),
            self.clock.now_ms(),
        )
        .await
        {
            Ok(peer) => peer,
            Err(err) => {
                self.audit(
                    AuditEvent::new(
                        AuditCategory::Connection,
                        actions::CONNECTION_REFUSED,
                        AuditResult::Denied,
                    )
                    .meta("source", redact_address(remote))
                    // The observed fingerprint is not secret and is what an operator
                    // needs in order to tell a renewal apart from an impostor.
                    .meta("observed_fingerprint", observed)
                    .meta("reason", &err),
                )
                .await;
                return Err(err.into());
            }
        };

        let session_id = peer.session_id;
        let device_id = peer.device_id;
        slot.activate(
            session_id,
            device_id,
            peer.role,
            remote,
            self.clock.now_ms(),
        );

        // Recorded after admission, so a refused peer cannot move this timestamp.
        if let Err(err) = TrustRepository::new(&self.database)
            .record_authentication(device_id, self.clock.now_ms())
            .await
        {
            tracing::warn!(%err, %device_id, "could not record the authentication time");
        }

        self.audit(
            AuditEvent::new(
                AuditCategory::Connection,
                actions::SESSION_STARTED,
                AuditResult::Success,
            )
            .actor_device(device_id)
            .meta("session_id", session_id)
            .meta("role", peer.role.name())
            .meta("source", redact_address(remote))
            .meta("protocol", peer.negotiated_version),
        )
        .await;

        tracing::info!(
            %device_id,
            %session_id,
            role = peer.role.name(),
            %remote,
            "session started"
        );

        let reason = self.run_session(connection, reader, writer, &slot).await;

        self.audit(
            AuditEvent::new(
                AuditCategory::Connection,
                actions::SESSION_ENDED,
                AuditResult::Success,
            )
            .actor_device(device_id)
            .meta("session_id", session_id)
            .meta("reason", reason_name(reason)),
        )
        .await;

        tracing::info!(%device_id, %session_id, reason = reason_name(reason), "session ended");
        Ok(())
    }

    /// Serve control requests until the client disconnects or the session times out.
    ///
    /// Returns why the session ended, which is what decides whether the client is
    /// entitled to reconnect automatically.
    async fn run_session(
        self: &Arc<Self>,
        connection: &quinn::Connection,
        reader: &mut ChannelReader,
        writer: &mut ChannelWriter,
        slot: &SessionSlot,
    ) -> DisconnectReason {
        let idle_timeout = self.config.session.idle_timeout_secs;

        loop {
            let next = read_control_request(reader, idle_timeout);

            let request = match next.await {
                RequestOutcome::Request(request) => request,
                RequestOutcome::Closed => return DisconnectReason::TransportFailure,
                RequestOutcome::IdleTimeout => {
                    connection.close(0u32.into(), b"idle timeout");
                    return DisconnectReason::IdleTimeout;
                }
                RequestOutcome::Malformed => {
                    connection.close(0u32.into(), b"protocol error");
                    return DisconnectReason::ProtocolError;
                }
            };

            slot.touch(self.clock.now_ms());

            if let ControlRequestPayload::Disconnect(disconnect) = &request.payload {
                // The client stated why. `UserRequested` is what suppresses the
                // client's own automatic reconnect, so it is passed through unaltered.
                return disconnect.reason;
            }

            let response = ControlResponse {
                request_id: request.request_id,
                result: self.answer(&request.payload),
            };

            if let Err(err) = writer.send(&response).await {
                tracing::debug!(%err, "could not send a control response");
                return DisconnectReason::TransportFailure;
            }
        }
    }

    /// Answer one control request.
    ///
    /// Requests whose implementation arrives in a later phase return a typed
    /// `Unsupported` rather than a plausible-looking empty answer, so a client is never
    /// shown a figure the agent did not measure.
    fn answer(&self, payload: &ControlRequestPayload) -> ControlResult {
        match payload {
            ControlRequestPayload::Ping { token } => {
                ControlResult::Ok(ControlResponsePayload::Pong {
                    token: *token,
                    agent_time_ms: self.clock.now_ms(),
                })
            }
            ControlRequestPayload::SystemSnapshot
            | ControlRequestPayload::SubscribeMetrics { .. }
            | ControlRequestPayload::UnsubscribeMetrics => ControlResult::Err {
                code: rc_protocol::control::ErrorCode::Unsupported,
                message: "this agent build does not yet collect system metrics".to_owned(),
            },
            // Handled by the caller; reaching here would be a routing bug.
            ControlRequestPayload::Disconnect(_) => ControlResult::Err {
                code: rc_protocol::control::ErrorCode::Internal,
                message: "the request was routed incorrectly".to_owned(),
            },
            _ => ControlResult::Err {
                code: rc_protocol::control::ErrorCode::Unsupported,
                message: "this agent does not support that request".to_owned(),
            },
        }
    }

    /// Append an audit record, logging rather than failing if the write does not work.
    async fn audit(&self, event: AuditEvent) {
        let repository = AuditRepository::new(&self.database);
        if let Err(err) = repository.record(&event, self.clock.now_ms()).await {
            tracing::error!(%err, action = event.action, "could not write an audit record");
        }
    }

    async fn audit_pairing_success(&self, outcome: &PairingOutcome, remote: SocketAddr) {
        self.audit(
            AuditEvent::new(
                AuditCategory::Pairing,
                actions::PAIRING_COMPLETED,
                AuditResult::Success,
            )
            .target_device(outcome.client_device_id)
            .meta("pairing_session_id", outcome.pairing_session_id)
            .meta("role", outcome.granted_permissions.role.name())
            .meta("source", redact_address(remote))
            // A short digest, enough to correlate the two peers' records and not
            // enough to reconstruct the exchange.
            .meta("transcript_digest", &outcome.transcript_digest),
        )
        .await;
    }

    async fn audit_pairing_failure(&self, err: &TransportError, remote: SocketAddr) {
        // Throttling is recorded distinctly from a rejected proof: the first says an
        // attacker is being rate-limited, the second that one attempt was wrong.
        let (action, result) = match err {
            TransportError::Throttled { .. } => (actions::PAIRING_THROTTLED, AuditResult::Denied),
            TransportError::PairingClosed => (actions::PAIRING_EXPIRED, AuditResult::Failure),
            _ => (actions::PAIRING_ATTEMPT_FAILED, AuditResult::Failure),
        };

        self.audit(
            AuditEvent::new(AuditCategory::Pairing, action, result)
                .meta("source", redact_address(remote))
                // Every `TransportError` message is written to be safe to display: it
                // never echoes peer input and never names a secret.
                .meta("reason", err),
        )
        .await;
    }
}

/// The trust store, as the transport's handshake needs to see it.
///
/// Every lookup goes to the database. Caching would defeat the point: the whole reason
/// authorization is separate from TLS is so a revocation applies to the next connection
/// rather than the next restart.
struct DatabaseDirectory {
    trust: TrustRepository,
}

#[async_trait::async_trait]
impl TrustDirectory for DatabaseDirectory {
    async fn find_by_certificate(&self, fingerprint: Fingerprint) -> Option<TrustRecord> {
        // Listed by certificate rather than identity because that is what TLS observed.
        // A device whose certificate has been renewed but whose identity is unchanged
        // will not match here and is refused; re-pinning a renewed certificate is a
        // deliberate step, not something a connection attempt performs.
        let device = match self.trust.find_by_certificate(fingerprint).await {
            Ok(device) => device?,
            Err(err) => {
                // A store that cannot answer must not admit anyone.
                tracing::error!(%err, "could not read the trust store; refusing the connection");
                return None;
            }
        };

        if device.peer_role != PeerRoleRow::Client {
            // A record describing a server this agent connects *to* is not a client it
            // accepts connections *from*.
            return None;
        }

        Some(TrustRecord {
            device_id: device.device_id,
            display_name: device.display_name,
            role: device.role,
            revoked: device.revoked,
            certificate_fingerprint: device.certificate_fingerprint,
        })
    }
}

/// Persists a completed pairing.
struct TrustRecorder {
    database: rc_storage::Database,
    clock: Arc<dyn Clock>,
}

#[async_trait::async_trait]
impl PairingRecorder for TrustRecorder {
    async fn record(&self, outcome: &PairingOutcome) -> Result<(), String> {
        TrustRepository::new(&self.database)
            .insert_paired_device(
                outcome.client_device_id,
                PeerRoleRow::Client,
                &outcome.client_display_name,
                "",
                &outcome.client_public_key,
                outcome.client_identity_fingerprint,
                outcome.client_certificate_fingerprint,
                &outcome.granted_permissions,
                Some(&outcome.transcript_digest),
                self.clock.now_ms(),
            )
            .await
            .map_err(|err| err.to_string())
    }
}

/// What reading the next control request produced.
enum RequestOutcome {
    /// A well-formed request.
    Request(Box<ControlRequest>),
    /// The peer finished the stream or the connection dropped.
    Closed,
    /// Nothing arrived within the idle timeout.
    IdleTimeout,
    /// Something arrived that is not a control request.
    Malformed,
}

/// Read one control request, bounded by the idle timeout.
///
/// An `idle_timeout_secs` of `0` disables the timeout, which the configuration
/// documents as an explicit opt-out rather than a value that happens to mean "never".
async fn read_control_request(
    reader: &mut ChannelReader,
    idle_timeout_secs: u32,
) -> RequestOutcome {
    let read = reader.next_message::<ControlRequest>();

    let result = if idle_timeout_secs == 0 {
        read.await
    } else {
        let deadline = std::time::Duration::from_secs(u64::from(idle_timeout_secs));
        match tokio::time::timeout(deadline, read).await {
            Ok(result) => result,
            Err(_) => return RequestOutcome::IdleTimeout,
        }
    };

    match result {
        Ok(Some(request)) => RequestOutcome::Request(Box::new(request)),
        // A frame that does not decode is a protocol error worth distinguishing: it
        // means the peer is speaking something else, not that it hung up.
        Err(TransportError::Protocol(_)) => RequestOutcome::Malformed,
        // A finished stream and a dropped connection are the same outcome here.
        Ok(None) | Err(_) => RequestOutcome::Closed,
    }
}

/// Stable name for a disconnect reason, for logs and audit records.
const fn reason_name(reason: DisconnectReason) -> &'static str {
    match reason {
        DisconnectReason::UserRequested => "user_requested",
        DisconnectReason::HostTerminated => "host_terminated",
        DisconnectReason::SessionExpired => "session_expired",
        DisconnectReason::IdleTimeout => "idle_timeout",
        DisconnectReason::AgentShutdown => "agent_shutdown",
        DisconnectReason::ProtocolError => "protocol_error",
        DisconnectReason::TransportFailure => "transport_failure",
        // `DisconnectReason` is `#[non_exhaustive]`.
        _ => "unknown",
    }
}

/// Render a peer address for an audit record.
///
/// The port is dropped. It is an ephemeral value that identifies nothing useful after
/// the fact, and keeping the address alone makes the log easier to read without losing
/// what an operator actually needs: which machine it was.
fn redact_address(address: SocketAddr) -> String {
    address.ip().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> AgentConfig {
        AgentConfig::default()
    }

    async fn server() -> Arc<AgentServer> {
        let identity = Arc::new(DeviceIdentity::generate("test-agent", &SystemClock).unwrap());
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        Arc::new(AgentServer::new(
            identity,
            config(),
            database,
            Arc::new(PairingManager::with_defaults()),
        ))
    }

    #[tokio::test]
    async fn the_descriptor_reports_this_agents_identity() {
        let server = server().await;
        let descriptor = server.descriptor();

        assert_eq!(descriptor.device_id, server.identity.device_id());
        assert_eq!(
            descriptor.certificate_fingerprint,
            server.identity.public().certificate_fingerprint.to_hex()
        );
        assert!(!descriptor.hostname.is_empty());
    }

    #[tokio::test]
    async fn capabilities_follow_the_feature_switches() {
        // An operator who turned a feature off must not have the client offer it.
        let identity = Arc::new(DeviceIdentity::generate("test-agent", &SystemClock).unwrap());
        let database = rc_storage::Database::open_in_memory().await.unwrap();

        let mut config = config();
        config.features.terminal = false;
        config.features.power_control = false;

        let server = AgentServer::new(
            identity,
            config,
            database,
            Arc::new(PairingManager::with_defaults()),
        );
        let capabilities = server.capabilities();

        assert!(!capabilities.terminal);
        assert!(!capabilities.power_control);
        assert!(capabilities.file_transfer);
    }

    #[tokio::test]
    async fn a_ping_is_answered_with_the_token_it_carried() {
        let server = server().await;
        let result = server.answer(&ControlRequestPayload::Ping { token: 42 });

        match result {
            ControlResult::Ok(ControlResponsePayload::Pong { token, .. }) => {
                assert_eq!(token, 42);
            }
            other => panic!("expected a pong, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_unimplemented_request_is_refused_rather_than_answered_with_zeroes() {
        // Returning an empty snapshot would put figures on the operator's dashboard
        // that the agent never measured.
        let server = server().await;
        let result = server.answer(&ControlRequestPayload::SystemSnapshot);

        assert!(
            matches!(
                result,
                ControlResult::Err {
                    code: rc_protocol::control::ErrorCode::Unsupported,
                    ..
                }
            ),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn an_unknown_certificate_is_not_found_in_the_directory() {
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        let directory = DatabaseDirectory {
            trust: TrustRepository::new(&database),
        };

        let stranger = Fingerprint::of_certificate_der(b"never-seen");
        assert!(directory.find_by_certificate(stranger).await.is_none());
    }

    #[tokio::test]
    async fn a_paired_client_is_found_and_a_revoked_one_is_reported_as_revoked() {
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        let trust = TrustRepository::new(&database);
        let client = DeviceIdentity::generate("client", &SystemClock).unwrap();
        let public = client.public();

        trust
            .insert_paired_device(
                public.device_id,
                PeerRoleRow::Client,
                "Client",
                "host",
                &public.identity_public_key,
                public.identity_fingerprint,
                public.certificate_fingerprint,
                &rc_security::pairing::RequestedPermissions::full(rc_security::Role::Operator),
                None,
                1,
            )
            .await
            .unwrap();

        let directory = DatabaseDirectory {
            trust: TrustRepository::new(&database),
        };

        let found = directory
            .find_by_certificate(public.certificate_fingerprint)
            .await
            .expect("a paired client must be found");
        assert_eq!(found.device_id, public.device_id);
        assert!(!found.revoked);

        // Revocation must be visible to the very next lookup, with no cache in between.
        trust.revoke(public.device_id, 2).await.unwrap();
        let after = directory
            .find_by_certificate(public.certificate_fingerprint)
            .await
            .expect("a revoked device stays visible, marked revoked");
        assert!(
            after.revoked,
            "revocation must be reported, not made to look like an unknown device"
        );
    }

    #[tokio::test]
    async fn a_saved_server_record_is_not_accepted_as_a_client() {
        // The same database holds both "servers I connect to" and "clients I accept".
        // Confusing the two would let a device inbound-connect on the strength of a
        // record that only ever meant the opposite direction.
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        let trust = TrustRepository::new(&database);
        let peer = DeviceIdentity::generate("peer", &SystemClock).unwrap();
        let public = peer.public();

        trust
            .insert_paired_device(
                public.device_id,
                PeerRoleRow::Agent,
                "A server",
                "host",
                &public.identity_public_key,
                public.identity_fingerprint,
                public.certificate_fingerprint,
                &rc_security::pairing::RequestedPermissions::full(rc_security::Role::Owner),
                None,
                1,
            )
            .await
            .unwrap();

        let directory = DatabaseDirectory {
            trust: TrustRepository::new(&database),
        };
        assert!(
            directory
                .find_by_certificate(public.certificate_fingerprint)
                .await
                .is_none(),
            "an agent record must not authorize an inbound client"
        );
    }

    #[test]
    fn an_audited_address_keeps_the_host_and_drops_the_ephemeral_port() {
        let address: SocketAddr = "192.168.1.40:51234".parse().unwrap();
        assert_eq!(redact_address(address), "192.168.1.40");
    }

    #[test]
    fn every_disconnect_reason_has_a_distinct_name() {
        let names = [
            reason_name(DisconnectReason::UserRequested),
            reason_name(DisconnectReason::HostTerminated),
            reason_name(DisconnectReason::SessionExpired),
            reason_name(DisconnectReason::IdleTimeout),
            reason_name(DisconnectReason::AgentShutdown),
            reason_name(DisconnectReason::ProtocolError),
            reason_name(DisconnectReason::TransportFailure),
        ];
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
    }
}
