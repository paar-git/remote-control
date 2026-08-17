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
//!        └── Opening::Hello ────► admission decision ──────────────────► session
//! ```
//!
//! # Why TLS admits unknown peers here
//!
//! The listener pins nothing, because it serves *many* clients and a single pin could
//! only ever match one of them. Admission is decided one layer up, in the handshake.
//!
//! That means an unknown peer can complete a TLS handshake and open a stream. What it
//! cannot do is anything else until admission decides. Completing TLS proves only
//! which key is on the other end. The handshake then asks
//! [`crate::access::authorize_connection`]: a trusted identity, an unattended
//! password, or a human clicking Accept. A refused peer learns only that it was
//! refused; see [`rc_transport::handshake`].
//!
//! # Bounds
//!
//! Concurrent sessions are capped by configuration. A connection arriving over the cap
//! is refused immediately, rather than queued — a queue would let anyone who can reach
//! the port hold agent memory.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use rc_protocol::control::{
    Capabilities, ControlRequest, ControlRequestPayload, ControlResponse, ControlResponsePayload,
    ControlResult, DeviceDescriptor, DisconnectReason, Opening, WireRefusal,
};
use rc_security::{Clock, DeviceIdentity, Permission, PermissionSet, SystemClock};
use rc_storage::{SessionHistoryRepository, SettingsRepository, TrustRepository};
use rc_transport::handshake::HandshakeAuthorization;
use rc_transport::{AgentListener, ChannelReader, ChannelWriter, PinPolicy, TransportError};

use crate::access::{
    AcceptAnswer, AcceptDecision, AcceptPrompt, AcceptRequest, AccessDeps, Authorization,
    ConnectionRequest, authorize_connection,
};
use crate::config::AgentConfig;
use crate::sessions::{Session, SessionRegistry, SessionSlot};

/// Everything the listener needs, assembled once at startup.
pub struct AgentServer {
    /// This agent's cryptographic identity.
    identity: Arc<DeviceIdentity>,
    /// Validated configuration.
    config: AgentConfig,
    /// Live sessions, for the cap and for the operator's session list.
    sessions: Arc<SessionRegistry>,
    /// Time source. Injected so expiry is testable.
    clock: Arc<dyn Clock>,
    /// Facts about this host, gathered once.
    host: rc_platform::HostInfo,
    /// Collects system metrics.
    ///
    /// One collector for the whole agent, not one per connection: CPU utilisation is
    /// measured across an interval, so several collectors would each pay for their own
    /// process enumeration and none would agree with the others.
    metrics: Arc<tokio::sync::Mutex<rc_monitoring::MetricsCollector>>,
    /// This machine's own access settings.
    settings: SettingsRepository,
    /// Recently seen and pinned peer identities.
    trust: TrustRepository,
    trust_service: crate::TrustService,
    history: SessionHistoryRepository,
    /// UI boundary for human accept/deny decisions.
    prompt: Arc<dyn AcceptPrompt>,
    /// Rate limiter for unattended-password attempts.
    throttle: tokio::sync::Mutex<rc_security::Throttle>,
    /// Serialises interactive accept dialogs.
    pending_dialog: tokio::sync::Mutex<()>,
    /// Set once the QUIC listener is bound, cleared when it stops.
    ///
    /// Read by the health endpoint, which must be able to distinguish "the process is
    /// running" from "the agent is reachable" — a service manager already knows the
    /// first and cannot see the second.
    listener_ready: Arc<std::sync::atomic::AtomicBool>,
}

/// Fail-closed accept prompt used by the standalone service binary.
#[derive(Debug, Default)]
pub struct DismissingPrompt;

#[async_trait::async_trait]
impl AcceptPrompt for DismissingPrompt {
    async fn ask(&self, request: AcceptRequest) -> AcceptAnswer {
        tracing::warn!(
            address = %request.address,
            identity = %request.identity_fingerprint,
            trusted = request.trusted,
            "no interactive accept prompt is attached; dismissing connection request"
        );
        AcceptAnswer {
            request_id: request.request_id,
            decision: AcceptDecision::Dismiss,
        }
    }
}

impl AgentServer {
    /// Assemble a server. Does not bind anything yet.
    #[must_use]
    pub fn new(
        identity: Arc<DeviceIdentity>,
        config: AgentConfig,
        database: &rc_storage::Database,
        prompt: Arc<dyn AcceptPrompt>,
    ) -> Self {
        let max_sessions = usize::from(config.network.max_sessions);
        Self {
            identity,
            config,
            sessions: Arc::new(SessionRegistry::new(max_sessions)),
            clock: Arc::new(SystemClock),
            host: rc_platform::HostInfo::detect(),
            metrics: Arc::new(tokio::sync::Mutex::new(
                rc_monitoring::MetricsCollector::new(),
            )),
            settings: SettingsRepository::new(database),
            trust: TrustRepository::new(database),
            trust_service: crate::TrustService::new(TrustRepository::new(database)),
            history: SessionHistoryRepository::new(database),
            prompt,
            throttle: tokio::sync::Mutex::new(rc_security::Throttle::with_defaults()),
            pending_dialog: tokio::sync::Mutex::new(()),
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

    /// Bind the listener and serve until `shutdown` resolves.
    ///
    /// # Errors
    /// Fails only if the socket cannot be bound. Per-connection failures are logged;
    /// they never stop the listener, because one hostile peer must not be able to take
    /// the agent off the network.
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
        //
        // A certificate carrying no Ed25519 identity key cannot be trusted or even
        // named, so such a connection is refused here rather than admitted under an
        // identity this build would have to invent for it.
        let der = rc_transport::peer_certificate_der(&connection)?;
        let observed = rc_transport::PeerIdentity::from_certificate_der(&der).map_err(|err| {
            tracing::warn!(%remote, %err, "refusing a peer whose certificate carries no identity");
            TransportError::IdentityProofRejected
        })?;

        let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await?;
        let opening = rc_transport::handshake::read_opening(&mut reader).await?;

        // `Opening` is `#[non_exhaustive]`: a purpose from a newer client that this
        // build does not know is refused, not approximated.
        let Opening::Hello(hello) = opening else {
            tracing::warn!(%remote, "a peer opened a connection for an unknown purpose");
            return Err(TransportError::UnexpectedMessage { expected: "Hello" }.into());
        };

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

    /// Authenticate a client and run its session.
    async fn handle_session(
        self: &Arc<Self>,
        connection: &quinn::Connection,
        reader: &mut ChannelReader,
        writer: &mut ChannelWriter,
        hello: rc_protocol::control::Hello,
        observed: rc_transport::PeerIdentity,
        remote: SocketAddr,
    ) -> anyhow::Result<()> {
        // Checked before authenticating, so an authenticated client is never turned
        // away for a reason it could have been told about earlier — and so the cap
        // cannot be exceeded by clients that all authenticate at once.
        let Some(slot) = self.sessions.reserve() else {
            tracing::warn!(
                %remote,
                source = %redact_address(remote),
                "refusing a connection: the session limit is reached"
            );
            return Err(TransportError::Throttled {
                retry_after_secs: 30,
            }
            .into());
        };

        // Taken before `hello` is moved into the handshake. Untrusted, like the display
        // name beside it, and stored only so My Devices can show what kind of machine a
        // trusted device is.
        let peer_os = os_family_name(hello.descriptor.os_family).to_owned();
        // Kept for the history record on the refusal path, where `peer` does not exist.
        let peer_name = hello.descriptor.display_name.clone();

        let peer = match rc_transport::handshake::finish_accept(
            reader,
            writer,
            observed,
            hello,
            self.descriptor(),
            self.capabilities(),
            self.clock.now_ms(),
            {
                let server = Arc::clone(self);
                let peer_os = peer_os.clone();
                move |identity, dialed_address, machine_name, unattended_password| async move {
                    server
                        .decide(ConnectionRequest {
                            address: dialed_address,
                            identity,
                            machine_name,
                            os_family: peer_os,
                            unattended_password,
                        })
                        .await
                }
            },
        )
        .await
        {
            Ok(peer) => peer,
            Err(err) => {
                self.on_refused(connection, observed, remote, &peer_name, &err)
                    .await;
                return Err(err.into());
            }
        };

        let session_id = peer.session_id;
        let device_id = peer.device_id;
        slot.activate(
            session_id,
            device_id,
            peer.identity_fingerprint,
            peer.display_name.clone(),
            peer.permissions,
            remote,
            self.clock.now_ms(),
        );

        record_session_start(&peer, remote);

        let history_id = self
            .record_history(&rc_storage::NewSessionRecord {
                session_id: Some(session_id.to_canonical_string()),
                identity_fingerprint: Some(peer.identity_fingerprint),
                device_name: peer.display_name.clone(),
                direction: rc_storage::SessionDirection::Incoming,
                address: redact_address(remote),
                started_ms: self.clock.now_ms(),
                permissions: peer.permissions,
                outcome: rc_storage::SessionOutcome::Completed,
                end_reason: None,
            })
            .await;

        // The permissions this connection was admitted with, re-checked on every
        // request rather than assumed for the life of the session.
        let session = Session::new(peer.permissions, peer.identity_fingerprint);

        // A metrics subscription is asked for on the control channel and delivered on
        // the metrics channel, so the two need a handle in common. Created here, before
        // either exists, so neither ordering loses the subscription.
        let (subscription, subscribed) = tokio::sync::watch::channel(None);

        // Additional channels are served in their own task so a client's requests on
        // one do not block the control channel.
        let channel_server =
            self.spawn_channel_server(connection, session, device_id, session_id, subscribed);

        // Selected against the operator's Disconnect, so ending a session closes the
        // connection rather than only clearing it from a list. `HostTerminated` is not
        // eligible for automatic reconnection, so the peer does not immediately come
        // back — which is what someone pressing Disconnect means.
        let reason = tokio::select! {
            reason = self.run_session(connection, reader, writer, &slot, &session, &subscription) => reason,
            () = slot.ended() => {
                tracing::info!(%session_id, "the operator ended this session");
                DisconnectReason::HostTerminated
            }
        };

        channel_server.abort();

        tracing::info!(%device_id, %session_id, reason = reason_name(reason), "session ended");

        if let Some(id) = history_id
            && let Err(err) = self
                .history
                .finish(
                    id,
                    self.clock.now_ms(),
                    outcome_of(reason),
                    Some(reason_name(reason)),
                )
                .await
        {
            tracing::warn!(%err, "could not record how the session ended");
        }

        Ok(())
    }

    /// Apply the admission rule to one connection.
    ///
    /// The rule itself lives in [`crate::access`] and is shared with the desktop
    /// application, so the two cannot drift into deciding differently. This method
    /// supplies it with everything it reads and translates its answer into the coarse
    /// outcome the transport carries to the peer.
    ///
    /// A failure to *decide* is a refusal. Anything else would mean a database that had
    /// gone away could admit a connection nobody approved.
    async fn decide(&self, request: ConnectionRequest) -> HandshakeAuthorization {
        let deps = AccessDeps {
            settings: &self.settings,
            trust: &self.trust,
            prompt: self.prompt.as_ref(),
            throttle: &self.throttle,
            clock: self.clock.as_ref(),
            pending_dialog: &self.pending_dialog,
        };

        match authorize_connection(&request, &deps).await {
            Ok(Authorization::Granted(permissions)) => HandshakeAuthorization::Granted(permissions),
            Ok(Authorization::Refused(reason)) => HandshakeAuthorization::Refused(reason.into()),
            Err(err) => {
                tracing::error!(%err, "could not decide connection authorization");
                HandshakeAuthorization::Refused(WireRefusal::Rejected)
            }
        }
    }

    /// Log, record and wind down a connection that was not admitted.
    ///
    /// Separate from [`Self::handle_session`] because it is a whole story of its own —
    /// what the operator is told, what the peer is allowed to observe, and how the
    /// connection is closed — and because keeping it inline made the admission path
    /// harder to read than the branch it guards.
    async fn on_refused(
        &self,
        connection: &quinn::Connection,
        observed: rc_transport::PeerIdentity,
        remote: SocketAddr,
        peer_name: &str,
        err: &TransportError,
    ) {
        tracing::warn!(
            source = %redact_address(remote),
            // Neither value is secret, and together they are what an operator needs in
            // order to tell a renewal apart from an impostor: the identity is the same
            // across a renewal, the certificate is not.
            identity = %observed.identity_fingerprint,
            certificate = %observed.certificate_fingerprint,
            %err,
            "refusing a connection"
        );

        // The refusal has been written and its stream finished. Wait for the peer to
        // acknowledge by closing, rather than dropping the connection out from under the
        // frame: a peer that never receives its refusal sees a lost connection instead,
        // which is retryable, and would reconnect in a loop against a machine that had
        // already refused it.
        //
        // Bounded, because a peer that does not close is not something to wait on. Two
        // seconds is far longer than a loopback or LAN round trip.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), connection.closed()).await;

        // Recorded so the operator can see that someone was turned away. A refusal has
        // no session id, and a stranger has no trust row, so both travel as `None`
        // rather than being invented. The name is what the peer called itself, which is
        // untrusted and displayed as such.
        self.record_history(&rc_storage::NewSessionRecord {
            session_id: None,
            identity_fingerprint: None,
            device_name: peer_name.to_owned(),
            direction: rc_storage::SessionDirection::Incoming,
            address: redact_address(remote),
            started_ms: self.clock.now_ms(),
            permissions: PermissionSet::NONE,
            outcome: rc_storage::SessionOutcome::Refused,
            end_reason: None,
        })
        .await;
    }

    /// Write a history row, reporting a failure rather than failing the connection.
    ///
    /// A session that ran is a fact whether or not it could be written down, and a
    /// database that has gone away must not turn an admitted session into a refused
    /// one. The row id comes back so the session can be finished later.
    async fn record_history(&self, entry: &rc_storage::NewSessionRecord) -> Option<i64> {
        match self.history.record(entry).await {
            Ok(id) => Some(id),
            Err(err) => {
                tracing::warn!(%err, "could not record a session in the history");
                None
            }
        }
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
        session: &Session,
        subscription: &tokio::sync::watch::Sender<Option<u32>>,
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
                result: self.answer(&request.payload, session, subscription).await,
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
    async fn answer(
        &self,
        payload: &ControlRequestPayload,
        session: &Session,
        subscription: &tokio::sync::watch::Sender<Option<u32>>,
    ) -> ControlResult {
        match payload {
            ControlRequestPayload::Ping { token } => {
                ControlResult::Ok(ControlResponsePayload::Pong {
                    token: *token,
                    agent_time_ms: self.clock.now_ms(),
                })
            }

            ControlRequestPayload::SystemSnapshot => {
                // Checked against this connection's authorization on every request, not
                // once at connect: a device revoked mid-session must stop being answered.
                if session.require(Permission::ViewMetrics).is_err() {
                    return denied("view this server's status");
                }

                // The collector is shared across connections, so one lock is held while
                // a sample is taken. Sampling is milliseconds; duplicating the collector
                // per connection would multiply the load on the machine being watched,
                // which is the one cost a monitoring feature must not impose.
                let snapshot = self.metrics.lock().await.snapshot(self.clock.now_ms());
                ControlResult::Ok(ControlResponsePayload::Snapshot(Box::new(snapshot)))
            }

            ControlRequestPayload::HostInfo => {
                if session.require(Permission::ViewMetrics).is_err() {
                    return denied("view this server's status");
                }
                ControlResult::Ok(ControlResponsePayload::HostInfo(Box::new(
                    self.host_summary(),
                )))
            }

            ControlRequestPayload::SubscribeMetrics { interval_ms } => {
                if session.require(Permission::ViewMetrics).is_err() {
                    return denied("view this server's status");
                }
                // Clamped rather than honoured: a client asking for 10 ms would cost a
                // sample a hundred times a second on the machine it is supposed to be
                // observing.
                let interval_ms = rc_monitoring::MetricsCollector::clamp_interval(*interval_ms);

                // The metrics-channel task is the receiver. A send failing means that
                // task is gone, which for a live session means the connection is on its
                // way out — reported rather than answered with a success the client
                // would wait on forever.
                if subscription.send(Some(interval_ms)).is_err() {
                    return ControlResult::Err {
                        code: rc_protocol::control::ErrorCode::Internal,
                        message: "this session can no longer deliver metrics".to_owned(),
                    };
                }

                // The clamped figure, not the requested one, so a client displays the
                // rate it is actually getting.
                ControlResult::Ok(ControlResponsePayload::MetricsSubscribed { interval_ms })
            }

            ControlRequestPayload::UnsubscribeMetrics => {
                // Unsubscribing when nothing was subscribed is not an error: a client
                // tidying up on the way out should not have to remember whether it ever
                // started.
                let _ = subscription.send(None);
                ControlResult::Ok(ControlResponsePayload::Empty)
            }

            // Handled by the caller; reaching here would be a routing bug.
            ControlRequestPayload::Disconnect(_) => ControlResult::Err {
                code: rc_protocol::control::ErrorCode::Internal,
                message: "the request was routed incorrectly".to_owned(),
            },

            // Trust management, behind `Administer`. Delegated rather than inlined so
            // the no-self-modification rule lives in one place with its own tests.
            payload => match self.trust_service.handle(session, payload).await {
                Ok(Some(response)) => ControlResult::Ok(response),
                // `ControlRequestPayload` is `#[non_exhaustive]`: a request from a newer
                // client is refused rather than approximated.
                Ok(None) => ControlResult::Err {
                    code: rc_protocol::control::ErrorCode::Unsupported,
                    message: "this agent does not support that request".to_owned(),
                },
                Err(err) => access_error_result(&err),
            },
        }
    }

    /// Serve the channels a client opens after authenticating.
    ///
    /// The control channel is already established; this accepts the *additional*
    /// streams and serves each on its own task.
    ///
    /// Aborting the returned handle when the session ends is what guarantees no
    /// per-channel task outlives the connection that started it.
    fn spawn_channel_server(
        self: &Arc<Self>,
        connection: &quinn::Connection,
        session: Session,
        device_id: rc_protocol::DeviceId,
        session_id: rc_protocol::SessionId,
        subscribed: tokio::sync::watch::Receiver<Option<u32>>,
    ) -> tokio::task::JoinHandle<()> {
        let server = Arc::clone(self);
        let connection = connection.clone();
        tokio::spawn(async move {
            loop {
                let (writer, mut reader) = match rc_transport::accept_channel(&connection).await {
                    Ok(pair) => pair,
                    Err(err) => {
                        // The ordinary end: the connection closed.
                        tracing::debug!(%err, "stopped accepting channels");
                        break;
                    }
                };

                match reader.channel() {
                    rc_protocol::Channel::FileTransfer => {
                        let service = crate::file_service::FileService::new(
                            writer,
                            server.file_policy(),
                            server.config.features.max_transfer_bytes,
                            session,
                            device_id,
                            session_id,
                            server.config.features.file_transfer,
                        );
                        tokio::spawn(async move {
                            service.run(&mut reader).await;
                        });
                    }
                    rc_protocol::Channel::Metrics => {
                        let service = crate::metrics_service::MetricsService::new(
                            writer,
                            session,
                            Arc::clone(&server.metrics),
                            Arc::clone(&server.clock),
                            subscribed.clone(),
                        );
                        tokio::spawn(service.run());
                    }
                    rc_protocol::Channel::Input => {
                        // The sink is built per channel so a host that cannot inject
                        // reports that fact to this client rather than failing at
                        // startup for every client.
                        match rc_input::backend::enigo::EnigoSink::new() {
                            Ok(sink) => {
                                let service = crate::input_service::InputService::new(
                                    writer,
                                    session,
                                    sink,
                                    server.config.features.remote_desktop,
                                );
                                tokio::spawn(async move {
                                    service.run(&mut reader).await;
                                });
                            }
                            Err(err) => {
                                // Answered rather than ignored: a client waiting on an
                                // acknowledgement that never comes cannot tell a
                                // permission problem from a dead link.
                                tracing::warn!(%err, "input channel opened on a host that cannot inject");
                            }
                        }
                    }
                    rc_protocol::Channel::Video => {
                        // The source is built per channel for the same reason as the
                        // input sink: a host that cannot capture reports that fact to
                        // this client rather than failing at startup for every client.
                        match crate::video_service::new_source() {
                            Ok(source) => {
                                let service = crate::video_service::VideoService::new(
                                    writer,
                                    session,
                                    source,
                                    server.config.features.remote_desktop,
                                )
                                .with_clipboard(
                                    crate::video_service::new_clipboard(),
                                    server.config.features.clipboard_sync,
                                );
                                tokio::spawn(async move {
                                    service.run(&mut reader).await;
                                });
                            }
                            Err(err) => {
                                // Answered, not dropped: a closed channel is
                                // indistinguishable from a dead link, and this host's
                                // problem is one the operator can act on.
                                tracing::warn!(%err, "video channel opened on a host that cannot capture");
                                tokio::spawn(async move {
                                    crate::video_service::serve_without_capture(
                                        writer,
                                        &mut reader,
                                    )
                                    .await;
                                });
                            }
                        }
                    }
                    other @ rc_protocol::Channel::Control => {
                        // A channel this build does not serve is closed rather than left
                        // open: a client waiting on a stream nobody reads would appear
                        // to hang, which is worse than a clear end.
                        tracing::debug!(
                            channel = ?other,
                            "a client opened a channel this agent does not serve yet"
                        );
                    }
                }
            }
        })
    }

    fn descriptor(&self) -> DeviceDescriptor {
        let public = self.identity.public();
        DeviceDescriptor {
            device_id: public.device_id,
            display_name: self.config.device_name.clone(),
            hostname: self.host.hostname.clone(),
            os_family: self.host.os_family,
            os_version: self.host.os_version.clone(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            certificate_fingerprint: public.certificate_fingerprint.to_hex(),
        }
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            remote_desktop: self.config.features.remote_desktop
                && rc_input::backend::enigo::probe().is_usable(),
            file_transfer: self.config.features.file_transfer,
            monitoring: true,
            process_management: self.config.features.process_management,
            clipboard: self.config.features.clipboard_sync,
            wake_on_lan: false,
            // Reported rather than hardcoded, so a client can tell a single-monitor
            // host from a multi-monitor one before opening a session.
            display_count: u8::try_from(rc_input::backend::displays::enumerate().len())
                .unwrap_or(u8::MAX),
        }
    }

    /// Where connected clients may read and write files.
    ///
    /// Built from the configured roots on every connection rather than cached, so an
    /// operator narrowing the roots and restarting gets the narrower policy, and a
    /// misconfigured root that cannot be used fails closed to *no* file access rather
    /// than silently to unconfined access.
    fn file_policy(&self) -> rc_file_transfer::PathPolicy {
        let roots = &self.config.features.file_transfer_roots;

        if roots.is_empty() {
            // Documented in the configuration: an empty list means the whole
            // filesystem, which is the right default for a server the operator
            // administers.
            return rc_file_transfer::PathPolicy::unconfined();
        }

        let paths: Vec<std::path::PathBuf> = roots.iter().map(std::path::PathBuf::from).collect();

        rc_file_transfer::PathPolicy::confined_to(paths).unwrap_or_else(|err| {
            // Configuration validation already rejects a relative root, so this is
            // unreachable in practice. If it were ever reached, failing closed to a
            // policy that permits nothing is the only safe reading of "the operator
            // asked for confinement and it could not be applied".
            tracing::error!(%err, "the configured file-transfer roots are unusable");
            rc_file_transfer::PathPolicy::confined_to([std::path::PathBuf::from(
                NOTHING_IS_PERMITTED,
            )])
            .unwrap_or_default()
        })
    }

    /// Facts about this host that do not change between snapshots.
    fn host_summary(&self) -> rc_protocol::control::HostSummary {
        let host = &self.host;

        rc_protocol::control::HostSummary {
            hostname: host.hostname.clone(),
            os_family: host.os_family,
            os_version: host.os_version.clone(),
            kernel_version: host.kernel_version.clone(),
            architecture: host.architecture.clone(),
            logical_cores: u32::try_from(host.logical_cores).unwrap_or(u32::MAX),
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            agent_user: current_user(),
            agent_elevated: rc_platform::is_elevated(),
            booted_at_ms: boot_time_ms(self.clock.now_ms()),
        }
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

/// Record that a session began.
///
/// Called only after the peer has been admitted, so a refused connection never appears
/// to have started a session.
///
/// The trusted-device row's "last connected" is written by `authorize_connection`, which
/// belongs to admission rather than to this already-authenticated path — and which must
/// write it for an unattended reconnection that never reaches here as a decision at all.
fn record_session_start(peer: &rc_transport::AuthenticatedPeer, remote: SocketAddr) {
    tracing::info!(
        device_id = %peer.device_id,
        identity = %peer.identity_fingerprint,
        session_id = %peer.session_id,
        permissions = %permission_names(peer.permissions),
        %remote,
        "session started"
    );
}

/// The stored form of an operating-system family.
///
/// Kept next to its one caller rather than on the protocol type: this is the string the
/// database and the interface use, and pinning it here means a rename in the protocol
/// enum cannot silently change what is already stored in a trust row.
const fn os_family_name(family: rc_protocol::control::OsFamily) -> &'static str {
    match family {
        rc_protocol::control::OsFamily::Windows => "windows",
        rc_protocol::control::OsFamily::Linux => "linux",
        rc_protocol::control::OsFamily::MacOs => "macos",
        _ => "unknown",
    }
}

/// A typed access error as a control-channel result.
///
/// The message is a fixed string per variant, never the error's own display text: a
/// storage failure's message can name a file path, and a caller that was refused is not
/// entitled to learn one.
fn access_error_result(err: &crate::error::AccessError) -> ControlResult {
    use crate::error::AccessError;
    match err {
        AccessError::PermissionDenied { permission } => denied(permission),
        AccessError::InvalidArgument { field } => ControlResult::Err {
            code: rc_protocol::control::ErrorCode::InvalidArgument,
            message: format!("the {field} in this request is not valid"),
        },
        AccessError::Storage(storage) => {
            tracing::warn!(%storage, "a trust-management request could not be served");
            ControlResult::Err {
                code: rc_protocol::control::ErrorCode::Internal,
                message: "the request could not be completed".to_owned(),
            }
        }
    }
}

/// How a session that ended for `reason` is recorded.
///
/// Only a transport failure or a protocol error is a failure; everything else, including
/// an idle timeout and a host-initiated disconnect, is a session that ran and finished.
const fn outcome_of(reason: DisconnectReason) -> rc_storage::SessionOutcome {
    match reason {
        DisconnectReason::TransportFailure | DisconnectReason::ProtocolError => {
            rc_storage::SessionOutcome::Failed
        }
        _ => rc_storage::SessionOutcome::Completed,
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

/// A root that cannot match any real path.
///
/// Used only when confinement was asked for and could not be applied, so the failure
/// mode is "no file access" rather than "all file access".
const NOTHING_IS_PERMITTED: &str = if cfg!(windows) {
    r"C:\rc-no-file-access-configured"
} else {
    "/rc-no-file-access-configured"
};

/// Refuse a request the connection's authorization does not cover.
///
/// The message names the operation in the operator's terms rather than the capability's
/// internal name, because the person reading it is being told what they may not do, not
/// which enum variant governs it.
fn denied(operation: &str) -> ControlResult {
    ControlResult::Err {
        code: rc_protocol::control::ErrorCode::PermissionDenied,
        message: format!("This device is not permitted to {operation}."),
    }
}

/// The account the agent runs as.
///
/// Reported so an operator can see whether the agent is running as a service account or
/// as themselves, which decides what it can reach. `"unknown"` rather than a guess when
/// the platform does not say.
fn current_user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_owned())
}

/// When the host booted, derived from its uptime.
///
/// Computed from `now` rather than read from a separate clock so it agrees with every
/// other timestamp the agent produces.
fn boot_time_ms(now_ms: i64) -> i64 {
    let uptime_ms = i64::try_from(sysinfo::System::uptime().saturating_mul(1000)).unwrap_or(0);
    now_ms.saturating_sub(uptime_ms)
}

/// Render a peer address for an audit record.
///
/// The port is dropped. It is an ephemeral value that identifies nothing useful after
/// the fact, and keeping the address alone makes the log easier to read without losing
/// what an operator actually needs: which machine it was.
fn redact_address(address: SocketAddr) -> String {
    address.ip().to_string()
}

/// Render a session's granted permissions for logs and audit records, as a
/// comma-separated list of their stable names.
fn permission_names(permissions: PermissionSet) -> String {
    permissions
        .iter()
        .map(Permission::name)
        .collect::<Vec<_>>()
        .join(",")
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
            &database,
            Arc::new(DismissingPrompt),
        ))
    }

    /// Every permission, which is what an ordinary session carries.
    fn owner() -> Session {
        Session::new(
            PermissionSet::ALL,
            rc_security::Fingerprint::from_bytes([1u8; 32]),
        )
    }

    fn no_permissions() -> Session {
        Session::new(
            PermissionSet::NONE,
            rc_security::Fingerprint::from_bytes([1u8; 32]),
        )
    }

    /// A session's metrics-subscription handle.
    ///
    /// The receiver is returned rather than dropped because a `watch` sender with no
    /// receivers fails to send — which is exactly how a real session reports that its
    /// metrics task has gone, so a test that dropped it would be testing that path
    /// instead of the one it named.
    fn subscription() -> (
        tokio::sync::watch::Sender<Option<u32>>,
        tokio::sync::watch::Receiver<Option<u32>>,
    ) {
        tokio::sync::watch::channel(None)
    }

    #[tokio::test]
    async fn a_session_without_administer_cannot_read_the_trusted_devices() {
        // The dispatch is what is under test here; the rule itself has its own tests in
        // `trust_service`. What this pins is that the request actually reaches that rule
        // rather than falling through to the `Unsupported` arm, which would look like a
        // refusal while meaning something entirely different.
        let server = server().await;
        let (subscription, _receiver) = subscription();

        let result = server
            .answer(
                &ControlRequestPayload::ListTrustedDevices,
                &no_permissions(),
                &subscription,
            )
            .await;

        assert!(
            matches!(
                result,
                ControlResult::Err {
                    code: rc_protocol::control::ErrorCode::PermissionDenied,
                    ..
                }
            ),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn an_administrator_session_can_read_the_trusted_devices() {
        let server = server().await;
        let (subscription, _receiver) = subscription();

        let result = server
            .answer(
                &ControlRequestPayload::ListTrustedDevices,
                &owner(),
                &subscription,
            )
            .await;

        assert!(
            matches!(
                result,
                ControlResult::Ok(ControlResponsePayload::TrustedDevices(_))
            ),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn an_administrator_cannot_revoke_itself_over_the_control_channel() {
        // The end-to-end shape of the no-self-modification rule: it must survive the
        // trip through dispatch, not only hold inside the service.
        let server = server().await;
        let (subscription, _receiver) = subscription();
        let caller = owner();

        let result = server
            .answer(
                &ControlRequestPayload::RevokeDevice {
                    identity: caller.identity().to_hex(),
                },
                &caller,
                &subscription,
            )
            .await;

        assert!(
            matches!(
                result,
                ControlResult::Err {
                    code: rc_protocol::control::ErrorCode::PermissionDenied,
                    ..
                }
            ),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_storage_failure_does_not_disclose_what_went_wrong() {
        // An error message is shown to a remote peer. A storage error's own text can
        // name a file path, so the wire message is a fixed string per variant.
        let result = access_error_result(&crate::error::AccessError::Storage(
            rc_storage::StorageError::NotFound,
        ));

        let ControlResult::Err { code, message } = result else {
            panic!("expected an error")
        };
        assert_eq!(code, rc_protocol::control::ErrorCode::Internal);
        assert_eq!(message, "the request could not be completed");
    }

    #[tokio::test]
    async fn a_ping_is_answered_with_the_token_it_carried() {
        let server = server().await;
        let (subscription, _receiver) = subscription();
        let result = server
            .answer(
                &ControlRequestPayload::Ping { token: 42 },
                &owner(),
                &subscription,
            )
            .await;

        match result {
            ControlResult::Ok(ControlResponsePayload::Pong { token, .. }) => {
                assert_eq!(token, 42);
            }
            other => panic!("expected a pong, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_snapshot_carries_values_the_agent_actually_measured() {
        let server = server().await;
        let (subscription, _receiver) = subscription();
        let result = server
            .answer(
                &ControlRequestPayload::SystemSnapshot,
                &owner(),
                &subscription,
            )
            .await;

        match result {
            ControlResult::Ok(ControlResponsePayload::Snapshot(snapshot)) => {
                assert!(snapshot.cpu.logical_cores >= 1);
                assert!(snapshot.memory.total_bytes > 0);
                assert!(
                    !snapshot.top_processes.is_empty(),
                    "a running host has processes"
                );
            }
            other => panic!("expected a snapshot, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn host_facts_are_reported_separately_from_live_readings() {
        // Sending the CPU model and kernel version on every tick would make them look
        // like live readings when they are not.
        let server = server().await;
        let (subscription, _receiver) = subscription();
        let result = server
            .answer(&ControlRequestPayload::HostInfo, &owner(), &subscription)
            .await;

        match result {
            ControlResult::Ok(ControlResponsePayload::HostInfo(host)) => {
                assert!(!host.hostname.is_empty());
                assert!(!host.architecture.is_empty());
                assert!(host.logical_cores >= 1);
                assert_eq!(host.agent_version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("expected host facts, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_session_with_only_view_metrics_may_still_read_the_dashboard() {
        // A session holding only ViewMetrics is what a metrics-only grant is for;
        // refusing it would leave that permission with nothing it could do.
        let server = server().await;
        let view_only = Session::new(
            PermissionSet::NONE.with(Permission::ViewMetrics),
            rc_security::Fingerprint::from_bytes([1u8; 32]),
        );

        let (subscription, _receiver) = subscription();
        let result = server
            .answer(
                &ControlRequestPayload::SystemSnapshot,
                &view_only,
                &subscription,
            )
            .await;
        assert!(matches!(
            result,
            ControlResult::Ok(ControlResponsePayload::Snapshot(_))
        ));
    }

    #[tokio::test]
    async fn a_session_without_view_metrics_is_refused_even_mid_session() {
        // The check is against the live permission set on every request, so a
        // permission lost mid-session does not wait for the connection to end.
        let server = server().await;
        let revoked = Session::new(
            PermissionSet::NONE,
            rc_security::Fingerprint::from_bytes([1u8; 32]),
        );

        let (subscription, _receiver) = subscription();
        let result = server
            .answer(
                &ControlRequestPayload::SystemSnapshot,
                &revoked,
                &subscription,
            )
            .await;
        assert!(
            matches!(
                result,
                ControlResult::Err {
                    code: rc_protocol::control::ErrorCode::PermissionDenied,
                    ..
                }
            ),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_metrics_interval_is_clamped_rather_than_honoured_as_asked() {
        // A client asking for 10 ms would cost a full process enumeration a hundred
        // times a second on the machine it is supposed to be observing.
        let server = server().await;
        let (subscription, _receiver) = subscription();
        let result = server
            .answer(
                &ControlRequestPayload::SubscribeMetrics { interval_ms: 1 },
                &owner(),
                &subscription,
            )
            .await;

        match result {
            ControlResult::Ok(ControlResponsePayload::MetricsSubscribed { interval_ms }) => {
                assert_eq!(interval_ms, rc_monitoring::MIN_SAMPLE_INTERVAL_MS);
            }
            other => panic!("expected a subscription, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribing_arms_the_handle_the_metrics_channel_reads() {
        // The subscription is asked for on the control channel and delivered on the
        // metrics channel. If the answer did not reach the handle, a client would be
        // told it had subscribed and then receive nothing at all.
        let server = server().await;
        let (subscription, receiver) = subscription();

        assert_eq!(*receiver.borrow(), None, "nothing is pushed unasked");

        let result = server
            .answer(
                &ControlRequestPayload::SubscribeMetrics { interval_ms: 2_000 },
                &owner(),
                &subscription,
            )
            .await;

        assert!(matches!(
            result,
            ControlResult::Ok(ControlResponsePayload::MetricsSubscribed { interval_ms: 2_000 })
        ));
        assert_eq!(
            *receiver.borrow(),
            Some(2_000),
            "the metrics channel must see the interval the client was promised"
        );
    }

    #[tokio::test]
    async fn unsubscribing_disarms_the_handle() {
        let server = server().await;
        let (subscription, receiver) = subscription();

        server
            .answer(
                &ControlRequestPayload::SubscribeMetrics { interval_ms: 2_000 },
                &owner(),
                &subscription,
            )
            .await;
        server
            .answer(
                &ControlRequestPayload::UnsubscribeMetrics,
                &owner(),
                &subscription,
            )
            .await;

        assert_eq!(
            *receiver.borrow(),
            None,
            "a client that asked to stop must actually stop being sampled"
        );
    }

    #[tokio::test]
    async fn unsubscribing_without_a_subscription_is_not_an_error() {
        // A client tidying up on the way out should not have to remember whether it
        // ever started.
        let server = server().await;
        let (subscription, _receiver) = subscription();

        let result = server
            .answer(
                &ControlRequestPayload::UnsubscribeMetrics,
                &owner(),
                &subscription,
            )
            .await;

        assert!(matches!(
            result,
            ControlResult::Ok(ControlResponsePayload::Empty)
        ));
    }

    #[tokio::test]
    async fn a_session_without_view_metrics_cannot_subscribe_to_metrics() {
        // Denial must leave the handle untouched: a refused subscription that still
        // armed the pusher would stream readings to a device that was just refused.
        let server = server().await;
        let (subscription, receiver) = subscription();

        let result = server
            .answer(
                &ControlRequestPayload::SubscribeMetrics { interval_ms: 2_000 },
                &no_permissions(),
                &subscription,
            )
            .await;

        assert!(matches!(
            result,
            ControlResult::Err {
                code: rc_protocol::control::ErrorCode::PermissionDenied,
                ..
            }
        ));
        assert_eq!(
            *receiver.borrow(),
            None,
            "a refused subscription must not arm the pusher"
        );
    }

    #[tokio::test]
    async fn a_request_this_build_does_not_implement_is_refused_not_faked() {
        // Returning an empty answer would put figures on the operator's dashboard that
        // the agent never measured.
        let server = server().await;
        let (subscription, _receiver) = subscription();
        let result = server
            .answer(
                &ControlRequestPayload::Disconnect(rc_protocol::control::Disconnect {
                    reason: DisconnectReason::UserRequested,
                    detail: None,
                }),
                &owner(),
                &subscription,
            )
            .await;

        assert!(
            matches!(result, ControlResult::Err { .. }),
            "a misrouted request must not be answered as though it succeeded"
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
