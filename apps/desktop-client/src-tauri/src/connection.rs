//! The client's connection to a saved server.
//!
//! # The state machine
//!
//! ```text
//!   Offline ──connect──► Connecting ──► Authenticating ──► Connected
//!      ▲                      │                │               │
//!      │                      └────────────────┴───────────────┘
//!      │                                   failure
//!      │                                      │
//!      │                          ┌───────────┴────────────┐
//!      │                          │                        │
//!      └────── refused ───────────┘              WaitingToRetry ◄─────lost ────┘
//!         (identity changed,                        │
//!          revoked, not paired)                     └──► Reconnecting ──► …
//! ```
//!
//! # Automatic reconnect happens only after an accident
//!
//! This is the rule the whole module is arranged around. Pressing Disconnect sets
//! [`ConnectionManager::intentional_disconnect`], and every retry path checks it. A
//! connection that ends because the operator ended it is never retried — otherwise
//! Disconnect would be a button that briefly disconnects.
//!
//! Two further cases must not retry, for a different reason: a refused connection
//! (unknown device, revoked device, changed identity) and an incompatible peer. Retrying
//! those would turn a loud, visible failure into a quiet loop that nobody sees, which is
//! precisely the failure mode a fingerprint mismatch exists to make noisy.
//! [`rc_transport::TransportError::permits_auto_reconnect`] encodes that distinction and
//! is the single place it is decided.
//!
//! # Where the address comes from
//!
//! In order, stopping at the first that works:
//!
//! 1. The address the last successful connection used.
//! 2. The operator-typed hostname or address.

use std::net::SocketAddr;
use std::sync::Arc;

use rc_protocol::control::{
    Capabilities, ControlRequest, ControlRequestPayload, ControlResponse, ControlResponsePayload,
    ControlResult, DeviceDescriptor, Disconnect, DisconnectReason, WireRefusal,
};
use rc_protocol::files::{FileAgentMessage, FileClientMessage};
use rc_protocol::system::MetricsAgentMessage;
use rc_protocol::{DeviceId, RequestId, SessionId};
use rc_security::{DeviceIdentity, Fingerprint};
use rc_transport::{
    ChannelReader, ChannelWriter, ClientConnector, PeerAddress, PinPolicy, TransportError,
};
use serde::Serialize;
use tokio::sync::Mutex;

/// How long to wait for a connection attempt before trying the next address.
pub const CONNECT_TIMEOUT_SECS: u64 = 8;

/// How long to wait for the server to answer a file request.
///
/// Generous: hashing a large file before a download begins is real work on the server.
/// Bounded: a server that never answers must not leave the UI waiting forever.
pub const FILE_REPLY_TIMEOUT_SECS: u64 = 120;

/// Most messages one file request may draw before the client gives up.
///
/// A download of a very large file legitimately produces many chunks; this is a ceiling
/// on a server streaming without end, not a limit on ordinary transfers.
const MAX_FILE_REPLIES: usize = 200_000;

/// The file channel, shared by every file operation on one connection.
///
/// Both halves live behind one lock because file messages carry no request id: two
/// overlapping requests would produce replies nothing could attribute. Serialising is
/// what makes a reply belong to its request.
struct FileChannel {
    writer: ChannelWriter,
    reader: ChannelReader,
}

/// Where pushed metrics are delivered.
///
/// A callback so the caller decides how to deliver them — the desktop client emits a
/// Tauri event, and a test collects into a vector.
pub type MetricsSink = Arc<dyn Fn(MetricsAgentMessage) + Send + Sync>;

/// Forward pushed metrics to `sink` until the channel closes.
///
/// The metrics channel carries only agent-to-client pushes — a subscription is started
/// and stopped on the *control* channel — so there is nothing to write here and no
/// request to correlate a reply with.
fn spawn_metrics_reader(mut reader: ChannelReader, sink: MetricsSink) {
    tokio::spawn(async move {
        while let Ok(Some(message)) = reader.next_message::<MetricsAgentMessage>().await {
            sink(message);
        }
        tracing::debug!("the metrics channel closed");
    });
}

/// Where a connection is in its lifecycle.
///
/// Mirrors the states listed in the product specification, so the UI can present a
/// precise reason rather than a generic failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
#[non_exhaustive]
pub enum ConnectionState {
    /// Not connected, and not trying.
    Offline,
    /// A transport connection is being established.
    Connecting {
        /// Where the attempt is aimed.
        address: String,
    },
    /// Connected at the transport layer; the handshake is running.
    Authenticating,
    /// Connected and authenticated.
    Connected {
        /// The session the agent assigned.
        session_id: String,
        /// Where the connection actually landed.
        address: String,
    },
    /// A disconnect is in progress.
    Disconnecting,
    /// A previous connection was lost and is being re-established.
    Reconnecting {
        /// Which attempt this is.
        attempt: u32,
    },
    /// Waiting out the backoff before the next attempt.
    WaitingToRetry {
        /// Which attempt comes next.
        attempt: u32,
        /// How long until it starts.
        retry_in_ms: u64,
    },
    /// The agent refused this device. Never retried automatically.
    Refused {
        /// Machine-readable reason the UI branches on.
        reason: RefusalReason,
        /// A sentence safe to show the operator.
        message: String,
    },
    /// The attempt failed for a transient reason and will not be retried, because the
    /// retry budget is exhausted or automatic reconnect is off.
    Failed {
        /// A sentence safe to show the operator.
        message: String,
    },
}

/// Why an agent refused a connection, as far as the client can tell.
///
/// The agent collapses a dismissal, a wrong unattended password and a lockout into one
/// [`WireRefusal::Rejected`] before it answers, so this client genuinely cannot tell
/// them apart — that is what stops the answer from being an oracle for whether
/// unattended access is configured. The variants below are the most this side can
/// determine: the coarse reason it was told, plus what it can see for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RefusalReason {
    /// The agent presented a different certificate than the pinned one.
    IdentityChanged,
    /// The agent did not accept this device. Covers unknown and revoked alike.
    NotAuthorized,
    /// The two builds cannot talk to each other.
    ProtocolMismatch,
    /// The agent is rate-limiting this client.
    Throttled,
}

impl RefusalReason {
    /// Classify a transport failure that must not be retried.
    ///
    /// Returns `None` for failures that *may* be retried; the caller applies the
    /// backoff to those instead.
    #[must_use]
    pub fn classify(error: &TransportError) -> Option<Self> {
        match error {
            TransportError::FingerprintMismatch
            | TransportError::SessionRefused {
                reason: WireRefusal::IdentityChanged,
            } => Some(Self::IdentityChanged),
            TransportError::SessionRefused {
                reason: WireRefusal::NotAccepting | WireRefusal::Rejected,
            }
            | TransportError::NotTrusted
            | TransportError::Revoked => Some(Self::NotAuthorized),
            TransportError::IncompatibleVersion => Some(Self::ProtocolMismatch),
            TransportError::Throttled { .. } => Some(Self::Throttled),
            _ => None,
        }
    }
}

/// Backoff between reconnect attempts.
///
/// Exponential with full jitter. The jitter matters for more than politeness: without
/// it, a client and an agent that restart together retry in lockstep forever, and a
/// several-client deployment synchronises its retries into a thundering herd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// Delay before the first retry, in milliseconds.
    pub initial_ms: u64,
    /// Ceiling on the delay, in milliseconds.
    pub max_ms: u64,
    /// How many attempts before giving up. `0` means keep trying.
    pub max_attempts: u32,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial_ms: 500,
            max_ms: 30_000,
            max_attempts: 10,
        }
    }
}

impl BackoffPolicy {
    /// The delay before `attempt`, which is 1-based.
    ///
    /// `random_unit` is a value in `[0, 1)`; it is a parameter rather than drawn here so
    /// the jitter can be tested deterministically.
    #[must_use]
    pub fn delay_ms(&self, attempt: u32, random_unit: f64) -> u64 {
        let exponent = attempt.saturating_sub(1).min(20);
        let uncapped = self.initial_ms.saturating_mul(1u64 << exponent);
        let capped = uncapped.min(self.max_ms);

        // Full jitter: uniform over [0, capped]. Halving the range instead would keep a
        // synchronised herd synchronised, just more slowly.
        let clamped = random_unit.clamp(0.0, 1.0);
        #[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
        #[allow(clippy::cast_possible_truncation)]
        let jittered = (capped as f64 * clamped) as u64;
        jittered
    }

    /// Whether another attempt is permitted.
    #[must_use]
    pub const fn permits(&self, attempt: u32) -> bool {
        self.max_attempts == 0 || attempt <= self.max_attempts
    }
}

/// A saved server, as the connection manager needs to see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedServer {
    /// Which device.
    pub device_id: DeviceId,
    /// Name to show.
    pub display_name: String,
    /// The certificate fingerprint to pin.
    pub certificate_fingerprint: Fingerprint,
    /// The identity fingerprint, which survives certificate renewal.
    pub identity_fingerprint: Fingerprint,
    /// The address the last successful connection used.
    pub last_known_address: Option<SocketAddr>,
    /// An operator-configured host and port.
    pub configured_endpoint: Option<String>,
}

/// The addresses to try, in order.
///
/// Separated from the connecting itself so the ordering rule can be tested without a
/// network: the last address that worked comes first, because on a home LAN it is
/// almost always still right.
#[must_use]
pub fn candidate_addresses(server: &SavedServer) -> Vec<SocketAddr> {
    let mut candidates = Vec::new();
    let mut push = |address: SocketAddr| {
        if !candidates.contains(&address) {
            candidates.push(address);
        }
    };

    if let Some(address) = server.last_known_address {
        push(address);
    }
    if let Some(endpoint) = &server.configured_endpoint
        && let Some(address) = parse_endpoint(endpoint)
    {
        push(address);
    }

    candidates
}

/// Parse an operator-typed endpoint into a socket address.
///
/// Accepts `host:port` and a bare address, defaulting the port. Returns `None` rather
/// than guessing at anything else: a value that cannot be parsed is a configuration
/// error the operator should see, not one to work around.
#[must_use]
pub fn parse_endpoint(endpoint: &str) -> Option<SocketAddr> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(address) = trimmed.parse::<SocketAddr>() {
        return Some(address);
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, rc_protocol::DEFAULT_AGENT_PORT));
    }

    // A hostname needs resolving, which is I/O; the caller does that. Reporting `None`
    // here keeps this function pure and testable.
    None
}

/// A live, authenticated connection.
struct ActiveConnection {
    connection: quinn::Connection,
    writer: ChannelWriter,
    reader: ChannelReader,
    session_id: SessionId,
    address: SocketAddr,
}

/// Owns at most one connection to one server.
pub struct ConnectionManager {
    identity: Arc<DeviceIdentity>,
    descriptor: DeviceDescriptor,
    capabilities: Capabilities,
    state: std::sync::Mutex<ConnectionState>,
    active: Mutex<Option<ActiveConnection>>,
    /// The file channel, opened lazily on the first file operation.
    files: Mutex<Option<Arc<Mutex<FileChannel>>>>,
    /// The metrics channel, opened lazily on the first subscription.
    ///
    /// Holds the send half even though the client never writes on it: the metrics
    /// channel carries only pushes, and dropping the writer would close the stream the
    /// agent is pushing on. Kept for the life of the connection — the agent samples
    /// nothing until a subscription exists, so an open channel with nobody watching
    /// costs a parked task and no load on the server.
    metrics: Mutex<Option<ChannelWriter>>,
    /// Set by [`ConnectionManager::disconnect`] and cleared by an explicit connect.
    ///
    /// The single flag that separates "the link dropped" from "the operator ended it".
    intentional_disconnect: std::sync::atomic::AtomicBool,
    backoff: BackoffPolicy,
}

impl ConnectionManager {
    /// A manager for this client's identity.
    #[must_use]
    pub fn new(
        identity: Arc<DeviceIdentity>,
        descriptor: DeviceDescriptor,
        capabilities: Capabilities,
    ) -> Self {
        Self {
            identity,
            descriptor,
            capabilities,
            state: std::sync::Mutex::new(ConnectionState::Offline),
            active: Mutex::new(None),
            files: Mutex::new(None),
            metrics: Mutex::new(None),
            intentional_disconnect: std::sync::atomic::AtomicBool::new(false),
            backoff: BackoffPolicy::default(),
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> ConnectionState {
        self.state
            .lock()
            .map_or(ConnectionState::Offline, |guard| guard.clone())
    }

    /// Whether the last disconnect was the operator's doing.
    #[must_use]
    pub fn was_intentional(&self) -> bool {
        self.intentional_disconnect
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn set_state(&self, state: ConnectionState) {
        if let Ok(mut guard) = self.state.lock() {
            tracing::debug!(?state, "connection state changed");
            *guard = state;
        }
    }

    /// Connect to `server`, trying each candidate address in turn.
    ///
    /// # Errors
    /// The failure of the last address tried. A refusal is reported as-is and is not
    /// retried; see the module documentation.
    pub async fn connect(&self, server: &SavedServer) -> Result<SessionId, TransportError> {
        // An explicit connect clears the flag: the operator has asked for a connection,
        // so a later accidental drop is eligible for automatic reconnect again.
        self.intentional_disconnect
            .store(false, std::sync::atomic::Ordering::Release);

        let candidates = candidate_addresses(server);
        if candidates.is_empty() {
            let message = "No address is known for this server. Connect it to the network, or set \
                 its address in the device settings."
                .to_owned();
            self.set_state(ConnectionState::Failed {
                message: message.clone(),
            });
            return Err(TransportError::Connect { reason: message });
        }

        let mut last_error = None;
        for address in candidates {
            self.set_state(ConnectionState::Connecting {
                address: address.to_string(),
            });

            match self.attempt(server, address).await {
                Ok(session_id) => return Ok(session_id),
                Err(err) => {
                    // A refusal is a decision, not a transport hiccup: trying the next
                    // address would only produce the same refusal from the same agent.
                    if let Some(reason) = RefusalReason::classify(&err) {
                        self.set_state(ConnectionState::Refused {
                            reason,
                            message: err.to_string(),
                        });
                        return Err(err);
                    }
                    tracing::debug!(%address, %err, "connection attempt failed");
                    last_error = Some(err);
                }
            }
        }

        let err = last_error.unwrap_or(TransportError::Connect {
            reason: "no address could be reached".to_owned(),
        });
        self.set_state(ConnectionState::Failed {
            message: err.to_string(),
        });
        Err(err)
    }

    /// One connection attempt against one address.
    async fn attempt(
        &self,
        server: &SavedServer,
        address: SocketAddr,
    ) -> Result<SessionId, TransportError> {
        // Pinned to the certificate recorded for this server. An agent that renewed its
        // certificate without the client recording the rotation fails here — loudly,
        // which is the intent.
        let (connector, _observed) = ClientConnector::new(
            &self.identity,
            PinPolicy::Pinned(server.certificate_fingerprint),
        )?;

        let connection = tokio::time::timeout(
            std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS),
            connector.connect(address),
        )
        .await
        .map_err(|_| TransportError::Connect {
            reason: format!("{address} did not answer within {CONNECT_TIMEOUT_SECS} seconds"),
        })??;

        self.set_state(ConnectionState::Authenticating);

        let (mut writer, mut reader) =
            rc_transport::open_channel(&connection, rc_protocol::Channel::Control).await?;
        let dialed_address = address.to_string().parse::<PeerAddress>()?;

        let ack = rc_transport::handshake::begin_handshake(
            &mut reader,
            &mut writer,
            self.descriptor.clone(),
            self.capabilities.clone(),
            dialed_address,
            None,
            rc_protocol::now_ms(),
        )
        .await?;

        // The agent's identity is verified by TLS against the pin; this is a second,
        // cheaper check that the peer is the device the client meant to reach, and it
        // catches a saved record that has drifted from the pin it was stored with.
        if ack.descriptor.device_id != server.device_id {
            return Err(TransportError::FingerprintMismatch);
        }

        let session_id = ack.session_id;
        self.set_state(ConnectionState::Connected {
            session_id: session_id.to_canonical_string(),
            address: address.to_string(),
        });

        // The connector is held by the active connection: dropping it would close the
        // endpoint underneath the connection that was just established.
        std::mem::forget(connector);

        // Any channels belonged to a previous connection.
        *self.files.lock().await = None;

        *self.active.lock().await = Some(ActiveConnection {
            connection,
            writer,
            reader,
            session_id,
            address,
        });

        tracing::info!(%address, %session_id, "connected");
        Ok(session_id)
    }

    /// Where the live connection landed, if there is one.
    pub async fn connected_address(&self) -> Option<SocketAddr> {
        self.active.lock().await.as_ref().map(|a| a.address)
    }

    /// Send a control request and wait for its response.
    ///
    /// # Errors
    /// [`TransportError::Closed`] when nothing is connected, or the underlying
    /// transport failure.
    pub async fn request(
        &self,
        payload: ControlRequestPayload,
    ) -> Result<ControlResult, TransportError> {
        let mut guard = self.active.lock().await;
        let active = guard.as_mut().ok_or(TransportError::Closed {
            reason: "not connected".to_owned(),
        })?;

        let request_id = RequestId::generate();
        active
            .writer
            .send(&ControlRequest {
                request_id,
                session_id: active.session_id,
                sent_at_ms: rc_protocol::now_ms(),
                nonce: fresh_nonce(),
                payload,
            })
            .await?;

        let response: ControlResponse =
            active
                .reader
                .next_message()
                .await?
                .ok_or(TransportError::ConnectionLost {
                    reason: "the agent closed the connection".to_owned(),
                })?;

        // A reply that answers a different request means the stream has desynchronised,
        // which is a protocol error rather than something to match up later.
        if response.request_id != request_id {
            return Err(TransportError::UnexpectedMessage {
                expected: "a response to this request",
            });
        }

        Ok(response.result)
    }

    /// Measure the round trip to the agent.
    ///
    /// # Errors
    /// As [`ConnectionManager::request`].
    pub async fn ping(&self) -> Result<u64, TransportError> {
        let started = std::time::Instant::now();
        let token = u64::from(rand_u32());

        let result = self.request(ControlRequestPayload::Ping { token }).await?;

        match result {
            ControlResult::Ok(ControlResponsePayload::Pong { token: echoed, .. })
                if echoed == token =>
            {
                let elapsed = started.elapsed().as_millis();
                Ok(u64::try_from(elapsed).unwrap_or(u64::MAX))
            }
            // An echo that does not match means the reply is not ours.
            _ => Err(TransportError::UnexpectedMessage {
                expected: "a pong echoing this token",
            }),
        }
    }

    /// Send a file request and collect the agent's reply.
    ///
    /// The file channel is request/response for most operations but streams for
    /// transfers, so the caller says how many messages to gather with `until`: it is
    /// given each reply and returns whether that was the last one.
    ///
    /// # Errors
    /// [`TransportError::Closed`] when nothing is connected, or the underlying transport
    /// failure. A reply that never arrives fails on the deadline rather than hanging.
    pub async fn file_request(
        &self,
        request: &FileClientMessage,
        until: impl Fn(&FileAgentMessage) -> bool,
    ) -> Result<Vec<FileAgentMessage>, TransportError> {
        let channel = self.ensure_file_channel().await?;

        // One request at a time on this channel. The messages carry a transfer id but
        // not a request id, so two overlapping listings would be indistinguishable;
        // serialising here is what keeps a reply attributable to its request.
        let mut guard = channel.lock().await;

        guard.writer.send(request).await?;

        let mut replies = Vec::new();
        loop {
            let deadline = std::time::Duration::from_secs(FILE_REPLY_TIMEOUT_SECS);
            let message = tokio::time::timeout(deadline, guard.reader.next_message())
                .await
                .map_err(|_| TransportError::HandshakeTimeout)?
                .and_then(|message| {
                    message.ok_or(TransportError::ConnectionLost {
                        reason: "the server closed the file channel".to_owned(),
                    })
                })?;

            let done = until(&message);
            replies.push(message);

            if done {
                return Ok(replies);
            }

            // Bounded: a server streaming without end must not grow this without limit.
            if replies.len() > MAX_FILE_REPLIES {
                return Err(TransportError::Protocol(
                    rc_protocol::ProtocolError::MalformedBody,
                ));
            }
        }
    }

    /// Send a file message that draws no reply.
    ///
    /// Upload chunks are the only such message: the agent answers when the transfer is
    /// ended, not per chunk, because a round trip per chunk would halve the throughput
    /// of every transfer for no added safety — the checksum already covers the result.
    ///
    /// # Errors
    /// [`TransportError::Closed`] when nothing is connected.
    pub async fn send_file_message(
        &self,
        message: &FileClientMessage,
    ) -> Result<(), TransportError> {
        let channel = self.ensure_file_channel().await?;
        let mut guard = channel.lock().await;
        guard.writer.send(message).await
    }

    /// Open the file channel if it is not already open.
    async fn ensure_file_channel(&self) -> Result<Arc<Mutex<FileChannel>>, TransportError> {
        let mut slot = self.files.lock().await;

        if let Some(existing) = slot.as_ref() {
            return Ok(Arc::clone(existing));
        }

        let guard = self.active.lock().await;
        let active = guard.as_ref().ok_or(TransportError::Closed {
            reason: "not connected".to_owned(),
        })?;

        let (writer, reader) =
            rc_transport::open_channel(&active.connection, rc_protocol::Channel::FileTransfer)
                .await?;
        drop(guard);

        let channel = Arc::new(Mutex::new(FileChannel { writer, reader }));
        *slot = Some(Arc::clone(&channel));
        Ok(channel)
    }

    /// Start receiving pushed metrics, and return the interval the agent accepted.
    ///
    /// The answer is the agent's clamped figure, not what was asked for, so the screen
    /// can say how often it is actually being updated rather than what it hoped for.
    ///
    /// The channel is opened *before* the subscription is requested. The agent tolerates
    /// either order, but opening first means the first tick has somewhere to arrive.
    ///
    /// # Errors
    /// The connection is gone, or the agent refused the subscription — which a
    /// view-only-revoked device is entitled to be told rather than left waiting.
    pub async fn subscribe_metrics(
        &self,
        interval_ms: u32,
        sink: MetricsSink,
    ) -> Result<u32, TransportError> {
        self.ensure_metrics_channel(sink).await?;

        let result = self
            .request(ControlRequestPayload::SubscribeMetrics { interval_ms })
            .await?;

        match result {
            ControlResult::Ok(ControlResponsePayload::MetricsSubscribed { interval_ms }) => {
                Ok(interval_ms)
            }
            ControlResult::Err { message, .. } => Err(TransportError::Closed { reason: message }),
            // An answer of another shape means the two builds disagree about what a
            // subscription is. Reporting it beats waiting for pushes that never come.
            ControlResult::Ok(_) => Err(TransportError::Closed {
                reason: "the server did not accept the metrics subscription".to_owned(),
            }),
        }
    }

    /// Stop receiving pushed metrics.
    ///
    /// The channel is left open: subscribing again is then a single control request
    /// rather than a new stream, and an open channel with no subscription costs nothing.
    ///
    /// # Errors
    /// The connection is gone.
    pub async fn unsubscribe_metrics(&self) -> Result<(), TransportError> {
        self.request(ControlRequestPayload::UnsubscribeMetrics)
            .await?;
        Ok(())
    }

    /// Open the metrics channel if it is not already open.
    async fn ensure_metrics_channel(&self, sink: MetricsSink) -> Result<(), TransportError> {
        let mut slot = self.metrics.lock().await;
        if slot.is_some() {
            return Ok(());
        }

        let guard = self.active.lock().await;
        let active = guard.as_ref().ok_or(TransportError::Closed {
            reason: "not connected".to_owned(),
        })?;

        let (writer, reader) =
            rc_transport::open_channel(&active.connection, rc_protocol::Channel::Metrics).await?;
        drop(guard);

        spawn_metrics_reader(reader, sink);
        *slot = Some(writer);
        Ok(())
    }

    /// Disconnect deliberately.
    ///
    /// Sets the flag that suppresses automatic reconnection. That is the entire point:
    /// without it, Disconnect would be a button that disconnects for half a second.
    pub async fn disconnect(&self) {
        self.intentional_disconnect
            .store(true, std::sync::atomic::Ordering::Release);
        self.set_state(ConnectionState::Disconnecting);

        // Every channel belongs to the connection being closed; a later connection opens
        // fresh ones rather than writing into a dead stream.
        *self.files.lock().await = None;
        *self.metrics.lock().await = None;

        if let Some(mut active) = self.active.lock().await.take() {
            // Best-effort: tell the agent why, so its audit trail records an intentional
            // end rather than a dropped link. A failure here changes nothing.
            let notice = ControlRequest {
                request_id: RequestId::generate(),
                session_id: active.session_id,
                sent_at_ms: rc_protocol::now_ms(),
                nonce: fresh_nonce(),
                payload: ControlRequestPayload::Disconnect(Disconnect {
                    reason: DisconnectReason::UserRequested,
                    detail: None,
                }),
            };
            if let Err(err) = active.writer.send(&notice).await {
                tracing::debug!(%err, "could not send the disconnect notice");
            }
            active
                .connection
                .close(0u32.into(), b"disconnected by the operator");
        }

        self.set_state(ConnectionState::Offline);
        tracing::info!("disconnected at the operator's request");
    }

    /// Whether an error should start the automatic reconnect loop.
    ///
    /// Two conditions, both required: the operator did not ask for the disconnect, and
    /// the error is one that retrying could plausibly fix.
    #[must_use]
    pub fn should_auto_reconnect(&self, error: &TransportError) -> bool {
        !self.was_intentional() && error.permits_auto_reconnect()
    }

    /// Reconnect after an accidental loss, applying the backoff.
    ///
    /// # Errors
    /// The last failure, after the retry budget is spent.
    pub async fn reconnect(&self, server: &SavedServer) -> Result<SessionId, TransportError> {
        let mut attempt = 1;

        loop {
            if self.was_intentional() {
                // The operator pressed Disconnect while a retry was pending. Honour it.
                self.set_state(ConnectionState::Offline);
                return Err(TransportError::Closed {
                    reason: "reconnection was cancelled".to_owned(),
                });
            }

            if !self.backoff.permits(attempt) {
                let message = format!(
                    "Could not reconnect after {} attempts. Check that the server is on \
                     and reachable.",
                    attempt - 1
                );
                self.set_state(ConnectionState::Failed {
                    message: message.clone(),
                });
                return Err(TransportError::Connect { reason: message });
            }

            let delay = self.backoff.delay_ms(attempt, random_unit());
            self.set_state(ConnectionState::WaitingToRetry {
                attempt,
                retry_in_ms: delay,
            });
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;

            if self.was_intentional() {
                self.set_state(ConnectionState::Offline);
                return Err(TransportError::Closed {
                    reason: "reconnection was cancelled".to_owned(),
                });
            }

            self.set_state(ConnectionState::Reconnecting { attempt });

            match self.connect(server).await {
                Ok(session_id) => {
                    tracing::info!(attempt, "reconnected");
                    return Ok(session_id);
                }
                Err(err) => {
                    // A refusal ends the loop: the answer will not change by asking
                    // again, and hiding it behind retries is how a real problem goes
                    // unnoticed.
                    if RefusalReason::classify(&err).is_some() {
                        return Err(err);
                    }
                    attempt += 1;
                }
            }
        }
    }
}

/// A fresh anti-replay nonce.
fn fresh_nonce() -> [u8; 16] {
    use rc_security::RandomSourceExt as _;
    rc_security::OsRandom.bytes()
}

/// A random `u32` from the OS CSPRNG.
fn rand_u32() -> u32 {
    use rc_security::RandomSourceExt as _;
    let bytes: [u8; 4] = rc_security::OsRandom.bytes();
    u32::from_le_bytes(bytes)
}

/// A random value in `[0, 1)`, for backoff jitter.
fn random_unit() -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let unit = f64::from(rand_u32()) / f64::from(u32::MAX);
    unit
}

/// Build the descriptor this client presents.
#[must_use]
pub fn client_descriptor(
    identity: &DeviceIdentity,
    host: &rc_platform::HostInfo,
) -> DeviceDescriptor {
    let public = identity.public();
    DeviceDescriptor {
        device_id: public.device_id,
        display_name: host.hostname.clone(),
        hostname: host.hostname.clone(),
        os_family: host.os_family,
        os_version: host.os_version.clone(),
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        // Self-reported, for display. The agent uses what its TLS connection observed.
        certificate_fingerprint: public.certificate_fingerprint.to_hex(),
    }
}

/// What this client can do.
#[must_use]
pub const fn client_capabilities() -> Capabilities {
    Capabilities {
        remote_desktop: false,
        file_transfer: false,
        monitoring: true,
        process_management: false,
        clipboard: false,
        wake_on_lan: false,
        display_count: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use rc_protocol::control::OsFamily;

    use rc_security::SystemClock;

    use super::*;

    fn address(last_octet: u8, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, last_octet)), port)
    }

    fn server() -> SavedServer {
        SavedServer {
            device_id: DeviceId::generate(),
            display_name: "home-server".to_owned(),
            certificate_fingerprint: Fingerprint::of_certificate_der(b"cert"),
            identity_fingerprint: Fingerprint::of_public_key(&[1u8; 32]),
            last_known_address: None,
            configured_endpoint: None,
        }
    }

    fn manager() -> ConnectionManager {
        let identity = Arc::new(DeviceIdentity::generate("client", &SystemClock).unwrap());
        let host = rc_platform::HostInfo::detect();
        let descriptor = client_descriptor(&identity, &host);
        ConnectionManager::new(identity, descriptor, client_capabilities())
    }

    // -- address selection ---------------------------------------------------

    #[test]
    fn the_last_working_address_is_tried_first() {
        // On a home LAN it is nearly always still right.
        let mut saved = server();
        saved.last_known_address = Some(address(50, 47811));
        saved.configured_endpoint = Some("192.168.1.60:47811".to_owned());

        let candidates = candidate_addresses(&saved);
        assert_eq!(candidates[0], address(50, 47811));
        assert_eq!(candidates[1], address(60, 47811));
    }

    #[test]
    fn a_configured_endpoint_is_used_when_nothing_is_saved() {
        let mut saved = server();
        saved.configured_endpoint = Some("192.168.1.60:47811".to_owned());

        let candidates = candidate_addresses(&saved);
        assert_eq!(candidates, vec![address(60, 47811)]);
    }

    #[test]
    fn a_duplicated_address_is_tried_once() {
        let mut saved = server();
        saved.last_known_address = Some(address(50, 47811));
        saved.configured_endpoint = Some("192.168.1.50:47811".to_owned());

        assert_eq!(candidate_addresses(&saved), vec![address(50, 47811)]);
    }

    #[test]
    fn a_server_with_nowhere_to_dial_yields_no_candidates() {
        assert!(candidate_addresses(&server()).is_empty());
    }

    #[test]
    fn an_endpoint_without_a_port_gets_the_default() {
        assert_eq!(
            parse_endpoint("10.0.0.4"),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
                rc_protocol::DEFAULT_AGENT_PORT
            ))
        );
    }

    #[test]
    fn an_unparseable_endpoint_is_reported_rather_than_guessed_at() {
        // A hostname needs resolving, which is the caller's job; anything else is a
        // configuration error the operator should see.
        assert_eq!(parse_endpoint(""), None);
        assert_eq!(parse_endpoint("   "), None);
        assert_eq!(parse_endpoint("not an address"), None);
        assert_eq!(parse_endpoint("server.local"), None);
    }

    // -- reconnect policy ----------------------------------------------------

    #[tokio::test]
    async fn a_deliberate_disconnect_suppresses_automatic_reconnect() {
        // The rule this module is arranged around.
        let manager = manager();
        manager.disconnect().await;

        assert!(manager.was_intentional());
        assert!(
            !manager.should_auto_reconnect(&TransportError::ConnectionLost {
                reason: "network went away".to_owned()
            })
        );
    }

    #[tokio::test]
    async fn an_accidental_loss_permits_automatic_reconnect() {
        let manager = manager();
        assert!(
            manager.should_auto_reconnect(&TransportError::ConnectionLost {
                reason: "network went away".to_owned()
            })
        );
    }

    #[tokio::test]
    async fn connecting_again_re_arms_automatic_reconnect() {
        // After a deliberate disconnect and a deliberate reconnect, a later accidental
        // drop must be retried again.
        let manager = manager();
        manager.disconnect().await;
        assert!(manager.was_intentional());

        // The connect fails — there is nothing to connect to — but the flag it clears
        // is what is being asserted.
        let _ = manager.connect(&server()).await;
        assert!(!manager.was_intentional());
    }

    #[test]
    fn a_refusal_is_never_retried_automatically() {
        // Retrying would turn a loud failure into a quiet loop nobody notices.
        let manager = manager();
        for error in [
            TransportError::FingerprintMismatch,
            TransportError::NotTrusted,
            TransportError::Revoked,
            TransportError::IncompatibleVersion,
        ] {
            assert!(
                !manager.should_auto_reconnect(&error),
                "{error:?} must not be retried"
            );
            assert!(
                RefusalReason::classify(&error).is_some(),
                "{error:?} must be classified as a refusal"
            );
        }
    }

    #[test]
    fn a_transient_failure_is_not_classified_as_a_refusal() {
        assert_eq!(
            RefusalReason::classify(&TransportError::ConnectionLost {
                reason: "reset".to_owned()
            }),
            None
        );
        assert_eq!(
            RefusalReason::classify(&TransportError::HandshakeTimeout),
            None
        );
    }

    #[test]
    fn a_changed_identity_is_reported_distinctly_from_a_plain_refusal() {
        // The operator needs to be told the difference: one means "pair again", the
        // other means "something is wrong".
        assert_eq!(
            RefusalReason::classify(&TransportError::FingerprintMismatch),
            Some(RefusalReason::IdentityChanged)
        );
        assert_eq!(
            RefusalReason::classify(&TransportError::NotTrusted),
            Some(RefusalReason::NotAuthorized)
        );
    }

    #[test]
    fn an_unknown_and_a_revoked_device_are_indistinguishable_to_the_client() {
        // Deliberate: the agent reports them identically so its port cannot be used to
        // enumerate which devices it trusts.
        assert_eq!(
            RefusalReason::classify(&TransportError::NotTrusted),
            RefusalReason::classify(&TransportError::Revoked)
        );
    }

    // -- backoff -------------------------------------------------------------

    #[test]
    fn the_delay_grows_exponentially_and_stops_at_the_ceiling() {
        let policy = BackoffPolicy {
            initial_ms: 100,
            max_ms: 1_000,
            max_attempts: 0,
        };

        // With the jitter at its maximum, the delay is the uncapped-then-capped value.
        assert_eq!(policy.delay_ms(1, 1.0), 100);
        assert_eq!(policy.delay_ms(2, 1.0), 200);
        assert_eq!(policy.delay_ms(3, 1.0), 400);
        assert_eq!(policy.delay_ms(10, 1.0), 1_000, "capped");
        assert_eq!(policy.delay_ms(1_000, 1.0), 1_000, "still capped");
    }

    #[test]
    fn jitter_spreads_retries_across_the_whole_window() {
        // Full jitter, not half: a herd that all halve their delay stays a herd.
        let policy = BackoffPolicy {
            initial_ms: 1_000,
            max_ms: 60_000,
            max_attempts: 0,
        };

        assert_eq!(policy.delay_ms(3, 0.0), 0);
        assert_eq!(policy.delay_ms(3, 0.5), 2_000);
        assert_eq!(policy.delay_ms(3, 1.0), 4_000);
    }

    #[test]
    fn an_out_of_range_jitter_value_cannot_produce_a_wild_delay() {
        let policy = BackoffPolicy::default();
        assert_eq!(policy.delay_ms(1, -5.0), 0);
        assert_eq!(policy.delay_ms(1, 5.0), policy.initial_ms);
    }

    #[test]
    fn a_huge_attempt_number_does_not_overflow() {
        let policy = BackoffPolicy::default();
        assert_eq!(policy.delay_ms(u32::MAX, 1.0), policy.max_ms);
    }

    #[test]
    fn the_retry_budget_is_enforced_and_zero_means_forever() {
        let limited = BackoffPolicy {
            max_attempts: 3,
            ..BackoffPolicy::default()
        };
        assert!(limited.permits(3));
        assert!(!limited.permits(4));

        let unlimited = BackoffPolicy {
            max_attempts: 0,
            ..BackoffPolicy::default()
        };
        assert!(unlimited.permits(1_000_000));
    }

    #[test]
    fn the_generated_jitter_stays_in_range() {
        for _ in 0..100 {
            let unit = random_unit();
            assert!((0.0..=1.0).contains(&unit), "got {unit}");
        }
    }

    // -- state ---------------------------------------------------------------

    #[tokio::test]
    async fn a_manager_starts_offline() {
        assert_eq!(manager().state(), ConnectionState::Offline);
    }

    #[tokio::test]
    async fn connecting_with_no_address_reports_what_the_operator_should_do() {
        // "Something went wrong" is not an acceptable answer here.
        let manager = manager();
        let result = manager.connect(&server()).await;

        assert!(result.is_err());
        match manager.state() {
            ConnectionState::Failed { message } => {
                assert!(
                    message.contains("address"),
                    "the message must say what is missing: {message}"
                );
            }
            other => panic!("expected a failed state, got {other:?}"),
        }
    }

    #[test]
    fn every_connection_state_serialises_with_a_tag_the_ui_can_switch_on() {
        let states = [
            ConnectionState::Offline,
            ConnectionState::Connecting {
                address: "10.0.0.1:1".to_owned(),
            },
            ConnectionState::Authenticating,
            ConnectionState::Connected {
                session_id: "ses_x".to_owned(),
                address: "10.0.0.1:1".to_owned(),
            },
            ConnectionState::Disconnecting,
            ConnectionState::Reconnecting { attempt: 1 },
            ConnectionState::WaitingToRetry {
                attempt: 2,
                retry_in_ms: 500,
            },
            ConnectionState::Refused {
                reason: RefusalReason::IdentityChanged,
                message: "changed".to_owned(),
            },
            ConnectionState::Failed {
                message: "nope".to_owned(),
            },
        ];

        let tags: Vec<String> = states
            .iter()
            .map(|state| {
                serde_json::to_value(state).unwrap()["state"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();

        assert_eq!(tags.len(), 9);
        assert!(tags.contains(&"connected".to_owned()));
        assert!(tags.contains(&"waiting_to_retry".to_owned()));
    }

    #[test]
    fn a_serialised_state_carries_no_key_material() {
        let state = ConnectionState::Connected {
            session_id: SessionId::generate().to_canonical_string(),
            address: "10.0.0.1:47811".to_owned(),
        };
        let rendered = serde_json::to_string(&state).unwrap();

        for forbidden in ["PRIVATE", "password", "verifier", "token"] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn the_client_advertises_only_what_it_implements() {
        // Claiming a capability the client cannot honour would make the agent offer an
        // operation that then fails.
        let capabilities = client_capabilities();
        assert!(!capabilities.remote_desktop);
        assert!(capabilities.monitoring);
    }

    #[test]
    fn the_descriptor_reports_this_clients_identity() {
        let identity = DeviceIdentity::generate("client", &SystemClock).unwrap();
        let descriptor = client_descriptor(&identity, &rc_platform::HostInfo::detect());

        assert_eq!(descriptor.device_id, identity.device_id());
        assert_eq!(
            descriptor.certificate_fingerprint,
            identity.public().certificate_fingerprint.to_hex()
        );
    }

    #[test]
    fn the_descriptor_reports_the_os_this_build_runs_on() {
        let identity = DeviceIdentity::generate("client", &SystemClock).unwrap();
        let descriptor = client_descriptor(&identity, &rc_platform::HostInfo::detect());

        if cfg!(target_os = "windows") {
            assert_eq!(descriptor.os_family, OsFamily::Windows);
        } else if cfg!(target_os = "linux") {
            assert_eq!(descriptor.os_family, OsFamily::Linux);
        }
        assert!(!descriptor.os_version.is_empty());
    }
}
