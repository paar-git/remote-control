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
use rc_protocol::desktop::{DesktopAgentMessage, DesktopClientMessage, DisplayInfo};
use rc_protocol::files::{FileAgentMessage, FileClientMessage};
use rc_protocol::system::MetricsAgentMessage;
use rc_protocol::{InputEvent, InputMessage, RequestId, SessionId};
use rc_security::{DeviceIdentity, PermissionSet};
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

/// Where acknowledgements and display topology pushed on the input channel are
/// delivered.
///
/// A callback for the same reason as [`MetricsSink`]: the desktop client emits Tauri
/// events, a test collects into a vector. This is also what keeps
/// [`ConnectionManager::send_input`] honest about the constraint in this module's
/// callers — a `Failed` acknowledgement (a revoked `control_input` grant, for instance)
/// must reach the sink rather than being read and discarded, since this client does not
/// enforce that permission itself.
pub type InputSink = Arc<dyn Fn(InputMessage) + Send + Sync>;

/// Forward acknowledgements and display topology to `sink` until the channel closes.
fn spawn_input_reader(mut reader: ChannelReader, sink: InputSink) {
    tokio::spawn(async move {
        while let Ok(Some(message)) = reader.next_message::<InputMessage>().await {
            sink(message);
        }
        tracing::debug!("the input channel closed");
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
        /// What the other machine granted this session, by stable permission name.
        ///
        /// Carried on the state rather than fetched separately, so it arrives with the
        /// session and disappears with it. The interface uses it to decide which tools
        /// to offer; the authority is still the other machine, which re-checks on every
        /// request.
        permissions: Vec<String>,
        /// The name the other machine reported, for the session toolbar.
        device_name: String,
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

/// Where a connection is aimed, and what it offers on arrival.
///
/// There is no saved-device record to pin against any more: the user types an address
/// and the machine on the other end decides. So a target is the address as typed, plus
/// the unattended password if one was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The address the user typed, canonicalised. This exact string is what the
    /// responder keys its pin on, so it travels on `Authenticate` unchanged.
    pub address: PeerAddress,
    /// The unattended-access password, when the user supplied one.
    ///
    /// Not logged and not stored. It is sent inside the already-authenticated TLS
    /// exchange and dropped when the attempt ends.
    pub unattended_password: Option<String>,
    /// Identity previously seen at this address, if any.
    pub pinned_identity: Option<rc_security::Fingerprint>,
}

impl Target {
    /// A target with no password offered, which is the common case.
    #[must_use]
    pub const fn new(address: PeerAddress) -> Self {
        Self {
            address,
            unattended_password: None,
            pinned_identity: None,
        }
    }
}

/// A live, authenticated connection.
struct ActiveConnection {
    connection: quinn::Connection,
    writer: ChannelWriter,
    reader: ChannelReader,
    session_id: SessionId,
    address: SocketAddr,
    /// Kept so the QUIC endpoint outlives the connection.
    _connector: ClientConnector,
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
    /// The write half of the video channel, while a stream is running.
    ///
    /// Held so [`ConnectionManager::video_stop_stream`] and
    /// [`ConnectionManager::video_request_keyframe`] can reach it, and so the frame
    /// reader task started by [`ConnectionManager::video_start_stream`] can ask for a
    /// keyframe itself when the decoder falls behind. `Arc` because both this struct
    /// and that task hold it at once.
    video: Mutex<Option<Arc<Mutex<ChannelWriter>>>>,
    /// The write half of the input channel, once opened.
    ///
    /// Opened lazily on the first input command and kept for the life of the
    /// connection, mirroring `metrics`: a mouse-move stream would otherwise pay for a
    /// fresh QUIC stream on every sample.
    input: Mutex<Option<ChannelWriter>>,
    /// Monotonic counter for `InputEvent::seq`.
    ///
    /// Shared by every input command on this connection so the host's acknowledgements
    /// and applied watermark stay unambiguous. Gaps are fine — an event this build
    /// dropped locally (see `input_commands::classify`) simply never uses its number —
    /// repeats are not.
    input_seq: std::sync::atomic::AtomicU32,
    /// Who answered, once a connection is established.
    ///
    /// Arrives on `SessionAuthorization::Granted`, so it exists only for an admitted
    /// session — a refused peer is told nothing about the machine it reached, and this
    /// side has nothing to record. Used for the name shown in the session and written
    /// to the recent list.
    peer: Mutex<Option<DeviceDescriptor>>,
    /// Identity extracted from the certificate presented on the last admitted session.
    peer_identity: Mutex<Option<rc_security::Fingerprint>>,
    /// Row in `session_history` for the current outgoing session, if one was written.
    outgoing_history_id: Mutex<Option<i64>>,
    /// What the agent granted this session, and therefore what this client may ask of
    /// it.
    ///
    /// Not a cache of a decision made here: the agent decided it, sent it on
    /// `SessionAuthorization::Granted`, and enforces it on every request of its own.
    /// This copy exists so the client refuses locally too, and shows the operator
    /// controls that can actually work rather than buttons that will be denied.
    ///
    /// Cleared by [`ConnectionManager::set_state`] on any state that is not
    /// `Connected`, so a permission cannot outlive the session that carried it. That is
    /// why it lives beside `state` and is written only there.
    granted: std::sync::Mutex<PermissionSet>,
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
            peer: Mutex::new(None),
            peer_identity: Mutex::new(None),
            outgoing_history_id: Mutex::new(None),
            granted: std::sync::Mutex::new(PermissionSet::NONE),
            active: Mutex::new(None),
            files: Mutex::new(None),
            metrics: Mutex::new(None),
            video: Mutex::new(None),
            input: Mutex::new(None),
            input_seq: std::sync::atomic::AtomicU32::new(0),
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

    /// Who answered on the live connection, if one is up.
    pub async fn peer(&self) -> Option<DeviceDescriptor> {
        self.peer.lock().await.clone()
    }

    /// Identity the last admitted peer proved, if one was observed.
    pub async fn peer_identity(&self) -> Option<rc_security::Fingerprint> {
        *self.peer_identity.lock().await
    }

    /// Remember the history row for this outgoing session.
    pub async fn set_outgoing_history_id(&self, id: i64) {
        *self.outgoing_history_id.lock().await = Some(id);
    }

    /// Take the history row so it can be finished exactly once.
    pub async fn take_outgoing_history_id(&self) -> Option<i64> {
        self.outgoing_history_id.lock().await.take()
    }

    /// Wait until the live QUIC connection ends, if one is up.
    pub async fn wait_until_closed(&self) {
        let connection = {
            let guard = self.active.lock().await;
            guard.as_ref().map(|active| active.connection.clone())
        };
        if let Some(connection) = connection {
            connection.closed().await;
        }
    }

    /// Wait for the live QUIC connection to end, then reconnect unless the operator
    /// disconnected on purpose. After a successful reconnect, watch the new link too —
    /// a one-shot watch would leave the next drop sitting as "connected" forever.
    pub fn watch_for_loss(self: &Arc<Self>, target: Target) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                this.wait_until_closed().await;
                if this.was_intentional() {
                    return;
                }
                if let Err(err) = this.reconnect(&target).await {
                    tracing::warn!(%err, "automatic reconnect ended");
                    return;
                }
            }
        });
    }

    /// What the connected agent granted this session.
    ///
    /// [`PermissionSet::NONE`] whenever nothing is connected, which is what makes every
    /// gated command fail closed between sessions rather than carrying the last one's
    /// grant forward.
    #[must_use]
    pub fn granted(&self) -> PermissionSet {
        self.granted
            .lock()
            .map_or(PermissionSet::NONE, |guard| *guard)
    }

    /// Record what the agent granted, for the life of this connection.
    fn set_granted(&self, permissions: PermissionSet) {
        if let Ok(mut guard) = self.granted.lock() {
            *guard = permissions;
        }
    }

    fn set_state(&self, state: ConnectionState) {
        // Any state but `Connected` means there is no session, so there is nothing
        // granted. Clearing here rather than at each call site is what stops a grant
        // outliving its session: every path out of `Connected` goes through this
        // function, including the ones that end a connection by failing.
        if !matches!(state, ConnectionState::Connected { .. }) {
            self.set_granted(PermissionSet::NONE);
        }
        if let Ok(mut guard) = self.state.lock() {
            tracing::debug!(?state, "connection state changed");
            *guard = state;
        }
    }

    /// Connect to `target`, trying each address it resolves to in turn.
    ///
    /// A hostname can resolve to several addresses; all are tried in the order the
    /// resolver gave them, because the first is not reliably the reachable one.
    ///
    /// # Errors
    /// The failure of the last address tried. A refusal is reported as-is and is never
    /// retried against another address: it is a decision by the machine on the other
    /// end, and the same machine answers on every address it has.
    pub async fn connect(&self, target: &Target) -> Result<SessionId, TransportError> {
        // An explicit connect clears the flag: the operator has asked for a connection,
        // so a later accidental drop is eligible for automatic reconnect again.
        self.intentional_disconnect
            .store(false, std::sync::atomic::Ordering::Release);

        let candidates = match target.address.to_socket_addrs() {
            Ok(candidates) => candidates,
            Err(err) => {
                self.set_state(ConnectionState::Failed {
                    message: err.to_string(),
                });
                return Err(err);
            }
        };

        let mut last_error = None;
        for address in candidates {
            self.set_state(ConnectionState::Connecting {
                address: target.address.to_string(),
            });

            match self.attempt(target, address).await {
                Ok(session_id) => return Ok(session_id),
                Err(err) => {
                    // A refusal is a decision, not a transport hiccup: trying the next
                    // address would only produce the same refusal from the same machine.
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

    /// One connection attempt against one resolved address.
    ///
    /// The *dialled* address travels on `Authenticate`, never `address` — the responder
    /// keys its pin on what the user typed, and a resolved socket address would key a
    /// different entry every time a hostname resolved differently.
    async fn attempt(
        &self,
        target: &Target,
        address: SocketAddr,
    ) -> Result<SessionId, TransportError> {
        // TLS still uses trust-on-first-use so a certificate renewal is not a
        // mismatch. The identity extracted from that certificate is compared below
        // against any pin recorded for this address.
        let (connector, observed) =
            ClientConnector::new(&self.identity, PinPolicy::TrustOnFirstUse)?;

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

        let ack = rc_transport::handshake::begin_handshake(
            &mut reader,
            &mut writer,
            self.descriptor.clone(),
            self.capabilities.clone(),
            target.address.clone(),
            target.unattended_password.clone(),
            rc_protocol::now_ms(),
        )
        .await?;

        let session_id = ack.session_id;

        if let Some(certificate) = observed.get() {
            let identity = rc_security::identity_fingerprint_of_certificate(&certificate.der)
                .map_err(|_| TransportError::FingerprintMismatch)?;
            if let Some(pinned) = target.pinned_identity
                && !pinned.ct_eq(&identity)
            {
                return Err(TransportError::FingerprintMismatch);
            }
            *self.peer_identity.lock().await = Some(identity);
        }

        // Set after `set_state`, which clears it for every state but `Connected`.
        self.set_state(ConnectionState::Connected {
            session_id: session_id.to_canonical_string(),
            address: target.address.to_string(),
            permissions: ack
                .permissions
                .iter()
                .map(|p| p.name().to_owned())
                .collect(),
            device_name: ack.descriptor.display_name.clone(),
        });
        self.set_granted(ack.permissions);
        *self.peer.lock().await = Some(ack.descriptor.clone());
        tracing::info!(
            granted = ?ack.permissions,
            machine = %ack.descriptor.display_name,
            "the other machine admitted this session"
        );

        // Any channels belonged to a previous connection.
        *self.files.lock().await = None;

        *self.active.lock().await = Some(ActiveConnection {
            connection,
            writer,
            reader,
            session_id,
            address,
            _connector: connector,
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

    /// Ask the agent to list its capturable displays.
    ///
    /// A fresh channel, used once and dropped: display enumeration happens before a
    /// stream exists, so there is nothing yet worth keeping open.
    ///
    /// # Errors
    /// The connection is gone, or the agent answered with something other than a
    /// listing.
    pub async fn video_list_displays(&self) -> Result<Vec<DisplayInfo>, TransportError> {
        let (mut writer, mut reader) = self.open_video_channel().await?;
        writer.send(&DesktopClientMessage::ListDisplays).await?;

        match Self::next_video_message(&mut reader).await? {
            DesktopAgentMessage::Displays(displays) => Ok(displays),
            DesktopAgentMessage::Error { message, .. } => {
                Err(TransportError::Closed { reason: message })
            }
            _ => Err(TransportError::Closed {
                reason: "the agent did not answer with a display list".to_owned(),
            }),
        }
    }

    /// Open the video channel and ask the agent to start streaming.
    ///
    /// The write half is kept on `self.video` so [`Self::video_stop_stream`] and
    /// [`Self::video_request_keyframe`] can reach it later, and so the caller can hand
    /// its own clone to the task that reads frames — that task asks for a keyframe on
    /// its own when the decoder falls behind, without a round trip back through here.
    ///
    /// # Errors
    /// The connection is gone, the agent refused, or it answered with something other
    /// than `StreamStarted`.
    pub async fn video_start_stream(
        &self,
        request: &DesktopClientMessage,
    ) -> Result<
        (
            DesktopAgentMessage,
            Arc<Mutex<ChannelWriter>>,
            ChannelReader,
        ),
        TransportError,
    > {
        let (mut writer, mut reader) = self.open_video_channel().await?;
        writer.send(request).await?;

        let reply = Self::next_video_message(&mut reader).await?;
        if let DesktopAgentMessage::Error { message, .. } = reply {
            *self.video.lock().await = None;
            return Err(TransportError::Closed { reason: message });
        }
        if !matches!(reply, DesktopAgentMessage::StreamStarted { .. }) {
            *self.video.lock().await = None;
            return Err(TransportError::Closed {
                reason: "the agent did not answer with StreamStarted".to_owned(),
            });
        }

        let writer = Arc::new(Mutex::new(writer));
        *self.video.lock().await = Some(Arc::clone(&writer));
        Ok((reply, writer, reader))
    }

    /// Tell the agent to stop streaming.
    ///
    /// The write half is left in place rather than dropped: the reader task ends the
    /// stream on its own once it sees `StreamStopped` or the channel close, and doing
    /// it there keeps one place responsible for tearing the channel down.
    ///
    /// # Errors
    /// The connection is gone, or nothing is streaming.
    pub async fn video_stop_stream(&self) -> Result<(), TransportError> {
        let writer = self.video_writer().await?;
        let mut guard = writer.lock().await;
        guard.send(&DesktopClientMessage::StopStream).await
    }

    /// Ask the agent for a fresh keyframe, e.g. after the decoder detects a gap.
    ///
    /// # Errors
    /// The connection is gone, or nothing is streaming.
    pub async fn video_request_keyframe(&self) -> Result<(), TransportError> {
        let writer = self.video_writer().await?;
        let mut guard = writer.lock().await;
        guard.send(&DesktopClientMessage::RequestKeyframe).await
    }

    /// The video channel's write half, if a stream is open.
    async fn video_writer(&self) -> Result<Arc<Mutex<ChannelWriter>>, TransportError> {
        self.video
            .lock()
            .await
            .as_ref()
            .map(Arc::clone)
            .ok_or(TransportError::Closed {
                reason: "no video stream is running".to_owned(),
            })
    }

    /// Open a fresh video channel on the active connection.
    async fn open_video_channel(&self) -> Result<(ChannelWriter, ChannelReader), TransportError> {
        let guard = self.active.lock().await;
        let active = guard.as_ref().ok_or(TransportError::Closed {
            reason: "not connected".to_owned(),
        })?;

        let channel =
            rc_transport::open_channel(&active.connection, rc_protocol::Channel::Video).await?;
        drop(guard);
        Ok(channel)
    }

    /// The next sequence number for an input event on this connection.
    #[must_use]
    pub fn next_input_seq(&self) -> u32 {
        self.input_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// How many input events have been given a sequence number so far.
    ///
    /// Compared against the host's applied watermark to say how far behind the host is.
    #[must_use]
    pub fn input_seq_issued(&self) -> u32 {
        self.input_seq.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Send one input event, opening the input channel first if this is the first
    /// event sent on this connection.
    ///
    /// # Errors
    /// The connection is gone, or the transport failed.
    pub async fn send_input(
        &self,
        event: &InputEvent,
        sink: InputSink,
    ) -> Result<(), TransportError> {
        self.ensure_input_channel(sink).await?;
        let mut slot = self.input.lock().await;
        let writer = slot.as_mut().ok_or(TransportError::Closed {
            reason: "not connected".to_owned(),
        })?;
        writer.send(event).await
    }

    /// Open the input channel if it is not already open, and start draining
    /// acknowledgements and display topology into `sink`.
    async fn ensure_input_channel(&self, sink: InputSink) -> Result<(), TransportError> {
        let mut slot = self.input.lock().await;
        if slot.is_some() {
            return Ok(());
        }

        let guard = self.active.lock().await;
        let active = guard.as_ref().ok_or(TransportError::Closed {
            reason: "not connected".to_owned(),
        })?;

        let (writer, reader) =
            rc_transport::open_channel(&active.connection, rc_protocol::Channel::Input).await?;
        drop(guard);

        spawn_input_reader(reader, sink);
        *slot = Some(writer);
        Ok(())
    }

    /// Read one message off the video channel, mapping a closed stream to an error.
    async fn next_video_message(
        reader: &mut ChannelReader,
    ) -> Result<DesktopAgentMessage, TransportError> {
        reader
            .next_message::<DesktopAgentMessage>()
            .await?
            .ok_or(TransportError::ConnectionLost {
                reason: "the agent closed the video channel".to_owned(),
            })
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
        *self.video.lock().await = None;
        *self.input.lock().await = None;

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
    pub async fn reconnect(&self, target: &Target) -> Result<SessionId, TransportError> {
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

            match self.connect(target).await {
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
    use rc_protocol::control::OsFamily;

    use rc_security::SystemClock;

    use super::*;

    fn manager() -> ConnectionManager {
        let identity = Arc::new(DeviceIdentity::generate("client", &SystemClock).unwrap());
        let host = rc_platform::HostInfo::detect();
        let descriptor = client_descriptor(&identity, &host);
        ConnectionManager::new(identity, descriptor, client_capabilities())
    }

    // -- targets -------------------------------------------------------------

    #[test]
    fn a_target_offers_no_password_unless_one_was_given() {
        // The common case. A password is something the user types for a machine that
        // asked for one, not a field that quietly carries an empty string.
        let target = Target::new("192.168.1.77".parse().unwrap());
        assert_eq!(target.unattended_password, None);
        assert_eq!(target.address.to_string(), "192.168.1.77:7443");
    }

    #[test]
    fn a_target_keeps_the_address_as_typed_rather_than_resolving_it() {
        // The dialled address is what the responder keys its pin on. Resolving it here
        // would key a different entry every time a hostname resolved differently.
        let target = Target::new("work-laptop.local:9000".parse().unwrap());
        assert_eq!(target.address.host, "work-laptop.local");
        assert_eq!(target.address.port, 9000);
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
    async fn an_outgoing_history_id_is_taken_exactly_once() {
        let manager = manager();
        manager.set_outgoing_history_id(7).await;
        assert_eq!(manager.take_outgoing_history_id().await, Some(7));
        assert_eq!(manager.take_outgoing_history_id().await, None);
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
        let _ = manager
            .connect(&Target::new("192.0.2.1".parse().unwrap()))
            .await;
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
    async fn connecting_to_a_name_that_does_not_resolve_says_so() {
        // "Something went wrong" is not an acceptable answer here. `.invalid` is
        // reserved by RFC 2606 precisely so it never resolves.
        let manager = manager();
        let result = manager
            .connect(&Target::new("nothing.invalid".parse().unwrap()))
            .await;

        assert!(result.is_err());
        match manager.state() {
            ConnectionState::Failed { message } => {
                assert!(
                    message.contains("nothing.invalid"),
                    "the message must name the address: {message}"
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
                permissions: Vec::new(),
                device_name: "pc".to_owned(),
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
            permissions: Vec::new(),
            device_name: "pc".to_owned(),
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
