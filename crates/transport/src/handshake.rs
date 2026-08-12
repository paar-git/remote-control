//! The application handshake that runs after TLS succeeds.
//!
//! # Why there is a second handshake at all
//!
//! TLS answers "which key is on the other end". It cannot answer "may that key have a
//! session", because that is a decision the machine being controlled makes — and, in
//! this design, one its user makes by hand. So the agent runs an exchange on the
//! control channel and decides, per connection, whether to admit the peer:
//!
//! ```text
//!   client                                    agent
//!     │──── Hello ─────────────────────────────►│
//!     │                                          ├─ version and role checks
//!     │◄──── HelloAck ──── or ──── Reject ───────│
//!     │──── Authenticate ───────────────────────►│
//!     │                                          ├─ observed fingerprint from TLS
//!     │                                          ├─ admission decision
//!     │◄──── SessionAuthorization ────────────────│
//! ```
//!
//! [`HelloAck`] is sent to every peer that passes the version and role checks; it is
//! not an admission decision. The admission decision — whether this peer may actually
//! hold a session, and with what permissions — is made only after [`Authenticate`]
//! arrives, and is reported back as a [`SessionAuthorization`]. Splitting the two is
//! what lets the password (if any) travel inside the already-authenticated exchange
//! rather than inside [`Hello`], which a peer sends before it has seen who it is
//! talking to.
//!
//! # The decision is made from the observed fingerprint, never from a claim
//!
//! [`Hello`] carries a device id, but that value is *asserted by the peer*. Any
//! admission decision uses the certificate fingerprint recorded by the TLS verifier
//! ([`crate::tls::ObservedPeer`]) and carried on [`AuthenticatedPeer`]. The claimed id
//! is never what performs a lookup.
//!
//! # This crate does not decide; it carries the decision
//!
//! The rule for *what* to admit — a pinned peer, an unattended password, or a human
//! answering a prompt — lives in `rc-host-agent`'s `access` module, which this crate
//! must not depend on. [`finish_accept`] and [`accept_handshake`] instead take an
//! `authorize` callback supplied by the caller, and carry only [`HandshakeAuthorization`]
//! — the coarse two-way outcome (granted permissions, or a [`WireRefusal`] safe to tell
//! the peer) — across the boundary.
//!
//! # Refusals are coarse on the wire
//!
//! What the peer is told is exactly [`WireRefusal`]; the caller's finer-grained local
//! reason is never sent. See that type's documentation for why.

use std::future::Future;

use rc_protocol::control::{
    Authenticate, Capabilities, DeviceDescriptor, Hello, HelloAck, Opening, PeerRole, Reject,
    RejectReason, SessionAuthorization, WirePermissions, WireRefusal,
};
use rc_protocol::frame::Channel;
use rc_protocol::{DeviceId, ProtocolVersion, SessionId};
use rc_security::{Fingerprint, PermissionSet};

use crate::PeerAddress;
use crate::channel::{ChannelReader, ChannelWriter};
use crate::error::{Result, TransportError};

/// How long a peer has to complete the application handshake.
///
/// A connection that has completed TLS but sends nothing consumes agent resources. The
/// deadline is generous for a slow link and still bounded. It is applied to each leg of
/// the exchange separately (`Hello`, then `Authenticate`), rather than once for the
/// whole handshake, so a peer that is merely slow to decide on a password is not
/// penalised for time already spent completing an earlier leg.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 15;

/// What the agent learned about an admitted peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    /// Derived deterministically from the observed certificate fingerprint. There is no
    /// trusted-device store in this build to assign a stable id from, so this is the
    /// closest available analogue: the same peer, presenting the same certificate,
    /// always yields the same id, without anything being persisted about it.
    pub device_id: DeviceId,
    /// Name to show in the UI. Untrusted text; sanitise before rendering.
    pub display_name: String,
    /// Permissions this session was admitted with.
    pub permissions: PermissionSet,
    /// Certificate fingerprint observed on this connection.
    pub certificate_fingerprint: Fingerprint,
    /// Version both peers agreed on.
    pub negotiated_version: ProtocolVersion,
    /// What the peer says it can do.
    pub capabilities: Capabilities,
    /// Identifier assigned to this session, for audit correlation.
    pub session_id: SessionId,
}

/// What the caller of [`finish_accept`] decided about a candidate connection, once its
/// identity and any offered credential are known.
///
/// This is the entire boundary between this crate and whatever decides admission
/// (`rc-host-agent`'s `access` module, in production). It carries only what is safe and
/// necessary to cross that boundary: the granted [`PermissionSet`] or a [`WireRefusal`]
/// safe to disclose to the peer — never the caller's finer-grained local reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeAuthorization {
    /// Admit the peer, holding exactly these permissions for the whole session.
    Granted(PermissionSet),
    /// Refuse, for a reason safe to disclose to the peer.
    Refused(WireRefusal),
}

/// Whether two protocol versions can talk to each other.
///
/// Majors must match exactly. A newer minor is accepted — minors are additive by
/// contract — but a differing major is refused rather than approximated.
#[must_use]
pub const fn versions_compatible(ours: ProtocolVersion, theirs: ProtocolVersion) -> bool {
    ours.major == theirs.major
}

/// The version two peers settle on: the lower minor of a matching major.
#[must_use]
pub const fn negotiate(ours: ProtocolVersion, theirs: ProtocolVersion) -> ProtocolVersion {
    ProtocolVersion {
        major: ours.major,
        minor: if ours.minor < theirs.minor {
            ours.minor
        } else {
            theirs.minor
        },
    }
}

/// Run the agent's side of the handshake.
///
/// `observed` is the fingerprint the TLS verifier recorded for this connection. Passing
/// anything else — in particular anything from the peer's message — defeats the point.
///
/// `authorize` is called once, after `Authenticate` arrives, with the observed
/// fingerprint, the peer's self-reported machine name (from [`Hello`], untrusted) and
/// any unattended password it offered. It decides admission; this function only carries
/// the decision to the peer and, on success, builds the [`AuthenticatedPeer`] the caller
/// runs the session against.
///
/// # Errors
/// [`TransportError::SessionRefused`] when `authorize` refuses the peer, after a
/// [`SessionAuthorization::Refused`] has been sent. [`TransportError::HandshakeTimeout`]
/// if the peer does not complete its side in time.
pub async fn accept_handshake<F, Fut>(
    reader: &mut ChannelReader,
    writer: &mut ChannelWriter,
    observed: Fingerprint,
    agent_descriptor: DeviceDescriptor,
    agent_capabilities: Capabilities,
    now_ms: i64,
    authorize: F,
) -> Result<AuthenticatedPeer>
where
    F: FnOnce(Fingerprint, PeerAddress, String, Option<String>) -> Fut + Send,
    Fut: Future<Output = HandshakeAuthorization> + Send,
{
    let Opening::Hello(hello) = read_opening(reader).await? else {
        // `Opening` is `#[non_exhaustive]`: an opening from a newer peer that this build
        // does not know is refused, not approximated.
        send_reject(writer, RejectReason::BadRequest).await;
        return Err(TransportError::UnexpectedMessage { expected: "Hello" });
    };

    finish_accept(
        reader,
        writer,
        observed,
        *hello,
        agent_descriptor,
        agent_capabilities,
        now_ms,
        authorize,
    )
    .await
}

/// Read the opening message, bounded by the handshake deadline.
///
/// # Errors
/// [`TransportError::HandshakeTimeout`] if nothing arrives in time, or
/// [`TransportError::UnexpectedMessage`] if the stream ends first.
pub async fn read_opening(reader: &mut ChannelReader) -> Result<Opening> {
    let deadline = std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);

    tokio::time::timeout(deadline, reader.next_message())
        .await
        .map_err(|_| TransportError::HandshakeTimeout)?
        .and_then(|message| message.ok_or(TransportError::UnexpectedMessage { expected: "Hello" }))
}

/// Check an already-read [`Hello`], acknowledge it, then read [`Authenticate`] and
/// decide whether to admit the peer.
///
/// Split out from [`accept_handshake`] so an agent that has already consumed the
/// opening can finish without reading a second one.
///
/// # Errors
/// As [`accept_handshake`].
pub async fn finish_accept<F, Fut>(
    reader: &mut ChannelReader,
    writer: &mut ChannelWriter,
    observed: Fingerprint,
    hello: Hello,
    agent_descriptor: DeviceDescriptor,
    agent_capabilities: Capabilities,
    now_ms: i64,
    authorize: F,
) -> Result<AuthenticatedPeer>
where
    F: FnOnce(Fingerprint, PeerAddress, String, Option<String>) -> Fut + Send,
    Fut: Future<Output = HandshakeAuthorization> + Send,
{
    // A client that announces itself as an agent is not something to accommodate.
    if hello.role != PeerRole::Client {
        send_reject(writer, RejectReason::BadRequest).await;
        return Err(TransportError::UnexpectedMessage {
            expected: "Hello from a client",
        });
    }

    if !versions_compatible(rc_protocol::CURRENT_VERSION, hello.version) {
        tracing::warn!(
            ours = %rc_protocol::CURRENT_VERSION,
            theirs = %hello.version,
            "refusing an incompatible protocol version"
        );
        send_reject(writer, RejectReason::IncompatibleVersion).await;
        return Err(TransportError::IncompatibleVersion);
    }

    let negotiated_version = negotiate(rc_protocol::CURRENT_VERSION, hello.version);
    let session_id = SessionId::generate();

    // Sent to every peer that passes the checks above. This is not an admission
    // decision — see the module documentation — so it discloses nothing that a peer
    // completing TLS could not already have inferred.
    writer
        .send(&HelloAck {
            negotiated_version,
            descriptor: agent_descriptor.clone(),
            capabilities: agent_capabilities,
            sent_at_ms: now_ms,
            session_id,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
        })
        .await?;

    let authenticate = read_authenticate(reader).await?;
    let Ok(dialed_address) = authenticate.dialed_address.parse::<PeerAddress>() else {
        tracing::warn!("refusing a connection with an invalid dialed address");
        send_session_refusal(writer, WireRefusal::Rejected).await;
        return Err(TransportError::UnexpectedMessage {
            expected: "Authenticate with a valid dialed address",
        });
    };

    let outcome = authorize(
        observed,
        dialed_address,
        hello.descriptor.display_name.clone(),
        authenticate.unattended_password,
    )
    .await;

    match outcome {
        HandshakeAuthorization::Granted(permissions) => {
            writer
                .send(&SessionAuthorization::Granted {
                    permissions: to_wire_permissions(permissions),
                    machine_name: agent_descriptor.display_name,
                })
                .await?;

            tracing::info!(
                session_id = %session_id,
                version = %negotiated_version,
                "client authenticated"
            );

            Ok(AuthenticatedPeer {
                device_id: rc_security::derive_device_id(observed.as_bytes()),
                display_name: hello.descriptor.display_name,
                permissions,
                certificate_fingerprint: observed,
                negotiated_version,
                capabilities: hello.capabilities,
                session_id,
            })
        }
        HandshakeAuthorization::Refused(reason) => {
            tracing::warn!(
                observed = %observed,
                reason = ?reason,
                "refusing a connection after authentication"
            );
            send_session_refusal(writer, reason).await;
            Err(TransportError::SessionRefused { reason })
        }
    }
}

/// Read the [`Authenticate`] frame, bounded by its own handshake deadline.
///
/// # Errors
/// [`TransportError::HandshakeTimeout`] if nothing arrives in time, or
/// [`TransportError::UnexpectedMessage`] if the stream ends first or sends something
/// else.
async fn read_authenticate(reader: &mut ChannelReader) -> Result<Authenticate> {
    let deadline = std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);

    tokio::time::timeout(deadline, reader.next_message())
        .await
        .map_err(|_| TransportError::HandshakeTimeout)?
        .and_then(|message| {
            message.ok_or(TransportError::UnexpectedMessage {
                expected: "Authenticate",
            })
        })
}

/// Idle seconds after which the agent ends a session.
///
/// A session left open on an unattended desk is a session someone else can use. Thirty
/// minutes is long enough not to interrupt a working operator — the client sends
/// keep-alives while a stream is active — and short enough to matter.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u32 = 1800;

/// What the initiator learns once the responder has decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedSession {
    /// The responder's descriptor from the acknowledgement.
    pub descriptor: DeviceDescriptor,
    /// The responder's capabilities from the acknowledgement.
    pub capabilities: Capabilities,
    /// The permissions this session was granted. Fixed for the session's lifetime.
    pub permissions: PermissionSet,
    /// The responder's machine name, for the initiator's Recent list.
    pub machine_name: String,
    /// Identifier assigned to this session, for audit correlation.
    pub session_id: SessionId,
    /// Seconds of inactivity after which the responder will end the session, or `0`
    /// when no idle timeout applies.
    pub idle_timeout_secs: u32,
}

/// Run the client's side of the handshake.
///
/// `unattended_password` is sent inside [`Authenticate`], after [`HelloAck`] — never
/// inside [`Hello`] itself, which is sent before the peer has been seen at all.
///
/// # Errors
/// [`TransportError::SessionRefused`] if the agent refuses after authenticating,
/// [`TransportError::NotTrusted`] if it refuses before that,
/// [`TransportError::IncompatibleVersion`] on a version mismatch, or
/// [`TransportError::HandshakeTimeout`] if either leg does not complete in time.
pub async fn begin_handshake(
    reader: &mut ChannelReader,
    writer: &mut ChannelWriter,
    descriptor: DeviceDescriptor,
    capabilities: Capabilities,
    dialed_address: PeerAddress,
    unattended_password: Option<String>,
    now_ms: i64,
) -> Result<AdmittedSession> {
    writer
        .send(&Opening::Hello(Box::new(Hello {
            version: rc_protocol::CURRENT_VERSION,
            role: PeerRole::Client,
            descriptor,
            capabilities,
            sent_at_ms: now_ms,
        })))
        .await?;

    let deadline = std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    let frame = tokio::time::timeout(deadline, reader.next_frame())
        .await
        .map_err(|_| TransportError::HandshakeTimeout)?
        .and_then(|frame| {
            frame.ok_or(TransportError::UnexpectedMessage {
                expected: "HelloAck",
            })
        })?;

    // The agent replies with either an ack or a rejection; both arrive here.
    let ack = if let Ok(ack) = frame.decode_body::<HelloAck>()
        && versions_compatible(rc_protocol::CURRENT_VERSION, ack.negotiated_version)
    {
        ack
    } else if let Ok(reject) = frame.decode_body::<Reject>() {
        return Err(match reject.reason {
            RejectReason::IncompatibleVersion => TransportError::IncompatibleVersion,
            RejectReason::RateLimited => TransportError::Throttled {
                retry_after_secs: reject.retry_after_secs.unwrap_or(60).into(),
            },
            RejectReason::NotAuthorized => TransportError::NotTrusted,
            // `RejectReason` is `#[non_exhaustive]`. A reason from a newer agent that
            // this build does not recognise is treated as a plain refusal — not
            // retried, since we cannot know it is safe to.
            RejectReason::Unavailable | RejectReason::BadRequest | _ => TransportError::Closed {
                reason: "the agent refused the connection".to_owned(),
            },
        });
    } else {
        return Err(TransportError::UnexpectedMessage {
            expected: "HelloAck",
        });
    };

    writer
        .send(&Authenticate {
            dialed_address: dialed_address.to_string(),
            unattended_password,
        })
        .await?;

    let authorization: SessionAuthorization = tokio::time::timeout(deadline, reader.next_message())
        .await
        .map_err(|_| TransportError::HandshakeTimeout)?
        .and_then(|message| {
            message.ok_or(TransportError::UnexpectedMessage {
                expected: "SessionAuthorization",
            })
        })?;

    match authorization {
        SessionAuthorization::Granted {
            permissions,
            machine_name,
        } => {
            let permissions =
                from_wire_permissions(permissions).ok_or(TransportError::UnknownPermissions)?;
            Ok(AdmittedSession {
                descriptor: ack.descriptor,
                capabilities: ack.capabilities,
                permissions,
                machine_name,
                session_id: ack.session_id,
                idle_timeout_secs: ack.idle_timeout_secs,
            })
        }
        SessionAuthorization::Refused { reason } => Err(TransportError::SessionRefused { reason }),
        // `SessionAuthorization` is `#[non_exhaustive]`: a variant from a newer agent
        // that this build does not know is treated as a plain refusal, not guessed at.
        _ => Err(TransportError::UnexpectedMessage {
            expected: "a recognised SessionAuthorization",
        }),
    }
}

/// Convert a granted permission set to its wire representation.
///
/// A plain function rather than a `From` impl: neither [`PermissionSet`] nor
/// [`WirePermissions`] is local to this crate, so implementing a foreign trait between
/// two foreign types would violate the orphan rules. See [`WirePermissions`]'s
/// documentation for why the two types are kept separate at all.
const fn to_wire_permissions(permissions: PermissionSet) -> WirePermissions {
    WirePermissions(permissions.bits())
}

/// Convert a wire permission set back, refusing rather than masking any bit this build
/// does not recognise. See [`PermissionSet::from_bits`].
fn from_wire_permissions(permissions: WirePermissions) -> Option<PermissionSet> {
    PermissionSet::from_bits(permissions.0)
}

/// Send a rejection, ignoring a write failure — the connection is ending anyway.
async fn send_reject(writer: &mut ChannelWriter, reason: RejectReason) {
    let reject = Reject {
        reason,
        retry_after_secs: None,
    };
    if let Err(err) = writer.send(&reject).await {
        tracing::debug!(%err, "could not deliver a rejection");
    }
}

/// Tell the peer it was refused, ignoring a write failure — the connection is ending
/// anyway.
///
/// Only [`WireRefusal`] crosses this boundary; the caller's finer-grained local reason
/// stays local. See [`WireRefusal`] for why.
async fn send_session_refusal(writer: &mut ChannelWriter, reason: WireRefusal) {
    if let Err(err) = writer.send(&SessionAuthorization::Refused { reason }).await {
        tracing::debug!(%err, "could not deliver a session refusal");
    }
}

/// The control channel both sides use for this exchange.
pub const HANDSHAKE_CHANNEL: Channel = Channel::Control;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_negotiate_to_the_lower_minor() {
        let ours = ProtocolVersion { major: 1, minor: 4 };
        let newer = ProtocolVersion { major: 1, minor: 9 };
        let older = ProtocolVersion { major: 1, minor: 1 };

        assert_eq!(negotiate(ours, newer), ours);
        assert_eq!(negotiate(ours, older), older);
    }

    #[test]
    fn a_different_major_is_incompatible() {
        let ours = ProtocolVersion { major: 1, minor: 0 };
        assert!(!versions_compatible(
            ours,
            ProtocolVersion { major: 2, minor: 0 }
        ));
        assert!(!versions_compatible(
            ours,
            ProtocolVersion { major: 0, minor: 9 }
        ));
        assert!(versions_compatible(
            ours,
            ProtocolVersion { major: 1, minor: 7 }
        ));
    }

    #[test]
    fn wire_permissions_round_trip_through_known_bits() {
        let set = PermissionSet::ALL;
        assert_eq!(from_wire_permissions(to_wire_permissions(set)), Some(set));
    }

    #[test]
    fn an_unknown_permission_bit_is_refused_not_masked() {
        // A peer sending a bit this build does not know must not have it silently
        // dropped: the same wire value would then mean different things on either
        // side.
        assert_eq!(from_wire_permissions(WirePermissions(0b1000_0000)), None);
    }
}
