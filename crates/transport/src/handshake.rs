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
//!     │                                          ├─ observed fingerprint from TLS
//!     │                                          ├─ admission decision
//!     │◄──── HelloAck ──── or ──── Reject ───────│
//! ```
//!
//! # This build admits nobody
//!
//! The pairing protocol that used to make the admission decision has been deleted, and
//! the accept path that replaces it is not here yet. There is therefore no way to
//! authorise a peer, and [`accept_handshake`] refuses every connection with
//! [`TransportError::AuthorizationUnavailable`] after the version check.
//!
//! This is deliberate and it is the only safe reading of "no authorisation step
//! exists": a build that admitted whoever completed TLS would be a remote-control agent
//! with no authorisation at all. When the accept path arrives, it replaces the refusal
//! in [`refuse_unauthorized`] and nothing else in this exchange changes.
//!
//! # The decision is made from the observed fingerprint, never from a claim
//!
//! [`Hello`] carries a device id, but that value is *asserted by the peer*. Any
//! admission decision uses the certificate fingerprint recorded by the TLS verifier
//! ([`crate::tls::ObservedPeer`]) and carried on [`AuthenticatedPeer`]. The claimed id
//! is never what performs a lookup.
//!
//! # Rejections are uniform
//!
//! Every refusal produces the identical [`RejectReason::NotAuthorized`] on the wire.
//! The precise cause is recorded locally. Distinguishing them would let anyone who can
//! reach the port learn something about the agent's state.

use rc_protocol::control::{
    Capabilities, DeviceDescriptor, Hello, HelloAck, Opening, PeerRole, Reject, RejectReason,
};

use rc_protocol::frame::Channel;
use rc_protocol::{DeviceId, ProtocolVersion, SessionId};
use rc_security::{Fingerprint, PermissionSet};

use crate::channel::{ChannelReader, ChannelWriter};
use crate::error::{Result, TransportError};

/// How long a peer has to complete the application handshake.
///
/// A connection that has completed TLS but sends nothing consumes agent resources. The
/// deadline is generous for a slow link and still bounded.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 15;

/// What the agent learned about an admitted peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    /// The device id this session runs under. Never taken from the peer's claim.
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
/// # Errors
/// [`TransportError::AuthorizationUnavailable`] for every peer this build cannot
/// authorise, after a `Reject` has been sent; see the module documentation.
/// [`TransportError::HandshakeTimeout`] if the peer does not send a `Hello` in time.
pub async fn accept_handshake(
    reader: &mut ChannelReader,
    writer: &mut ChannelWriter,
    observed: Fingerprint,
) -> Result<AuthenticatedPeer> {
    let Opening::Hello(hello) = read_opening(reader).await? else {
        // `Opening` is `#[non_exhaustive]`: an opening from a newer peer that this build
        // does not know is refused, not approximated.
        send_reject(writer, RejectReason::BadRequest).await;
        return Err(TransportError::UnexpectedMessage { expected: "Hello" });
    };

    finish_accept(writer, observed, *hello).await
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

/// Check an already-read [`Hello`] and decide whether to admit the peer.
///
/// Split out from [`accept_handshake`] so an agent that has already consumed the
/// opening can finish without reading a second one.
///
/// # Errors
/// As [`accept_handshake`].
pub async fn finish_accept(
    writer: &mut ChannelWriter,
    observed: Fingerprint,
    hello: Hello,
) -> Result<AuthenticatedPeer> {
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

    Err(refuse_unauthorized(writer, observed).await)
}

/// The admission decision, which in this build admits nobody.
///
/// This function *is* the agent's authorisation step. The pairing protocol that used to
/// perform it has been deleted and the accept path that replaces it is not here yet, so
/// there is nothing to authorise against and every peer is refused. Returning an
/// `AuthenticatedPeer` from here without a decision having been made would give the
/// agent no authorisation at all, which is the one outcome this build must not have.
///
/// The peer is told only [`RejectReason::NotAuthorized`]; the reason it was refused is
/// recorded locally.
async fn refuse_unauthorized(writer: &mut ChannelWriter, observed: Fingerprint) -> TransportError {
    tracing::warn!(
        observed = %observed,
        "refusing a connection: this build has no way to authorise a session"
    );
    send_reject(writer, RejectReason::NotAuthorized).await;
    TransportError::AuthorizationUnavailable
}

/// Idle seconds after which the agent ends a session.
///
/// A session left open on an unattended desk is a session someone else can use. Thirty
/// minutes is long enough not to interrupt a working operator — the client sends
/// keep-alives while a stream is active — and short enough to matter.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u32 = 1800;

/// Run the client's side of the handshake.
///
/// # Errors
/// [`TransportError::NotTrusted`] if the agent refuses, or
/// [`TransportError::IncompatibleVersion`] on a version mismatch.
pub async fn begin_handshake(
    reader: &mut ChannelReader,
    writer: &mut ChannelWriter,
    descriptor: DeviceDescriptor,
    capabilities: Capabilities,
    now_ms: i64,
) -> Result<HelloAck> {
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
    if let Ok(ack) = frame.decode_body::<HelloAck>()
        && versions_compatible(rc_protocol::CURRENT_VERSION, ack.negotiated_version)
    {
        return Ok(ack);
    }

    if let Ok(reject) = frame.decode_body::<Reject>() {
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
    }

    Err(TransportError::UnexpectedMessage {
        expected: "HelloAck",
    })
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
}
