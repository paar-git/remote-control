//! The application handshake that runs after TLS succeeds.
//!
//! # Why there is a second handshake at all
//!
//! TLS answers "which key is on the other end". It cannot answer "is that key still
//! trusted", because revocation happens in a database long after a certificate was
//! pinned. A connection that relied on the TLS result alone would only notice a
//! revocation if the certificate happened to change — which is to say, never.
//!
//! So the agent runs this exchange on the control channel and, before admitting the
//! peer, performs a **fresh** trust lookup against the authoritative store:
//!
//! ```text
//!   client                                    agent
//!     │──── Hello ─────────────────────────────►│
//!     │                                          ├─ observed fingerprint from TLS
//!     │                                          ├─ TrustDirectory::authorize()
//!     │                                          │    unknown?  → reject
//!     │                                          │    revoked?  → reject
//!     │                                          │    changed fingerprint? → reject
//!     │◄──── HelloAck ──── or ──── Reject ───────│
//! ```
//!
//! # The lookup is by observed fingerprint, never by claim
//!
//! [`Hello`] carries a device id, but that value is *asserted by the peer*. The
//! authorization decision uses the certificate fingerprint recorded by the TLS verifier
//! ([`crate::tls::ObservedPeer`]). The claimed id is compared against the record found
//! that way and a mismatch is a rejection — the claim is never what performs the lookup.
//!
//! # Rejections are uniform
//!
//! Unknown, revoked and fingerprint-changed all produce the identical
//! [`RejectReason::NotAuthorized`]. The precise cause is recorded locally through
//! [`RejectionCause`]. Distinguishing them on the wire would let anyone who can reach
//! the port enumerate which devices an agent knows.

use rc_protocol::control::{
    Capabilities, DeviceDescriptor, Hello, HelloAck, Opening, PeerRole, Reject, RejectReason,
};
use rc_protocol::frame::Channel;
use rc_protocol::{DeviceId, ProtocolVersion, SessionId};
use rc_security::{Fingerprint, Role};

use crate::channel::{ChannelReader, ChannelWriter};
use crate::error::{RejectionCause, Result, TransportError};

/// How long a peer has to complete the application handshake.
///
/// A connection that has completed TLS but sends nothing consumes agent resources. The
/// deadline is generous for a slow link and still bounded.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 15;

/// What the agent learned about an admitted peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    /// The trusted device's id, taken from the **stored record**, not the peer's claim.
    pub device_id: DeviceId,
    /// Name to show in the UI. Untrusted text; sanitise before rendering.
    pub display_name: String,
    /// Role recorded for this device.
    pub role: Role,
    /// Certificate fingerprint observed on this connection.
    pub certificate_fingerprint: Fingerprint,
    /// Version both peers agreed on.
    pub negotiated_version: ProtocolVersion,
    /// What the peer says it can do.
    pub capabilities: Capabilities,
    /// Identifier assigned to this session, for audit correlation.
    pub session_id: SessionId,
}

/// A trusted device as the authorization store sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRecord {
    /// Stored device id.
    pub device_id: DeviceId,
    /// Stored display name.
    pub display_name: String,
    /// Stored role.
    pub role: Role,
    /// Whether trust has been revoked.
    pub revoked: bool,
    /// The certificate fingerprint last recorded for this device.
    pub certificate_fingerprint: Fingerprint,
}

/// The authorization store, as the transport needs to see it.
///
/// Defined as a trait so the transport does not depend on `rc-storage`, and so the
/// handshake can be tested exhaustively — including revocation races — without a
/// database. The agent supplies the real implementation over its trust repository.
///
/// Implementations **must** read through to the authoritative store on every call.
/// Caching here would reintroduce exactly the staleness this layer exists to prevent.
#[async_trait::async_trait]
pub trait TrustDirectory: Send + Sync {
    /// Look a device up by the certificate fingerprint observed on the connection.
    ///
    /// Returns `None` when no device matches, and also when the store cannot be read —
    /// a directory that cannot answer must not admit anyone. Implementations log the
    /// underlying failure; it is deliberately not distinguishable here, because every
    /// caller would have to treat it as a refusal anyway.
    async fn find_by_certificate(&self, fingerprint: Fingerprint) -> Option<TrustRecord>;
}

/// Decide whether an observed peer may be admitted.
///
/// Separated from the message exchange so the decision can be tested directly, and so
/// there is exactly one place where admission is decided.
///
/// # Errors
/// Never returns `Err`; the decision is expressed as `Result<TrustRecord, RejectionCause>`.
pub async fn authorize(
    directory: &dyn TrustDirectory,
    observed: Fingerprint,
    claimed_device_id: DeviceId,
) -> std::result::Result<TrustRecord, RejectionCause> {
    // The lookup key is what TLS observed, never what the peer claimed.
    let Some(record) = directory.find_by_certificate(observed).await else {
        return Err(RejectionCause::UnknownDevice);
    };

    // Checked on every connection, against the live store. This is the revocation
    // re-check that the whole two-stage handshake exists to make possible.
    if record.revoked {
        return Err(RejectionCause::RevokedDevice(record.device_id));
    }

    // A peer holding a trusted certificate but claiming a different id is either
    // confused or probing. Either way it is not admitted under the claimed id.
    if record.device_id != claimed_device_id {
        return Err(RejectionCause::FingerprintChanged(record.device_id));
    }

    // Defensive: the record must be the one the fingerprint selected.
    if !record.certificate_fingerprint.ct_eq(&observed) {
        return Err(RejectionCause::FingerprintChanged(record.device_id));
    }

    Ok(record)
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
/// [`TransportError::NotTrusted`] when the peer is refused, after a `Reject` has been
/// sent. [`TransportError::HandshakeTimeout`] if the peer does not send a `Hello` in
/// time.
pub async fn accept_handshake(
    reader: &mut ChannelReader,
    writer: &mut ChannelWriter,
    directory: &dyn TrustDirectory,
    observed: Fingerprint,
    agent_descriptor: DeviceDescriptor,
    agent_capabilities: Capabilities,
    now_ms: i64,
) -> Result<AuthenticatedPeer> {
    // A pairing exchange arriving here means the caller routed the connection wrongly:
    // the agent decides which connections may pair, and a session handshake is not
    // that path.
    let Opening::Hello(hello) = read_opening(reader).await? else {
        send_reject(writer, RejectReason::BadRequest).await;
        return Err(TransportError::UnexpectedMessage { expected: "Hello" });
    };
    let hello = *hello;

    finish_accept(
        writer,
        directory,
        observed,
        hello,
        agent_descriptor,
        agent_capabilities,
        now_ms,
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
        .and_then(|message| {
            message.ok_or(TransportError::UnexpectedMessage {
                expected: "Hello or Pairing",
            })
        })
}

/// Authorize an already-read [`Hello`] and reply.
///
/// Split out from [`accept_handshake`] so an agent that has already consumed the
/// opening — to decide whether the connection is pairing or a session — can finish the
/// session path without reading a second one.
///
/// # Errors
/// As [`accept_handshake`].
pub async fn finish_accept(
    writer: &mut ChannelWriter,
    directory: &dyn TrustDirectory,
    observed: Fingerprint,
    hello: Hello,
    agent_descriptor: DeviceDescriptor,
    agent_capabilities: Capabilities,
    now_ms: i64,
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

    let record = match authorize(directory, observed, hello.descriptor.device_id).await {
        Ok(record) => record,
        Err(cause) => {
            // Precise locally, uniform on the wire.
            tracing::warn!(
                cause = cause.name(),
                observed = %observed,
                "refusing a connection"
            );
            send_reject(writer, RejectReason::NotAuthorized).await;
            return Err(cause.wire_error());
        }
    };

    let negotiated_version = negotiate(rc_protocol::CURRENT_VERSION, hello.version);
    let session_id = SessionId::generate();

    writer
        .send(&HelloAck {
            negotiated_version,
            descriptor: agent_descriptor,
            capabilities: agent_capabilities,
            sent_at_ms: now_ms,
            already_paired: true,
            session_id,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
        })
        .await?;

    tracing::info!(
        device_id = %record.device_id,
        session_id = %session_id,
        role = record.role.name(),
        version = %negotiated_version,
        "client authenticated"
    );

    Ok(AuthenticatedPeer {
        device_id: record.device_id,
        display_name: record.display_name,
        role: record.role,
        certificate_fingerprint: observed,
        negotiated_version,
        capabilities: hello.capabilities,
        session_id,
    })
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
    use std::collections::HashMap;
    use std::sync::Mutex;

    use rc_security::{DeviceIdentity, SystemClock};

    use super::*;

    /// An in-memory directory whose contents can change between calls, so a revocation
    /// landing mid-connection can be modelled.
    #[derive(Debug, Default)]
    struct FakeDirectory {
        records: Mutex<HashMap<String, TrustRecord>>,
    }

    impl FakeDirectory {
        fn with(record: TrustRecord) -> Self {
            let directory = Self::default();
            directory.insert(record);
            directory
        }

        fn insert(&self, record: TrustRecord) {
            self.records
                .lock()
                .unwrap()
                .insert(record.certificate_fingerprint.to_hex(), record);
        }

        fn revoke_all(&self) {
            for record in self.records.lock().unwrap().values_mut() {
                record.revoked = true;
            }
        }
    }

    #[async_trait::async_trait]
    impl TrustDirectory for FakeDirectory {
        async fn find_by_certificate(&self, fingerprint: Fingerprint) -> Option<TrustRecord> {
            self.records
                .lock()
                .unwrap()
                .get(&fingerprint.to_hex())
                .cloned()
        }
    }

    fn identity(name: &str) -> DeviceIdentity {
        DeviceIdentity::generate(name, &SystemClock).unwrap()
    }

    fn record_for(id: &DeviceIdentity, role: Role) -> TrustRecord {
        TrustRecord {
            device_id: id.device_id(),
            display_name: "Test Client".to_owned(),
            role,
            revoked: false,
            certificate_fingerprint: id.public().certificate_fingerprint,
        }
    }

    #[tokio::test]
    async fn a_trusted_device_is_admitted() {
        let client = identity("client");
        let directory = FakeDirectory::with(record_for(&client, Role::Operator));

        let admitted = authorize(
            &directory,
            client.public().certificate_fingerprint,
            client.device_id(),
        )
        .await
        .expect("a trusted device is admitted");

        assert_eq!(admitted.device_id, client.device_id());
        assert_eq!(admitted.role, Role::Operator);
    }

    #[tokio::test]
    async fn an_unknown_device_is_refused() {
        let stranger = identity("stranger");
        let directory = FakeDirectory::default();

        assert_eq!(
            authorize(
                &directory,
                stranger.public().certificate_fingerprint,
                stranger.device_id()
            )
            .await,
            Err(RejectionCause::UnknownDevice)
        );
    }

    #[tokio::test]
    async fn revocation_takes_effect_on_the_very_next_connection() {
        // The property Phase 3 must not break: revoking is immediate, not "immediate
        // once the certificate changes" and not "once a cache expires".
        let client = identity("client");
        let directory = FakeDirectory::with(record_for(&client, Role::Owner));
        let fingerprint = client.public().certificate_fingerprint;

        assert!(
            authorize(&directory, fingerprint, client.device_id())
                .await
                .is_ok()
        );

        directory.revoke_all();

        assert_eq!(
            authorize(&directory, fingerprint, client.device_id()).await,
            Err(RejectionCause::RevokedDevice(client.device_id())),
            "a revoked device must be refused on its next connection"
        );
    }

    #[tokio::test]
    async fn a_peer_claiming_someone_elses_device_id_is_refused() {
        // The certificate is trusted, but the claimed id does not match the record it
        // selected. Admitting under the claim would let a device impersonate another.
        let client = identity("client");
        let other = identity("other");
        let directory = FakeDirectory::with(record_for(&client, Role::Operator));

        let result = authorize(
            &directory,
            client.public().certificate_fingerprint,
            other.device_id(),
        )
        .await;
        assert!(
            matches!(result, Err(RejectionCause::FingerprintChanged(_))),
            "a mismatched claim must be refused, got {result:?}"
        );
    }

    #[tokio::test]
    async fn the_lookup_uses_the_observed_fingerprint_not_the_claim() {
        // An attacker holding an untrusted certificate cannot get in by naming a
        // trusted device's id.
        let trusted = identity("trusted");
        let attacker = identity("attacker");
        let directory = FakeDirectory::with(record_for(&trusted, Role::Owner));

        let result = authorize(
            &directory,
            attacker.public().certificate_fingerprint,
            trusted.device_id(),
        )
        .await;
        assert_eq!(
            result,
            Err(RejectionCause::UnknownDevice),
            "naming a trusted id must not admit an untrusted certificate"
        );
    }

    #[tokio::test]
    async fn a_record_whose_fingerprint_disagrees_is_refused() {
        // Defensive: a store that returns a record not matching the lookup key must not
        // be trusted to have meant it.
        let client = identity("client");
        let other = identity("other");
        let mut record = record_for(&client, Role::Owner);
        record.certificate_fingerprint = other.public().certificate_fingerprint;

        let directory = FakeDirectory::default();
        directory
            .records
            .lock()
            .unwrap()
            .insert(client.public().certificate_fingerprint.to_hex(), record);

        assert!(
            authorize(
                &directory,
                client.public().certificate_fingerprint,
                client.device_id()
            )
            .await
            .is_err(),
            "an inconsistent record must not admit a peer"
        );
    }

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

    #[tokio::test]
    async fn every_refusal_reports_the_same_thing_to_the_peer() {
        let client = identity("client");
        let stranger = identity("stranger");

        let revoked_dir = FakeDirectory::with({
            let mut r = record_for(&client, Role::Owner);
            r.revoked = true;
            r
        });
        let empty_dir = FakeDirectory::default();

        let revoked = authorize(
            &revoked_dir,
            client.public().certificate_fingerprint,
            client.device_id(),
        )
        .await
        .unwrap_err();
        let unknown = authorize(
            &empty_dir,
            stranger.public().certificate_fingerprint,
            stranger.device_id(),
        )
        .await
        .unwrap_err();

        assert_ne!(
            revoked.name(),
            unknown.name(),
            "audit must distinguish them"
        );
        assert_eq!(
            revoked.wire_error().to_string(),
            unknown.wire_error().to_string(),
            "the peer must not be able to tell them apart"
        );
    }
}
