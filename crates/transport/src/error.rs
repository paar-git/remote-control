//! Typed transport errors.
//!
//! As with [`rc_security::SecurityError`], every message here is written on the
//! assumption that it may be shown to an operator and written to a log. None carries a
//! key, a token, a pairing code or a proof, and none echoes attacker-supplied input.
//!
//! Authentication failures are deliberately coarse. A peer that is refused learns that
//! it was refused, not which check rejected it — the distinction between "unknown
//! device", "revoked device" and "changed fingerprint" is recorded locally in the audit
//! trail and never sent across the wire.

use rc_protocol::DeviceId;

/// Result alias for transport operations.
pub type Result<T> = std::result::Result<T, TransportError>;

/// Errors raised while establishing or running a connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The listener could not bind its socket.
    #[error("could not bind the listener: {reason}")]
    Bind {
        /// What went wrong.
        reason: String,
    },

    /// The endpoint could not be configured.
    #[error("could not configure the endpoint: {reason}")]
    Configuration {
        /// What went wrong.
        reason: String,
    },

    /// A connection attempt failed before the handshake completed.
    #[error("could not connect to the agent: {reason}")]
    Connect {
        /// What went wrong.
        reason: String,
    },

    /// The peer presented a certificate that does not match the pinned fingerprint.
    ///
    /// This is the loud one. It is never retried automatically and never silently
    /// re-trusted: it means either a misconfiguration or an active attacker.
    #[error(
        "the device presented a different identity than the one saved for it; \
         refusing to connect"
    )]
    FingerprintMismatch,

    /// The agent refused to admit this device.
    ///
    /// This is what every refused peer sees, and what the agent's audit trail records
    /// for a refused connection, so the wording states the outcome and nothing about
    /// which check produced it.
    #[error("the agent did not admit this device")]
    NotTrusted,

    /// The peer's trust was revoked.
    #[error("access for this device has been revoked")]
    Revoked,

    /// The peer failed to prove it holds the identity key behind its certificate.
    #[error("the device could not prove its identity")]
    IdentityProofRejected,

    /// The peer speaks a protocol version this build cannot talk to.
    #[error("the other device speaks an incompatible protocol version")]
    IncompatibleVersion,

    /// The handshake did not complete within its deadline.
    #[error("the handshake timed out")]
    HandshakeTimeout,

    /// The peer closed the connection.
    #[error("the connection was closed: {reason}")]
    Closed {
        /// Why, in terms safe to display.
        reason: String,
    },

    /// The connection was lost.
    #[error("the connection was lost: {reason}")]
    ConnectionLost {
        /// What went wrong.
        reason: String,
    },

    /// A stream could not be opened or accepted.
    #[error("could not open a {channel} stream: {reason}")]
    Stream {
        /// Which channel.
        channel: &'static str,
        /// What went wrong.
        reason: String,
    },

    /// A frame could not be encoded, decoded, or exceeded its channel limit.
    #[error("protocol error: {0}")]
    Protocol(#[from] rc_protocol::ProtocolError),

    /// A security operation failed.
    #[error("security error: {0}")]
    Security(#[from] rc_security::SecurityError),

    /// The peer sent a message that is not valid at this point in the exchange.
    #[error("the other device sent an unexpected {expected} message")]
    UnexpectedMessage {
        /// What was expected instead.
        expected: &'static str,
    },

    /// A session token was missing, malformed, expired or already used.
    #[error("the session is no longer valid; authenticate again")]
    SessionInvalid,

    /// This build has no way to decide whether an incoming peer may be admitted.
    ///
    /// The pairing protocol has been removed and the accept path that replaces it is
    /// not present yet, so the agent has nothing to authorise against. It refuses every
    /// session rather than admitting a peer it cannot authorise: a build with no
    /// authorisation step must not behave as though every peer passed one.
    #[error("this build cannot authorise a session; the agent has no way to admit a peer")]
    AuthorizationUnavailable,

    /// Too many connections or attempts from this source.
    #[error("too many attempts; try again in {retry_after_secs} seconds")]
    Throttled {
        /// How long to wait.
        retry_after_secs: u64,
    },

    /// The text the user typed is not an address this transport can dial.
    ///
    /// Distinct from [`Self::UnresolvableAddress`] because the two need different
    /// remedies: this one means "you typed it wrong", the other means "that machine
    /// could not be found". Collapsing them would leave the operator guessing which.
    #[error("`{0}` is not a valid address")]
    InvalidAddress(String),

    /// The address is well formed but names nothing reachable.
    #[error("`{address}` could not be found: {reason}")]
    UnresolvableAddress {
        /// The address as the user would recognise it.
        address: String,
        /// What the resolver said.
        reason: String,
    },

    /// An I/O failure not covered by the cases above.
    #[error("transport I/O failed: {reason}")]
    Io {
        /// What went wrong.
        reason: String,
    },
}

impl TransportError {
    /// Whether a client should retry automatically after this error.
    ///
    /// The rule is that anything which could indicate an attack, or which cannot
    /// succeed without a human doing something, must **not** be retried. Reconnecting
    /// into a fingerprint mismatch would turn a loud, visible failure into a quiet loop
    /// that an operator never sees.
    #[must_use]
    pub const fn permits_auto_reconnect(&self) -> bool {
        match self {
            // Transient: the network went away, or the agent restarted.
            Self::ConnectionLost { .. }
            | Self::Connect { .. }
            | Self::HandshakeTimeout
            | Self::Io { .. } => true,

            // Requires a human, or indicates an attack. Never retried.
            //
            // Both address errors sit here rather than with the transient cases. A
            // mistyped address fails identically however many times it is tried, and a
            // name that does not resolve needs the address corrected or DNS fixed —
            // neither happens by waiting. A machine that is merely switched off
            // resolves fine and fails at `Connect`, which does retry.
            Self::InvalidAddress(_)
            | Self::UnresolvableAddress { .. }
            | Self::FingerprintMismatch
            | Self::NotTrusted
            | Self::Revoked
            | Self::IdentityProofRejected
            | Self::IncompatibleVersion
            | Self::SessionInvalid
            | Self::AuthorizationUnavailable
            | Self::Throttled { .. }
            | Self::Bind { .. }
            | Self::Configuration { .. }
            | Self::Closed { .. }
            | Self::Stream { .. }
            | Self::Protocol(_)
            | Self::Security(_)
            | Self::UnexpectedMessage { .. } => false,
        }
    }

    /// Whether this error indicates a security-relevant rejection worth auditing.
    #[must_use]
    pub const fn is_security_rejection(&self) -> bool {
        matches!(
            self,
            Self::FingerprintMismatch
                | Self::NotTrusted
                | Self::Revoked
                | Self::IdentityProofRejected
                | Self::SessionInvalid
                | Self::AuthorizationUnavailable
        )
    }
}

/// Why a peer was refused, for the **local** audit trail only.
///
/// The wire carries only a coarse rejection. This type exists so the agent can record
/// precisely what happened without telling the peer, which would otherwise turn the
/// handshake into an oracle for probing which device ids are known.
///
/// **Nothing produces these variants in this build.** The trust lookup that used to was
/// deleted with the pairing protocol, and the handshake currently refuses every peer
/// with [`TransportError::AuthorizationUnavailable`] instead. The type is kept, tested
/// and exported for the accept path, which will produce it again; it is not a live
/// decision path today.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionCause {
    /// No trusted-device record matched the presented identity.
    UnknownDevice,
    /// A record matched but has been revoked.
    RevokedDevice(DeviceId),
    /// A record matched but the certificate fingerprint changed unexpectedly.
    FingerprintChanged(DeviceId),
    /// The peer could not prove possession of its identity key.
    ProofRejected,
    /// The peer offered an unusable protocol version.
    VersionMismatch,
}

impl RejectionCause {
    /// Stable name for the audit record.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::UnknownDevice => "unknown_device",
            Self::RevokedDevice(_) => "revoked_device",
            Self::FingerprintChanged(_) => "fingerprint_changed",
            Self::ProofRejected => "proof_rejected",
            Self::VersionMismatch => "version_mismatch",
        }
    }

    /// The single coarse error every rejected peer receives.
    ///
    /// Deliberately lossy: an unknown device and a revoked device are indistinguishable
    /// to the peer, so the handshake cannot be used to enumerate which devices the agent
    /// knows about.
    #[must_use]
    pub const fn wire_error(&self) -> TransportError {
        TransportError::NotTrusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_shaped_failures_are_never_retried() {
        // The whole point of a fingerprint mismatch is that a human sees it.
        for err in [
            TransportError::FingerprintMismatch,
            TransportError::NotTrusted,
            TransportError::Revoked,
            TransportError::IdentityProofRejected,
            TransportError::SessionInvalid,
        ] {
            assert!(
                !err.permits_auto_reconnect(),
                "{err:?} must not reconnect automatically"
            );
            assert!(err.is_security_rejection(), "{err:?} must be auditable");
        }
    }

    #[test]
    fn transient_failures_are_retried() {
        for err in [
            TransportError::ConnectionLost {
                reason: "timeout".to_owned(),
            },
            TransportError::HandshakeTimeout,
            TransportError::Io {
                reason: "reset".to_owned(),
            },
        ] {
            assert!(err.permits_auto_reconnect(), "{err:?} should reconnect");
            assert!(!err.is_security_rejection());
        }
    }

    #[test]
    fn every_rejection_cause_yields_the_same_wire_error() {
        // Account-enumeration protection at the transport layer: the peer must not be
        // able to tell "I was never paired" from "I was revoked".
        let device = DeviceId::generate();
        let causes = [
            RejectionCause::UnknownDevice,
            RejectionCause::RevokedDevice(device),
            RejectionCause::FingerprintChanged(device),
            RejectionCause::ProofRejected,
        ];

        let rendered: Vec<String> = causes.iter().map(|c| c.wire_error().to_string()).collect();
        assert!(
            rendered.windows(2).all(|w| w[0] == w[1]),
            "rejections must be indistinguishable on the wire, got {rendered:?}"
        );
    }

    #[test]
    fn rejection_causes_have_distinct_audit_names() {
        let device = DeviceId::generate();
        let names = [
            RejectionCause::UnknownDevice.name(),
            RejectionCause::RevokedDevice(device).name(),
            RejectionCause::FingerprintChanged(device).name(),
            RejectionCause::ProofRejected.name(),
            RejectionCause::VersionMismatch.name(),
        ];
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len(), "audit names must be distinct");
    }

    #[test]
    fn no_error_message_leaks_internal_detail() {
        // Messages reach the operator. They must not carry paths, keys or raw peer input.
        let messages = [
            TransportError::FingerprintMismatch.to_string(),
            TransportError::NotTrusted.to_string(),
            TransportError::Revoked.to_string(),
            TransportError::SessionInvalid.to_string(),
        ];
        for message in messages {
            assert!(!message.contains("C:\\"), "{message}");
            assert!(!message.is_empty());
        }
    }
}
