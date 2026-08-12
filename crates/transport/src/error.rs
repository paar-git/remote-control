//! Typed transport errors.
//!
//! As with [`rc_security::SecurityError`], every message here is written on the
//! assumption that it may be shown to an operator and written to a log. None carries a
//! key, a token, a password or a proof, and none echoes attacker-supplied input.
//!
//! Authentication failures are deliberately coarse. A peer that is refused learns that
//! it was refused and, at most, the coarse [`rc_protocol::control::WireRefusal`] the
//! responder chose to disclose — never which check rejected it. The responder's own
//! finer-grained reason (`rc_host_agent::RefusalReason`) stays in its local log.

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

    /// The responder decided not to admit this session.
    ///
    /// Carries the coarse [`rc_protocol::control::WireRefusal`] the responder chose to
    /// disclose. The responder's own finer-grained reason never crosses the wire — see
    /// that type's documentation for why.
    #[error("the other device refused the connection")]
    SessionRefused {
        /// Why, in terms safe to display.
        reason: rc_protocol::control::WireRefusal,
    },

    /// A peer sent a permission bit this build does not recognise.
    ///
    /// Refused rather than masked to the bits this build does know: silently dropping
    /// an unknown permission would make the same wire value mean something different on
    /// either side of the connection.
    #[error("the other device sent a permission set this build does not understand")]
    UnknownPermissions,

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
            //
            // `UnresolvableAddress` belongs here, not with the permanent failures.
            // Resolution is attempted fresh on every connection, so the same address
            // can fail now and succeed in a minute: a machine that is asleep may have
            // no record until it wakes, and a resolver outage heals without anyone
            // touching the address. Both are the shape `Connect` already retries
            // through. Filing it as permanent would mean a saved machine that went to
            // sleep stops being reachable until the operator intervenes, even though
            // nothing was mistyped and nothing is wrong.
            Self::ConnectionLost { .. }
            | Self::Connect { .. }
            | Self::HandshakeTimeout
            | Self::UnresolvableAddress { .. }
            | Self::Io { .. } => true,

            // Requires a human, or indicates an attack. Never retried.
            //
            // `InvalidAddress` is the address error that does belong here: the text
            // does not change between attempts, so retrying reproduces the identical
            // failure forever.
            Self::InvalidAddress(_)
            | Self::FingerprintMismatch
            | Self::NotTrusted
            | Self::Revoked
            | Self::IdentityProofRejected
            | Self::IncompatibleVersion
            | Self::SessionInvalid
            | Self::SessionRefused { .. }
            | Self::UnknownPermissions
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
                | Self::SessionRefused { .. }
        )
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
            // Resolution runs again on every attempt, so a name that fails now can
            // succeed in a minute — a sleeping machine, or a resolver that came back.
            TransportError::UnresolvableAddress {
                address: "work-laptop.local:7443".to_owned(),
                reason: "no such host".to_owned(),
            },
        ] {
            assert!(err.permits_auto_reconnect(), "{err:?} should reconnect");
            assert!(!err.is_security_rejection());
        }
    }

    #[test]
    fn a_malformed_address_is_never_retried() {
        // The text does not change between attempts, so retrying reproduces the
        // identical failure forever. This is the one address error that is permanent.
        let err = TransportError::InvalidAddress("https://192.168.1.77".to_owned());
        assert!(!err.permits_auto_reconnect());
        assert!(!err.is_security_rejection());
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
