//! Typed protocol errors.
//!
//! Every fallible operation in this crate returns [`ProtocolError`]. The variants are
//! deliberately coarse-grained and free of attacker-controlled payload echoes so that
//! they are safe to log and safe to send to a peer.

use crate::version::ProtocolVersion;

/// Errors produced while encoding, decoding or validating protocol data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// A frame header declared a body larger than the negotiated limit.
    #[error("frame body of {actual} bytes exceeds the {limit} byte limit")]
    FrameTooLarge {
        /// Declared body length.
        actual: usize,
        /// Maximum permitted body length.
        limit: usize,
    },

    /// A frame header declared a zero-length body, which is never valid.
    #[error("frame body must not be empty")]
    EmptyFrame,

    /// The magic prefix did not match, so this is not one of our frames.
    #[error("bad frame magic")]
    BadMagic,

    /// The frame's channel byte did not map to a known channel.
    #[error("unknown channel id {0}")]
    UnknownChannel(u8),

    /// Body bytes could not be deserialized into the expected message type.
    #[error("malformed message body")]
    MalformedBody,

    /// Serialization failed. This indicates a bug rather than hostile input.
    #[error("failed to encode message")]
    Encode,

    /// The peer speaks a protocol version we cannot interoperate with.
    #[error("incompatible protocol version: peer speaks {peer}, we speak {ours}")]
    IncompatibleVersion {
        /// Version advertised by the peer.
        peer: ProtocolVersion,
        /// Version advertised by this build.
        ours: ProtocolVersion,
    },

    /// A field failed validation (empty, out of range, or otherwise unusable).
    #[error("invalid value for field `{field}`: {reason}")]
    InvalidField {
        /// Name of the offending field.
        field: &'static str,
        /// Why it was rejected. Must not contain attacker-controlled data.
        reason: &'static str,
    },

    /// An identifier could not be parsed from its textual form.
    #[error("malformed identifier")]
    MalformedId,
}

/// Convenience result alias for protocol operations.
pub type Result<T> = std::result::Result<T, ProtocolError>;
