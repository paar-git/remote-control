//! Pairing-exchange messages.
//!
//! Pairing is the only operation permitted over a connection whose client certificate
//! is not yet trusted. It establishes mutual trust between exactly one client and one
//! agent using a short-lived, single-use code that the operator moves out-of-band
//! (reading it off the server console or scanning a QR payload).
//!
//! The code is never sent over the wire in the clear. Both sides derive a proof from
//! the code **bound to both certificate fingerprints**, so an attacker who relays the
//! exchange between different endpoints cannot make the proofs match.

use serde::{Deserialize, Serialize};

use crate::control::DeviceDescriptor;

/// Number of characters in a pairing code, excluding separators.
pub const PAIRING_CODE_LEN: usize = 9;

/// Default lifetime of a pairing code, in seconds.
pub const PAIRING_CODE_TTL_SECS: u64 = 180;

/// Maximum number of failed pairing attempts before the code is destroyed.
pub const PAIRING_MAX_ATTEMPTS: u32 = 5;

/// Client's opening move in the pairing exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequest {
    /// Who is asking to be trusted.
    pub descriptor: DeviceDescriptor,
    /// Client-chosen random value, mixed into both proofs.
    pub client_nonce: [u8; 32],
}

/// Agent's challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairChallenge {
    /// Who the client is talking to.
    pub descriptor: DeviceDescriptor,
    /// Agent-chosen random value, mixed into both proofs.
    pub agent_nonce: [u8; 32],
    /// Seconds remaining before the active code expires.
    pub expires_in_secs: u64,
}

/// Client's proof that it knows the pairing code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairProof {
    /// MAC over the transcript, keyed by the pairing code.
    pub proof: [u8; 32],
    /// Signature by the client's identity key over the same transcript, binding the
    /// long-lived identity key to this exchange.
    pub identity_signature: Vec<u8>,
    /// Client's Ed25519 identity public key.
    pub identity_public_key: [u8; 32],
}

/// Agent's confirmation, proving it also knew the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairConfirm {
    /// MAC over the transcript with a distinct label, keyed by the pairing code.
    pub proof: [u8; 32],
    /// Signature by the agent's identity key over the transcript.
    pub identity_signature: Vec<u8>,
    /// Agent's Ed25519 identity public key.
    pub identity_public_key: [u8; 32],
}

/// Why a pairing attempt was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PairFailure {
    /// No pairing window is currently open on the agent.
    NotInPairingMode,
    /// The code has expired or was already consumed.
    CodeExpired,
    /// The proof did not verify. Indistinguishable from a wrong code by design.
    ProofRejected,
    /// Too many failed attempts; the code has been destroyed.
    TooManyAttempts,
    /// The submitted descriptor or key failed validation.
    BadRequest,
}

/// Any message on the pairing sub-protocol.
///
/// Externally tagged: the wire format (postcard) is not self-describing, so serde's
/// internally- and adjacently-tagged representations cannot be deserialized from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PairingMessage {
    /// Client → agent.
    Request(PairRequest),
    /// Agent → client.
    Challenge(PairChallenge),
    /// Client → agent.
    Proof(PairProof),
    /// Agent → client. Pairing succeeded and both sides have stored each other.
    Confirm(PairConfirm),
    /// Agent → client. Pairing failed; the connection will be closed.
    Failed(PairFailure),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_message_tag_is_stable() {
        let msg = PairingMessage::Failed(PairFailure::CodeExpired);
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"failed":"code_expired"}"#);
    }

    #[test]
    fn pairing_messages_survive_the_real_wire_format() {
        let msg = PairingMessage::Challenge(PairChallenge {
            descriptor: crate::test_support::sample_descriptor(),
            agent_nonce: [7u8; 32],
            expires_in_secs: 120,
        });
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let back: PairingMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn code_ttl_is_short() {
        const {
            assert!(
                PAIRING_CODE_TTL_SECS <= 300,
                "pairing window must stay short"
            );
        };
    }
}
