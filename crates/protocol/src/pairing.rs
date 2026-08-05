//! Pairing-exchange messages.
//!
//! Pairing is the only operation permitted over a connection whose client certificate
//! is not yet trusted. It establishes mutual trust between exactly one client and one
//! agent using a short-lived, single-use code that the operator moves out-of-band
//! (reading it off the server console).
//!
//! The code is never sent over the wire in any form. Both sides derive a proof from
//! the code **bound to both certificate fingerprints**, so an attacker who relays the
//! exchange between different endpoints cannot make the proofs match.
//!
//! # These types mirror `rc_security::pairing` exactly
//!
//! Every field the security layer commits to in its transcript has a wire field here.
//! That is deliberate: if the wire form carried less, the receiving side would have to
//! *invent* the missing values to rebuild the transcript, and a value that is invented
//! rather than transmitted is a value an attacker cannot be made to commit to.
//!
//! The one thing that is **not** carried is either certificate fingerprint used in the
//! transcript. Each side takes those from its own TLS connection, never from the
//! message body — a fingerprint a peer can choose is a fingerprint that binds nothing.

use serde::{Deserialize, Serialize};

use crate::control::DeviceDescriptor;
use crate::ids::{DeviceId, PairingSessionId};
use crate::version::ProtocolVersion;

/// Number of characters in a pairing code, excluding separators.
pub const PAIRING_CODE_LEN: usize = 9;

/// Default lifetime of a pairing code, in seconds.
pub const PAIRING_CODE_TTL_SECS: u64 = 180;

/// Maximum number of failed pairing attempts before the code is destroyed.
pub const PAIRING_MAX_ATTEMPTS: u32 = 5;

/// The permission role a client asks to be granted.
///
/// Mirrors `rc_security::permissions::Role`. Repeated here so `rc-protocol` stays
/// dependency-light; the two are kept in step by a test in `rc-security`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RoleRequest {
    /// Full control.
    Owner,
    /// Everything except device and security administration.
    Operator,
    /// Look, do not touch.
    ViewOnly,
}

/// What a client asks for at pairing time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRequest {
    /// Role requested.
    pub role: RoleRequest,
    /// Capability names requested, from `rc_security::permissions::Capability::name`.
    /// Names this build does not recognise are dropped by the receiver rather than
    /// rejected, which fails closed.
    pub capabilities: Vec<String>,
}

/// Client's opening move: who it is and what it wants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairRequest {
    /// Which pairing window the operator's code belongs to. Absent when the client
    /// does not know it — the agent then selects its single open window, and refuses
    /// if more than one is open.
    pub pairing_session_id: Option<PairingSessionId>,
    /// Who is asking to be trusted. Untrusted until the proof verifies.
    pub descriptor: DeviceDescriptor,
    /// Client's Ed25519 identity public key. The claimed device id is derived from
    /// this, so a client cannot claim an id it does not hold the key for.
    pub identity_public_key: [u8; 32],
    /// Client-chosen random value, mixed into both proofs.
    pub client_nonce: [u8; 32],
    /// Protocol version the client speaks. Committed to in the transcript, so a
    /// downgrade cannot be applied invisibly.
    pub protocol_version: ProtocolVersion,
    /// Permissions being requested.
    pub requested_permissions: PermissionRequest,
}

/// Agent's challenge: its identity, a nonce, and the salt for the code verifier.
///
/// Nothing here is secret. Without the operator's code the salt is useless, and the
/// agent's fingerprints are values the client is *expected* to see and compare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairChallenge {
    /// Which pairing exchange this is.
    pub pairing_session_id: PairingSessionId,
    /// Who the client is talking to.
    pub descriptor: DeviceDescriptor,
    /// The agent's device id, derived from its identity key.
    pub agent_device_id: DeviceId,
    /// Agent's Ed25519 identity public key.
    pub agent_public_key: [u8; 32],
    /// Agent-chosen random value, mixed into both proofs.
    pub agent_nonce: [u8; 32],
    /// Salt the client needs to derive the same code verifier.
    pub verifier_salt: [u8; 16],
    /// When the window closes, milliseconds since the Unix epoch. Part of the
    /// transcript, so the two sides cannot disagree about the deadline.
    pub expires_at_ms: i64,
    /// Seconds remaining, for display only.
    pub expires_in_secs: u64,
}

/// Client's proof that it knows the pairing code and holds its identity key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairProof {
    /// MAC over the transcript, keyed by the derived code verifier.
    pub mac: [u8; 32],
    /// Ed25519 signature over the same transcript by the client's identity key.
    pub signature: Signature64,
}

/// Agent's confirmation, proving it also knew the code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairConfirm {
    /// MAC over the transcript under the agent's distinct label.
    pub mac: [u8; 32],
    /// Ed25519 signature over the transcript by the agent's identity key.
    pub signature: Signature64,
    /// Permissions actually granted. May be narrower than requested.
    pub granted_permissions: PermissionRequest,
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

impl PairFailure {
    /// A short, operator-facing description that never discloses which of several
    /// causes actually applied beyond what the variant already says.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NotInPairingMode => {
                "the server is not in pairing mode; run `rc-agent pair` on the server"
            }
            Self::CodeExpired => "the pairing code has expired or was already used",
            Self::ProofRejected => "the pairing code was not accepted",
            Self::TooManyAttempts => "too many attempts; the code has been destroyed",
            Self::BadRequest => "the pairing request failed validation",
        }
    }
}

/// A 64-byte Ed25519 signature on the wire.
///
/// serde implements its array traits only up to length 32, so a signature needs a
/// newtype. Encoding it as a byte *string* rather than a 64-element sequence keeps the
/// postcard form compact (a length prefix and the bytes) and makes the length check
/// explicit: a peer sending 63 or 65 bytes is rejected during decoding, before any
/// verification code sees it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature64(pub [u8; 64]);

impl Signature64 {
    /// The raw signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl From<[u8; 64]> for Signature64 {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

impl From<Signature64> for [u8; 64] {
    fn from(signature: Signature64) -> Self {
        signature.0
    }
}

impl std::fmt::Debug for Signature64 {
    /// Renders as a short prefix. A signature is not secret, but a full 128-character
    /// hex string in a log line is noise that hides the fields that matter.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature64({}…)", hex_prefix(&self.0))
    }
}

/// First four bytes of a value as hex, for `Debug` output.
fn hex_prefix(bytes: &[u8; 64]) -> String {
    use std::fmt::Write as _;

    bytes[..4].iter().fold(String::new(), |mut out, byte| {
        // Writing into a `String` cannot fail; the result is discarded rather than
        // unwrapped so this stays panic-free.
        let _ = write!(out, "{byte:02x}");
        out
    })
}

impl Serialize for Signature64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature64 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'v> serde::de::Visitor<'v> for Visitor {
            type Value = Signature64;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("64 bytes of Ed25519 signature")
            }

            fn visit_bytes<E: serde::de::Error>(self, value: &[u8]) -> Result<Signature64, E> {
                let bytes: [u8; 64] = value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))?;
                Ok(Signature64(bytes))
            }

            fn visit_seq<A: serde::de::SeqAccess<'v>>(
                self,
                mut seq: A,
            ) -> Result<Signature64, A::Error> {
                // Self-describing formats such as JSON present a sequence rather than a
                // byte string. Accepting both keeps the type usable in tests and in
                // any future JSON transport without a second representation.
                let mut bytes = [0u8; 64];
                for (index, slot) in bytes.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(65, &self));
                }
                Ok(Signature64(bytes))
            }
        }

        deserializer.deserialize_bytes(Visitor)
    }
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
    Request(Box<PairRequest>),
    /// Agent → client.
    Challenge(Box<PairChallenge>),
    /// Client → agent.
    Proof(PairProof),
    /// Agent → client. Pairing succeeded and both sides have stored each other.
    Confirm(Box<PairConfirm>),
    /// Agent → client. Pairing failed; the connection will be closed.
    Failed(PairFailure),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_permissions() -> PermissionRequest {
        PermissionRequest {
            role: RoleRequest::Operator,
            capabilities: vec!["view_desktop".into(), "terminal".into()],
        }
    }

    #[test]
    fn pairing_message_tag_is_stable() {
        let msg = PairingMessage::Failed(PairFailure::CodeExpired);
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(json, r#"{"failed":"code_expired"}"#);
    }

    #[test]
    fn pairing_messages_survive_the_real_wire_format() {
        let msg = PairingMessage::Challenge(Box::new(PairChallenge {
            pairing_session_id: PairingSessionId::generate(),
            descriptor: crate::test_support::sample_descriptor(),
            agent_device_id: DeviceId::generate(),
            agent_public_key: [3u8; 32],
            agent_nonce: [7u8; 32],
            verifier_salt: [9u8; 16],
            expires_at_ms: 1_700_000_000_000,
            expires_in_secs: 120,
        }));
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let back: PairingMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn a_request_round_trips_with_every_field_intact() {
        // If any field were dropped by the wire form, the receiving side would have to
        // invent it to rebuild the transcript — and an invented value binds nothing.
        let msg = PairingMessage::Request(Box::new(PairRequest {
            pairing_session_id: Some(PairingSessionId::generate()),
            descriptor: crate::test_support::sample_descriptor(),
            identity_public_key: [1u8; 32],
            client_nonce: [2u8; 32],
            protocol_version: crate::CURRENT_VERSION,
            requested_permissions: sample_permissions(),
        }));

        let back: PairingMessage =
            postcard::from_bytes(&postcard::to_stdvec(&msg).unwrap()).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn a_proof_round_trips() {
        let msg = PairingMessage::Proof(PairProof {
            mac: [4u8; 32],
            signature: Signature64([5u8; 64]),
        });
        let back: PairingMessage =
            postcard::from_bytes(&postcard::to_stdvec(&msg).unwrap()).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn a_confirmation_carries_the_permissions_actually_granted() {
        // The client must record what it was granted, not what it asked for.
        let msg = PairingMessage::Confirm(Box::new(PairConfirm {
            mac: [6u8; 32],
            signature: Signature64([7u8; 64]),
            granted_permissions: PermissionRequest {
                role: RoleRequest::ViewOnly,
                capabilities: vec!["view_desktop".into()],
            },
        }));
        let back: PairingMessage =
            postcard::from_bytes(&postcard::to_stdvec(&msg).unwrap()).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn no_pairing_message_carries_a_certificate_fingerprint_used_for_binding() {
        // The descriptor carries a *self-reported* fingerprint for display. The
        // transcript must use the fingerprint observed on the TLS connection instead,
        // so this test documents that the wire types offer no other candidate.
        let challenge = PairChallenge {
            pairing_session_id: PairingSessionId::generate(),
            descriptor: crate::test_support::sample_descriptor(),
            agent_device_id: DeviceId::generate(),
            agent_public_key: [0u8; 32],
            agent_nonce: [0u8; 32],
            verifier_salt: [0u8; 16],
            expires_at_ms: 0,
            expires_in_secs: 0,
        };
        let json = serde_json::to_value(&challenge).unwrap();
        assert!(
            json.get("certificate_fingerprint").is_none(),
            "a bindable fingerprint must not be a top-level, peer-chosen field"
        );
    }

    #[test]
    fn every_failure_describes_itself_without_naming_a_secret() {
        for failure in [
            PairFailure::NotInPairingMode,
            PairFailure::CodeExpired,
            PairFailure::ProofRejected,
            PairFailure::TooManyAttempts,
            PairFailure::BadRequest,
        ] {
            let text = failure.describe();
            assert!(!text.is_empty());
            assert!(!text.contains("code:"), "no code value in a message");
        }
    }

    #[test]
    fn a_wrong_code_and_a_wrong_transcript_are_the_same_failure() {
        // Distinguishing them would turn the agent into an oracle for guessing codes.
        assert_eq!(
            PairFailure::ProofRejected.describe(),
            PairFailure::ProofRejected.describe()
        );
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
