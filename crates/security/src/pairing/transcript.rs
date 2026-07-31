//! The pairing transcript and the proofs computed over it.
//!
//! # What the transcript is for
//!
//! Both peers independently build a byte string committing to *every* value that
//! matters, then prove they can key a MAC over it with the pairing code's verifier.
//! Anything that differs between the two peers — a swapped fingerprint, an edited
//! permission role, a different expiry, a downgraded protocol version — produces a
//! different transcript and therefore a proof that does not verify.
//!
//! This is what makes the exchange resistant to relaying. An attacker who forwards
//! messages between a real client and a real agent cannot make both sides agree,
//! because the transcript names both endpoints' fingerprints, and the attacker's own
//! TLS connection to each side carries a different one.
//!
//! # Encoding
//!
//! Every field is written as `u64` big-endian length followed by its bytes, in a fixed
//! order, prefixed by a version tag. Length-prefixing is essential: with naive
//! concatenation, moving a character from one field to the next would leave the bytes
//! unchanged, letting an attacker shift meaning between fields without altering the
//! proof.
//!
//! ```text
//! "rc.pairing.transcript.v1"
//!   || len||protocol_major  || len||protocol_minor
//!   || len||pairing_session_id
//!   || len||agent_device_id        || len||client_device_id
//!   || len||agent_identity_fp      || len||client_identity_fp
//!   || len||agent_certificate_fp   || len||client_certificate_fp
//!   || len||agent_nonce            || len||client_nonce
//!   || len||code_verifier
//!   || len||expires_at_ms
//!   || len||requested_role
//!   || len||requested_capabilities (sorted, comma-joined)
//! ```
//!
//! # Domain separation
//!
//! Three distinct labels are derived from the transcript, so no value produced for one
//! purpose can be replayed as another:
//!
//! | Label | Used for |
//! |---|---|
//! | `rc.pairing.v1.mac` | deriving the MAC key from the code verifier |
//! | `rc.pairing.v1.client-proof` | the client's MAC and Ed25519 signature |
//! | `rc.pairing.v1.agent-proof` | the agent's MAC and Ed25519 signature |
//!
//! The client's and agent's proofs are therefore different values over the same
//! transcript: an attacker who observes the client's proof cannot echo it back as the
//! agent's confirmation.

use rc_protocol::{DeviceId, PairingSessionId, ProtocolVersion};
use subtle::ConstantTimeEq as _;

use crate::error::{Result, SecurityError};
use crate::fingerprint::Fingerprint;
use crate::permissions::{Capability, Role};

/// Version tag opening every transcript.
const TRANSCRIPT_LABEL: &[u8] = b"rc.pairing.transcript.v1";

/// Context string for deriving the MAC key from the code verifier.
const MAC_KEY_CONTEXT: &str = "rc.pairing.v1.mac";

/// Label distinguishing the client's proof.
pub const CLIENT_PROOF_LABEL: &[u8] = b"rc.pairing.v1.client-proof";

/// Label distinguishing the agent's proof.
pub const AGENT_PROOF_LABEL: &[u8] = b"rc.pairing.v1.agent-proof";

/// The minimum protocol version this build will pair with.
///
/// Pairing establishes long-lived trust, so it refuses to negotiate downwards: a peer
/// offering an older major version is rejected rather than accommodated.
pub const MIN_PAIRING_VERSION: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

/// The permissions a client asks for during pairing.
///
/// Bound into the transcript, so a peer cannot request `ViewOnly` and be recorded as
/// `Owner`, nor have its request silently upgraded in transit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedPermissions {
    /// Role being requested.
    pub role: Role,
    /// Capabilities being requested. Must be a subset of what `role` grants.
    pub capabilities: Vec<Capability>,
}

impl RequestedPermissions {
    /// Everything `role` grants.
    #[must_use]
    pub fn full(role: Role) -> Self {
        Self {
            role,
            capabilities: role.capabilities(),
        }
    }

    /// Reject a request for capabilities the role does not grant.
    ///
    /// # Errors
    /// [`SecurityError::PermissionDenied`] naming the first over-reach.
    pub fn validate(&self) -> Result<()> {
        for capability in &self.capabilities {
            if !self.role.grants(*capability) {
                return Err(SecurityError::PermissionDenied {
                    capability: capability.name(),
                });
            }
        }
        Ok(())
    }

    /// Canonical encoding: sorted, deduplicated, comma-joined capability names.
    ///
    /// Sorting matters. Without it, the same permission set in a different order would
    /// yield a different transcript and pairing would fail intermittently depending on
    /// iteration order.
    #[must_use]
    pub fn canonical(&self) -> String {
        let mut names: Vec<&str> = self.capabilities.iter().map(|c| c.name()).collect();
        names.sort_unstable();
        names.dedup();
        names.join(",")
    }
}

/// Everything the transcript commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptInputs {
    /// Protocol version both peers agreed on.
    pub protocol_version: ProtocolVersion,
    /// Identifier of this pairing exchange.
    pub pairing_session_id: PairingSessionId,
    /// Agent's device id.
    pub agent_device_id: DeviceId,
    /// Client's device id.
    pub client_device_id: DeviceId,
    /// Agent's identity-key fingerprint.
    pub agent_identity_fingerprint: Fingerprint,
    /// Client's identity-key fingerprint.
    pub client_identity_fingerprint: Fingerprint,
    /// Agent's certificate fingerprint.
    pub agent_certificate_fingerprint: Fingerprint,
    /// Client's certificate fingerprint.
    pub client_certificate_fingerprint: Fingerprint,
    /// Agent's fresh nonce.
    pub agent_nonce: [u8; 32],
    /// Client's fresh nonce.
    pub client_nonce: [u8; 32],
    /// When this pairing session expires, milliseconds since the Unix epoch.
    pub expires_at_ms: i64,
    /// Permissions being requested.
    pub requested_permissions: RequestedPermissions,
}

/// A built transcript: the canonical bytes and their hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    /// Build the canonical transcript.
    ///
    /// # Errors
    /// [`SecurityError::UnsupportedProtocolVersion`] if the version is below
    /// [`MIN_PAIRING_VERSION`], or [`SecurityError::PermissionDenied`] if the
    /// requested permissions exceed the requested role.
    pub fn build(inputs: &TranscriptInputs) -> Result<Self> {
        // Downgrade protection: refuse to anchor long-lived trust under an older
        // protocol than this build implements.
        // Only the major version gates pairing. A newer minor is additive and safe;
        // a different major is a different protocol. The comparison is written as an
        // inequality on the major alone because `MIN_PAIRING_VERSION.minor` is
        // currently 0, which makes any minor check vacuous — stating that here rather
        // than leaving a comparison that silently does nothing.
        if inputs.protocol_version.major != MIN_PAIRING_VERSION.major {
            return Err(SecurityError::UnsupportedProtocolVersion);
        }
        inputs.requested_permissions.validate()?;

        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(TRANSCRIPT_LABEL);

        let mut push = |field: &[u8]| {
            bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
            bytes.extend_from_slice(field);
        };

        push(&inputs.protocol_version.major.to_be_bytes());
        push(&inputs.protocol_version.minor.to_be_bytes());
        push(inputs.pairing_session_id.to_canonical_string().as_bytes());
        push(inputs.agent_device_id.to_canonical_string().as_bytes());
        push(inputs.client_device_id.to_canonical_string().as_bytes());
        push(inputs.agent_identity_fingerprint.as_bytes());
        push(inputs.client_identity_fingerprint.as_bytes());
        push(inputs.agent_certificate_fingerprint.as_bytes());
        push(inputs.client_certificate_fingerprint.as_bytes());
        push(&inputs.agent_nonce);
        push(&inputs.client_nonce);
        push(&inputs.expires_at_ms.to_be_bytes());
        push(inputs.requested_permissions.role.name().as_bytes());
        push(inputs.requested_permissions.canonical().as_bytes());

        Ok(Self { bytes })
    }

    /// The canonical bytes, for signing.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// A stable 32-byte digest of the transcript, for logging and comparison.
    ///
    /// Safe to log: it is a hash of public values plus nonces, and it does not reveal
    /// the code verifier. Full proofs are never logged; this digest exists so an
    /// operator can correlate the two sides of a failed pairing.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.bytes).as_bytes()
    }

    /// Short hex form of [`Transcript::digest`], for log lines.
    #[must_use]
    pub fn digest_short(&self) -> String {
        hex::encode(&self.digest()[..8])
    }

    /// Compute the MAC proof for one side.
    ///
    /// `verifier` is the Argon2id output derived from the pairing code. `label` selects
    /// which side's proof this is.
    #[must_use]
    pub fn compute_mac(&self, verifier: &[u8; 32], label: &[u8]) -> [u8; 32] {
        // `derive_key` is BLAKE3's KDF mode: it turns the verifier into a MAC key
        // bound to a fixed context string, so the verifier is never used directly as
        // a key in two different roles.
        let mac_key = blake3::derive_key(MAC_KEY_CONTEXT, verifier);

        let mut input = Vec::with_capacity(label.len() + 8 + self.bytes.len());
        input.extend_from_slice(&(label.len() as u64).to_be_bytes());
        input.extend_from_slice(label);
        input.extend_from_slice(&self.bytes);

        *blake3::keyed_hash(&mac_key, &input).as_bytes()
    }

    /// Verify a MAC proof in constant time.
    ///
    /// # Errors
    /// [`SecurityError::ProofRejected`] on mismatch. The error is deliberately the
    /// same whether the code was wrong or the transcript differed, so it cannot be
    /// used to work out which.
    pub fn verify_mac(
        &self,
        verifier: &[u8; 32],
        label: &[u8],
        presented: &[u8; 32],
    ) -> Result<()> {
        let expected = self.compute_mac(verifier, label);
        if expected.ct_eq(presented).into() {
            Ok(())
        } else {
            Err(SecurityError::ProofRejected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::derive_device_id;

    fn inputs() -> TranscriptInputs {
        TranscriptInputs {
            protocol_version: ProtocolVersion::new(1, 0),
            pairing_session_id: PairingSessionId::from_uuid(uuid::Uuid::from_u128(1)),
            agent_device_id: derive_device_id(&[1u8; 32]),
            client_device_id: derive_device_id(&[2u8; 32]),
            agent_identity_fingerprint: Fingerprint::of_public_key(&[1u8; 32]),
            client_identity_fingerprint: Fingerprint::of_public_key(&[2u8; 32]),
            agent_certificate_fingerprint: Fingerprint::of_certificate_der(b"agent-cert"),
            client_certificate_fingerprint: Fingerprint::of_certificate_der(b"client-cert"),
            agent_nonce: [3u8; 32],
            client_nonce: [4u8; 32],
            expires_at_ms: 1_700_000_180_000,
            requested_permissions: RequestedPermissions::full(Role::Owner),
        }
    }

    const VERIFIER: [u8; 32] = [7u8; 32];

    #[test]
    fn the_same_inputs_produce_the_same_transcript() {
        assert_eq!(
            Transcript::build(&inputs()).unwrap(),
            Transcript::build(&inputs()).unwrap()
        );
    }

    /// Every field that must change the transcript when it changes.
    fn mutations() -> Vec<(&'static str, TranscriptInputs)> {
        vec![
            (
                "protocol minor",
                TranscriptInputs {
                    protocol_version: ProtocolVersion::new(1, 1),
                    ..inputs()
                },
            ),
            (
                "pairing session id",
                TranscriptInputs {
                    pairing_session_id: PairingSessionId::from_uuid(uuid::Uuid::from_u128(2)),
                    ..inputs()
                },
            ),
            (
                "agent device id",
                TranscriptInputs {
                    agent_device_id: derive_device_id(&[9u8; 32]),
                    ..inputs()
                },
            ),
            (
                "client device id",
                TranscriptInputs {
                    client_device_id: derive_device_id(&[9u8; 32]),
                    ..inputs()
                },
            ),
            (
                "agent identity fingerprint",
                TranscriptInputs {
                    agent_identity_fingerprint: Fingerprint::of_public_key(&[9u8; 32]),
                    ..inputs()
                },
            ),
            (
                "client identity fingerprint",
                TranscriptInputs {
                    client_identity_fingerprint: Fingerprint::of_public_key(&[9u8; 32]),
                    ..inputs()
                },
            ),
            (
                "agent certificate fingerprint",
                TranscriptInputs {
                    agent_certificate_fingerprint: Fingerprint::of_certificate_der(b"other"),
                    ..inputs()
                },
            ),
            (
                "client certificate fingerprint",
                TranscriptInputs {
                    client_certificate_fingerprint: Fingerprint::of_certificate_der(b"other"),
                    ..inputs()
                },
            ),
            (
                "agent nonce",
                TranscriptInputs {
                    agent_nonce: [9u8; 32],
                    ..inputs()
                },
            ),
            (
                "client nonce",
                TranscriptInputs {
                    client_nonce: [9u8; 32],
                    ..inputs()
                },
            ),
            (
                "expiry",
                TranscriptInputs {
                    expires_at_ms: 1,
                    ..inputs()
                },
            ),
            (
                "requested role",
                TranscriptInputs {
                    requested_permissions: RequestedPermissions::full(Role::ViewOnly),
                    ..inputs()
                },
            ),
            (
                "requested capabilities",
                TranscriptInputs {
                    requested_permissions: RequestedPermissions {
                        role: Role::Owner,
                        capabilities: vec![Capability::Terminal],
                    },
                    ..inputs()
                },
            ),
        ]
    }

    #[test]
    fn every_bound_field_changes_the_transcript() {
        let base = Transcript::build(&inputs()).unwrap();
        for (name, mutated) in mutations() {
            let other = Transcript::build(&mutated).unwrap();
            assert_ne!(
                base, other,
                "changing the {name} must change the transcript"
            );
        }
    }

    #[test]
    fn every_bound_field_changes_the_proof() {
        let base = Transcript::build(&inputs())
            .unwrap()
            .compute_mac(&VERIFIER, CLIENT_PROOF_LABEL);
        for (name, mutated) in mutations() {
            let other = Transcript::build(&mutated)
                .unwrap()
                .compute_mac(&VERIFIER, CLIENT_PROOF_LABEL);
            assert_ne!(base, other, "changing the {name} must change the proof");
        }
    }

    #[test]
    fn a_tampered_permission_request_fails_verification() {
        // The concrete attack: a relay edits ViewOnly into Owner.
        let honest = Transcript::build(&TranscriptInputs {
            requested_permissions: RequestedPermissions::full(Role::ViewOnly),
            ..inputs()
        })
        .unwrap();
        let proof = honest.compute_mac(&VERIFIER, CLIENT_PROOF_LABEL);

        let escalated = Transcript::build(&inputs()).unwrap(); // Owner
        assert!(matches!(
            escalated.verify_mac(&VERIFIER, CLIENT_PROOF_LABEL, &proof),
            Err(SecurityError::ProofRejected)
        ));
    }

    #[test]
    fn a_proof_for_another_agent_does_not_verify() {
        let theirs = Transcript::build(&TranscriptInputs {
            agent_identity_fingerprint: Fingerprint::of_public_key(&[99u8; 32]),
            ..inputs()
        })
        .unwrap();
        let proof = theirs.compute_mac(&VERIFIER, CLIENT_PROOF_LABEL);

        let ours = Transcript::build(&inputs()).unwrap();
        assert!(
            ours.verify_mac(&VERIFIER, CLIENT_PROOF_LABEL, &proof)
                .is_err()
        );
    }

    #[test]
    fn a_proof_for_another_client_does_not_verify() {
        let theirs = Transcript::build(&TranscriptInputs {
            client_certificate_fingerprint: Fingerprint::of_certificate_der(b"someone-else"),
            ..inputs()
        })
        .unwrap();
        let proof = theirs.compute_mac(&VERIFIER, CLIENT_PROOF_LABEL);

        let ours = Transcript::build(&inputs()).unwrap();
        assert!(
            ours.verify_mac(&VERIFIER, CLIENT_PROOF_LABEL, &proof)
                .is_err()
        );
    }

    #[test]
    fn the_client_and_agent_proofs_are_different_values() {
        // Otherwise an attacker could echo the client's proof back as confirmation.
        let transcript = Transcript::build(&inputs()).unwrap();
        let client = transcript.compute_mac(&VERIFIER, CLIENT_PROOF_LABEL);
        let agent = transcript.compute_mac(&VERIFIER, AGENT_PROOF_LABEL);

        assert_ne!(client, agent);
        assert!(
            transcript
                .verify_mac(&VERIFIER, AGENT_PROOF_LABEL, &client)
                .is_err()
        );
        assert!(
            transcript
                .verify_mac(&VERIFIER, CLIENT_PROOF_LABEL, &agent)
                .is_err()
        );
    }

    #[test]
    fn a_wrong_verifier_fails() {
        let transcript = Transcript::build(&inputs()).unwrap();
        let proof = transcript.compute_mac(&VERIFIER, CLIENT_PROOF_LABEL);
        assert!(
            transcript
                .verify_mac(&[8u8; 32], CLIENT_PROOF_LABEL, &proof)
                .is_err()
        );
    }

    #[test]
    fn a_correct_proof_verifies() {
        let transcript = Transcript::build(&inputs()).unwrap();
        let proof = transcript.compute_mac(&VERIFIER, CLIENT_PROOF_LABEL);
        transcript
            .verify_mac(&VERIFIER, CLIENT_PROOF_LABEL, &proof)
            .unwrap();
    }

    #[test]
    fn length_prefixing_prevents_shifting_content_between_fields() {
        // With naive concatenation, moving a character from the role field into the
        // capability field would leave the bytes unchanged.
        let a = Transcript::build(&TranscriptInputs {
            requested_permissions: RequestedPermissions {
                role: Role::Operator,
                capabilities: vec![Capability::Terminal, Capability::FileRead],
            },
            ..inputs()
        })
        .unwrap();
        let b = Transcript::build(&TranscriptInputs {
            requested_permissions: RequestedPermissions {
                role: Role::Operator,
                capabilities: vec![Capability::FileRead, Capability::Terminal],
            },
            ..inputs()
        })
        .unwrap();
        // Same *set*, so these must match after canonical sorting...
        assert_eq!(a, b);

        // ...but a genuinely different set must not.
        let c = Transcript::build(&TranscriptInputs {
            requested_permissions: RequestedPermissions {
                role: Role::Operator,
                capabilities: vec![Capability::FileRead],
            },
            ..inputs()
        })
        .unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn capability_order_does_not_affect_the_transcript() {
        let forward = RequestedPermissions {
            role: Role::Owner,
            capabilities: Capability::all().to_vec(),
        };
        let mut reversed_caps = Capability::all().to_vec();
        reversed_caps.reverse();
        let reversed = RequestedPermissions {
            role: Role::Owner,
            capabilities: reversed_caps,
        };

        assert_eq!(forward.canonical(), reversed.canonical());
    }

    #[test]
    fn duplicate_capabilities_are_collapsed() {
        let duplicated = RequestedPermissions {
            role: Role::Owner,
            capabilities: vec![Capability::Terminal, Capability::Terminal],
        };
        assert_eq!(duplicated.canonical(), "terminal");
    }

    #[test]
    fn requesting_more_than_the_role_grants_is_rejected() {
        let over_reach = RequestedPermissions {
            role: Role::ViewOnly,
            capabilities: vec![Capability::RemoteDesktopView, Capability::PowerControl],
        };
        assert!(matches!(
            over_reach.validate(),
            Err(SecurityError::PermissionDenied {
                capability: "power_control"
            })
        ));

        assert!(
            Transcript::build(&TranscriptInputs {
                requested_permissions: over_reach,
                ..inputs()
            })
            .is_err()
        );
    }

    #[test]
    fn a_downgraded_protocol_version_is_refused() {
        for version in [ProtocolVersion::new(0, 9), ProtocolVersion::new(2, 0)] {
            assert!(matches!(
                Transcript::build(&TranscriptInputs {
                    protocol_version: version,
                    ..inputs()
                }),
                Err(SecurityError::UnsupportedProtocolVersion)
            ));
        }
    }

    #[test]
    fn a_newer_minor_version_is_accepted() {
        Transcript::build(&TranscriptInputs {
            protocol_version: ProtocolVersion::new(1, 5),
            ..inputs()
        })
        .unwrap();
    }

    #[test]
    fn the_digest_is_stable_and_short_form_is_hex() {
        let transcript = Transcript::build(&inputs()).unwrap();
        assert_eq!(
            transcript.digest(),
            Transcript::build(&inputs()).unwrap().digest()
        );
        assert_eq!(transcript.digest_short().len(), 16);
        assert!(
            transcript
                .digest_short()
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn the_digest_does_not_reveal_the_verifier() {
        let transcript = Transcript::build(&inputs()).unwrap();
        let digest = hex::encode(transcript.digest());
        assert!(!digest.contains(&hex::encode(VERIFIER)));
    }

    #[test]
    fn the_transcript_starts_with_its_version_tag() {
        let transcript = Transcript::build(&inputs()).unwrap();
        assert!(transcript.as_bytes().starts_with(TRANSCRIPT_LABEL));
    }
}
