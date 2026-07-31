//! The client half of the pairing exchange.
//!
//! The client's job is to take the code the operator typed, derive the same verifier
//! the agent holds, build the identical transcript, and prove it. If any value differs
//! — including the agent's fingerprints, which the client is seeing for the first time
//! — the proof will not verify and pairing fails safely.

use rc_protocol::{DeviceId, PairingSessionId, ProtocolVersion};

use crate::error::{Result, SecurityError};
use crate::fingerprint::Fingerprint;
use crate::identity::DeviceIdentity;
use crate::pairing::code::{CodeVerifier, PairingCode};
use crate::pairing::session::{
    AgentConfirmation, ClientIdentityClaim, ClientProof, PairingChallenge,
};
use crate::pairing::transcript::{
    AGENT_PROOF_LABEL, CLIENT_PROOF_LABEL, RequestedPermissions, Transcript, TranscriptInputs,
};

/// What the client has after a successful exchange: the agent identity to pin.
#[derive(Debug, Clone)]
pub struct PairedAgent {
    /// The agent's device id.
    pub device_id: DeviceId,
    /// The agent's Ed25519 public key.
    pub public_key: [u8; 32],
    /// Identity fingerprint. **This is what the client pins.**
    pub identity_fingerprint: Fingerprint,
    /// Certificate fingerprint at pairing time. Expected to change on renewal.
    pub certificate_fingerprint: Fingerprint,
    /// Permissions the client was granted.
    pub granted_permissions: RequestedPermissions,
    /// Short transcript digest, safe to log.
    pub transcript_digest: String,
}

/// Builds the client's claim, proof, and verifies the agent's confirmation.
#[derive(Debug)]
pub struct PairingClient {
    protocol_version: ProtocolVersion,
}

impl PairingClient {
    /// A client speaking `protocol_version`.
    #[must_use]
    pub const fn new(protocol_version: ProtocolVersion) -> Self {
        Self { protocol_version }
    }

    /// A client speaking this build's protocol version.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            protocol_version: rc_protocol::CURRENT_VERSION,
        }
    }

    /// Build the identity claim to send to the agent.
    #[must_use]
    pub fn build_claim(
        &self,
        identity: &DeviceIdentity,
        nonce: [u8; 32],
        display_name: String,
        requested_permissions: RequestedPermissions,
    ) -> ClientIdentityClaim {
        let public = identity.public();
        ClientIdentityClaim {
            device_id: public.device_id,
            public_key: public.identity_public_key,
            certificate_fingerprint: public.certificate_fingerprint,
            nonce,
            requested_permissions,
            protocol_version: self.protocol_version,
            display_name,
        }
    }

    /// Rebuild the transcript from the challenge and the client's own values.
    ///
    /// # Errors
    /// Propagates transcript construction failures, including a rejected protocol
    /// version or an over-reaching permission request.
    pub fn build_transcript(
        &self,
        challenge: &PairingChallenge,
        claim: &ClientIdentityClaim,
    ) -> Result<Transcript> {
        Transcript::build(&TranscriptInputs {
            protocol_version: self.protocol_version,
            pairing_session_id: challenge.pairing_session_id,
            agent_device_id: challenge.agent_device_id,
            client_device_id: claim.device_id,
            agent_identity_fingerprint: challenge.agent_identity_fingerprint,
            client_identity_fingerprint: Fingerprint::of_public_key(&claim.public_key),
            agent_certificate_fingerprint: challenge.agent_certificate_fingerprint,
            client_certificate_fingerprint: claim.certificate_fingerprint,
            agent_nonce: challenge.agent_nonce,
            client_nonce: claim.nonce,
            expires_at_ms: challenge.expires_at_ms,
            requested_permissions: claim.requested_permissions.clone(),
        })
    }

    /// Derive the code verifier from the operator-entered code and the agent's salt.
    ///
    /// # Errors
    /// Propagates hashing failures.
    pub fn derive_verifier(
        code: &PairingCode,
        challenge: &PairingChallenge,
    ) -> Result<CodeVerifier> {
        code.derive_verifier(&challenge.verifier_salt)
    }

    /// Produce the client's proof.
    ///
    /// # Errors
    /// Propagates transcript construction failures.
    pub fn build_proof(
        &self,
        identity: &DeviceIdentity,
        verifier: &CodeVerifier,
        transcript: &Transcript,
    ) -> Result<ClientProof> {
        Ok(ClientProof {
            mac: transcript.compute_mac(verifier.as_key_material(), CLIENT_PROOF_LABEL),
            signature: identity.sign(CLIENT_PROOF_LABEL, transcript.as_bytes()),
        })
    }

    /// Verify the agent's confirmation and produce the identity to pin.
    ///
    /// Both the MAC and the agent's signature must check out. The MAC proves the agent
    /// knew the pairing code; the signature proves it holds the private key behind the
    /// fingerprint the client is about to trust. Accepting either alone would let an
    /// attacker who learned the code impersonate the agent.
    ///
    /// # Errors
    /// [`SecurityError::ProofRejected`] if the MAC fails, [`SecurityError::BadSignature`]
    /// if the signature fails.
    pub fn verify_confirmation(
        &self,
        challenge: &PairingChallenge,
        transcript: &Transcript,
        verifier: &CodeVerifier,
        confirmation: &AgentConfirmation,
        granted_permissions: RequestedPermissions,
    ) -> Result<PairedAgent> {
        transcript.verify_mac(
            verifier.as_key_material(),
            AGENT_PROOF_LABEL,
            &confirmation.mac,
        )?;

        verify_agent_signature(&challenge.agent_public_key, transcript, confirmation)?;

        // The fingerprint the client is about to pin must actually be the fingerprint
        // of the key that just signed. Otherwise the agent could present one key and
        // have a different one recorded.
        let derived = Fingerprint::of_public_key(&challenge.agent_public_key);
        if derived != challenge.agent_identity_fingerprint {
            return Err(SecurityError::IdentityMismatch);
        }
        if challenge.agent_device_id
            != crate::identity::derive_device_id(&challenge.agent_public_key)
        {
            return Err(SecurityError::IdentityMismatch);
        }

        Ok(PairedAgent {
            device_id: challenge.agent_device_id,
            public_key: challenge.agent_public_key,
            identity_fingerprint: derived,
            certificate_fingerprint: challenge.agent_certificate_fingerprint,
            granted_permissions,
            transcript_digest: transcript.digest_short(),
        })
    }
}

/// Verify the agent's Ed25519 signature over the transcript.
fn verify_agent_signature(
    public_key: &[u8; 32],
    transcript: &Transcript,
    confirmation: &AgentConfirmation,
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let verifying =
        VerifyingKey::from_bytes(public_key).map_err(|_| SecurityError::MalformedIdentity)?;

    // Must match `DeviceIdentity::sign`'s framing exactly.
    let mut message = Vec::with_capacity(4 + AGENT_PROOF_LABEL.len() + transcript.as_bytes().len());
    message.extend_from_slice(
        &u32::try_from(AGENT_PROOF_LABEL.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    message.extend_from_slice(AGENT_PROOF_LABEL);
    message.extend_from_slice(transcript.as_bytes());

    verifying
        .verify(&message, &Signature::from_bytes(&confirmation.signature))
        .map_err(|_| SecurityError::BadSignature)
}

/// A pairing session id, re-exported for callers driving the exchange.
pub use rc_protocol::PairingSessionId as ClientPairingSessionId;

#[allow(dead_code)]
fn _assert_id_type(_: PairingSessionId) {}
