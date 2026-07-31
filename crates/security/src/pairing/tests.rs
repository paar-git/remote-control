//! End-to-end pairing tests.
//!
//! These drive the real agent and client halves against each other. Nothing is
//! stubbed: the same [`PairingManager`] the agent uses and the same [`PairingClient`]
//! the desktop app uses talk to one another through the real transcript and proofs.

use std::sync::Arc;

use rc_protocol::ProtocolVersion;

use super::*;
use crate::clock::{OsRandom, RandomSourceExt as _, TestClock};
use crate::error::SecurityError;
use crate::fingerprint::Fingerprint;
use crate::identity::DeviceIdentity;
use crate::pairing::session::{DEFAULT_MAX_ATTEMPTS, DEFAULT_PAIRING_TTL_SECS};
use crate::permissions::{Capability, Role};

/// Both ends of a pairing exchange, ready to drive.
struct Harness {
    manager: PairingManager,
    agent: DeviceIdentity,
    client_identity: DeviceIdentity,
    clock: TestClock,
    rng: OsRandom,
}

impl Harness {
    fn new() -> Self {
        Self::with_policy(PairingPolicy::default())
    }

    fn with_policy(policy: PairingPolicy) -> Self {
        let clock = TestClock::default();
        Self {
            agent: DeviceIdentity::generate("home-server", &clock).unwrap(),
            client_identity: DeviceIdentity::generate("main-pc", &clock).unwrap(),
            manager: PairingManager::new(policy),
            clock,
            rng: OsRandom,
        }
    }

    fn open(&self) -> OpenedPairing {
        self.manager.begin_pairing(&self.clock, &self.rng).unwrap()
    }

    fn claim(&self, permissions: RequestedPermissions) -> ClientIdentityClaim {
        PairingClient::current().build_claim(
            &self.client_identity,
            self.rng.bytes(),
            "Main PC".to_string(),
            permissions,
        )
    }

    fn challenge(
        &self,
        opened: &OpenedPairing,
        claim: ClientIdentityClaim,
    ) -> Result<PairingChallenge, SecurityError> {
        self.manager.submit_client_identity(
            opened.pairing_session_id,
            claim,
            &self.agent,
            &self.clock,
        )
    }

    /// Run the whole exchange with the correct code, returning both sides' results.
    fn complete(&self) -> (PairingOutcome, PairedAgent) {
        let opened = self.open();
        let claim = self.claim(RequestedPermissions::full(Role::Owner));
        let challenge = self.challenge(&opened, claim.clone()).unwrap();

        let client = PairingClient::current();
        let transcript = client.build_transcript(&challenge, &claim).unwrap();
        let verifier = PairingClient::derive_verifier(&opened.code, &challenge).unwrap();
        let proof = client
            .build_proof(&self.client_identity, &verifier, &transcript)
            .unwrap();

        let outcome = self
            .manager
            .verify_client_proof(opened.pairing_session_id, &proof, &self.agent, &self.clock)
            .unwrap();

        let paired = client
            .verify_confirmation(
                &challenge,
                &transcript,
                &verifier,
                &outcome.confirmation,
                outcome.granted_permissions.clone(),
            )
            .unwrap();

        (outcome, paired)
    }

    /// Submit a proof built from `code`, which may be the wrong one.
    fn attempt_with_code(
        &self,
        opened: &OpenedPairing,
        challenge: &PairingChallenge,
        claim: &ClientIdentityClaim,
        code: &PairingCode,
    ) -> Result<PairingOutcome, SecurityError> {
        let client = PairingClient::current();
        let transcript = client.build_transcript(challenge, claim).unwrap();
        let verifier = PairingClient::derive_verifier(code, challenge).unwrap();
        let proof = client
            .build_proof(&self.client_identity, &verifier, &transcript)
            .unwrap();

        self.manager.verify_client_proof(
            opened.pairing_session_id,
            &proof,
            &self.agent,
            &self.clock,
        )
    }
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[test]
fn a_full_exchange_with_the_correct_code_succeeds() {
    let harness = Harness::new();
    let (outcome, paired) = harness.complete();

    assert_eq!(
        outcome.client_device_id,
        harness.client_identity.device_id()
    );
    assert_eq!(paired.device_id, harness.agent.device_id());
}

#[test]
fn both_sides_pin_each_others_identity_fingerprints() {
    let harness = Harness::new();
    let (outcome, paired) = harness.complete();

    assert_eq!(
        paired.identity_fingerprint,
        harness.agent.public().identity_fingerprint,
        "the client must pin the agent's real identity"
    );
    assert_eq!(
        outcome.client_identity_fingerprint,
        harness.client_identity.public().identity_fingerprint,
        "the agent must record the client's real identity"
    );
}

#[test]
fn both_sides_derive_the_same_transcript() {
    let harness = Harness::new();
    let (outcome, paired) = harness.complete();
    assert_eq!(outcome.transcript_digest, paired.transcript_digest);
}

#[test]
fn the_operator_sees_a_well_formed_code() {
    let harness = Harness::new();
    let opened = harness.open();
    let display = opened.code.expose_for_display();

    assert_eq!(display.len(), 11);
    assert!(PairingCode::parse(&display).is_ok());
}

#[test]
fn the_stored_verifier_is_not_the_code() {
    let harness = Harness::new();
    let opened = harness.open();
    let raw = opened.code.expose_for_display().replace('-', "");

    assert!(!opened.verifier_hex.contains(&raw));
    assert!(!opened.salt_hex.contains(&raw));
    assert_eq!(opened.verifier_hex.len(), 64);
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

#[test]
fn a_code_expires_after_its_window() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));

    harness.clock.advance_secs(DEFAULT_PAIRING_TTL_SECS + 1);

    assert!(matches!(
        harness.challenge(&opened, claim),
        Err(SecurityError::PairingExpired)
    ));
}

#[test]
fn a_code_is_still_valid_just_before_expiry() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));

    harness.clock.advance_secs(DEFAULT_PAIRING_TTL_SECS - 1);
    assert!(harness.challenge(&opened, claim).is_ok());
}

#[test]
fn a_session_that_expires_mid_exchange_cannot_be_completed() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    // The operator walks away between the challenge and the proof.
    harness.clock.advance_secs(DEFAULT_PAIRING_TTL_SECS + 1);

    assert!(matches!(
        harness.attempt_with_code(&opened, &challenge, &claim, &opened.code),
        Err(SecurityError::PairingExpired)
    ));
}

#[test]
fn expiry_is_reported_by_state_queries() {
    let harness = Harness::new();
    let opened = harness.open();

    assert_eq!(
        harness
            .manager
            .state_of(opened.pairing_session_id, &harness.clock),
        Some(PairingState::Open)
    );
    harness.clock.advance_secs(DEFAULT_PAIRING_TTL_SECS + 1);
    assert_eq!(
        harness
            .manager
            .state_of(opened.pairing_session_id, &harness.clock),
        Some(PairingState::Expired)
    );
}

#[test]
fn expired_sessions_are_swept() {
    let harness = Harness::new();
    harness.open();
    assert_eq!(harness.manager.session_count(), 1);

    harness.clock.advance_secs(DEFAULT_PAIRING_TTL_SECS + 1);
    assert_eq!(harness.manager.sweep(&harness.clock), 1);
    assert_eq!(harness.manager.session_count(), 0);
}

// ---------------------------------------------------------------------------
// Single use and duplicate completion
// ---------------------------------------------------------------------------

#[test]
fn a_code_cannot_be_used_twice() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    harness
        .attempt_with_code(&opened, &challenge, &claim, &opened.code)
        .unwrap();

    // Replaying the identical, valid proof must fail.
    assert!(matches!(
        harness.attempt_with_code(&opened, &challenge, &claim, &opened.code),
        Err(SecurityError::PairingAlreadyConsumed)
    ));
}

#[test]
fn a_consumed_session_rejects_a_new_client_identity() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();
    harness
        .attempt_with_code(&opened, &challenge, &claim, &opened.code)
        .unwrap();

    assert!(matches!(
        harness.challenge(&opened, claim),
        Err(SecurityError::PairingAlreadyConsumed)
    ));
}

#[test]
fn concurrent_submissions_of_the_same_valid_proof_yield_exactly_one_success() {
    // The atomicity property: two threads racing with an identical valid proof.
    let harness = Arc::new(Harness::new());
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    let client = PairingClient::current();
    let transcript = client.build_transcript(&challenge, &claim).unwrap();
    let verifier = PairingClient::derive_verifier(&opened.code, &challenge).unwrap();
    let proof = Arc::new(
        client
            .build_proof(&harness.client_identity, &verifier, &transcript)
            .unwrap(),
    );

    let session_id = opened.pairing_session_id;
    let barrier = Arc::new(std::sync::Barrier::new(8));

    let handles: Vec<_> = (0..8)
        .map(|_| {
            let harness = Arc::clone(&harness);
            let proof = Arc::clone(&proof);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                harness
                    .manager
                    .verify_client_proof(session_id, &proof, &harness.agent, &harness.clock)
                    .is_ok()
            })
        })
        .collect();

    let successes = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|ok| *ok)
        .count();

    assert_eq!(
        successes, 1,
        "exactly one concurrent submission may succeed"
    );
}

// ---------------------------------------------------------------------------
// Wrong codes and the attempt cap
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_code_is_rejected() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    let wrong = PairingCode::generate(&OsRandom);
    assert!(matches!(
        harness.attempt_with_code(&opened, &challenge, &claim, &wrong),
        Err(SecurityError::ProofRejected)
    ));
}

#[test]
fn the_attempt_cap_destroys_the_code() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();
    let wrong = PairingCode::generate(&OsRandom);

    for attempt in 1..DEFAULT_MAX_ATTEMPTS {
        assert!(
            matches!(
                harness.attempt_with_code(&opened, &challenge, &claim, &wrong),
                Err(SecurityError::ProofRejected)
            ),
            "attempt {attempt} should be a plain rejection"
        );
    }

    // The final permitted failure exhausts the code.
    assert!(matches!(
        harness.attempt_with_code(&opened, &challenge, &claim, &wrong),
        Err(SecurityError::PairingAttemptsExhausted)
    ));

    // And now even the *correct* code is useless.
    assert!(matches!(
        harness.attempt_with_code(&opened, &challenge, &claim, &opened.code),
        Err(SecurityError::PairingAttemptsExhausted)
    ));
}

#[test]
fn the_attempt_cap_is_configurable() {
    let harness = Harness::with_policy(PairingPolicy {
        max_attempts: 2,
        ..Default::default()
    });
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();
    let wrong = PairingCode::generate(&OsRandom);

    assert!(matches!(
        harness.attempt_with_code(&opened, &challenge, &claim, &wrong),
        Err(SecurityError::ProofRejected)
    ));
    assert!(matches!(
        harness.attempt_with_code(&opened, &challenge, &claim, &wrong),
        Err(SecurityError::PairingAttemptsExhausted)
    ));
}

#[test]
fn a_wrong_code_and_a_bad_transcript_are_indistinguishable() {
    // Neither failure may act as an oracle telling an attacker which they got wrong.
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    let wrong_code = harness
        .attempt_with_code(
            &opened,
            &challenge,
            &claim,
            &PairingCode::generate(&OsRandom),
        )
        .unwrap_err();

    let harness2 = Harness::new();
    let opened2 = harness2.open();
    let claim2 = harness2.claim(RequestedPermissions::full(Role::Owner));
    let challenge2 = harness2.challenge(&opened2, claim2.clone()).unwrap();

    // Right code, tampered transcript (permissions escalated after the fact).
    let client = PairingClient::current();
    let tampered_claim = ClientIdentityClaim {
        requested_permissions: RequestedPermissions::full(Role::ViewOnly),
        ..claim2.clone()
    };
    let transcript = client
        .build_transcript(&challenge2, &tampered_claim)
        .unwrap();
    let verifier = PairingClient::derive_verifier(&opened2.code, &challenge2).unwrap();
    let proof = client
        .build_proof(&harness2.client_identity, &verifier, &transcript)
        .unwrap();
    let bad_transcript = harness2
        .manager
        .verify_client_proof(
            opened2.pairing_session_id,
            &proof,
            &harness2.agent,
            &harness2.clock,
        )
        .unwrap_err();

    assert_eq!(wrong_code.to_string(), bad_transcript.to_string());
}

// ---------------------------------------------------------------------------
// Tampering, relaying and replay
// ---------------------------------------------------------------------------

#[test]
fn a_proof_from_another_pairing_session_is_rejected() {
    let harness = Harness::new();

    let first = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let first_challenge = harness.challenge(&first, claim.clone()).unwrap();

    let second = harness.open();
    // Issued only to move the second session into `Challenged`, so the rejection below
    // is attributable to the transcript binding rather than to a wrong-state check.
    let _second_challenge = harness.challenge(&second, claim.clone()).unwrap();

    // Build a proof for the first session, submit it against the second.
    let client = PairingClient::current();
    let transcript = client.build_transcript(&first_challenge, &claim).unwrap();
    let verifier = PairingClient::derive_verifier(&first.code, &first_challenge).unwrap();
    let proof = client
        .build_proof(&harness.client_identity, &verifier, &transcript)
        .unwrap();

    assert!(matches!(
        harness.manager.verify_client_proof(
            second.pairing_session_id,
            &proof,
            &harness.agent,
            &harness.clock
        ),
        Err(SecurityError::ProofRejected)
    ));
}

#[test]
fn a_proof_made_for_a_different_agent_is_rejected() {
    // The relay scenario: an attacker forwards a client's proof to the real agent.
    let victim = Harness::new();
    let attacker_agent = DeviceIdentity::generate("impostor", &victim.clock).unwrap();

    let opened = victim.open();
    let claim = victim.claim(RequestedPermissions::full(Role::Owner));
    let real_challenge = victim.challenge(&opened, claim.clone()).unwrap();

    // The client was shown the attacker's fingerprints instead of the real agent's.
    let spoofed = PairingChallenge {
        agent_device_id: attacker_agent.device_id(),
        agent_identity_fingerprint: attacker_agent.public().identity_fingerprint,
        agent_certificate_fingerprint: attacker_agent.public().certificate_fingerprint,
        agent_public_key: attacker_agent.public().identity_public_key,
        ..real_challenge.clone()
    };

    let client = PairingClient::current();
    let transcript = client.build_transcript(&spoofed, &claim).unwrap();
    let verifier = PairingClient::derive_verifier(&opened.code, &spoofed).unwrap();
    let proof = client
        .build_proof(&victim.client_identity, &verifier, &transcript)
        .unwrap();

    assert!(
        matches!(
            victim.manager.verify_client_proof(
                opened.pairing_session_id,
                &proof,
                &victim.agent,
                &victim.clock
            ),
            Err(SecurityError::ProofRejected)
        ),
        "a proof bound to another agent's identity must not verify"
    );
}

#[test]
fn a_tampered_certificate_fingerprint_is_rejected() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    // The client signs a transcript naming a different client certificate than the
    // one the agent recorded from the claim.
    let altered = ClientIdentityClaim {
        certificate_fingerprint: Fingerprint::of_certificate_der(b"someone-elses-cert"),
        ..claim.clone()
    };

    let client = PairingClient::current();
    let transcript = client.build_transcript(&challenge, &altered).unwrap();
    let verifier = PairingClient::derive_verifier(&opened.code, &challenge).unwrap();
    let proof = client
        .build_proof(&harness.client_identity, &verifier, &transcript)
        .unwrap();

    assert!(matches!(
        harness.manager.verify_client_proof(
            opened.pairing_session_id,
            &proof,
            &harness.agent,
            &harness.clock
        ),
        Err(SecurityError::ProofRejected)
    ));
}

#[test]
fn a_replayed_nonce_produces_a_different_session_and_still_fails() {
    // Nonces are per-session; reusing a client nonce in a new session does not help
    // because the session id and agent nonce also differ.
    let harness = Harness::new();
    let fixed_nonce = [42u8; 32];

    let first = harness.open();
    let claim = PairingClient::current().build_claim(
        &harness.client_identity,
        fixed_nonce,
        "Main PC".into(),
        RequestedPermissions::full(Role::Owner),
    );
    let first_challenge = harness.challenge(&first, claim.clone()).unwrap();

    let client = PairingClient::current();
    let transcript = client.build_transcript(&first_challenge, &claim).unwrap();
    let verifier = PairingClient::derive_verifier(&first.code, &first_challenge).unwrap();
    let proof = client
        .build_proof(&harness.client_identity, &verifier, &transcript)
        .unwrap();

    let second = harness.open();
    harness.challenge(&second, claim).unwrap();

    assert!(matches!(
        harness.manager.verify_client_proof(
            second.pairing_session_id,
            &proof,
            &harness.agent,
            &harness.clock
        ),
        Err(SecurityError::ProofRejected)
    ));
}

#[test]
fn a_client_cannot_claim_a_device_id_it_does_not_own() {
    let harness = Harness::new();
    let opened = harness.open();

    let mut claim = harness.claim(RequestedPermissions::full(Role::Owner));
    claim.device_id = harness.agent.device_id(); // impersonate the agent's id

    assert!(matches!(
        harness.challenge(&opened, claim),
        Err(SecurityError::IdentityMismatch)
    ));
}

#[test]
fn a_client_cannot_request_more_than_its_role_grants() {
    let harness = Harness::new();
    let opened = harness.open();

    let claim = harness.claim(RequestedPermissions {
        role: Role::ViewOnly,
        capabilities: vec![Capability::RemoteDesktopView, Capability::PowerControl],
    });

    assert!(matches!(
        harness.challenge(&opened, claim),
        Err(SecurityError::PermissionDenied {
            capability: "power_control"
        })
    ));
}

#[test]
fn a_forged_signature_with_a_valid_mac_is_rejected() {
    // Knowing the code is not enough: the client must also hold its identity key.
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    let client = PairingClient::current();
    let transcript = client.build_transcript(&challenge, &claim).unwrap();
    let verifier = PairingClient::derive_verifier(&opened.code, &challenge).unwrap();

    let mut proof = client
        .build_proof(&harness.client_identity, &verifier, &transcript)
        .unwrap();
    proof.signature[0] ^= 0xFF; // MAC still correct, signature broken

    assert!(
        harness
            .manager
            .verify_client_proof(
                opened.pairing_session_id,
                &proof,
                &harness.agent,
                &harness.clock
            )
            .is_err()
    );
}

#[test]
fn a_valid_signature_with_a_forged_mac_is_rejected() {
    // Holding the identity key is not enough: the operator's code is still required.
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    let client = PairingClient::current();
    let transcript = client.build_transcript(&challenge, &claim).unwrap();
    let verifier = PairingClient::derive_verifier(&opened.code, &challenge).unwrap();

    let mut proof = client
        .build_proof(&harness.client_identity, &verifier, &transcript)
        .unwrap();
    proof.mac[0] ^= 0xFF;

    assert!(
        harness
            .manager
            .verify_client_proof(
                opened.pairing_session_id,
                &proof,
                &harness.agent,
                &harness.clock
            )
            .is_err()
    );
}

#[test]
fn the_client_rejects_a_forged_agent_confirmation() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    let client = PairingClient::current();
    let transcript = client.build_transcript(&challenge, &claim).unwrap();
    let verifier = PairingClient::derive_verifier(&opened.code, &challenge).unwrap();
    let proof = client
        .build_proof(&harness.client_identity, &verifier, &transcript)
        .unwrap();
    let outcome = harness
        .manager
        .verify_client_proof(
            opened.pairing_session_id,
            &proof,
            &harness.agent,
            &harness.clock,
        )
        .unwrap();

    let mut forged = outcome.confirmation.clone();
    forged.mac[0] ^= 0xFF;
    assert!(
        client
            .verify_confirmation(
                &challenge,
                &transcript,
                &verifier,
                &forged,
                outcome.granted_permissions.clone()
            )
            .is_err()
    );

    let mut forged = outcome.confirmation.clone();
    forged.signature[0] ^= 0xFF;
    assert!(
        client
            .verify_confirmation(
                &challenge,
                &transcript,
                &verifier,
                &forged,
                outcome.granted_permissions
            )
            .is_err()
    );
}

#[test]
fn the_client_rejects_an_agent_whose_fingerprint_does_not_match_its_key() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));
    let mut challenge = harness.challenge(&opened, claim.clone()).unwrap();

    let client = PairingClient::current();
    let transcript = client.build_transcript(&challenge, &claim).unwrap();
    let verifier = PairingClient::derive_verifier(&opened.code, &challenge).unwrap();
    let proof = client
        .build_proof(&harness.client_identity, &verifier, &transcript)
        .unwrap();
    let outcome = harness
        .manager
        .verify_client_proof(
            opened.pairing_session_id,
            &proof,
            &harness.agent,
            &harness.clock,
        )
        .unwrap();

    // The agent claims a fingerprint that is not the hash of the key it signed with.
    // Pinning that would trust an identity nobody proved possession of.
    challenge.agent_identity_fingerprint = Fingerprint::of_public_key(&[0xAB; 32]);

    assert!(matches!(
        client.verify_confirmation(
            &challenge,
            &transcript,
            &verifier,
            &outcome.confirmation,
            outcome.granted_permissions
        ),
        Err(SecurityError::IdentityMismatch)
    ));
}

// ---------------------------------------------------------------------------
// Protocol version
// ---------------------------------------------------------------------------

#[test]
fn pairing_refuses_an_unsupported_protocol_version() {
    let harness = Harness::new();
    let opened = harness.open();

    let downgraded = PairingClient::new(ProtocolVersion::new(0, 9));
    let claim = downgraded.build_claim(
        &harness.client_identity,
        harness.rng.bytes(),
        "Main PC".into(),
        RequestedPermissions::full(Role::Owner),
    );
    let challenge = harness.challenge(&opened, claim.clone()).unwrap();

    assert!(matches!(
        downgraded.build_transcript(&challenge, &claim),
        Err(SecurityError::UnsupportedProtocolVersion)
    ));
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_session_id_is_rejected() {
    let harness = Harness::new();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));

    assert!(matches!(
        harness.manager.submit_client_identity(
            rc_protocol::PairingSessionId::generate(),
            claim,
            &harness.agent,
            &harness.clock
        ),
        Err(SecurityError::PairingSessionUnknown)
    ));
}

#[test]
fn a_proof_cannot_be_submitted_before_the_client_identifies_itself() {
    let harness = Harness::new();
    let opened = harness.open();

    let proof = ClientProof {
        mac: [0u8; 32],
        signature: [0u8; 64],
    };
    assert!(matches!(
        harness.manager.verify_client_proof(
            opened.pairing_session_id,
            &proof,
            &harness.agent,
            &harness.clock
        ),
        Err(SecurityError::PairingWrongState)
    ));
}

#[test]
fn cancelling_a_window_makes_it_unusable() {
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));

    harness.manager.cancel(opened.pairing_session_id).unwrap();

    assert!(matches!(
        harness.challenge(&opened, claim),
        Err(SecurityError::PairingExpired)
    ));
}

#[test]
fn the_number_of_open_windows_is_bounded() {
    let harness = Harness::with_policy(PairingPolicy {
        max_sessions: 2,
        ..Default::default()
    });

    harness
        .manager
        .begin_pairing(&harness.clock, &harness.rng)
        .unwrap();
    harness
        .manager
        .begin_pairing(&harness.clock, &harness.rng)
        .unwrap();

    assert!(
        harness
            .manager
            .begin_pairing(&harness.clock, &harness.rng)
            .is_err()
    );
}

#[test]
fn expired_windows_free_up_the_budget() {
    let harness = Harness::with_policy(PairingPolicy {
        max_sessions: 1,
        ..Default::default()
    });

    harness
        .manager
        .begin_pairing(&harness.clock, &harness.rng)
        .unwrap();
    assert!(
        harness
            .manager
            .begin_pairing(&harness.clock, &harness.rng)
            .is_err()
    );

    harness.clock.advance_secs(DEFAULT_PAIRING_TTL_SECS + 1);
    harness
        .manager
        .begin_pairing(&harness.clock, &harness.rng)
        .unwrap();
}

#[test]
fn each_window_gets_a_distinct_code_and_session_id() {
    let harness = Harness::new();
    let a = harness.open();
    let b = harness.open();

    assert_ne!(a.pairing_session_id, b.pairing_session_id);
    assert_ne!(a.code.expose_for_display(), b.code.expose_for_display());
    assert_ne!(a.verifier_hex, b.verifier_hex);
    assert_ne!(a.salt_hex, b.salt_hex);
}

#[test]
fn a_display_name_is_validated() {
    let harness = Harness::new();
    let opened = harness.open();

    for bad in ["", "   ", "bad\u{0}name", &"n".repeat(200)] {
        let claim = PairingClient::current().build_claim(
            &harness.client_identity,
            harness.rng.bytes(),
            bad.to_string(),
            RequestedPermissions::full(Role::Owner),
        );
        assert!(
            harness.challenge(&opened, claim).is_err(),
            "must reject name {bad:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Restart behaviour
// ---------------------------------------------------------------------------

#[test]
fn open_windows_do_not_survive_an_agent_restart() {
    // Sessions are in-memory by design: a code shown before a crash must not still
    // work afterwards.
    let harness = Harness::new();
    let opened = harness.open();
    let claim = harness.claim(RequestedPermissions::full(Role::Owner));

    // A "restart" is a fresh manager over the same identity.
    let restarted = PairingManager::with_defaults();
    assert!(matches!(
        restarted.submit_client_identity(
            opened.pairing_session_id,
            claim,
            &harness.agent,
            &harness.clock
        ),
        Err(SecurityError::PairingSessionUnknown)
    ));
}
