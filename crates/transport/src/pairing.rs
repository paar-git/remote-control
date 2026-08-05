//! Running the pairing exchange over a live connection.
//!
//! [`rc_security::pairing`] owns the cryptography; this module owns the four messages
//! that carry it across a QUIC stream and the rules about what may be taken from those
//! messages.
//!
//! # The one rule that matters
//!
//! **Certificate fingerprints in the transcript come from the TLS connection, never
//! from a message.**
//!
//! Each side reads its peer's fingerprint with
//! [`crate::peer_certificate_fingerprint`] and its own from its own identity. Neither
//! is ever taken from the wire, and the wire types deliberately offer no field that
//! could be mistaken for one.
//!
//! This is the entire anti-relay property. An attacker who sits between a real client
//! and a real agent has two separate TLS connections, presenting its own certificate on
//! each. The client's transcript therefore names the attacker's fingerprint where the
//! agent's transcript names the client's, the two transcripts differ, and neither proof
//! verifies. If either side accepted a fingerprint from the message body, the attacker
//! would simply forward the honest values and the property would evaporate.
//!
//! # Pairing is permitted only inside a window
//!
//! An unpaired connection is admitted at the TLS layer under
//! [`crate::PinPolicy::TrustOnFirstUse`] — there is no pin yet, which is the problem
//! pairing exists to solve. The agent must therefore decide, before running any of
//! this, whether a pairing window is open at all. A connection that reaches
//! [`serve_pairing`] with no open window is refused with
//! [`rc_protocol::pairing::PairFailure::NotInPairingMode`].

use rc_protocol::PairingSessionId;
use rc_protocol::control::{DeviceDescriptor, Opening};
use rc_protocol::pairing::{
    PairChallenge, PairConfirm, PairFailure, PairProof, PairRequest, PairingMessage, Signature64,
};
use rc_security::pairing::{
    AgentConfirmation, ClientIdentityClaim, ClientProof, PairedAgent, PairingChallenge,
    PairingClient, PairingCode, PairingManager, PairingOutcome, RequestedPermissions,
};
use rc_security::{
    Clock, DeviceIdentity, Fingerprint, RandomSourceExt as _, SecurityError, derive_device_id,
};

use crate::channel::{ChannelReader, ChannelWriter};
use crate::error::{Result, TransportError};

/// How long each side waits for the other's next pairing message.
///
/// Generous, because a human is typing a code somewhere in this loop, but bounded: a
/// half-finished exchange holds one of a small number of concurrent pairing slots.
pub const PAIRING_STEP_TIMEOUT_SECS: u64 = 60;

/// Records a completed pairing durably.
///
/// Implemented by the agent over its trust repository. It is a trait so this crate does
/// not depend on `rc-storage`, and so the ordering guarantee below can be tested with
/// an implementation that fails on demand.
///
/// **Called before the confirmation is sent.** If recording fails, the client is told
/// pairing failed and no confirmation is sent, so a client can never end up believing
/// it is paired with an agent that has no record of it.
#[async_trait::async_trait]
pub trait PairingRecorder: Send + Sync {
    /// Persist the outcome. Returning `Err` aborts the exchange.
    ///
    /// # Errors
    /// Implementation-defined; the string is logged, not sent to the peer.
    async fn record(&self, outcome: &PairingOutcome) -> std::result::Result<(), String>;
}

/// Run the client half of the exchange over an established connection.
///
/// The connection must have been made with [`crate::PinPolicy::TrustOnFirstUse`]: the
/// client has nothing to pin yet.
///
/// # Errors
/// [`TransportError::Security`] if the agent's confirmation does not verify — which
/// includes the ordinary case of a mistyped code — or [`TransportError::Closed`]
/// carrying the agent's stated reason for refusing.
pub async fn pair_as_client(
    connection: &quinn::Connection,
    identity: &DeviceIdentity,
    descriptor: DeviceDescriptor,
    code: &PairingCode,
    requested: RequestedPermissions,
    pairing_session_id: Option<PairingSessionId>,
) -> Result<PairedAgent> {
    // From TLS, not from any message. See the module documentation.
    let agent_certificate_fingerprint = crate::peer_certificate_fingerprint(connection)?;

    let (mut writer, mut reader) =
        crate::open_channel(connection, rc_protocol::Channel::Control).await?;

    let public = identity.public();
    let client_nonce = rc_security::OsRandom.bytes();
    let display_name = descriptor.display_name.clone();

    writer
        .send(&Opening::Pairing(Box::new(PairingMessage::Request(
            Box::new(PairRequest {
                pairing_session_id,
                descriptor,
                identity_public_key: public.identity_public_key,
                client_nonce,
                protocol_version: rc_protocol::CURRENT_VERSION,
                requested_permissions: requested.to_wire(),
            }),
        ))))
        .await?;

    let challenge = match next_pairing_message(&mut reader).await? {
        PairingMessage::Challenge(challenge) => *challenge,
        PairingMessage::Failed(failure) => return Err(refused(failure)),
        _ => {
            return Err(TransportError::UnexpectedMessage {
                expected: "pairing challenge",
            });
        }
    };

    // The agent's identity fingerprint is *derived* from the key it sent, never read
    // as a separate field: a peer that could state its own fingerprint independently of
    // its key could state one that does not belong to it.
    let agent_identity_fingerprint = Fingerprint::of_public_key(&challenge.agent_public_key);

    let local_challenge = PairingChallenge {
        pairing_session_id: challenge.pairing_session_id,
        agent_device_id: challenge.agent_device_id,
        agent_identity_fingerprint,
        agent_certificate_fingerprint,
        agent_public_key: challenge.agent_public_key,
        agent_nonce: challenge.agent_nonce,
        verifier_salt: challenge.verifier_salt,
        expires_at_ms: challenge.expires_at_ms,
        expires_in_secs: challenge.expires_in_secs,
    };

    let claim = ClientIdentityClaim {
        device_id: public.device_id,
        public_key: public.identity_public_key,
        // Our own certificate, from our own identity.
        certificate_fingerprint: public.certificate_fingerprint,
        nonce: client_nonce,
        requested_permissions: requested.clone(),
        protocol_version: rc_protocol::CURRENT_VERSION,
        display_name,
    };

    let client = PairingClient::current();
    let transcript = client.build_transcript(&local_challenge, &claim)?;
    let verifier = PairingClient::derive_verifier(code, &local_challenge)?;
    let proof = client.build_proof(identity, &verifier, &transcript)?;

    writer
        .send(&PairingMessage::Proof(PairProof {
            mac: proof.mac,
            signature: Signature64(proof.signature),
        }))
        .await?;

    let confirmation = match next_pairing_message(&mut reader).await? {
        PairingMessage::Confirm(confirm) => *confirm,
        PairingMessage::Failed(failure) => return Err(refused(failure)),
        _ => {
            return Err(TransportError::UnexpectedMessage {
                expected: "pairing confirmation",
            });
        }
    };

    // What the agent says it granted, which may be narrower than what was asked for.
    // Verified as part of the transcript below only insofar as the *request* was; the
    // grant is recorded, not proven, and is deliberately allowed to be smaller.
    let granted = RequestedPermissions::from_wire(&confirmation.granted_permissions)?;
    reject_widened_grant(&requested, &granted)?;

    let paired = client.verify_confirmation(
        &local_challenge,
        &transcript,
        &verifier,
        &AgentConfirmation {
            mac: confirmation.mac,
            signature: confirmation.signature.into(),
        },
        granted,
    )?;

    tracing::info!(
        agent_device_id = %paired.device_id,
        transcript = %paired.transcript_digest,
        "paired with an agent"
    );
    Ok(paired)
}

/// Everything the agent needs to answer a pairing request.
///
/// Bundled rather than passed as loose arguments so that the pieces which must agree —
/// the manager holding the window, the identity the transcript commits to, and the
/// recorder that persists the result — travel together and cannot be mismatched at a
/// call site.
pub struct PairingService<'a> {
    /// Holds the open pairing windows.
    pub manager: &'a PairingManager,
    /// The agent's own identity. Signs the confirmation.
    pub identity: &'a DeviceIdentity,
    /// What the agent tells the client about itself, for display.
    pub descriptor: DeviceDescriptor,
    /// Time source.
    pub clock: &'a dyn Clock,
    /// Persists a completed pairing before the client is told about it.
    pub recorder: &'a dyn PairingRecorder,
}

impl PairingService<'_> {
    /// Run the agent half of the exchange, having already read the opening request.
    ///
    /// `client_certificate_fingerprint` must come from
    /// [`crate::peer_certificate_fingerprint`] on this connection.
    ///
    /// # Errors
    /// Returns the reason the exchange failed **after** having told the peer, so the
    /// caller only has to audit and close.
    pub async fn serve(
        &self,
        reader: &mut ChannelReader,
        writer: &mut ChannelWriter,
        request: &PairRequest,
        client_certificate_fingerprint: Fingerprint,
    ) -> Result<PairingOutcome> {
        let Self {
            manager,
            identity,
            clock,
            recorder,
            ..
        } = *self;
        let agent_descriptor = self.descriptor.clone();

        let session_id = match select_session(manager, request.pairing_session_id, clock) {
            Ok(id) => id,
            Err(failure) => {
                send_failure(writer, failure).await;
                return Err(TransportError::PairingClosed);
            }
        };

        let claim = match build_claim(request, client_certificate_fingerprint) {
            Ok(claim) => claim,
            Err(err) => {
                send_failure(writer, PairFailure::BadRequest).await;
                return Err(err.into());
            }
        };

        let challenge = match manager.submit_client_identity(session_id, claim, identity, clock) {
            Ok(challenge) => challenge,
            Err(err) => {
                send_failure(writer, failure_for(&err)).await;
                return Err(err.into());
            }
        };

        writer
            .send(&PairingMessage::Challenge(Box::new(PairChallenge {
                pairing_session_id: challenge.pairing_session_id,
                descriptor: agent_descriptor,
                agent_device_id: challenge.agent_device_id,
                agent_public_key: challenge.agent_public_key,
                agent_nonce: challenge.agent_nonce,
                verifier_salt: challenge.verifier_salt,
                expires_at_ms: challenge.expires_at_ms,
                expires_in_secs: challenge.expires_in_secs,
            })))
            .await?;

        // Anything other than a proof at this point is a protocol error, not a variant to
        // be accommodated.
        let PairingMessage::Proof(proof) = next_pairing_message(reader).await? else {
            send_failure(writer, PairFailure::BadRequest).await;
            return Err(TransportError::UnexpectedMessage {
                expected: "pairing proof",
            });
        };

        let outcome = match manager.verify_client_proof(
            session_id,
            &ClientProof {
                mac: proof.mac,
                signature: proof.signature.into(),
            },
            identity,
            clock,
        ) {
            Ok(outcome) => outcome,
            Err(err) => {
                send_failure(writer, failure_for(&err)).await;
                return Err(err.into());
            }
        };

        // Persisted before the client is told. The other order would let a storage failure
        // leave a client believing it is paired with an agent that will refuse it.
        if let Err(reason) = recorder.record(&outcome).await {
            tracing::error!(
                %reason,
                pairing_session_id = %session_id,
                "could not record a completed pairing; refusing to confirm it"
            );
            send_failure(writer, PairFailure::BadRequest).await;
            return Err(TransportError::Io { reason });
        }

        writer
            .send(&PairingMessage::Confirm(Box::new(PairConfirm {
                mac: outcome.confirmation.mac,
                signature: Signature64(outcome.confirmation.signature),
                granted_permissions: outcome.granted_permissions.to_wire(),
            })))
            .await?;

        Ok(outcome)
    }
}

/// Decide which pairing window an incoming request belongs to.
fn select_session(
    manager: &PairingManager,
    requested: Option<PairingSessionId>,
    clock: &dyn Clock,
) -> std::result::Result<PairingSessionId, PairFailure> {
    let open = manager.open_session_ids(clock);

    match requested {
        // A named window must actually be open. Accepting a name for a closed window
        // and reporting a later failure would tell the caller which ids exist.
        Some(id) if open.contains(&id) => Ok(id),
        Some(_) => Err(PairFailure::CodeExpired),
        None => match open.as_slice() {
            [only] => Ok(*only),
            [] => Err(PairFailure::NotInPairingMode),
            // Never guess. Picking one would let a client spend the attempt budget of
            // a window whose code it was never given.
            _ => Err(PairFailure::BadRequest),
        },
    }
}

/// Turn the wire request into the claim the security layer verifies.
fn build_claim(
    request: &PairRequest,
    client_certificate_fingerprint: Fingerprint,
) -> std::result::Result<ClientIdentityClaim, SecurityError> {
    // The claimed id must be the one derived from the presented key. The security layer
    // checks this too; checking here means a mismatched claim never reaches it.
    let derived = derive_device_id(&request.identity_public_key);
    if derived != request.descriptor.device_id {
        return Err(SecurityError::IdentityMismatch);
    }

    Ok(ClientIdentityClaim {
        device_id: derived,
        public_key: request.identity_public_key,
        // From TLS. Never `request.descriptor.certificate_fingerprint`, which the peer
        // chose and which is carried only for display.
        certificate_fingerprint: client_certificate_fingerprint,
        nonce: request.client_nonce,
        requested_permissions: RequestedPermissions::from_wire(&request.requested_permissions)?,
        protocol_version: request.protocol_version,
        display_name: request.descriptor.display_name.clone(),
    })
}

/// Refuse a grant that is wider than what was requested.
///
/// The client committed to a specific permission set in the transcript. An agent that
/// answers with a *broader* set is either misbehaving or being impersonated, and
/// silently accepting it would mean recording authority the operator never approved.
/// A narrower grant is fine, and expected.
fn reject_widened_grant(
    requested: &RequestedPermissions,
    granted: &RequestedPermissions,
) -> Result<()> {
    if granted.role != requested.role {
        return Err(TransportError::Security(SecurityError::PermissionDenied {
            capability: "role",
        }));
    }

    for capability in &granted.capabilities {
        if !requested.capabilities.contains(capability) {
            return Err(TransportError::Security(SecurityError::PermissionDenied {
                capability: capability.name(),
            }));
        }
    }
    Ok(())
}

/// Read the next pairing message, bounded by the step timeout.
async fn next_pairing_message(reader: &mut ChannelReader) -> Result<PairingMessage> {
    let deadline = std::time::Duration::from_secs(PAIRING_STEP_TIMEOUT_SECS);

    tokio::time::timeout(deadline, reader.next_message())
        .await
        .map_err(|_| TransportError::HandshakeTimeout)?
        .and_then(|message| {
            message.ok_or(TransportError::UnexpectedMessage {
                expected: "a pairing message",
            })
        })
}

/// Tell the peer the exchange failed. Best-effort: the connection is ending.
async fn send_failure(writer: &mut ChannelWriter, failure: PairFailure) {
    if let Err(err) = writer.send(&PairingMessage::Failed(failure)).await {
        tracing::debug!(%err, "could not deliver a pairing failure");
    }
}

/// Map a security error onto what the peer is told.
///
/// A rejected proof and a wrong code produce the same value, deliberately: the agent
/// must not be usable as an oracle for guessing codes.
const fn failure_for(err: &SecurityError) -> PairFailure {
    match err {
        SecurityError::PairingAttemptsExhausted => PairFailure::TooManyAttempts,
        SecurityError::PairingExpired | SecurityError::PairingAlreadyConsumed => {
            PairFailure::CodeExpired
        }
        SecurityError::PairingSessionUnknown => PairFailure::NotInPairingMode,
        SecurityError::ProofRejected | SecurityError::BadSignature => PairFailure::ProofRejected,
        _ => PairFailure::BadRequest,
    }
}

/// Turn the agent's stated refusal into an error carrying its explanation.
fn refused(failure: PairFailure) -> TransportError {
    TransportError::Closed {
        reason: failure.describe().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use rc_security::pairing::PairingPolicy;
    use rc_security::permissions::{Capability, Role};
    use rc_security::{OsRandom, SystemClock};

    use super::*;

    fn identity(name: &str) -> DeviceIdentity {
        DeviceIdentity::generate(name, &SystemClock).unwrap()
    }

    fn manager_with_one_window() -> (PairingManager, PairingSessionId, PairingCode) {
        let manager = PairingManager::with_defaults();
        let opened = manager.begin_pairing(&SystemClock, &OsRandom).unwrap();
        (manager, opened.pairing_session_id, opened.code)
    }

    #[test]
    fn a_request_naming_the_open_window_selects_it() {
        let (manager, id, _code) = manager_with_one_window();
        assert_eq!(select_session(&manager, Some(id), &SystemClock), Ok(id));
    }

    #[test]
    fn a_request_naming_no_window_selects_the_only_open_one() {
        // The ordinary case: the operator types a code, not a session id.
        let (manager, id, _code) = manager_with_one_window();
        assert_eq!(select_session(&manager, None, &SystemClock), Ok(id));
    }

    #[test]
    fn a_request_with_no_window_open_is_told_pairing_is_closed() {
        let manager = PairingManager::with_defaults();
        assert_eq!(
            select_session(&manager, None, &SystemClock),
            Err(PairFailure::NotInPairingMode)
        );
    }

    #[test]
    fn a_request_naming_an_unknown_window_is_not_told_which_windows_exist() {
        // The reply must be the same as for a window that expired, so the id space
        // cannot be probed.
        let (manager, _id, _code) = manager_with_one_window();
        let outcome = select_session(&manager, Some(PairingSessionId::generate()), &SystemClock);
        assert_eq!(outcome, Err(PairFailure::CodeExpired));
    }

    #[test]
    fn several_open_windows_and_no_named_one_is_refused_rather_than_guessed() {
        // Guessing would let a client spend the attempt budget of a window whose code
        // it was never given.
        let manager = PairingManager::new(PairingPolicy::default());
        manager.begin_pairing(&SystemClock, &OsRandom).unwrap();
        manager.begin_pairing(&SystemClock, &OsRandom).unwrap();

        assert_eq!(
            select_session(&manager, None, &SystemClock),
            Err(PairFailure::BadRequest)
        );
    }

    fn sample_request(client: &DeviceIdentity) -> PairRequest {
        let public = client.public();
        PairRequest {
            pairing_session_id: None,
            descriptor: DeviceDescriptor {
                device_id: public.device_id,
                display_name: "Test Client".to_owned(),
                hostname: "test".to_owned(),
                os_family: rc_protocol::control::OsFamily::Windows,
                os_version: "test".to_owned(),
                app_version: "0.1.0".to_owned(),
                certificate_fingerprint: public.certificate_fingerprint.to_hex(),
            },
            identity_public_key: public.identity_public_key,
            client_nonce: [1u8; 32],
            protocol_version: rc_protocol::CURRENT_VERSION,
            requested_permissions: RequestedPermissions::full(Role::Operator).to_wire(),
        }
    }

    #[test]
    fn the_claim_uses_the_observed_certificate_not_the_one_in_the_message() {
        // The anti-relay property lives or dies here.
        let client = identity("client");
        let attacker_visible = Fingerprint::of_certificate_der(b"what-tls-actually-saw");

        let claim = build_claim(&sample_request(&client), attacker_visible).unwrap();

        assert_eq!(claim.certificate_fingerprint, attacker_visible);
        assert_ne!(
            claim.certificate_fingerprint,
            client.public().certificate_fingerprint,
            "the message's self-reported fingerprint must be ignored"
        );
    }

    #[test]
    fn a_claim_whose_device_id_does_not_match_its_key_is_refused() {
        let client = identity("client");
        let other = identity("other");

        let mut request = sample_request(&client);
        request.descriptor.device_id = other.public().device_id;

        assert!(matches!(
            build_claim(&request, client.public().certificate_fingerprint),
            Err(SecurityError::IdentityMismatch)
        ));
    }

    #[test]
    fn a_narrower_grant_than_requested_is_accepted() {
        let requested = RequestedPermissions::full(Role::Operator);
        let granted = RequestedPermissions {
            role: Role::Operator,
            capabilities: vec![Capability::RemoteDesktopView],
        };
        reject_widened_grant(&requested, &granted).unwrap();
    }

    #[test]
    fn a_grant_wider_than_requested_is_refused() {
        // Recording authority the operator never approved is not something to accept
        // quietly, even from an agent that has proved it knows the code.
        let requested = RequestedPermissions {
            role: Role::Operator,
            capabilities: vec![Capability::RemoteDesktopView],
        };
        let granted = RequestedPermissions::full(Role::Operator);

        assert!(reject_widened_grant(&requested, &granted).is_err());
    }

    #[test]
    fn a_grant_with_a_different_role_is_refused() {
        let requested = RequestedPermissions::full(Role::ViewOnly);
        let granted = RequestedPermissions::full(Role::Owner);
        assert!(reject_widened_grant(&requested, &granted).is_err());
    }

    #[test]
    fn a_wrong_code_and_a_bad_signature_are_reported_identically() {
        assert_eq!(
            failure_for(&SecurityError::ProofRejected),
            failure_for(&SecurityError::BadSignature)
        );
    }

    #[test]
    fn exhaustion_and_expiry_are_distinguishable_from_a_rejected_proof() {
        // These say something operationally different and are not oracles: they are
        // states the operator already knows about.
        assert_eq!(
            failure_for(&SecurityError::PairingAttemptsExhausted),
            PairFailure::TooManyAttempts
        );
        assert_eq!(
            failure_for(&SecurityError::PairingExpired),
            PairFailure::CodeExpired
        );
        assert_ne!(
            failure_for(&SecurityError::PairingExpired),
            failure_for(&SecurityError::ProofRejected)
        );
    }

    #[test]
    fn a_consumed_session_looks_the_same_as_an_expired_one() {
        // Otherwise a replayed proof would confirm that a pairing had succeeded.
        assert_eq!(
            failure_for(&SecurityError::PairingAlreadyConsumed),
            failure_for(&SecurityError::PairingExpired)
        );
    }
}
