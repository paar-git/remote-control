//! The agent-side pairing state machine.
//!
//! # Lifecycle
//!
//! ```text
//!   begin_pairing()          submit_client_identity()      verify_client_proof()
//!  ─────────────────►  Open  ────────────────────────►  Challenged  ──────────────►  Consumed
//!                       │                                    │                  (terminal)
//!                       │  expiry / cancel                   │  bad proof ×5
//!                       ▼                                    ▼
//!                    Expired                            AttemptsExhausted
//!                   (terminal)                             (terminal)
//! ```
//!
//! Every terminal state is final. A consumed session cannot be completed twice, an
//! expired one cannot be revived, and an exhausted one is destroyed rather than left
//! for the attacker to keep guessing at.
//!
//! # Concurrency
//!
//! Consumption is **atomic**. [`PairingManager`] holds its sessions behind a single
//! mutex and transitions `Challenged → Consumed` inside the same critical section that
//! verifies the proof, so two concurrent requests bearing the same valid proof cannot
//! both succeed — the second observes `Consumed` and is rejected.
//!
//! # Lifetime
//!
//! Sessions live in memory only. A restart therefore invalidates every open pairing
//! window, which is the safe default: a code displayed before a crash should not still
//! be usable afterwards. Audit rows recording that a code was created and how it ended
//! are written to the database separately, and contain no usable secret.

use std::collections::HashMap;
use std::sync::Mutex;

use rc_protocol::{DeviceId, PairingSessionId, ProtocolVersion};

use crate::clock::{Clock, RandomSource, RandomSourceExt as _};
use crate::error::{Result, SecurityError};
use crate::fingerprint::Fingerprint;
use crate::identity::{DeviceIdentity, derive_device_id};
use crate::pairing::code::{CodeVerifier, PairingCode};
use crate::pairing::transcript::{
    AGENT_PROOF_LABEL, CLIENT_PROOF_LABEL, RequestedPermissions, Transcript, TranscriptInputs,
};

/// Default pairing window, in seconds.
pub const DEFAULT_PAIRING_TTL_SECS: u64 = 180;

/// Default cap on failed proof submissions before a code is destroyed.
pub const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Maximum pairing sessions open at once, bounding memory.
pub const MAX_CONCURRENT_SESSIONS: usize = 4;

/// Longest pairing window this build will ever open, in seconds.
///
/// A hard ceiling rather than a default. `PairingPolicy::ttl_secs` is what an operator
/// gets when they do not say; this is what they cannot exceed when they do. Fifteen
/// minutes is long enough to walk between two machines and short enough that a window
/// left open by mistake closes on its own within a coffee break.
pub const MAX_PAIRING_TTL_SECS: u64 = 900;

/// Shortest pairing window this build will open, in seconds.
///
/// Below this the operator cannot realistically finish typing, and a window that
/// expires mid-exchange is indistinguishable from a wrong code.
pub const MIN_PAIRING_TTL_SECS: u64 = 30;

/// Tunable pairing parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingPolicy {
    /// How long a code stays valid, in seconds.
    pub ttl_secs: u64,
    /// Failed proof submissions tolerated before the code is destroyed.
    pub max_attempts: u32,
    /// Concurrent open sessions permitted.
    pub max_sessions: usize,
}

impl Default for PairingPolicy {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_PAIRING_TTL_SECS,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            max_sessions: MAX_CONCURRENT_SESSIONS,
        }
    }
}

/// Observable state of a pairing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PairingState {
    /// A code has been issued; no client has presented itself yet.
    Open,
    /// A client has submitted its identity and been given a challenge.
    Challenged,
    /// Pairing completed successfully. Terminal.
    Consumed,
    /// The window closed before the code was used. Terminal.
    Expired,
    /// Too many failed attempts. Terminal.
    AttemptsExhausted,
    /// Cancelled by the operator. Terminal.
    Cancelled,
}

impl PairingState {
    /// Whether no further transitions are possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Consumed | Self::Expired | Self::AttemptsExhausted | Self::Cancelled
        )
    }
}

/// What the client learns when it presents itself.
#[derive(Debug, Clone)]
pub struct PairingChallenge {
    /// Which pairing exchange this is.
    pub pairing_session_id: PairingSessionId,
    /// The agent's identity, for the client to pin.
    pub agent_device_id: DeviceId,
    /// Agent's identity-key fingerprint.
    pub agent_identity_fingerprint: Fingerprint,
    /// Agent's certificate fingerprint.
    pub agent_certificate_fingerprint: Fingerprint,
    /// Agent's Ed25519 public key.
    pub agent_public_key: [u8; 32],
    /// Agent's fresh nonce.
    pub agent_nonce: [u8; 32],
    /// Salt the client needs to derive the same code verifier.
    pub verifier_salt: [u8; 16],
    /// When this session expires, milliseconds since the Unix epoch.
    pub expires_at_ms: i64,
    /// Seconds remaining, for display.
    pub expires_in_secs: u64,
}

/// What the client submits to identify itself.
#[derive(Debug, Clone)]
pub struct ClientIdentityClaim {
    /// Client's claimed device id. Verified against its public key.
    pub device_id: DeviceId,
    /// Client's Ed25519 public key.
    pub public_key: [u8; 32],
    /// Client's certificate fingerprint, as observed on its TLS connection.
    pub certificate_fingerprint: Fingerprint,
    /// Client's fresh nonce.
    pub nonce: [u8; 32],
    /// Permissions being requested.
    pub requested_permissions: RequestedPermissions,
    /// Protocol version the client speaks.
    pub protocol_version: ProtocolVersion,
    /// Human-readable name the client wants recorded.
    pub display_name: String,
}

/// The client's proof that it knows the pairing code.
#[derive(Debug, Clone)]
pub struct ClientProof {
    /// MAC over the transcript, keyed by the code verifier.
    pub mac: [u8; 32],
    /// Ed25519 signature over the transcript by the client's identity key.
    pub signature: [u8; 64],
}

/// The agent's confirmation, proving it also knew the code.
#[derive(Debug, Clone)]
pub struct AgentConfirmation {
    /// MAC over the transcript under the agent's label.
    pub mac: [u8; 32],
    /// Ed25519 signature over the transcript by the agent's identity key.
    pub signature: [u8; 64],
}

/// The result of a successful pairing: everything needed to record trust.
#[derive(Debug, Clone)]
pub struct PairingOutcome {
    /// Which exchange completed.
    pub pairing_session_id: PairingSessionId,
    /// The newly trusted client's device id.
    pub client_device_id: DeviceId,
    /// Its identity public key.
    pub client_public_key: [u8; 32],
    /// Its identity fingerprint — the value to pin.
    pub client_identity_fingerprint: Fingerprint,
    /// Its certificate fingerprint at pairing time.
    pub client_certificate_fingerprint: Fingerprint,
    /// The name it asked to be recorded under. Untrusted; sanitise before display.
    pub client_display_name: String,
    /// Permissions granted.
    pub granted_permissions: RequestedPermissions,
    /// The agent's confirmation, to be returned to the client.
    pub confirmation: AgentConfirmation,
    /// Short digest of the transcript, safe to log for correlation.
    pub transcript_digest: String,
}

/// One in-flight pairing exchange.
///
/// The session id is not stored here: it is the key of the map that owns this value, and
/// duplicating it would allow the two to drift apart.
#[derive(Debug)]
struct PairingSession {
    state: PairingState,
    verifier: CodeVerifier,
    agent_nonce: [u8; 32],
    created_at_ms: i64,
    expires_at_ms: i64,
    failed_attempts: u32,
    /// Populated once the client has presented itself.
    client: Option<ClientIdentityClaim>,
}

impl PairingSession {
    /// Move to a terminal state if the window has closed.
    fn refresh(&mut self, now_ms: i64) {
        if !self.state.is_terminal() && now_ms >= self.expires_at_ms {
            self.state = PairingState::Expired;
        }
    }

    /// Map the current state onto the error a caller should see.
    const fn state_error(&self) -> SecurityError {
        match self.state {
            PairingState::Consumed => SecurityError::PairingAlreadyConsumed,
            PairingState::Expired | PairingState::Cancelled => SecurityError::PairingExpired,
            PairingState::AttemptsExhausted => SecurityError::PairingAttemptsExhausted,
            PairingState::Open | PairingState::Challenged => SecurityError::PairingWrongState,
        }
    }
}

/// A newly opened pairing window.
pub struct OpenedPairing {
    /// Identifier for the exchange.
    pub pairing_session_id: PairingSessionId,
    /// The code to show the operator. Display only; never log it.
    pub code: PairingCode,
    /// When the window closes.
    pub expires_at_ms: i64,
    /// Hex verifier and salt, for the audit/state row. Contains no usable code.
    pub verifier_hex: String,
    /// Hex salt.
    pub salt_hex: String,
}

/// Owns every in-flight pairing exchange for one agent.
#[derive(Debug)]
pub struct PairingManager {
    policy: PairingPolicy,
    sessions: Mutex<HashMap<PairingSessionId, PairingSession>>,
}

impl PairingManager {
    /// A manager using `policy`.
    #[must_use]
    pub fn new(policy: PairingPolicy) -> Self {
        Self {
            policy,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// A manager using the default policy.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PairingPolicy::default())
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &PairingPolicy {
        &self.policy
    }

    /// Number of sessions currently tracked, expired ones included until swept.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map_or(0, |s| s.len())
    }

    /// Every session that is still usable, newest first.
    ///
    /// The agent needs this to answer a client that connected without naming a session
    /// id — the ordinary case, since the operator types a code, not a UUID. When more
    /// than one window is open the caller must **refuse** rather than pick: guessing
    /// would let a client aim its attempt at a window whose code it was not given, and
    /// spend that window's attempt budget.
    #[must_use]
    pub fn open_session_ids(&self, clock: &dyn Clock) -> Vec<PairingSessionId> {
        let now = clock.now_ms();
        let Ok(mut sessions) = self.sessions.lock() else {
            return Vec::new();
        };

        let mut open: Vec<(PairingSessionId, i64)> = sessions
            .iter_mut()
            .filter_map(|(id, session)| {
                session.refresh(now);
                (!session.state.is_terminal()).then_some((*id, session.created_at_ms))
            })
            .collect();

        open.sort_by_key(|(_, created_at)| std::cmp::Reverse(*created_at));
        open.into_iter().map(|(id, _)| id).collect()
    }

    /// Open a pairing window and generate a code.
    ///
    /// # Errors
    /// [`SecurityError::Invalid`] if too many windows are already open, or a hashing
    /// failure while deriving the verifier.
    pub fn begin_pairing(
        &self,
        clock: &dyn Clock,
        rng: &dyn RandomSource,
    ) -> Result<OpenedPairing> {
        self.begin_pairing_with_ttl(clock, rng, self.policy.ttl_secs)
    }

    /// Open a pairing window with an operator-chosen lifetime.
    ///
    /// The manager is shared and long-lived, so its policy cannot be replaced per
    /// request; the TTL is passed instead. It is clamped into
    /// [`MIN_PAIRING_TTL_SECS`]..=[`MAX_PAIRING_TTL_SECS`] here as well as validated by
    /// the caller, so no path can open a window longer than this build allows.
    ///
    /// # Errors
    /// As [`PairingManager::begin_pairing`].
    pub fn begin_pairing_with_ttl(
        &self,
        clock: &dyn Clock,
        rng: &dyn RandomSource,
        ttl_secs: u64,
    ) -> Result<OpenedPairing> {
        let ttl_secs = ttl_secs.clamp(MIN_PAIRING_TTL_SECS, MAX_PAIRING_TTL_SECS);
        let now = clock.now_ms();
        let mut sessions = self.lock()?;

        // Sweep first so expired windows do not occupy the budget.
        sessions.retain(|_, session| {
            session.refresh(now);
            !session.state.is_terminal()
        });

        if sessions.len() >= self.policy.max_sessions {
            return Err(SecurityError::Invalid {
                field: "pairing",
                reason: "too many pairing windows are already open",
            });
        }

        let code = PairingCode::generate(rng);
        let salt = PairingCode::generate_salt(rng);
        let verifier = code.derive_verifier(&salt)?;

        let id = PairingSessionId::generate();
        let expires_at_ms =
            now.saturating_add(i64::try_from(ttl_secs.saturating_mul(1000)).unwrap_or(i64::MAX));

        let opened = OpenedPairing {
            pairing_session_id: id,
            expires_at_ms,
            verifier_hex: verifier.to_storage_hex(),
            salt_hex: verifier.salt_to_storage_hex(),
            code,
        };

        sessions.insert(
            id,
            PairingSession {
                state: PairingState::Open,
                verifier,
                agent_nonce: rng.bytes(),
                created_at_ms: now,
                expires_at_ms,
                failed_attempts: 0,
                client: None,
            },
        );

        // The code itself is never logged — only that a window opened.
        tracing::info!(
            pairing_session_id = %id,
            ttl_secs,
            "pairing window opened"
        );

        Ok(opened)
    }

    /// Record the client's identity and return the challenge.
    ///
    /// # Errors
    /// Fails if the session is unknown or terminal, if the claimed device id does not
    /// match the presented public key, or if the requested permissions are invalid.
    pub fn submit_client_identity(
        &self,
        pairing_session_id: PairingSessionId,
        claim: ClientIdentityClaim,
        agent_identity: &DeviceIdentity,
        clock: &dyn Clock,
    ) -> Result<PairingChallenge> {
        // A client could otherwise claim any device id it liked and have it recorded
        // as trusted; binding the id to the key makes the claim self-certifying.
        if claim.device_id != derive_device_id(&claim.public_key) {
            return Err(SecurityError::IdentityMismatch);
        }
        claim.requested_permissions.validate()?;
        validate_display_name(&claim.display_name)?;

        let now = clock.now_ms();
        let mut sessions = self.lock()?;
        let session = sessions
            .get_mut(&pairing_session_id)
            .ok_or(SecurityError::PairingSessionUnknown)?;

        session.refresh(now);
        if session.state.is_terminal() {
            return Err(session.state_error());
        }

        session.state = PairingState::Challenged;
        session.client = Some(claim);

        let public = agent_identity.public();
        Ok(PairingChallenge {
            pairing_session_id,
            agent_device_id: public.device_id,
            agent_identity_fingerprint: public.identity_fingerprint,
            agent_certificate_fingerprint: public.certificate_fingerprint,
            agent_public_key: public.identity_public_key,
            agent_nonce: session.agent_nonce,
            verifier_salt: *session.verifier.salt(),
            expires_at_ms: session.expires_at_ms,
            expires_in_secs: session.expires_at_ms.saturating_sub(now).unsigned_abs() / 1000,
        })
    }

    /// Verify the client's proof and, on success, consume the session atomically.
    ///
    /// # Errors
    /// [`SecurityError::ProofRejected`] for a bad proof or wrong code — the two are
    /// deliberately indistinguishable. Other variants cover expiry, exhaustion and
    /// duplicate completion.
    pub fn verify_client_proof(
        &self,
        pairing_session_id: PairingSessionId,
        proof: &ClientProof,
        agent_identity: &DeviceIdentity,
        clock: &dyn Clock,
    ) -> Result<PairingOutcome> {
        let now = clock.now_ms();

        // The whole verify-and-consume sequence happens under one lock, so two
        // concurrent submissions of the same valid proof cannot both succeed.
        let mut sessions = self.lock()?;
        let session = sessions
            .get_mut(&pairing_session_id)
            .ok_or(SecurityError::PairingSessionUnknown)?;

        session.refresh(now);
        if session.state.is_terminal() {
            return Err(session.state_error());
        }
        if session.state != PairingState::Challenged {
            return Err(SecurityError::PairingWrongState);
        }

        let claim = session
            .client
            .clone()
            .ok_or(SecurityError::PairingWrongState)?;
        let agent_public = agent_identity.public();

        let transcript = Transcript::build(&TranscriptInputs {
            protocol_version: claim.protocol_version,
            pairing_session_id,
            agent_device_id: agent_public.device_id,
            client_device_id: claim.device_id,
            agent_identity_fingerprint: agent_public.identity_fingerprint,
            client_identity_fingerprint: Fingerprint::of_public_key(&claim.public_key),
            agent_certificate_fingerprint: agent_public.certificate_fingerprint,
            client_certificate_fingerprint: claim.certificate_fingerprint,
            agent_nonce: session.agent_nonce,
            client_nonce: claim.nonce,
            expires_at_ms: session.expires_at_ms,
            requested_permissions: claim.requested_permissions.clone(),
        })?;

        // Both checks must pass: the MAC proves knowledge of the code, the signature
        // proves possession of the identity private key. Neither alone is sufficient.
        let mac_ok = transcript
            .verify_mac(
                session.verifier.as_key_material(),
                CLIENT_PROOF_LABEL,
                &proof.mac,
            )
            .is_ok();
        let signature_ok = verify_client_signature(&claim.public_key, &transcript, proof).is_ok();

        if !(mac_ok && signature_ok) {
            session.failed_attempts = session.failed_attempts.saturating_add(1);
            let exhausted = session.failed_attempts >= self.policy.max_attempts;
            if exhausted {
                session.state = PairingState::AttemptsExhausted;
            }

            tracing::warn!(
                pairing_session_id = %pairing_session_id,
                attempt = session.failed_attempts,
                max_attempts = self.policy.max_attempts,
                exhausted,
                "pairing proof rejected"
            );

            return Err(if exhausted {
                SecurityError::PairingAttemptsExhausted
            } else {
                SecurityError::ProofRejected
            });
        }

        // Atomic consumption: the state flips before the lock is released.
        session.state = PairingState::Consumed;

        let confirmation = AgentConfirmation {
            mac: transcript.compute_mac(session.verifier.as_key_material(), AGENT_PROOF_LABEL),
            signature: agent_identity.sign(AGENT_PROOF_LABEL, transcript.as_bytes()),
        };

        let digest = transcript.digest_short();
        tracing::info!(
            pairing_session_id = %pairing_session_id,
            client_device_id = %claim.device_id,
            transcript = %digest,
            role = claim.requested_permissions.role.name(),
            "pairing completed"
        );

        Ok(PairingOutcome {
            pairing_session_id,
            client_device_id: claim.device_id,
            client_public_key: claim.public_key,
            client_identity_fingerprint: Fingerprint::of_public_key(&claim.public_key),
            client_certificate_fingerprint: claim.certificate_fingerprint,
            client_display_name: claim.display_name,
            granted_permissions: claim.requested_permissions,
            confirmation,
            transcript_digest: digest,
        })
    }

    /// Cancel an open window.
    ///
    /// # Errors
    /// [`SecurityError::PairingSessionUnknown`] if there is no such session.
    pub fn cancel(&self, pairing_session_id: PairingSessionId) -> Result<()> {
        let mut sessions = self.lock()?;
        let session = sessions
            .get_mut(&pairing_session_id)
            .ok_or(SecurityError::PairingSessionUnknown)?;

        if !session.state.is_terminal() {
            session.state = PairingState::Cancelled;
            tracing::info!(pairing_session_id = %pairing_session_id, "pairing window cancelled");
        }
        Ok(())
    }

    /// Current state of a session, if it is still tracked.
    #[must_use]
    pub fn state_of(
        &self,
        pairing_session_id: PairingSessionId,
        clock: &dyn Clock,
    ) -> Option<PairingState> {
        let now = clock.now_ms();
        let mut sessions = self.sessions.lock().ok()?;
        let session = sessions.get_mut(&pairing_session_id)?;
        session.refresh(now);
        Some(session.state)
    }

    /// Drop terminal sessions. Returns how many were removed.
    pub fn sweep(&self, clock: &dyn Clock) -> usize {
        let now = clock.now_ms();
        let Ok(mut sessions) = self.sessions.lock() else {
            return 0;
        };

        let before = sessions.len();
        sessions.retain(|_, session| {
            session.refresh(now);
            !session.state.is_terminal()
        });
        before - sessions.len()
    }

    /// When a session was opened, for audit records.
    #[must_use]
    pub fn created_at_ms(&self, pairing_session_id: PairingSessionId) -> Option<i64> {
        self.sessions
            .lock()
            .ok()?
            .get(&pairing_session_id)
            .map(|s| s.created_at_ms)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<PairingSessionId, PairingSession>>> {
        // A poisoned mutex means a previous holder panicked mid-transition. Refusing
        // to proceed is the safe response: the state may be half-updated.
        self.sessions.lock().map_err(|_| SecurityError::Invalid {
            field: "pairing manager",
            reason: "internal state is unusable after a previous failure",
        })
    }
}

impl Default for PairingManager {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Verify the client's Ed25519 signature over the transcript.
fn verify_client_signature(
    public_key: &[u8; 32],
    transcript: &Transcript,
    proof: &ClientProof,
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    let verifying =
        VerifyingKey::from_bytes(public_key).map_err(|_| SecurityError::MalformedIdentity)?;

    // Must match `DeviceIdentity::sign`'s framing exactly.
    let mut message =
        Vec::with_capacity(4 + CLIENT_PROOF_LABEL.len() + transcript.as_bytes().len());
    message.extend_from_slice(
        &u32::try_from(CLIENT_PROOF_LABEL.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    message.extend_from_slice(CLIENT_PROOF_LABEL);
    message.extend_from_slice(transcript.as_bytes());

    verifying
        .verify(&message, &Signature::from_bytes(&proof.signature))
        .map_err(|_| SecurityError::BadSignature)
}

/// Reject display names that would be unsafe or useless to store.
fn validate_display_name(name: &str) -> Result<()> {
    if name.trim().is_empty() {
        return Err(SecurityError::Invalid {
            field: "device name",
            reason: "must not be empty",
        });
    }
    if name.len() > rc_protocol::limits::MAX_DEVICE_NAME_BYTES {
        return Err(SecurityError::Invalid {
            field: "device name",
            reason: "is too long",
        });
    }
    if name.chars().any(char::is_control) {
        return Err(SecurityError::Invalid {
            field: "device name",
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::clock::{DeterministicRandom, OsRandom, SystemClock, TestClock};

    use super::*;

    #[test]
    fn an_operator_chosen_window_is_honoured_within_the_build_limits() {
        let manager = PairingManager::with_defaults();
        let clock = TestClock::default();
        let rng = DeterministicRandom::default();

        let opened = manager.begin_pairing_with_ttl(&clock, &rng, 300).unwrap();

        let remaining_secs = (opened.expires_at_ms - clock.now_ms()) / 1000;
        assert!(
            (295..=300).contains(&remaining_secs),
            "expected roughly 300 seconds, got {remaining_secs}"
        );
    }

    #[test]
    fn an_over_long_window_is_clamped_rather_than_granted() {
        // A request is validated by the caller *and* clamped here, so no path can open
        // a window longer than this build allows.
        let manager = PairingManager::with_defaults();
        let clock = TestClock::default();
        let rng = DeterministicRandom::default();

        let opened = manager
            .begin_pairing_with_ttl(&clock, &rng, u64::MAX)
            .unwrap();

        let remaining_secs = (opened.expires_at_ms - clock.now_ms()) / 1000;
        assert!(
            remaining_secs <= i64::try_from(MAX_PAIRING_TTL_SECS).unwrap(),
            "got {remaining_secs}"
        );
    }

    #[test]
    fn an_impossibly_short_window_is_raised_to_the_floor() {
        let manager = PairingManager::with_defaults();
        let clock = TestClock::default();
        let rng = DeterministicRandom::default();

        let opened = manager.begin_pairing_with_ttl(&clock, &rng, 0).unwrap();

        let remaining_secs = (opened.expires_at_ms - clock.now_ms()) / 1000;
        assert!(
            remaining_secs >= i64::try_from(MIN_PAIRING_TTL_SECS).unwrap(),
            "a window that expires before it can be typed is not a window: got {remaining_secs}"
        );
    }

    #[test]
    fn open_windows_are_listed_newest_first_and_terminal_ones_are_not_listed() {
        let manager = PairingManager::with_defaults();
        let clock = SystemClock;

        let first = manager.begin_pairing(&clock, &OsRandom).unwrap();
        let second = manager.begin_pairing(&clock, &OsRandom).unwrap();

        let open = manager.open_session_ids(&clock);
        assert_eq!(open.len(), 2);
        assert!(open.contains(&first.pairing_session_id));
        assert!(open.contains(&second.pairing_session_id));

        manager.cancel(first.pairing_session_id).unwrap();
        let after = manager.open_session_ids(&clock);
        assert_eq!(after, vec![second.pairing_session_id]);
    }
}
