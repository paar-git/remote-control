//! Agent identity and pairing entry points.
//!
//! These back the `identity` and `pair` subcommands. Pairing sessions live in memory
//! and die with the process, so the `pair` command holds the window open for its
//! lifetime and prints the code to the console — the one sanctioned path by which a
//! code becomes visible. The code is never written to the log.

use anyhow::Context as _;
use rc_protocol::{DeviceId, PairingSessionId};
use rc_security::pairing::{ClientProof, PairingManager, PairingOutcome, PairingPolicy};
use rc_security::{Clock, DeviceIdentity, Keystore, OsRandom, SecurityError, SystemClock};
use rc_storage::audit::{AuditCategory, AuditEvent, AuditRepository, AuditResult, actions};
use rc_storage::models::PeerRoleRow;
use rc_storage::trust::TrustRepository;

use crate::config::AgentConfig;

/// How the identity returned by [`load_identity`] came to be.
///
/// The caller needs this to audit correctly: creating an identity is a one-time,
/// security-significant event, whereas loading one happens on every start and would
/// drown the trail if recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOrigin {
    /// No keystore existed; a new identity was generated.
    Created,
    /// An existing identity was loaded unchanged.
    Loaded,
    /// An existing identity was loaded and its certificate reissued. The device id and
    /// identity fingerprint are unchanged, so trust is preserved.
    CertificateRenewed,
}

/// Load the agent's identity, creating it on first run.
///
/// Returns the identity together with how it was obtained, so the caller can write the
/// matching audit record once the database is open.
///
/// # Errors
/// Fails if the keystore is corrupt, has unsafe permissions, or was written under a
/// different OS identity. It never silently regenerates: doing so would change the
/// agent's identity and break every existing pairing.
pub fn load_identity(
    paths: &rc_platform::AppPaths,
    config: &AgentConfig,
) -> anyhow::Result<(DeviceIdentity, IdentityOrigin)> {
    let keystore = Keystore::in_data_dir(paths.data_dir());
    let clock = SystemClock;

    // Sampled before `load_or_create`, which is what makes creation distinguishable
    // from an ordinary load.
    let existed = keystore.exists();

    let identity = keystore
        .load_or_create(&config.device_name, &clock)
        .context("could not load or create the agent identity")?;

    // A certificate that has expired, or is about to, is renewed in place. The device
    // id and identity fingerprint are preserved, so paired clients are unaffected.
    let public = identity.public();
    if existed && public.needs_renewal_at(clock.now_ms()) {
        tracing::info!(
            expires_at_ms = public.certificate_not_after_ms,
            "certificate is due for renewal; issuing a new one"
        );
        let renewed = identity
            .renew_certificate(&config.device_name, &clock)
            .context("could not renew the device certificate")?;
        keystore
            .store(&renewed, &config.device_name, &clock)
            .context("could not persist the renewed certificate")?;
        return Ok((renewed, IdentityOrigin::CertificateRenewed));
    }

    let origin = if existed {
        IdentityOrigin::Loaded
    } else {
        IdentityOrigin::Created
    };
    Ok((identity, origin))
}

/// Write the audit record for how the identity was obtained.
///
/// A plain load produces no record: it happens on every start, and a trail that logs
/// every boot buries the events that matter. Only creation and renewal are recorded,
/// and neither carries key material — the device id and identity fingerprint are both
/// public values a client is expected to see.
///
/// # Errors
/// Propagates a failure to write the audit row. Identity creation that cannot be
/// audited is treated as a failure rather than proceeding silently.
pub async fn record_identity_event(
    audit: &AuditRepository,
    origin: IdentityOrigin,
    identity: &DeviceIdentity,
    clock: &dyn Clock,
) -> anyhow::Result<()> {
    let action = match origin {
        IdentityOrigin::Loaded => return Ok(()),
        IdentityOrigin::Created => actions::IDENTITY_CREATED,
        IdentityOrigin::CertificateRenewed => actions::CERTIFICATE_RENEWED,
    };

    let public = identity.public();
    audit
        .record(
            &AuditEvent::new(AuditCategory::Config, action, AuditResult::Success)
                .actor_device(public.device_id)
                .meta("identity_fingerprint", public.identity_fingerprint)
                .meta("certificate_version", public.certificate_version),
            clock.now_ms(),
        )
        .await
        .context("could not write the identity audit record")?;

    Ok(())
}

/// Print this agent's identity for the operator to compare during pairing.
pub fn print_identity(identity: &DeviceIdentity) {
    let public = identity.public();
    println!("Device ID:              {}", public.device_id);
    println!(
        "Identity fingerprint:   {}",
        public.identity_fingerprint.to_display_groups()
    );
    println!(
        "Certificate fingerprint: {}",
        public.certificate_fingerprint.to_display_groups()
    );
    println!("Certificate version:    {}", public.certificate_version);
    println!(
        "Certificate valid until: {}",
        format_timestamp(public.certificate_not_after_ms)
    );
    println!();
    println!("The identity fingerprint is what a client pins. It does not change when the");
    println!("certificate is renewed. Compare it with what your client displays.");
}

/// Open a pairing window and hold it until it expires or the operator cancels.
///
/// # Errors
/// Fails if the window cannot be opened or the audit record cannot be written.
pub async fn run_pairing_window(
    identity: &DeviceIdentity,
    database: &rc_storage::Database,
    ttl_secs: u64,
) -> anyhow::Result<()> {
    let clock = SystemClock;
    let manager = PairingManager::new(PairingPolicy {
        ttl_secs,
        ..PairingPolicy::default()
    });
    let audit = AuditRepository::new(database);

    let opened = manager
        .begin_pairing(&clock, &OsRandom)
        .context("could not open a pairing window")?;

    // Persist the verifier, never the code. Reading this row does not yield a usable
    // code: it is an Argon2id output over a 44-bit space.
    sqlx::query(
        "INSERT INTO pairing_code (
             id, code_hash, code_salt, created_at_ms, expires_at_ms,
             max_attempts, pairing_session_id, outcome
         ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open')",
    )
    .bind(opened.pairing_session_id.to_canonical_string())
    .bind(&opened.verifier_hex)
    .bind(&opened.salt_hex)
    .bind(clock.now_ms())
    .bind(opened.expires_at_ms)
    .bind(i64::from(manager.policy().max_attempts))
    .bind(opened.pairing_session_id.to_canonical_string())
    .execute(database.pool())
    .await
    .context("could not record the pairing window")?;

    audit
        .record(
            &AuditEvent::new(
                AuditCategory::Pairing,
                actions::PAIRING_CODE_CREATED,
                AuditResult::Success,
            )
            .meta("ttl_secs", ttl_secs),
            clock.now_ms(),
        )
        .await
        .context("could not write the pairing audit record")?;

    let public = identity.public();
    println!();
    println!("  Pairing code:  {}", opened.code.expose_for_display());
    println!();
    println!("  This server:   {}", public.device_id);
    println!(
        "  Fingerprint:   {}",
        public.identity_fingerprint.to_display_groups()
    );
    println!();
    println!("  Enter the code on your client and check that the fingerprint matches.");
    println!("  The code expires in {ttl_secs} seconds and can be used once.");
    println!();

    // The code is deliberately absent from this record.
    tracing::info!(
        pairing_session_id = %opened.pairing_session_id,
        ttl_secs,
        "pairing window open; waiting for a client"
    );

    // Hold the window open. Phase 3's listener will complete the exchange; until then
    // this waits out the timer so the operator sees the real lifetime.
    let deadline = std::time::Duration::from_secs(ttl_secs);
    tokio::select! {
        () = tokio::time::sleep(deadline) => {
            println!("The pairing code has expired.");
            audit
                .record(
                    &AuditEvent::new(
                        AuditCategory::Pairing,
                        actions::PAIRING_EXPIRED,
                        AuditResult::Failure,
                    ),
                    clock.now_ms(),
                )
                .await
                .ok();
        }
        _ = tokio::signal::ctrl_c() => {
            manager.cancel(opened.pairing_session_id).ok();
            println!("Pairing cancelled.");
            audit
                .record(
                    &AuditEvent::new(
                        AuditCategory::Pairing,
                        actions::PAIRING_CANCELLED,
                        AuditResult::Failure,
                    ),
                    clock.now_ms(),
                )
                .await
                .ok();
        }
    }

    mark_window_closed(database, &opened.pairing_session_id.to_canonical_string()).await;
    Ok(())
}

/// Verify a client's pairing proof, record trust, and audit the outcome.
///
/// This is the agent-side completion step. Phase 3's listener calls it with a proof
/// received over the wire; it is written and tested now so the trust-recording and
/// audit behaviour is settled before a network path exists to reach it.
///
/// The three failure audits are deliberately distinct, because they mean different
/// things operationally: `PAIRING_THROTTLED` says an attacker is being rate-limited,
/// `PAIRING_EXPIRED` says a window closed unused, and `PAIRING_ATTEMPT_FAILED` says a
/// proof was actually rejected. None of them records the proof, the code or the
/// verifier — only the session id, which is not secret.
///
/// # Errors
/// Returns the underlying [`SecurityError`] when the proof is rejected, and a storage
/// error if trust cannot be recorded.
// Reached only from tests until Phase 3 binds the listener that supplies a proof. The
// allow is deliberate and scoped: the function is fully implemented and tested, not a
// stub, and removing it to satisfy dead-code analysis would mean rewriting it later
// without the tests that currently pin its behaviour.
#[allow(dead_code)]
pub async fn complete_pairing(
    manager: &PairingManager,
    session_id: PairingSessionId,
    proof: &ClientProof,
    agent: &DeviceIdentity,
    database: &rc_storage::Database,
    clock: &dyn Clock,
) -> anyhow::Result<PairingOutcome> {
    let audit = AuditRepository::new(database);
    let now = clock.now_ms();

    let outcome = match manager.verify_client_proof(session_id, proof, agent, clock) {
        Ok(outcome) => outcome,
        Err(err) => {
            let (action, result) = match err {
                // The attempt cap and an expired window are throttling outcomes: the
                // caller is being refused without its proof having been judged.
                SecurityError::PairingAttemptsExhausted | SecurityError::Throttled { .. } => {
                    (actions::PAIRING_THROTTLED, AuditResult::Denied)
                }
                SecurityError::PairingExpired => (actions::PAIRING_EXPIRED, AuditResult::Failure),
                _ => (actions::PAIRING_ATTEMPT_FAILED, AuditResult::Failure),
            };

            audit
                .record(
                    &AuditEvent::new(AuditCategory::Pairing, action, result)
                        .meta("pairing_session_id", session_id)
                        // The error's `Display` is written to be safe to surface: it
                        // never echoes attacker input and never names a secret.
                        .meta("reason", &err),
                    now,
                )
                .await
                .context("could not write the pairing failure audit record")?;

            return Err(err.into());
        }
    };

    // Trust is recorded before the confirmation is handed back, so a client can never
    // believe it is paired while the agent has no record of it.
    let trust = TrustRepository::new(database);
    trust
        .insert_paired_device(
            outcome.client_device_id,
            PeerRoleRow::Client,
            &outcome.client_display_name,
            "",
            &outcome.client_public_key,
            outcome.client_identity_fingerprint,
            outcome.client_certificate_fingerprint,
            &outcome.granted_permissions,
            Some(&outcome.transcript_digest),
            now,
        )
        .await
        .context("could not record the newly trusted device")?;

    mark_window_consumed(
        database,
        &session_id.to_canonical_string(),
        outcome.client_device_id,
        now,
    )
    .await;

    audit
        .record(
            &AuditEvent::new(
                AuditCategory::Pairing,
                actions::PAIRING_COMPLETED,
                AuditResult::Success,
            )
            .target_device(outcome.client_device_id)
            .meta("pairing_session_id", session_id)
            .meta("role", outcome.granted_permissions.role.name())
            // A short digest, not the transcript itself: enough to correlate the two
            // peers' records, not enough to reconstruct the exchange.
            .meta("transcript_digest", &outcome.transcript_digest),
            now,
        )
        .await
        .context("could not write the pairing completion audit record")?;

    Ok(outcome)
}

/// Mark a pairing window as successfully used.
///
/// Guarded on `outcome = 'open'` so a second completion cannot rewrite the row, which
/// keeps the persisted trail consistent with the in-memory single-use guarantee.
#[allow(dead_code)] // Called only by `complete_pairing`; see the note there.
async fn mark_window_consumed(
    database: &rc_storage::Database,
    session_id: &str,
    paired_device: DeviceId,
    now_ms: i64,
) {
    let result = sqlx::query(
        "UPDATE pairing_code
            SET outcome = 'consumed', consumed_at_ms = ?, paired_device_id = ?
          WHERE pairing_session_id = ? AND outcome = 'open'",
    )
    .bind(now_ms)
    .bind(paired_device.to_canonical_string())
    .bind(session_id)
    .execute(database.pool())
    .await;

    if let Err(err) = result {
        tracing::warn!(%err, "could not record the pairing window as consumed");
    }
}

/// Record the terminal outcome of a pairing window.
async fn mark_window_closed(database: &rc_storage::Database, session_id: &str) {
    let result = sqlx::query(
        "UPDATE pairing_code SET outcome = 'expired'
         WHERE pairing_session_id = ? AND outcome = 'open'",
    )
    .bind(session_id)
    .execute(database.pool())
    .await;

    if let Err(err) = result {
        tracing::warn!(%err, "could not record the pairing window outcome");
    }
}

/// Sweep pairing rows left `open` by a previous process run.
///
/// Sessions are in-memory, so any row still marked open after a restart describes a
/// window that can no longer be used. Recording that explicitly keeps the audit trail
/// honest rather than leaving rows that imply a live code.
pub async fn expire_stale_windows(database: &rc_storage::Database) -> anyhow::Result<u64> {
    let affected =
        sqlx::query("UPDATE pairing_code SET outcome = 'expired' WHERE outcome = 'open'")
            .execute(database.pool())
            .await
            .context("could not expire stale pairing windows")?
            .rows_affected();

    if affected > 0 {
        tracing::info!(
            count = affected,
            "expired pairing windows left open by a previous run"
        );
    }
    Ok(affected)
}

/// Format a millisecond timestamp for console output.
fn format_timestamp(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map_or_else(
        || "unknown".to_string(),
        |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use rc_security::pairing::{PairingClient, RequestedPermissions};
    use rc_security::permissions::Role;
    use rc_security::{OsRandom, RandomSourceExt as _};
    use rc_storage::audit::AuditCategory;

    use super::*;

    /// Drives a real pairing exchange against a real database.
    struct Fixture {
        database: rc_storage::Database,
        manager: PairingManager,
        agent: DeviceIdentity,
        client: DeviceIdentity,
        clock: SystemClock,
    }

    impl Fixture {
        async fn new() -> Self {
            let clock = SystemClock;
            Self {
                database: rc_storage::Database::open_in_memory().await.unwrap(),
                manager: PairingManager::with_defaults(),
                agent: DeviceIdentity::generate("test-agent", &clock).unwrap(),
                client: DeviceIdentity::generate("test-client", &clock).unwrap(),
                clock,
            }
        }

        /// Run the exchange up to the point a valid proof exists.
        fn proof_for(&self, role: Role) -> (PairingSessionId, ClientProof) {
            let opened = self.manager.begin_pairing(&self.clock, &OsRandom).unwrap();
            let permissions = RequestedPermissions::full(role);

            let client = PairingClient::current();
            let claim = client.build_claim(
                &self.client,
                OsRandom.bytes(),
                "Test Client".to_owned(),
                permissions.clone(),
            );

            let challenge = self
                .manager
                .submit_client_identity(
                    opened.pairing_session_id,
                    claim.clone(),
                    &self.agent,
                    &self.clock,
                )
                .unwrap();

            let transcript = client.build_transcript(&challenge, &claim).unwrap();
            let verifier = PairingClient::derive_verifier(&opened.code, &challenge).unwrap();
            let proof = client
                .build_proof(&self.client, &verifier, &transcript)
                .unwrap();

            (opened.pairing_session_id, proof)
        }

        async fn audit_actions(&self) -> Vec<String> {
            AuditRepository::new(&self.database)
                .recent_in_category(AuditCategory::Pairing, 20)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.action)
                .collect()
        }
    }

    #[tokio::test]
    async fn a_valid_proof_records_trust_and_audits_completion() {
        let fixture = Fixture::new().await;
        let (session_id, proof) = fixture.proof_for(Role::Operator);

        let outcome = complete_pairing(
            &fixture.manager,
            session_id,
            &proof,
            &fixture.agent,
            &fixture.database,
            &fixture.clock,
        )
        .await
        .unwrap();

        assert_eq!(outcome.client_device_id, fixture.client.device_id());

        // Trust is persisted, not merely returned.
        let trusted = TrustRepository::new(&fixture.database)
            .find(fixture.client.device_id())
            .await
            .unwrap()
            .expect("the paired device must be recorded");
        assert!(!trusted.revoked);

        assert!(
            fixture
                .audit_actions()
                .await
                .contains(&actions::PAIRING_COMPLETED.to_owned())
        );
    }

    #[tokio::test]
    async fn a_second_completion_of_the_same_session_is_refused() {
        let fixture = Fixture::new().await;
        let (session_id, proof) = fixture.proof_for(Role::Operator);

        complete_pairing(
            &fixture.manager,
            session_id,
            &proof,
            &fixture.agent,
            &fixture.database,
            &fixture.clock,
        )
        .await
        .unwrap();

        // Replaying the identical proof must not produce a second trusted device.
        let replay = complete_pairing(
            &fixture.manager,
            session_id,
            &proof,
            &fixture.agent,
            &fixture.database,
            &fixture.clock,
        )
        .await;
        assert!(replay.is_err(), "a consumed session must not pair twice");

        let devices = TrustRepository::new(&fixture.database)
            .list(PeerRoleRow::Client)
            .await
            .unwrap();
        assert_eq!(devices.len(), 1, "replay must not add a device");
    }

    #[tokio::test]
    async fn a_rejected_proof_audits_a_failed_attempt_and_records_no_trust() {
        let fixture = Fixture::new().await;
        let (session_id, mut proof) = fixture.proof_for(Role::Operator);

        // Corrupt the MAC: the shape stays valid, the proof does not.
        proof.mac[0] ^= 0xFF;

        let result = complete_pairing(
            &fixture.manager,
            session_id,
            &proof,
            &fixture.agent,
            &fixture.database,
            &fixture.clock,
        )
        .await;
        assert!(result.is_err());

        assert!(
            TrustRepository::new(&fixture.database)
                .list(PeerRoleRow::Client)
                .await
                .unwrap()
                .is_empty(),
            "a rejected proof must not create trust"
        );

        assert!(
            fixture
                .audit_actions()
                .await
                .contains(&actions::PAIRING_ATTEMPT_FAILED.to_owned())
        );
    }

    #[tokio::test]
    async fn exhausting_the_attempt_cap_audits_a_throttled_attempt() {
        let fixture = Fixture::new().await;
        let (session_id, good_proof) = fixture.proof_for(Role::Operator);

        let mut bad = good_proof;
        bad.mac[0] ^= 0xFF;

        // Spend every attempt, then one more: the cap turns the refusal into throttling
        // rather than another judged failure.
        let cap = fixture.manager.policy().max_attempts + 1;
        for _ in 0..cap {
            let _ = complete_pairing(
                &fixture.manager,
                session_id,
                &bad,
                &fixture.agent,
                &fixture.database,
                &fixture.clock,
            )
            .await;
        }

        assert!(
            fixture
                .audit_actions()
                .await
                .contains(&actions::PAIRING_THROTTLED.to_owned()),
            "the attempt cap must be audited distinctly from a rejected proof"
        );
    }

    #[tokio::test]
    async fn creating_an_identity_is_audited_but_loading_one_is_not() {
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        let audit = AuditRepository::new(&database);
        let clock = SystemClock;
        let identity = DeviceIdentity::generate("test-agent", &clock).unwrap();

        record_identity_event(&audit, IdentityOrigin::Loaded, &identity, &clock)
            .await
            .unwrap();
        assert_eq!(
            audit.count().await.unwrap(),
            0,
            "an ordinary load must not write a record on every boot"
        );

        record_identity_event(&audit, IdentityOrigin::Created, &identity, &clock)
            .await
            .unwrap();
        record_identity_event(
            &audit,
            IdentityOrigin::CertificateRenewed,
            &identity,
            &clock,
        )
        .await
        .unwrap();
        assert_eq!(audit.count().await.unwrap(), 2);

        // Neither record may carry key material.
        let rendered = format!("{:?}", audit.recent(10).await.unwrap());
        assert!(
            !rendered.contains("PRIVATE"),
            "no key material in the trail"
        );
    }

    #[test]
    fn timestamps_render_readably() {
        let rendered = format_timestamp(1_700_000_000_000);
        assert!(rendered.starts_with("2023-11-14"), "got {rendered}");
        assert!(rendered.ends_with("UTC"));
    }

    #[test]
    fn an_impossible_timestamp_does_not_panic() {
        assert_eq!(format_timestamp(i64::MAX), "unknown");
    }

    #[tokio::test]
    async fn stale_windows_are_expired_on_startup() {
        let db = rc_storage::Database::open_in_memory().await.unwrap();

        sqlx::query(
            "INSERT INTO pairing_code
                 (id, code_hash, code_salt, created_at_ms, expires_at_ms, outcome)
             VALUES ('p1', 'hash', 'salt', 1, 2, 'open')",
        )
        .execute(db.pool())
        .await
        .unwrap();

        assert_eq!(expire_stale_windows(&db).await.unwrap(), 1);

        let (outcome,): (String,) =
            sqlx::query_as("SELECT outcome FROM pairing_code WHERE id = 'p1'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            outcome, "expired",
            "a code from a previous run must not stay usable"
        );

        // Running again is a no-op.
        assert_eq!(expire_stale_windows(&db).await.unwrap(), 0);
    }
}
