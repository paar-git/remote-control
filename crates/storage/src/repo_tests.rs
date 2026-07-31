//! Repository tests: trust, owner authentication and audit.
//!
//! Every test runs against a real migrated SQLite database, in memory. Nothing is
//! mocked — these exercise the same SQL the agent runs.

use rc_security::clock::{Clock, OsRandom, TestClock};
use rc_security::error::SecurityError;
use rc_security::identity::derive_device_id;
use rc_security::pairing::RequestedPermissions;
use rc_security::password::HashingPolicy;
use rc_security::permissions::{Capability, Role};
use rc_security::{DeviceIdentity, Fingerprint};

use crate::audit::{AuditCategory, AuditEvent, AuditRepository, AuditResult, actions};
use crate::models::PeerRoleRow;
use crate::owner::OwnerRepository;
use crate::trust::{PresentedIdentity, TrustRepository};
use crate::{Database, StorageError};

const TEST_POLICY: HashingPolicy = HashingPolicy::FAST_FOR_TESTS;

async fn database() -> Database {
    Database::open_in_memory().await.unwrap()
}

/// A device identity plus everything needed to record it as trusted.
struct Peer {
    identity: DeviceIdentity,
}

impl Peer {
    fn new(name: &str, clock: &TestClock) -> Self {
        Self {
            identity: DeviceIdentity::generate(name, clock).unwrap(),
        }
    }

    fn presented(&self) -> PresentedIdentity {
        let public = self.identity.public();
        PresentedIdentity {
            device_id: public.device_id,
            identity_fingerprint: public.identity_fingerprint,
            certificate_fingerprint: public.certificate_fingerprint,
        }
    }
}

async fn trust_peer(
    repo: &TrustRepository,
    peer: &Peer,
    role: Role,
    now_ms: i64,
) -> crate::Result<()> {
    let public = peer.identity.public();
    repo.insert_paired_device(
        public.device_id,
        PeerRoleRow::Client,
        "Main PC",
        "main-pc",
        &public.identity_public_key,
        public.identity_fingerprint,
        public.certificate_fingerprint,
        &RequestedPermissions::full(role),
        Some("abc123"),
        now_ms,
    )
    .await
}

// ---------------------------------------------------------------------------
// Trusted devices
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_paired_device_is_stored_and_authorised() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();

    let outcome = repo.authorize(peer.presented()).await.unwrap();
    let (device, context) = outcome.expect("a freshly paired device must be authorised");

    assert_eq!(device.device_id, peer.identity.device_id());
    assert_eq!(device.role, Role::Owner);
    assert!(context.is_active());
    assert!(context.allows(Capability::Terminal));
}

#[tokio::test]
async fn trust_survives_a_process_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("trust.db");
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    {
        let db = Database::open(&path).await.unwrap();
        trust_peer(
            &TrustRepository::new(&db),
            &peer,
            Role::Owner,
            clock.now_ms(),
        )
        .await
        .unwrap();
        db.close().await;
    }

    // A fresh process opening the same file.
    let db = Database::open(&path).await.unwrap();
    let repo = TrustRepository::new(&db);
    let outcome = repo.authorize(peer.presented()).await.unwrap();

    assert!(outcome.is_ok(), "trust must survive a restart");
    assert_eq!(repo.list(PeerRoleRow::Client).await.unwrap().len(), 1);
}

#[tokio::test]
async fn revocation_takes_effect_immediately() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();
    assert!(repo.authorize(peer.presented()).await.unwrap().is_ok());

    repo.revoke(peer.identity.device_id(), clock.now_ms())
        .await
        .unwrap();

    // No restart, no cache invalidation — the very next authorization fails.
    let outcome = repo.authorize(peer.presented()).await.unwrap();
    assert!(matches!(outcome, Err(SecurityError::DeviceRevoked)));
}

#[tokio::test]
async fn a_revoked_device_grants_no_capabilities() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();
    repo.revoke(peer.identity.device_id(), clock.now_ms())
        .await
        .unwrap();

    let device = repo.find(peer.identity.device_id()).await.unwrap().unwrap();
    assert!(device.revoked);
    for capability in Capability::all() {
        assert!(
            !device.holds(*capability),
            "revoked device still holds {capability:?}"
        );
    }
    assert!(!device.authorization().is_active());
}

#[tokio::test]
async fn revocation_is_idempotent_and_preserves_the_original_timestamp() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();
    repo.revoke(peer.identity.device_id(), 1000).await.unwrap();
    repo.revoke(peer.identity.device_id(), 9999).await.unwrap();

    let device = repo.find(peer.identity.device_id()).await.unwrap().unwrap();
    assert_eq!(
        device.revoked_at_ms,
        Some(1000),
        "the first revocation time must stand"
    );
}

#[tokio::test]
async fn revoked_devices_are_retained_for_the_audit_trail() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();
    repo.revoke(peer.identity.device_id(), clock.now_ms())
        .await
        .unwrap();

    let listed = repo.list(PeerRoleRow::Client).await.unwrap();
    assert_eq!(
        listed.len(),
        1,
        "a revoked device must not vanish from the list"
    );
    assert!(listed[0].revoked);
}

#[tokio::test]
async fn an_unknown_identity_is_rejected() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let stranger = Peer::new("stranger", &clock);

    let outcome = repo.authorize(stranger.presented()).await.unwrap();
    assert!(matches!(outcome, Err(SecurityError::IdentityMismatch)));
}

#[tokio::test]
async fn a_changed_identity_fingerprint_is_never_silently_accepted() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();

    // Same claimed device id, different identity key.
    let impostor = Peer::new("main-pc", &clock);
    let presented = PresentedIdentity {
        device_id: peer.identity.device_id(),
        identity_fingerprint: impostor.identity.public().identity_fingerprint,
        certificate_fingerprint: impostor.identity.public().certificate_fingerprint,
    };

    let outcome = repo.authorize(presented).await.unwrap();
    assert!(matches!(outcome, Err(SecurityError::IdentityMismatch)));
}

#[tokio::test]
async fn a_known_identity_claiming_the_wrong_device_id_is_rejected() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();

    let presented = PresentedIdentity {
        device_id: derive_device_id(&[0xAB; 32]),
        ..peer.presented()
    };
    assert!(matches!(
        repo.authorize(presented).await.unwrap(),
        Err(SecurityError::IdentityMismatch)
    ));
}

#[tokio::test]
async fn the_same_identity_cannot_register_under_two_device_ids() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);
    let public = peer.identity.public();

    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();

    let err = repo
        .insert_paired_device(
            derive_device_id(&[0xCD; 32]), // a different device id
            PeerRoleRow::Client,
            "Impostor",
            "impostor",
            &public.identity_public_key,
            public.identity_fingerprint, // but the same identity
            public.certificate_fingerprint,
            &RequestedPermissions::full(Role::Owner),
            None,
            clock.now_ms(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, StorageError::Conflict), "got {err:?}");
}

#[tokio::test]
async fn certificate_rotation_keeps_the_same_trusted_device() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();

    clock.advance_secs(400 * 24 * 3600);
    let renewed = peer.identity.renew_certificate("main-pc", &clock).unwrap();

    repo.record_certificate_rotation(
        renewed.public().identity_fingerprint,
        renewed.public().certificate_fingerprint,
        renewed.public().certificate_version,
    )
    .await
    .unwrap();

    let device = repo.find(peer.identity.device_id()).await.unwrap().unwrap();
    assert_eq!(
        device.certificate_fingerprint,
        renewed.public().certificate_fingerprint
    );
    assert_eq!(device.certificate_version, 2);
    // The trust anchor is untouched.
    assert_eq!(
        device.identity_fingerprint,
        peer.identity.public().identity_fingerprint
    );

    // And the device still authorises under its new certificate.
    let presented = PresentedIdentity {
        device_id: renewed.device_id(),
        identity_fingerprint: renewed.public().identity_fingerprint,
        certificate_fingerprint: renewed.public().certificate_fingerprint,
    };
    assert!(repo.authorize(presented).await.unwrap().is_ok());
}

#[tokio::test]
async fn rotating_an_unknown_identity_fails() {
    let db = database().await;
    let repo = TrustRepository::new(&db);

    let err = repo
        .record_certificate_rotation(
            Fingerprint::of_public_key(&[1u8; 32]),
            Fingerprint::of_certificate_der(b"x"),
            2,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::NotFound));
}

#[tokio::test]
async fn renaming_validates_the_new_name() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);
    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();

    repo.rename(peer.identity.device_id(), "  Living Room PC  ")
        .await
        .unwrap();
    let device = repo.find(peer.identity.device_id()).await.unwrap().unwrap();
    assert_eq!(device.display_name, "Living Room PC", "names are trimmed");

    for bad in ["", "   ", "bad\u{0}name", &"n".repeat(200)] {
        let result = repo.rename(peer.identity.device_id(), bad).await;
        assert!(result.is_err(), "accepted {bad:?}");
    }

    // A rejected rename must leave the previous name intact.
    let device = repo.find(peer.identity.device_id()).await.unwrap().unwrap();
    assert_eq!(device.display_name, "Living Room PC");
}

#[tokio::test]
async fn operations_on_unknown_devices_report_not_found() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let unknown = derive_device_id(&[0xEE; 32]);

    assert!(matches!(
        repo.rename(unknown, "x").await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        repo.revoke(unknown, 1).await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        repo.set_favorite(unknown, true).await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        repo.record_authentication(unknown, 1).await,
        Err(StorageError::NotFound)
    ));
    assert!(repo.find(unknown).await.unwrap().is_none());
}

#[tokio::test]
async fn recording_authentication_updates_the_timestamp() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);
    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();

    assert!(
        repo.find(peer.identity.device_id())
            .await
            .unwrap()
            .unwrap()
            .last_authenticated_at_ms
            .is_none()
    );

    repo.record_authentication(peer.identity.device_id(), 12_345)
        .await
        .unwrap();
    assert_eq!(
        repo.find(peer.identity.device_id())
            .await
            .unwrap()
            .unwrap()
            .last_authenticated_at_ms,
        Some(12_345)
    );
}

#[tokio::test]
async fn a_revoked_device_cannot_record_an_authentication() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);
    trust_peer(&repo, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();
    repo.revoke(peer.identity.device_id(), clock.now_ms())
        .await
        .unwrap();

    assert!(matches!(
        repo.record_authentication(peer.identity.device_id(), 1)
            .await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
async fn granted_capabilities_are_recorded_and_bound() {
    let db = database().await;
    let repo = TrustRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("viewer", &clock);

    trust_peer(&repo, &peer, Role::ViewOnly, clock.now_ms())
        .await
        .unwrap();

    let device = repo.find(peer.identity.device_id()).await.unwrap().unwrap();
    assert!(device.holds(Capability::RemoteDesktopView));
    assert!(device.holds(Capability::FileRead));
    assert!(!device.holds(Capability::Terminal));
    assert!(!device.holds(Capability::PowerControl));
}

// ---------------------------------------------------------------------------
// Owner account
// ---------------------------------------------------------------------------

#[tokio::test]
async fn there_is_no_owner_account_until_one_is_created() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    assert!(
        !repo.exists().await.unwrap(),
        "there must be no default account"
    );
}

#[tokio::test]
async fn the_owner_can_authenticate() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();

    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();
    assert!(repo.exists().await.unwrap());

    let result = repo
        .authenticate("owner", "correct horse battery staple", &clock)
        .await
        .unwrap()
        .expect("correct credentials must authenticate");

    assert_eq!(result.username, "owner");
    assert_eq!(result.role, Role::Owner);
}

#[tokio::test]
async fn a_wrong_password_is_rejected() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();
    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();

    let result = repo
        .authenticate("owner", "wrong password entirely", &clock)
        .await
        .unwrap();
    assert!(matches!(result, Err(SecurityError::InvalidCredentials)));
}

#[tokio::test]
async fn an_unknown_account_is_indistinguishable_from_a_wrong_password() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();
    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();

    let wrong_password = repo
        .authenticate("owner", "wrong password entirely", &clock)
        .await
        .unwrap();
    let unknown_account = repo
        .authenticate("nobody", "wrong password entirely", &clock)
        .await
        .unwrap();

    let wrong = wrong_password.unwrap_err().to_string();
    let missing = unknown_account.unwrap_err().to_string();
    assert_eq!(wrong, missing, "the errors must be identical");
}

#[tokio::test]
async fn a_second_owner_account_cannot_be_created() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();

    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();
    let err = repo
        .create("other", "another password entirely", &clock, &OsRandom)
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::Conflict));
}

#[tokio::test]
async fn weak_passwords_are_refused_at_creation() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();

    for bad in ["", "short", "           "] {
        assert!(
            repo.create("owner", bad, &clock, &OsRandom).await.is_err(),
            "accepted {bad:?}"
        );
    }
    assert!(
        !repo.exists().await.unwrap(),
        "no account should have been created"
    );
}

#[tokio::test]
async fn usernames_are_validated() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();

    for bad in [
        "",
        "   ",
        " owner",
        "owner ",
        "bad\u{0}name",
        &"u".repeat(100),
    ] {
        assert!(
            repo.create(bad, "correct horse battery staple", &clock, &OsRandom)
                .await
                .is_err(),
            "accepted username {bad:?}"
        );
    }
}

#[tokio::test]
async fn repeated_failures_trigger_a_lockout() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();
    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();

    for _ in 0..3 {
        let _ = repo
            .authenticate("owner", "wrong password entirely", &clock)
            .await
            .unwrap();
    }

    let result = repo
        .authenticate("owner", "correct horse battery staple", &clock)
        .await
        .unwrap();
    assert!(
        matches!(result, Err(SecurityError::Throttled { .. })),
        "the correct password must still be refused while locked out"
    );
}

#[tokio::test]
async fn a_lockout_expires_and_the_owner_regains_access() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();
    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();

    for _ in 0..3 {
        let _ = repo
            .authenticate("owner", "wrong password entirely", &clock)
            .await
            .unwrap();
    }
    assert!(
        repo.authenticate("owner", "correct horse battery staple", &clock)
            .await
            .unwrap()
            .is_err()
    );

    // The cap exists so the owner is never permanently locked out.
    clock.advance_secs(400);
    let result = repo
        .authenticate("owner", "correct horse battery staple", &clock)
        .await
        .unwrap();
    assert!(
        result.is_ok(),
        "access must be restored after the lockout: {result:?}"
    );
}

#[tokio::test]
async fn a_successful_login_clears_the_failure_counter() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();
    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();

    let _ = repo
        .authenticate("owner", "wrong password entirely", &clock)
        .await
        .unwrap();
    let _ = repo
        .authenticate("owner", "wrong password entirely", &clock)
        .await
        .unwrap();
    assert_eq!(repo.failure_count("owner"), 2);

    repo.authenticate("owner", "correct horse battery staple", &clock)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(repo.failure_count("owner"), 0);
}

#[tokio::test]
async fn a_weak_password_hash_is_upgraded_on_the_next_login() {
    let db = database().await;
    let clock = TestClock::default();

    // Created under deliberately weak parameters...
    let weak = OwnerRepository::with_policy(&db, HashingPolicy::FAST_FOR_TESTS);
    weak.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();

    // ...then logged in under a stronger policy.
    let stronger = OwnerRepository::with_policy(
        &db,
        HashingPolicy {
            memory_kib: 256,
            iterations: 2,
            parallelism: 1,
        },
    );
    let result = stronger
        .authenticate("owner", "correct horse battery staple", &clock)
        .await
        .unwrap()
        .unwrap();

    assert!(
        result.password_hash_upgraded,
        "the hash should have been upgraded"
    );

    // The upgrade must not have broken the password.
    let again = stronger
        .authenticate("owner", "correct horse battery staple", &clock)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !again.password_hash_upgraded,
        "a second login should not re-upgrade"
    );
}

#[tokio::test]
async fn changing_the_password_requires_the_current_one() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();
    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();

    let refused = repo
        .change_password(
            "owner",
            "wrong current password",
            "a brand new password",
            &clock,
            &OsRandom,
        )
        .await
        .unwrap();
    assert!(matches!(refused, Err(SecurityError::InvalidCredentials)));

    repo.change_password(
        "owner",
        "correct horse battery staple",
        "a brand new password",
        &clock,
        &OsRandom,
    )
    .await
    .unwrap()
    .unwrap();

    assert!(
        repo.authenticate("owner", "a brand new password", &clock)
            .await
            .unwrap()
            .is_ok()
    );
    assert!(
        repo.authenticate("owner", "correct horse battery staple", &clock)
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn a_new_password_must_meet_policy() {
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();
    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();

    let result = repo
        .change_password(
            "owner",
            "correct horse battery staple",
            "short",
            &clock,
            &OsRandom,
        )
        .await
        .unwrap();
    assert!(matches!(result, Err(SecurityError::WeakPassword { .. })));
}

#[tokio::test]
async fn the_password_hash_is_never_returned_to_a_caller() {
    // `AuthenticatedOwner` carries no hash field; this pins that shape.
    let db = database().await;
    let repo = OwnerRepository::with_policy(&db, TEST_POLICY);
    let clock = TestClock::default();
    repo.create("owner", "correct horse battery staple", &clock, &OsRandom)
        .await
        .unwrap();

    let result = repo
        .authenticate("owner", "correct horse battery staple", &clock)
        .await
        .unwrap()
        .unwrap();

    let rendered = format!("{result:?}");
    assert!(!rendered.contains("argon2"));
    assert!(!rendered.contains("staple"));
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn events_are_recorded_and_read_back_newest_first() {
    let db = database().await;
    let repo = AuditRepository::new(&db);

    repo.record(
        &AuditEvent::new(
            AuditCategory::Auth,
            actions::LOGIN_SUCCEEDED,
            AuditResult::Success,
        ),
        1000,
    )
    .await
    .unwrap();
    repo.record(
        &AuditEvent::new(
            AuditCategory::Pairing,
            actions::PAIRING_COMPLETED,
            AuditResult::Success,
        ),
        2000,
    )
    .await
    .unwrap();

    let recent = repo.recent(10).await.unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].action, actions::PAIRING_COMPLETED);
    assert_eq!(repo.count().await.unwrap(), 2);
}

#[tokio::test]
async fn events_can_be_filtered_by_category() {
    let db = database().await;
    let repo = AuditRepository::new(&db);

    repo.record(
        &AuditEvent::new(
            AuditCategory::Auth,
            actions::LOGIN_FAILED,
            AuditResult::Failure,
        ),
        1,
    )
    .await
    .unwrap();
    repo.record(
        &AuditEvent::new(
            AuditCategory::Pairing,
            actions::PAIRING_EXPIRED,
            AuditResult::Failure,
        ),
        2,
    )
    .await
    .unwrap();

    let auth = repo
        .recent_in_category(AuditCategory::Auth, 10)
        .await
        .unwrap();
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0].action, actions::LOGIN_FAILED);
}

#[tokio::test]
async fn secret_looking_metadata_is_redacted() {
    let db = database().await;
    let repo = AuditRepository::new(&db);

    let event = AuditEvent::new(
        AuditCategory::Pairing,
        actions::PAIRING_COMPLETED,
        AuditResult::Success,
    )
    .meta("device_name", "Main PC")
    .meta("pairing_code", "ABC-DEF-GHJ")
    .meta("password", "hunter2")
    .meta("proof", "deadbeef")
    .meta("session_token", "tok_123")
    .meta("private_key", "MIIB...");

    repo.record(&event, 1).await.unwrap();

    let stored = &repo.recent(1).await.unwrap()[0].metadata_json;
    assert!(stored.contains("Main PC"), "safe metadata must survive");
    for secret in ["ABC-DEF-GHJ", "hunter2", "deadbeef", "tok_123", "MIIB"] {
        assert!(
            !stored.contains(secret),
            "audit log leaked {secret}: {stored}"
        );
    }
    assert!(stored.contains("<redacted>"));
}

#[tokio::test]
async fn metadata_values_are_length_bounded() {
    let db = database().await;
    let repo = AuditRepository::new(&db);

    let event = AuditEvent::new(
        AuditCategory::Connection,
        "connection.opened",
        AuditResult::Success,
    )
    .meta("remote_name", "x".repeat(10_000));

    repo.record(&event, 1).await.unwrap();
    let stored = &repo.recent(1).await.unwrap()[0].metadata_json;
    assert!(
        stored.len() < 1000,
        "an untrusted value must not bloat the log"
    );
}

#[tokio::test]
async fn the_result_limit_is_clamped() {
    let db = database().await;
    let repo = AuditRepository::new(&db);
    for i in 0..5 {
        repo.record(
            &AuditEvent::new(
                AuditCategory::Auth,
                actions::LOGIN_SUCCEEDED,
                AuditResult::Success,
            ),
            i,
        )
        .await
        .unwrap();
    }

    assert_eq!(
        repo.recent(0).await.unwrap().len(),
        1,
        "0 is clamped up to 1"
    );
    assert_eq!(repo.recent(u32::MAX).await.unwrap().len(), 5);
}

#[tokio::test]
async fn a_full_pairing_produces_a_correlated_audit_trail() {
    let db = database().await;
    let trust = TrustRepository::new(&db);
    let audit = AuditRepository::new(&db);
    let clock = TestClock::default();
    let peer = Peer::new("main-pc", &clock);

    audit
        .record(
            &AuditEvent::new(
                AuditCategory::Pairing,
                actions::PAIRING_CODE_CREATED,
                AuditResult::Success,
            ),
            clock.now_ms(),
        )
        .await
        .unwrap();

    trust_peer(&trust, &peer, Role::Owner, clock.now_ms())
        .await
        .unwrap();

    audit
        .record(
            &AuditEvent::new(
                AuditCategory::Pairing,
                actions::PAIRING_COMPLETED,
                AuditResult::Success,
            )
            .target_device(peer.identity.device_id())
            .meta("role", "owner"),
            clock.now_ms(),
        )
        .await
        .unwrap();

    let trail = audit
        .recent_in_category(AuditCategory::Pairing, 10)
        .await
        .unwrap();
    assert_eq!(trail.len(), 2);
    assert_eq!(
        trail[0].target_device_id,
        Some(peer.identity.device_id().to_canonical_string())
    );
}
