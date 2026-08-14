//! Managing this machine's trusted devices from a remote session.
//!
//! Every request here is gated on [`Permission::Administer`], re-checked per request
//! like every other permission, so authority withdrawn mid-session stops being answered
//! immediately rather than at the session's next reconnection.
//!
//! # A session may not modify its own trust row
//!
//! Enforced once, in [`TrustService::guard_target`], for all three mutating requests.
//! Without it an administrator could grant itself unattended access it was never given,
//! widen its own permissions, or make itself un-revokable — turning one deliberate grant
//! into a permanent, self-renewing one.
//!
//! The identity compared against is the one the session was **admitted under**, taken
//! from the connection when the service was constructed. It is never read from the
//! request body, because a caller that could name its own identity could name someone
//! else's and the check would protect nothing.
//!
//! # Reading is not exempt
//!
//! `ListTrustedDevices` is gated too. The list names every machine its owner trusts and
//! how far, which is reconnaissance for anyone deciding which one to impersonate.

use rc_protocol::control::{ControlRequestPayload, ControlResponsePayload, TrustedDeviceSummary};
use rc_security::{Fingerprint, Permission};
use rc_storage::{TrustRepository, TrustedDevice};

use crate::error::{AccessError, Result};
use crate::sessions::Session;

/// Serves the trust-management requests for one session.
#[derive(Debug, Clone)]
pub struct TrustService {
    trust: TrustRepository,
}

impl TrustService {
    /// A service over `trust`.
    ///
    /// The caller's own identity is not held here: it is read from the [`Session`] on
    /// every request, which is the value admission established from the connection. One
    /// service can then serve every session without any risk of it being constructed
    /// with the wrong caller.
    #[must_use]
    pub const fn new(trust: TrustRepository) -> Self {
        Self { trust }
    }

    /// Answer one trust-management request.
    ///
    /// Returns `Ok(None)` for a payload this service does not own, so the caller can go
    /// on to try the next service rather than this one having to know about them.
    ///
    /// # Errors
    /// [`AccessError::PermissionDenied`] if the session does not hold
    /// [`Permission::Administer`], or if the request targets the caller's own trust row.
    /// [`AccessError::InvalidArgument`] if the target identity is not a well-formed
    /// fingerprint. [`AccessError::Storage`] if the write fails.
    pub async fn handle(
        &self,
        session: &Session,
        payload: &ControlRequestPayload,
    ) -> Result<Option<ControlResponsePayload>> {
        // Before anything is parsed, so a caller without authority learns nothing about
        // whether its arguments were well formed.
        match payload {
            ControlRequestPayload::ListTrustedDevices
            | ControlRequestPayload::SetDevicePermissions { .. }
            | ControlRequestPayload::SetUnattendedAccess { .. }
            | ControlRequestPayload::RevokeDevice { .. } => {
                session.require(Permission::Administer)?;
            }
            _ => return Ok(None),
        }

        match payload {
            ControlRequestPayload::ListTrustedDevices => {
                let devices = self.trust.list().await?;
                Ok(Some(ControlResponsePayload::TrustedDevices(Box::new(
                    devices.iter().map(summarise).collect(),
                ))))
            }
            ControlRequestPayload::SetDevicePermissions {
                identity,
                permissions,
            } => {
                let target = Self::guard_target(session, identity)?;
                let permissions = rc_security::PermissionSet::from_bits(permissions.0).ok_or(
                    AccessError::InvalidArgument {
                        field: "permissions",
                    },
                )?;
                self.trust.set_permissions(target, permissions).await?;
                Ok(Some(ControlResponsePayload::Empty))
            }
            ControlRequestPayload::SetUnattendedAccess { identity, enabled } => {
                let target = Self::guard_target(session, identity)?;
                self.trust.set_unattended(target, *enabled).await?;
                Ok(Some(ControlResponsePayload::Empty))
            }
            ControlRequestPayload::RevokeDevice { identity } => {
                let target = Self::guard_target(session, identity)?;
                self.trust.revoke(target).await?;
                Ok(Some(ControlResponsePayload::Empty))
            }
            _ => Ok(None),
        }
    }

    /// Parse a target identity and refuse the caller's own.
    ///
    /// Parsing strictly is part of the guard rather than a separate concern: a target
    /// that did not round-trip through [`Fingerprint`] could differ in case or length
    /// from the caller's own hex and slip past a string comparison while still naming
    /// the same device.
    fn guard_target(session: &Session, identity: &str) -> Result<Fingerprint> {
        let target = identity
            .parse::<Fingerprint>()
            .map_err(|_| AccessError::InvalidArgument { field: "identity" })?;

        // `ct_eq`, like every other identity comparison in the tree.
        if target.ct_eq(&session.identity()) {
            return Err(AccessError::PermissionDenied {
                permission: "administer another device",
            });
        }

        Ok(target)
    }
}

/// A stored device as the wire describes it.
fn summarise(device: &TrustedDevice) -> TrustedDeviceSummary {
    TrustedDeviceSummary {
        identity_fingerprint: device.identity_fingerprint.to_hex(),
        device_id: device.device_id.clone(),
        display_name: device.display_name.clone(),
        os_family: os_family_of(&device.os_family),
        last_address: device.last_address.clone(),
        added_ms: device.added_ms,
        last_connected_ms: device.last_connected_ms,
        unattended: device.unattended,
        suspended: device.suspended,
        permissions: rc_protocol::control::WirePermissions(device.permissions.bits()),
    }
}

/// The stored operating-system string as the protocol enum.
///
/// An unrecognised value becomes `Unknown` rather than failing the whole listing: the
/// field is untrusted display text, and one odd row must not make a machine's trusted
/// devices unreadable.
fn os_family_of(stored: &str) -> rc_protocol::control::OsFamily {
    match stored {
        "windows" => rc_protocol::control::OsFamily::Windows,
        "linux" => rc_protocol::control::OsFamily::Linux,
        "macos" => rc_protocol::control::OsFamily::MacOs,
        _ => rc_protocol::control::OsFamily::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use rc_protocol::control::WirePermissions;
    use rc_security::{Fingerprint, Permission, PermissionSet};
    use rc_storage::{Database, NewTrustedDevice};

    use super::*;

    /// Bytes whose hex spelling contains letters, so an uppercase variant of it is
    /// genuinely a different string -- `[1u8; 32]` hexes to digits only, and a
    /// case-sensitivity test written against it would pass without testing anything.
    fn caller() -> Fingerprint {
        Fingerprint::from_bytes([0xab; 32])
    }

    fn other() -> Fingerprint {
        Fingerprint::from_bytes([0xcd; 32])
    }

    fn admin_session() -> Session {
        Session::new(PermissionSet::NONE.with(Permission::Administer), caller())
    }

    struct Harness {
        service: TrustService,
        trust: TrustRepository,
        _database: Database,
    }

    impl Harness {
        async fn new() -> Self {
            let database = Database::open_in_memory().await.unwrap();
            let trust = TrustRepository::new(&database);
            Self {
                service: TrustService::new(trust.clone()),
                trust,
                _database: database,
            }
        }

        async fn seed(&self, identity: Fingerprint, permissions: PermissionSet, unattended: bool) {
            self.trust
                .trust(&NewTrustedDevice {
                    identity_fingerprint: identity,
                    device_id: "dev".to_owned(),
                    display_name: "Box".to_owned(),
                    os_family: "windows".to_owned(),
                    address: "10.0.0.1:7443".to_owned(),
                    permissions,
                    unattended,
                    now_ms: 1_000,
                })
                .await
                .unwrap();
        }

        async fn stored(&self, identity: Fingerprint) -> TrustedDevice {
            self.trust.find(identity).await.unwrap().unwrap()
        }

        /// Every request this service owns, aimed at `target`.
        fn every_request(target: Fingerprint) -> Vec<ControlRequestPayload> {
            let mut all = vec![ControlRequestPayload::ListTrustedDevices];
            all.extend(Self::every_mutating_request(target));
            all
        }

        /// Every request that changes something, aimed at `target`.
        fn every_mutating_request(target: Fingerprint) -> Vec<ControlRequestPayload> {
            vec![
                ControlRequestPayload::SetDevicePermissions {
                    identity: target.to_hex(),
                    permissions: WirePermissions(PermissionSet::ALL.bits()),
                },
                ControlRequestPayload::SetUnattendedAccess {
                    identity: target.to_hex(),
                    enabled: true,
                },
                ControlRequestPayload::RevokeDevice {
                    identity: target.to_hex(),
                },
            ]
        }
    }

    #[tokio::test]
    async fn a_session_without_administer_is_refused_every_request() {
        // Holding everything else must not be enough. Re-checked per request like the
        // other three permissions, so authority withdrawn mid-session stops being
        // answered immediately.
        let harness = Harness::new().await;
        harness.seed(other(), PermissionSet::NONE, false).await;
        let session = Session::new(PermissionSet::ALL.without(Permission::Administer), caller());

        for payload in Harness::every_request(other()) {
            let error = harness
                .service
                .handle(&session, &payload)
                .await
                .expect_err("must be refused");
            assert!(
                matches!(error, AccessError::PermissionDenied { .. }),
                "got {error:?} for {payload:?}"
            );
        }

        let untouched = harness.stored(other()).await;
        assert!(!untouched.unattended);
        assert_eq!(untouched.permissions, PermissionSet::NONE);
    }

    #[tokio::test]
    async fn an_admin_session_can_change_another_device() {
        let harness = Harness::new().await;
        harness.seed(other(), PermissionSet::NONE, false).await;

        harness
            .service
            .handle(
                &admin_session(),
                &ControlRequestPayload::SetUnattendedAccess {
                    identity: other().to_hex(),
                    enabled: true,
                },
            )
            .await
            .unwrap();

        assert!(harness.stored(other()).await.unattended);
    }

    #[tokio::test]
    async fn an_admin_session_cannot_modify_its_own_trust_row() {
        // Without this an administrator could grant itself unattended access it was
        // never given, or make itself un-revokable. All three mutating requests must
        // refuse, not only the obvious one.
        let harness = Harness::new().await;
        harness
            .seed(
                caller(),
                PermissionSet::NONE.with(Permission::Administer),
                false,
            )
            .await;

        for payload in Harness::every_mutating_request(caller()) {
            let error = harness
                .service
                .handle(&admin_session(), &payload)
                .await
                .expect_err("self-modification must be refused");
            assert!(
                matches!(error, AccessError::PermissionDenied { .. }),
                "got {error:?} for {payload:?}"
            );
        }

        let unchanged = harness.stored(caller()).await;
        assert!(!unchanged.unattended, "it must not have let itself in");
        assert!(
            unchanged.permissions.contains(Permission::Administer),
            "and it must still be there to be revoked by someone else"
        );
    }

    #[tokio::test]
    async fn an_admin_session_may_still_read_the_list_that_contains_itself() {
        // The guard is on modification, not on visibility: an administrator that could
        // not see its own row would be looking at a list that quietly disagreed with
        // the machine's actual state.
        let harness = Harness::new().await;
        harness.seed(caller(), PermissionSet::ALL, true).await;

        let response = harness
            .service
            .handle(&admin_session(), &ControlRequestPayload::ListTrustedDevices)
            .await
            .unwrap()
            .unwrap();

        let ControlResponsePayload::TrustedDevices(devices) = response else {
            panic!("expected a listing")
        };
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].identity_fingerprint, caller().to_hex());
    }

    #[tokio::test]
    async fn revoking_another_device_removes_it() {
        let harness = Harness::new().await;
        harness.seed(other(), PermissionSet::ALL, true).await;

        harness
            .service
            .handle(
                &admin_session(),
                &ControlRequestPayload::RevokeDevice {
                    identity: other().to_hex(),
                },
            )
            .await
            .unwrap();

        assert!(harness.trust.find(other()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_listing_carries_no_credential() {
        // There is no secret attached to a trust relationship, and the summary must not
        // acquire one. This is a guard against a future field that would send one to a
        // remote peer.
        let harness = Harness::new().await;
        harness.seed(other(), PermissionSet::ALL, true).await;

        let response = harness
            .service
            .handle(&admin_session(), &ControlRequestPayload::ListTrustedDevices)
            .await
            .unwrap()
            .unwrap();

        let encoded = format!("{response:?}").to_lowercase();
        for forbidden in ["password", "secret", "token", "phc", "argon", "$"] {
            assert!(
                !encoded.contains(forbidden),
                "a listing must not carry {forbidden}: {encoded}"
            );
        }
    }

    #[tokio::test]
    async fn a_malformed_identity_is_refused_rather_than_matched_loosely() {
        let harness = Harness::new().await;

        for bad in ["", "not-hex", &"A".repeat(64), &"a".repeat(63)] {
            let error = harness
                .service
                .handle(
                    &admin_session(),
                    &ControlRequestPayload::RevokeDevice {
                        identity: bad.to_owned(),
                    },
                )
                .await
                .expect_err("must be refused");
            assert!(
                matches!(error, AccessError::InvalidArgument { .. }),
                "got {error:?} for {bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_caller_cannot_evade_the_guard_by_spelling_its_identity_differently() {
        // A string comparison would let an uppercase spelling of the caller's own
        // fingerprint through while still naming the same device. Parsing first is what
        // closes that, and `Fingerprint` refuses uppercase outright.
        let harness = Harness::new().await;
        harness.seed(caller(), PermissionSet::ALL, false).await;

        let spelled_differently = caller().to_hex().to_uppercase();
        assert_ne!(
            spelled_differently,
            caller().to_hex(),
            "the two spellings must actually differ, or this test proves nothing"
        );

        let error = harness
            .service
            .handle(
                &admin_session(),
                &ControlRequestPayload::SetUnattendedAccess {
                    identity: spelled_differently,
                    enabled: true,
                },
            )
            .await
            .expect_err("must be refused");

        assert!(matches!(error, AccessError::InvalidArgument { .. }));
        assert!(!harness.stored(caller()).await.unattended);
    }

    #[tokio::test]
    async fn a_permission_set_this_build_does_not_understand_is_refused() {
        // Masking the unknown bit away would store a grant that meant something
        // different from what the caller asked for.
        let harness = Harness::new().await;
        harness.seed(other(), PermissionSet::NONE, false).await;

        let error = harness
            .service
            .handle(
                &admin_session(),
                &ControlRequestPayload::SetDevicePermissions {
                    identity: other().to_hex(),
                    permissions: WirePermissions(0b1000_0000),
                },
            )
            .await
            .expect_err("must be refused");

        assert!(matches!(error, AccessError::InvalidArgument { .. }));
        assert_eq!(
            harness.stored(other()).await.permissions,
            PermissionSet::NONE
        );
    }

    #[tokio::test]
    async fn a_payload_this_service_does_not_own_is_passed_on() {
        let harness = Harness::new().await;

        let answered = harness
            .service
            .handle(&admin_session(), &ControlRequestPayload::SystemSnapshot)
            .await
            .unwrap();

        assert!(answered.is_none());
    }

    #[tokio::test]
    async fn an_unowned_payload_is_passed_on_without_checking_administer() {
        // The permission gate must not swallow requests belonging to other services: a
        // session with no `Administer` still has to be able to ask for metrics.
        let harness = Harness::new().await;
        let session = Session::new(PermissionSet::NONE.with(Permission::ViewMetrics), caller());

        let answered = harness
            .service
            .handle(&session, &ControlRequestPayload::SystemSnapshot)
            .await
            .unwrap();

        assert!(answered.is_none());
    }
}
