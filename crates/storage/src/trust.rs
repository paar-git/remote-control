//! Devices a human has decided to remember.
//!
//! Keyed on the **identity fingerprint** — the SHA-256 of a peer's Ed25519 identity
//! public key, read from the certificate it presented. Not on an address, and not on a
//! certificate digest: an address is not an identity, and a certificate is a credential
//! the identity rotates for itself. A device reached at a new address is the same
//! device and keeps its grant; a different device answering at a familiar address is a
//! stranger.
//!
//! # Two columns that must never move together
//!
//! `unattended` answers *how a device gets in*. `permissions` answers *what it may do*.
//! [`TrustRepository::set_unattended`] and [`TrustRepository::set_permissions`] each
//! write exactly one of them, and neither reads the other. Granting a laptop unattended
//! access to a desktop must not widen a single permission bit, and granting
//! Administrator must not let anything in that was not already allowed in.
//!
//! # `record_connection` never grants
//!
//! It runs on every admitted connection to keep the address and time current, and it
//! writes neither `unattended` nor `permissions`. If it did, a device whose grant a
//! human had narrowed would silently regain it by reconnecting — a permission change
//! with no human decision behind it, which is the same trap
//! [`crate::RecentRepository::record`] documents for the recent list.
//!
//! # Revocation is a delete
//!
//! There is no credential to invalidate: a device is authenticated by holding its
//! identity private key, not by presenting a stored token. Removing the row is
//! therefore the whole of revocation — the next connection finds nothing and is treated
//! as a stranger. [`TrustRepository::set_suspended`] exists for the reversible case.

use rc_security::{Fingerprint, PermissionSet};

use crate::error::Result;

/// A device this installation trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDevice {
    /// The trust key: fingerprint of the device's identity public key.
    pub identity_fingerprint: Fingerprint,
    /// The device id it reported. Display only.
    pub device_id: String,
    /// The name it reported. Untrusted text.
    pub display_name: String,
    /// The operating-system family it reported. Untrusted text.
    pub os_family: String,
    /// Where it last connected from. Display, and the identity-change check. Never
    /// authenticates anything.
    pub last_address: Option<String>,
    /// When a human first trusted it.
    pub added_ms: i64,
    /// When it was last admitted, or `None` if it has not connected since.
    pub last_connected_ms: Option<i64>,
    /// Whether it may reconnect without anyone approving.
    pub unattended: bool,
    /// Whether it is temporarily refused, with its settings retained.
    pub suspended: bool,
    /// What an admitted session receives, including [`rc_security::Permission::Administer`].
    pub permissions: PermissionSet,
}

/// A device about to be trusted for the first time, or re-trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTrustedDevice {
    /// The trust key.
    pub identity_fingerprint: Fingerprint,
    /// The device id it reported.
    pub device_id: String,
    /// The name it reported.
    pub display_name: String,
    /// The operating-system family it reported.
    pub os_family: String,
    /// The address this connection arrived from.
    pub address: String,
    /// What a session from it receives.
    pub permissions: PermissionSet,
    /// Whether it may reconnect without approval. A separate decision from trusting it.
    pub unattended: bool,
    /// When the decision was taken.
    pub now_ms: i64,
}

/// Reads and writes trusted devices.
#[derive(Debug, Clone)]
pub struct TrustRepository {
    pool: sqlx::Pool<sqlx::Sqlite>,
}

impl TrustRepository {
    /// A repository over `database`.
    #[must_use]
    pub fn new(database: &crate::Database) -> Self {
        Self {
            pool: database.pool().clone(),
        }
    }

    /// Every trusted device, most recently connected first, then most recently added.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn list(&self) -> Result<Vec<TrustedDevice>> {
        let rows = sqlx::query_as::<_, TrustedDeviceRaw>(
            "SELECT * FROM trusted_devices
             ORDER BY last_connected_ms DESC, added_ms DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Look up one device by the identity it proved.
    ///
    /// # Errors
    /// Propagates query failures. An untrusted identity yields `Ok(None)`.
    pub async fn find(&self, identity: Fingerprint) -> Result<Option<TrustedDevice>> {
        let row = sqlx::query_as::<_, TrustedDeviceRaw>(
            "SELECT * FROM trusted_devices WHERE identity_fingerprint = ?",
        )
        .bind(identity.to_hex())
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// The device that last connected from `address`, if one did.
    ///
    /// Answers one question only: *was this address a trusted device's, and is the
    /// caller a different device?* It must never be used to admit anyone — an address
    /// is not an identity, which is the whole reason this table is keyed the way it is.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn find_by_address(&self, address: &str) -> Result<Option<TrustedDevice>> {
        let row = sqlx::query_as::<_, TrustedDeviceRaw>(
            "SELECT * FROM trusted_devices WHERE last_address = ?",
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Trust a device, or update the trust already held in it.
    ///
    /// `suspended` is deliberately absent from the upsert's update clause: re-trusting a
    /// device must not quietly un-suspend it.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn trust(&self, device: &NewTrustedDevice) -> Result<()> {
        sqlx::query(
            "INSERT INTO trusted_devices
                 (identity_fingerprint, device_id, display_name, os_family, last_address,
                  added_ms, last_connected_ms, unattended, suspended, permissions)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
             ON CONFLICT(identity_fingerprint) DO UPDATE SET
                 device_id = excluded.device_id,
                 display_name = excluded.display_name,
                 os_family = excluded.os_family,
                 last_address = excluded.last_address,
                 last_connected_ms = excluded.last_connected_ms,
                 unattended = excluded.unattended,
                 permissions = excluded.permissions",
        )
        .bind(device.identity_fingerprint.to_hex())
        .bind(&device.device_id)
        .bind(&device.display_name)
        .bind(&device.os_family)
        .bind(&device.address)
        .bind(device.now_ms)
        .bind(device.now_ms)
        .bind(i64::from(device.unattended))
        .bind(i64::from(device.permissions.bits()))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Change what a trusted device may do. Touches nothing else.
    ///
    /// # Errors
    /// [`crate::StorageError::NotFound`] if the identity is not trusted.
    pub async fn set_permissions(
        &self,
        identity: Fingerprint,
        permissions: PermissionSet,
    ) -> Result<()> {
        self.update_one(
            "UPDATE trusted_devices SET permissions = ? WHERE identity_fingerprint = ?",
            i64::from(permissions.bits()),
            identity,
        )
        .await
    }

    /// Turn unattended reconnection on or off. Touches no permission.
    ///
    /// # Errors
    /// [`crate::StorageError::NotFound`] if the identity is not trusted.
    pub async fn set_unattended(&self, identity: Fingerprint, enabled: bool) -> Result<()> {
        self.update_one(
            "UPDATE trusted_devices SET unattended = ? WHERE identity_fingerprint = ?",
            i64::from(enabled),
            identity,
        )
        .await
    }

    /// Temporarily refuse a device, retaining everything about it.
    ///
    /// # Errors
    /// [`crate::StorageError::NotFound`] if the identity is not trusted.
    pub async fn set_suspended(&self, identity: Fingerprint, suspended: bool) -> Result<()> {
        self.update_one(
            "UPDATE trusted_devices SET suspended = ? WHERE identity_fingerprint = ?",
            i64::from(suspended),
            identity,
        )
        .await
    }

    /// Note that a trusted device connected, updating only where and when.
    ///
    /// Grants nothing — see the module documentation. Silently does nothing for an
    /// untrusted identity: a connection admitted by the human dialog without being
    /// remembered has no row, and that is not an error.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn record_connection(
        &self,
        identity: Fingerprint,
        address: &str,
        now_ms: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE trusted_devices
             SET last_address = ?, last_connected_ms = ?
             WHERE identity_fingerprint = ?",
        )
        .bind(address)
        .bind(now_ms)
        .bind(identity.to_hex())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Forget a device entirely.
    ///
    /// Revoking an unknown identity succeeds without changing anything: the caller
    /// wanted it gone, and it already is.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn revoke(&self, identity: Fingerprint) -> Result<()> {
        sqlx::query("DELETE FROM trusted_devices WHERE identity_fingerprint = ?")
            .bind(identity.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Run a single-column update, reporting a missing row rather than a silent no-op.
    ///
    /// The three setters differ only in their statement and value, and a caller that
    /// changed a permission on a device that is not trusted has made a mistake worth
    /// hearing about.
    async fn update_one(
        &self,
        statement: &'static str,
        value: i64,
        identity: Fingerprint,
    ) -> Result<()> {
        let affected = sqlx::query(statement)
            .bind(value)
            .bind(identity.to_hex())
            .execute(&self.pool)
            .await?
            .rows_affected();

        if affected == 0 {
            Err(crate::StorageError::NotFound)
        } else {
            Ok(())
        }
    }
}

/// Raw column mapping, converted so a malformed stored value surfaces as an error
/// rather than propagating as nonsense.
#[derive(Debug, sqlx::FromRow)]
struct TrustedDeviceRaw {
    identity_fingerprint: String,
    device_id: String,
    display_name: String,
    os_family: String,
    last_address: Option<String>,
    added_ms: i64,
    last_connected_ms: Option<i64>,
    unattended: i64,
    suspended: i64,
    permissions: i64,
}

impl TryFrom<TrustedDeviceRaw> for TrustedDevice {
    type Error = crate::StorageError;

    fn try_from(raw: TrustedDeviceRaw) -> Result<Self> {
        let identity_fingerprint =
            raw.identity_fingerprint
                .parse::<Fingerprint>()
                .map_err(|_| crate::StorageError::MalformedColumn {
                    column: "identity_fingerprint",
                })?;

        let bits =
            u8::try_from(raw.permissions).map_err(|_| crate::StorageError::MalformedColumn {
                column: "permissions",
            })?;
        let permissions =
            PermissionSet::from_bits(bits).ok_or(crate::StorageError::MalformedColumn {
                column: "permissions",
            })?;

        Ok(Self {
            identity_fingerprint,
            device_id: raw.device_id,
            display_name: raw.display_name,
            os_family: raw.os_family,
            last_address: raw.last_address,
            added_ms: raw.added_ms,
            last_connected_ms: raw.last_connected_ms,
            unattended: raw.unattended != 0,
            suspended: raw.suspended != 0,
            permissions,
        })
    }
}

#[cfg(test)]
mod tests {
    use rc_security::{Fingerprint, Permission, PermissionSet};

    use super::*;
    use crate::test_support::temp_database;

    fn identity(byte: u8) -> Fingerprint {
        Fingerprint::from_bytes([byte; 32])
    }

    fn candidate(byte: u8) -> NewTrustedDevice {
        NewTrustedDevice {
            identity_fingerprint: identity(byte),
            device_id: "dev-00000000-0000-0000-0000-000000000001".to_owned(),
            display_name: "Gaming PC".to_owned(),
            os_family: "windows".to_owned(),
            address: "192.168.1.77:7443".to_owned(),
            permissions: PermissionSet::NONE.with(Permission::ViewMetrics),
            unattended: false,
            now_ms: 1_700_000_000_000,
        }
    }

    #[tokio::test]
    async fn an_empty_database_trusts_nothing() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        assert!(repository.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn trusting_a_device_stores_it_under_its_identity() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        let found = repository.find(identity(7)).await.unwrap().unwrap();
        assert_eq!(found.display_name, "Gaming PC");
        assert_eq!(
            found.permissions,
            PermissionSet::NONE.with(Permission::ViewMetrics)
        );
        assert!(!found.unattended, "trust must not imply unattended access");
        assert!(!found.suspended);
        assert!(
            !found.permissions.contains(Permission::Administer),
            "trust must never imply administrator"
        );
    }

    #[tokio::test]
    async fn a_different_identity_is_a_different_device() {
        // The property the whole design rests on. Same name, same address, different
        // key: not the same device, and not covered by the other's grant.
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        assert!(repository.find(identity(8)).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn unattended_and_permissions_move_independently() {
        // Granting one must leave the other exactly where it was, in both directions.
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();
        let before = repository
            .find(identity(7))
            .await
            .unwrap()
            .unwrap()
            .permissions;

        repository.set_unattended(identity(7), true).await.unwrap();

        let after = repository.find(identity(7)).await.unwrap().unwrap();
        assert!(after.unattended);
        assert_eq!(
            after.permissions, before,
            "permissions must not move with access"
        );

        repository
            .set_permissions(identity(7), PermissionSet::ALL)
            .await
            .unwrap();
        let after = repository.find(identity(7)).await.unwrap().unwrap();
        assert!(after.unattended, "access must not move with permissions");
    }

    #[tokio::test]
    async fn revoking_removes_the_row_entirely() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();
        repository.set_unattended(identity(7), true).await.unwrap();

        repository.revoke(identity(7)).await.unwrap();

        assert!(repository.find(identity(7)).await.unwrap().is_none());
        assert!(
            repository
                .find_by_address("192.168.1.77:7443")
                .await
                .unwrap()
                .is_none(),
            "nothing about the relationship may survive a revocation"
        );
    }

    #[tokio::test]
    async fn revoking_an_untrusted_identity_is_not_an_error() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.revoke(identity(9)).await.unwrap();
    }

    #[tokio::test]
    async fn suspending_keeps_the_row_and_its_settings() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();
        repository.set_unattended(identity(7), true).await.unwrap();

        repository.set_suspended(identity(7), true).await.unwrap();

        let found = repository.find(identity(7)).await.unwrap().unwrap();
        assert!(found.suspended);
        assert!(
            found.unattended,
            "suspension is temporary; the settings are retained"
        );
    }

    #[tokio::test]
    async fn re_trusting_a_device_does_not_un_suspend_it() {
        // Otherwise a suspended device could clear its own suspension simply by being
        // accepted again at the dialog.
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();
        repository.set_suspended(identity(7), true).await.unwrap();

        repository.trust(&candidate(7)).await.unwrap();

        assert!(
            repository
                .find(identity(7))
                .await
                .unwrap()
                .unwrap()
                .suspended
        );
    }

    #[tokio::test]
    async fn trusting_the_same_identity_twice_updates_rather_than_duplicates() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        let mut again = candidate(7);
        again.display_name = "Renamed".to_owned();
        again.permissions = PermissionSet::ALL;
        repository.trust(&again).await.unwrap();

        let all = repository.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].display_name, "Renamed");
        assert_eq!(all[0].permissions, PermissionSet::ALL);
    }

    #[tokio::test]
    async fn find_by_address_answers_the_identity_change_check() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        let found = repository
            .find_by_address("192.168.1.77:7443")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.identity_fingerprint, identity(7));
        assert!(
            repository
                .find_by_address("10.0.0.1:7443")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn recording_a_connection_updates_the_address_and_time_only() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        repository
            .record_connection(identity(7), "10.0.0.5:7443", 1_700_000_999_000)
            .await
            .unwrap();

        let found = repository.find(identity(7)).await.unwrap().unwrap();
        assert_eq!(found.last_address.as_deref(), Some("10.0.0.5:7443"));
        assert_eq!(found.last_connected_ms, Some(1_700_000_999_000));
        assert_eq!(
            found.permissions,
            PermissionSet::NONE.with(Permission::ViewMetrics),
            "recording a connection must never widen a grant"
        );
        assert!(!found.unattended, "nor may it grant unattended access");
    }

    #[tokio::test]
    async fn recording_a_connection_for_an_untrusted_identity_does_nothing() {
        // A connection admitted at the dialog without being remembered has no row.
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository
            .record_connection(identity(9), "10.0.0.5:7443", 1_700_000_999_000)
            .await
            .unwrap();

        assert!(repository.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn changing_a_device_that_is_not_trusted_is_reported_rather_than_ignored() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);

        for outcome in [
            repository.set_unattended(identity(9), true).await,
            repository.set_suspended(identity(9), true).await,
            repository
                .set_permissions(identity(9), PermissionSet::ALL)
                .await,
        ] {
            assert!(matches!(outcome, Err(crate::StorageError::NotFound)));
        }
    }

    #[tokio::test]
    async fn administrator_is_stored_as_an_ordinary_permission_bit() {
        let database = temp_database().await;
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();

        repository
            .set_permissions(
                identity(7),
                PermissionSet::NONE.with(Permission::Administer),
            )
            .await
            .unwrap();

        assert!(
            repository
                .find(identity(7))
                .await
                .unwrap()
                .unwrap()
                .permissions
                .contains(Permission::Administer)
        );
    }

    #[tokio::test]
    async fn trust_survives_reopening_the_database() {
        // The persistence the whole feature promises, asserted against a real file
        // rather than against an in-memory database that could not fail it.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trust.db");

        let database = crate::Database::open(&path).await.unwrap();
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();
        repository.set_unattended(identity(7), true).await.unwrap();
        database.close().await;

        let database = crate::Database::open(&path).await.unwrap();
        let repository = TrustRepository::new(&database);
        let found = repository.find(identity(7)).await.unwrap().unwrap();
        assert!(found.unattended);
        assert_eq!(
            found.permissions,
            PermissionSet::NONE.with(Permission::ViewMetrics)
        );
        database.close().await;
    }

    #[tokio::test]
    async fn a_revocation_survives_reopening_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("revoked.db");

        let database = crate::Database::open(&path).await.unwrap();
        let repository = TrustRepository::new(&database);
        repository.trust(&candidate(7)).await.unwrap();
        repository.set_unattended(identity(7), true).await.unwrap();
        repository.revoke(identity(7)).await.unwrap();
        database.close().await;

        let database = crate::Database::open(&path).await.unwrap();
        let repository = TrustRepository::new(&database);
        assert!(
            repository.find(identity(7)).await.unwrap().is_none(),
            "a revoked device must not come back after a restart"
        );
        database.close().await;
    }
}
