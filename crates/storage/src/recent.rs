//! Machines this installation has connected to.
//!
//! One row per address, keyed by the address itself rather than by an identity: the
//! address is what the user typed, and a machine reached under a different address is
//! a different row by design — its pin has to be re-decided.
//!
//! # The pin is never silently re-granted
//!
//! [`RecentRepository::record`] runs on every connection, successful or not yet
//! authorized, to keep the "last connected" list current. It deliberately leaves
//! `pinned_fingerprint` and `pinned_permissions` untouched: those columns are written
//! only by [`RecentRepository::set_always_allow`], which is reached solely from a
//! human ticking "always allow" on the Accept dialog. If `record` touched the pin, a
//! machine the user had un-pinned would silently regain always-allow the next time it
//! was dialled — a permission grant with no human decision behind it.

use rc_security::{Fingerprint, PermissionSet};

use crate::error::Result;

/// A machine this installation has connected to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentConnection {
    /// The address the user typed to reach it.
    pub address: String,
    /// The name it reported, shown in the recent-connections list.
    pub machine_name: String,
    /// When a connection to it was last recorded.
    pub last_connected_ms: i64,
    /// The fingerprint pinned for always-allow, if the user set one.
    pub pinned_fingerprint: Option<Fingerprint>,
    /// The permissions an always-allow connection receives.
    ///
    /// Meaningless, and always [`PermissionSet::NONE`], when `pinned_fingerprint` is
    /// `None` — enforced by the schema's `CHECK` and by
    /// [`RecentRepository::set_always_allow`] never writing one without the other.
    pub pinned_permissions: PermissionSet,
}

/// Reads and writes recent connections.
#[derive(Debug, Clone)]
pub struct RecentRepository {
    pool: sqlx::Pool<sqlx::Sqlite>,
}

impl RecentRepository {
    /// A repository over `database`.
    #[must_use]
    pub fn new(database: &crate::Database) -> Self {
        Self {
            pool: database.pool().clone(),
        }
    }

    /// Every recorded connection, most recently connected first.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn list(&self) -> Result<Vec<RecentConnection>> {
        let rows = sqlx::query_as::<_, RecentConnectionRaw>(
            "SELECT * FROM recent_connections ORDER BY last_connected_ms DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Look up one connection by address.
    ///
    /// # Errors
    /// Propagates query failures. A missing address yields `Ok(None)`.
    pub async fn find(&self, address: &str) -> Result<Option<RecentConnection>> {
        let row = sqlx::query_as::<_, RecentConnectionRaw>(
            "SELECT * FROM recent_connections WHERE address = ?",
        )
        .bind(address)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Record that a connection to `address` was made, upserting the name and time.
    ///
    /// Deliberately leaves any existing pin untouched — see the module documentation.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn record(&self, address: &str, machine_name: &str, now_ms: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO recent_connections (address, machine_name, last_connected_ms)
             VALUES (?, ?, ?)
             ON CONFLICT(address) DO UPDATE SET
                 machine_name = excluded.machine_name,
                 last_connected_ms = excluded.last_connected_ms",
        )
        .bind(address)
        .bind(machine_name)
        .bind(now_ms)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Set or clear the always-allow pin for `address`.
    ///
    /// Passing `None` for `fingerprint` always writes [`PermissionSet::NONE`] for the
    /// permissions too, regardless of what was asked for — this is what makes the
    /// schema's `CHECK (pinned_fingerprint IS NOT NULL OR pinned_permissions = 0)`
    /// unreachable from this repository rather than merely guarded by it.
    ///
    /// # Errors
    /// [`crate::StorageError::NotFound`] if the address has no recorded connection yet.
    pub async fn set_always_allow(
        &self,
        address: &str,
        fingerprint: Option<Fingerprint>,
        permissions: PermissionSet,
    ) -> Result<()> {
        let (fingerprint_hex, permissions) = match fingerprint {
            Some(fingerprint) => (Some(fingerprint.to_hex()), permissions),
            None => (None, PermissionSet::NONE),
        };

        let affected = sqlx::query(
            "UPDATE recent_connections
             SET pinned_fingerprint = ?, pinned_permissions = ?
             WHERE address = ?",
        )
        .bind(fingerprint_hex)
        .bind(i64::from(permissions.bits()))
        .bind(address)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            Err(crate::StorageError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Forget a connection entirely, pin included.
    ///
    /// Removing an unknown address succeeds without changing anything: the caller
    /// wanted the address gone, and it already is.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn remove(&self, address: &str) -> Result<()> {
        sqlx::query("DELETE FROM recent_connections WHERE address = ?")
            .bind(address)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

/// Raw column mapping, converted into [`RecentConnection`] so a malformed stored value
/// surfaces as an error rather than propagating as nonsense.
#[derive(Debug, sqlx::FromRow)]
struct RecentConnectionRaw {
    address: String,
    machine_name: String,
    last_connected_ms: i64,
    pinned_fingerprint: Option<String>,
    pinned_permissions: i64,
}

impl TryFrom<RecentConnectionRaw> for RecentConnection {
    type Error = crate::StorageError;

    fn try_from(raw: RecentConnectionRaw) -> Result<Self> {
        let pinned_fingerprint = raw
            .pinned_fingerprint
            .map(|hex| {
                hex.parse::<Fingerprint>()
                    .map_err(|_| crate::StorageError::MalformedColumn {
                        column: "pinned_fingerprint",
                    })
            })
            .transpose()?;

        let bits = u8::try_from(raw.pinned_permissions).map_err(|_| {
            crate::StorageError::MalformedColumn {
                column: "pinned_permissions",
            }
        })?;
        let pinned_permissions =
            PermissionSet::from_bits(bits).ok_or(crate::StorageError::MalformedColumn {
                column: "pinned_permissions",
            })?;

        Ok(Self {
            address: raw.address,
            machine_name: raw.machine_name,
            last_connected_ms: raw.last_connected_ms,
            pinned_fingerprint,
            pinned_permissions,
        })
    }
}

#[cfg(test)]
mod tests {
    use rc_security::{Fingerprint, Permission, PermissionSet};

    use super::*;
    use crate::test_support::temp_database;

    #[tokio::test]
    async fn an_empty_database_lists_nothing() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        assert!(repository.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn recording_a_connection_makes_it_findable() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository
            .record("192.168.1.77", "WORK-LAPTOP", 1_700_000_000_000)
            .await
            .unwrap();

        let found = repository.find("192.168.1.77").await.unwrap().unwrap();
        assert_eq!(found.machine_name, "WORK-LAPTOP");
        assert_eq!(found.last_connected_ms, 1_700_000_000_000);
        assert!(found.pinned_fingerprint.is_none());
        assert!(found.pinned_permissions.is_empty());
    }

    #[tokio::test]
    async fn recording_the_same_address_twice_updates_rather_than_duplicates() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository
            .record("192.168.1.77", "OLD-NAME", 1_000)
            .await
            .unwrap();
        repository
            .record("192.168.1.77", "NEW-NAME", 2_000)
            .await
            .unwrap();

        let all = repository.list().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].machine_name, "NEW-NAME");
        assert_eq!(all[0].last_connected_ms, 2_000);
    }

    #[tokio::test]
    async fn the_list_is_most_recent_first() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository
            .record("10.0.0.1", "OLDEST", 1_000)
            .await
            .unwrap();
        repository
            .record("10.0.0.2", "NEWEST", 3_000)
            .await
            .unwrap();
        repository
            .record("10.0.0.3", "MIDDLE", 2_000)
            .await
            .unwrap();

        let names: Vec<String> = repository
            .list()
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.machine_name)
            .collect();
        assert_eq!(names, vec!["NEWEST", "MIDDLE", "OLDEST"]);
    }

    #[tokio::test]
    async fn always_allow_stores_the_pin_and_the_permissions() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "BOX", 1_000).await.unwrap();

        let fingerprint = Fingerprint::from_bytes([7u8; 32]);
        let granted = PermissionSet::NONE.with(Permission::TransferFiles);
        repository
            .set_always_allow("10.0.0.1", Some(fingerprint), granted)
            .await
            .unwrap();

        let found = repository.find("10.0.0.1").await.unwrap().unwrap();
        assert_eq!(found.pinned_fingerprint, Some(fingerprint));
        assert_eq!(found.pinned_permissions, granted);
    }

    #[tokio::test]
    async fn clearing_always_allow_clears_the_permissions_too() {
        // A row with permissions but no pin would be a grant nothing can match, which
        // the schema refuses. Clearing must clear both or the write fails.
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "BOX", 1_000).await.unwrap();
        repository
            .set_always_allow(
                "10.0.0.1",
                Some(Fingerprint::from_bytes([7u8; 32])),
                PermissionSet::ALL,
            )
            .await
            .unwrap();

        repository
            .set_always_allow("10.0.0.1", None, PermissionSet::ALL)
            .await
            .unwrap();

        let found = repository.find("10.0.0.1").await.unwrap().unwrap();
        assert!(found.pinned_fingerprint.is_none());
        assert!(found.pinned_permissions.is_empty());
    }

    #[tokio::test]
    async fn removing_an_entry_removes_its_pin() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "BOX", 1_000).await.unwrap();
        repository.remove("10.0.0.1").await.unwrap();
        assert!(repository.find("10.0.0.1").await.unwrap().is_none());
    }
}
