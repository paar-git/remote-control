//! Machines this installation has dialled.
//!
//! One row per address, keyed by the address itself, because the address is what the
//! user types to reach a machine. This is the *outgoing* history and nothing more: it
//! grants nothing and admits nobody. Incoming trust lives in [`crate::trust`], keyed on
//! a device identity, precisely because an address is not an identity.
//!
//! # `known_identity` is a pin, not a grant
//!
//! It records which identity answered at this address, written on the first successful
//! connection and compared on every later one, so a substituted machine at a familiar
//! address is visible rather than silently connected to. It pins the *identity* rather
//! than the certificate, so an ordinary renewal on the far side is not mistaken for a
//! different machine.
//!
//! [`RecentRepository::record`] runs on every connection, successful or not, to keep
//! the list current, and deliberately leaves `known_identity` untouched. If it did not,
//! a machine that had been substituted would overwrite the very value the comparison
//! exists to make.

use rc_security::Fingerprint;

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
    /// The identity that answered here, once one has. Compared, never trusted blindly.
    pub known_identity: Option<Fingerprint>,
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
    /// Deliberately leaves `known_identity` untouched — see the module documentation.
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

    /// Record the identity this address is now known to have.
    ///
    /// Written on the first successful connection and compared on every later one, so a
    /// substituted machine at a familiar address is visible rather than silent.
    ///
    /// # Errors
    /// [`crate::StorageError::NotFound`] if the address has no recorded connection yet.
    pub async fn set_known_identity(&self, address: &str, identity: Fingerprint) -> Result<()> {
        let affected =
            sqlx::query("UPDATE recent_connections SET known_identity = ? WHERE address = ?")
                .bind(identity.to_hex())
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

    /// Forget a connection entirely, its known identity included.
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
    known_identity: Option<String>,
}

impl TryFrom<RecentConnectionRaw> for RecentConnection {
    type Error = crate::StorageError;

    fn try_from(raw: RecentConnectionRaw) -> Result<Self> {
        let known_identity = raw
            .known_identity
            .map(|hex| {
                hex.parse::<Fingerprint>()
                    .map_err(|_| crate::StorageError::MalformedColumn {
                        column: "known_identity",
                    })
            })
            .transpose()?;

        Ok(Self {
            address: raw.address,
            machine_name: raw.machine_name,
            last_connected_ms: raw.last_connected_ms,
            known_identity,
        })
    }
}

#[cfg(test)]
mod tests {
    use rc_security::Fingerprint;

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
        assert!(found.known_identity.is_none());
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
    async fn the_known_identity_round_trips() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "BOX", 1_000).await.unwrap();

        let identity = Fingerprint::from_bytes([7u8; 32]);
        repository
            .set_known_identity("10.0.0.1", identity)
            .await
            .unwrap();

        let found = repository.find("10.0.0.1").await.unwrap().unwrap();
        assert_eq!(found.known_identity, Some(identity));
    }

    #[tokio::test]
    async fn recording_a_connection_leaves_the_known_identity_alone() {
        // If `record` overwrote it, a substituted machine would replace the very value
        // the comparison exists to make -- and the substitution would go unnoticed.
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "BOX", 1_000).await.unwrap();
        let identity = Fingerprint::from_bytes([7u8; 32]);
        repository
            .set_known_identity("10.0.0.1", identity)
            .await
            .unwrap();

        repository.record("10.0.0.1", "BOX", 2_000).await.unwrap();

        let found = repository.find("10.0.0.1").await.unwrap().unwrap();
        assert_eq!(found.known_identity, Some(identity));
        assert_eq!(found.last_connected_ms, 2_000);
    }

    #[tokio::test]
    async fn pinning_an_address_never_dialled_is_reported_rather_than_ignored() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);

        let outcome = repository
            .set_known_identity("10.0.0.9", Fingerprint::from_bytes([7u8; 32]))
            .await;

        assert!(matches!(outcome, Err(crate::StorageError::NotFound)));
    }

    #[tokio::test]
    async fn removing_an_entry_removes_its_known_identity() {
        let database = temp_database().await;
        let repository = RecentRepository::new(&database);
        repository.record("10.0.0.1", "BOX", 1_000).await.unwrap();
        repository.remove("10.0.0.1").await.unwrap();
        assert!(repository.find("10.0.0.1").await.unwrap().is_none());
    }
}
