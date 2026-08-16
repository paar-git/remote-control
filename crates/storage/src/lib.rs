//! SQLite persistence for the remote-control platform.
//!
//! Both the desktop client and the host agent embed this crate; each uses the subset
//! of tables it needs. The schema lives in `migrations/` and is embedded into the
//! binary at compile time, so a fresh install needs no external SQL files.
//!
//! # Safety properties
//!
//! * Migrations are **additive only**. [`Database::open`] refuses to run against a
//!   database whose schema is newer than the binary, rather than guessing.
//! * `PRAGMA foreign_keys` is enabled on every connection; SQLite defaults it off.
//! * The database file is created with restrictive permissions (see
//!   [`Database::open`]), because it holds password hashes and pinned identities.
//! * No secret is ever stored in plaintext — see the header comment in
//!   `migrations/0001_initial.sql`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod error;
pub mod history;
pub mod models;
pub mod recent;
pub mod settings;
pub mod trust;

#[cfg(test)]
mod repo_tests;
#[cfg(test)]
pub(crate) mod test_support;

use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Pool, Sqlite};

pub use error::{Result, StorageError};
pub use history::{
    HISTORY_LIMIT, NewSessionRecord, SessionDirection, SessionHistoryRepository, SessionOutcome,
    SessionRecord,
};
pub use recent::{RecentConnection, RecentRepository};
pub use settings::{HostSettings, SettingsRepository};
pub use trust::{NewTrustedDevice, TrustRepository, TrustedDevice};

/// Migrations compiled into the binary.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Highest migration version this build ships.
pub const SUPPORTED_SCHEMA_VERSION: i64 = 6;

/// An open, migrated database.
#[derive(Debug, Clone)]
pub struct Database {
    pool: Pool<Sqlite>,
    path: Option<PathBuf>,
}

impl Database {
    /// Open (creating if absent) the database at `path` and bring it up to date.
    ///
    /// The parent directory must already exist with appropriate permissions; this
    /// function does not create it, so that directory ownership stays the caller's
    /// explicit decision.
    ///
    /// # Errors
    /// Fails if the file cannot be opened, if a migration fails, or if the on-disk
    /// schema is newer than [`SUPPORTED_SCHEMA_VERSION`].
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .foreign_keys(true)
            // WAL keeps readers from blocking the agent's writers during a transfer.
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_secs(10));

        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect_with(options)
            .await
            .map_err(StorageError::Open)?;

        let db = Self {
            pool,
            path: Some(path.clone()),
        };
        db.restrict_file_permissions(&path)?;
        db.migrate().await?;
        Ok(db)
    }

    /// Open a private in-memory database, for tests.
    ///
    /// # Errors
    /// Fails if migrations cannot be applied.
    pub async fn open_in_memory() -> Result<Self> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(StorageError::Open)?
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            // An in-memory database vanishes when its last connection closes, so the
            // pool is pinned to a single, never-reaped connection.
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await
            .map_err(StorageError::Open)?;

        let db = Self { pool, path: None };
        db.migrate().await?;
        Ok(db)
    }

    /// Borrow the connection pool for queries.
    #[must_use]
    pub const fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }

    /// Path on disk, or `None` for an in-memory database.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Apply any migrations that have not run yet.
    async fn migrate(&self) -> Result<()> {
        let applied = self.schema_version().await?;
        if applied > SUPPORTED_SCHEMA_VERSION {
            return Err(StorageError::SchemaTooNew {
                found: applied,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }

        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(StorageError::Migrate)?;
        tracing::debug!(
            from = applied,
            to = SUPPORTED_SCHEMA_VERSION,
            "database schema ready"
        );
        Ok(())
    }

    /// Highest migration version currently recorded, or `0` on a fresh database.
    ///
    /// # Errors
    /// Fails only if the migrations table exists but cannot be read.
    pub async fn schema_version(&self) -> Result<i64> {
        // Absent on a fresh database; sqlx creates it during the first run.
        let exists: Option<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
        )
        .fetch_optional(&self.pool)
        .await?;

        if exists.is_none() {
            return Ok(0);
        }

        let row: Option<(i64,)> =
            sqlx::query_as("SELECT MAX(version) FROM _sqlx_migrations WHERE success = TRUE")
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map_or(0, |r| r.0))
    }

    /// Verify the database is usable. Backs the agent's local health check.
    ///
    /// # Errors
    /// Fails if the database cannot answer a trivial query.
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Close the pool, flushing WAL content.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Tighten filesystem permissions on the database file.
    ///
    /// On Unix the file is set to `0600`. On Windows the file inherits the parent
    /// directory's ACL; the installer is responsible for creating that directory
    /// with an ACL limited to the service account and Administrators, which is
    /// documented in `docs/installation.md`.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn restrict_file_permissions(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Ok(metadata) = std::fs::metadata(path) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o600);
                if let Err(err) = std::fs::set_permissions(path, perms) {
                    tracing::warn!(?err, "could not restrict database file permissions");
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fresh_database_migrates_to_the_supported_version() {
        let db = Database::open_in_memory().await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), SUPPORTED_SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn migrations_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");

        let db = Database::open(&path).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), SUPPORTED_SCHEMA_VERSION);
        db.close().await;

        // Re-opening must not re-run or fail on already-applied migrations.
        let db = Database::open(&path).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), SUPPORTED_SCHEMA_VERSION);
        db.health_check().await.unwrap();
        db.close().await;
    }

    #[tokio::test]
    async fn data_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("persist.db");

        let db = Database::open(&path).await.unwrap();
        sqlx::query("INSERT INTO app_setting (key, value_json, updated_at_ms) VALUES (?, ?, ?)")
            .bind("device_name")
            .bind(r#""home-server""#)
            .bind(1_700_000_000_000i64)
            .execute(db.pool())
            .await
            .unwrap();
        db.close().await;

        let db = Database::open(&path).await.unwrap();
        let (value,): (String,) =
            sqlx::query_as("SELECT value_json FROM app_setting WHERE key = ?")
                .bind("device_name")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(value, r#""home-server""#);
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        // The schema after migration 0003 has no foreign key left to violate — the one
        // that existed, session_token.account_id -> owner_account.id, was dropped along
        // with both tables. What is still verifiable, and still worth pinning, is that
        // enforcement itself is switched on for every connection, per the crate's
        // safety property that `PRAGMA foreign_keys` is always enabled.
        let db = Database::open_in_memory().await.unwrap();
        let (enabled,): (i64,) = sqlx::query_as("PRAGMA foreign_keys")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(enabled, 1, "foreign key enforcement must be on");
    }

    #[tokio::test]
    async fn check_constraints_reject_bad_enum_values() {
        let db = Database::open_in_memory().await.unwrap();
        let err = sqlx::query(
            "INSERT INTO host_settings (id, machine_name, accepting) VALUES (1, 'x', 5)",
        )
        .execute(db.pool())
        .await
        .unwrap_err();

        assert!(
            format!("{err}").to_uppercase().contains("CHECK"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn recent_connection_addresses_are_unique() {
        let db = Database::open_in_memory().await.unwrap();
        let insert = || {
            sqlx::query(
                "INSERT INTO recent_connections (address, machine_name, last_connected_ms)
                 VALUES ('10.0.0.1', 'box', 1)",
            )
            .execute(db.pool())
        };

        insert().await.unwrap();
        let err: StorageError = insert().await.unwrap_err().into();
        assert!(matches!(err, StorageError::Conflict), "got: {err}");
    }

    #[tokio::test]
    async fn transfer_state_cannot_exceed_its_total() {
        let db = Database::open_in_memory().await.unwrap();
        let err = sqlx::query(
            "INSERT INTO transfer_state
                 (transfer_id, device_id, direction, source_path, destination_path,
                  total_bytes, transferred_bytes, status, created_at_ms, updated_at_ms)
             VALUES ('t1', 'd1', 'upload', 'a', 'b', 10, 11, 'active', 1, 1)",
        )
        .execute(db.pool())
        .await
        .unwrap_err();

        assert!(
            format!("{err}").to_uppercase().contains("CHECK"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn in_memory_databases_are_isolated_from_each_other() {
        let a = Database::open_in_memory().await.unwrap();
        let b = Database::open_in_memory().await.unwrap();

        sqlx::query("INSERT INTO app_setting (key, value_json, updated_at_ms) VALUES ('k','1',1)")
            .execute(a.pool())
            .await
            .unwrap();

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM app_setting")
            .fetch_one(b.pool())
            .await
            .unwrap();
        assert_eq!(count.0, 0);
    }
}
