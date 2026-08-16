//! This machine's own settings: whether it accepts connections, its listen port, its
//! display name, and the optional unattended-access password.
//!
//! # The hash never reaches [`HostSettings`]
//!
//! [`HostSettings`] derives [`serde::Serialize`] because it crosses the Tauri IPC
//! boundary to the frontend. It therefore has no field that could hold a password or a
//! hash. The unattended password is read back only through
//! [`SettingsRepository::unattended_credential`], which returns a
//! [`PasswordCredential`] — a type with no [`serde::Serialize`] impl at all, so there
//! is no path from the stored hash to the webview even if a future edit tried to put
//! one there.

use rc_security::{PasswordCredential, PermissionSet};
use serde::Serialize;

use crate::error::Result;

/// The port a fresh installation listens on.
const DEFAULT_LISTEN_PORT: u16 = 7443;

/// This machine's own settings.
///
/// Crosses the Tauri IPC boundary; see the module documentation for why it can never
/// carry the unattended password or its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSettings {
    /// Whether this machine currently accepts incoming connections.
    pub accepting: bool,
    /// The QUIC port it listens on.
    pub listen_port: u16,
    /// The name shown to a peer connecting to this machine.
    pub machine_name: String,
    /// The permissions an unattended-password connection receives.
    ///
    /// Meaningless, and always [`PermissionSet::NONE`], when no unattended password is
    /// configured.
    pub unattended_permissions: PermissionSet,
}

/// Reads and writes this machine's settings.
#[derive(Debug, Clone)]
pub struct SettingsRepository {
    pool: sqlx::Pool<sqlx::Sqlite>,
}

impl SettingsRepository {
    /// A repository over `database`.
    #[must_use]
    pub fn new(database: &crate::Database) -> Self {
        Self {
            pool: database.pool().clone(),
        }
    }

    /// Load the settings, inserting the default row on first read.
    ///
    /// The default row's machine name is this operating system's hostname, so a fresh
    /// install shows a sensible name before the user has changed anything.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn load(&self) -> Result<HostSettings> {
        self.ensure_row_exists().await?;

        let row: HostSettingsRaw = sqlx::query_as("SELECT * FROM host_settings WHERE id = 1")
            .fetch_one(&self.pool)
            .await?;

        row.try_into()
    }

    /// The unattended-access credential, if one is configured.
    ///
    /// # Errors
    /// Propagates query failures, or a stored hash that no longer parses.
    pub async fn unattended_credential(&self) -> Result<Option<PasswordCredential>> {
        self.ensure_row_exists().await?;

        let row: (Option<String>,) =
            sqlx::query_as("SELECT unattended_phc FROM host_settings WHERE id = 1")
                .fetch_one(&self.pool)
                .await?;

        row.0
            .map(|phc| {
                PasswordCredential::from_phc(phc).map_err(|_| {
                    crate::StorageError::MalformedColumn {
                        column: "unattended_phc",
                    }
                })
            })
            .transpose()
    }

    /// Turn accepting connections on or off.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn set_accepting(&self, accepting: bool) -> Result<()> {
        self.ensure_row_exists().await?;
        sqlx::query("UPDATE host_settings SET accepting = ? WHERE id = 1")
            .bind(accepting)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Change the listen port.
    ///
    /// # Errors
    /// [`crate::StorageError::Invalid`] for a port of `0`.
    pub async fn set_listen_port(&self, port: u16) -> Result<()> {
        if port == 0 {
            return Err(crate::StorageError::Invalid {
                field: "listen_port",
                reason: "must not be 0",
            });
        }

        self.ensure_row_exists().await?;
        sqlx::query("UPDATE host_settings SET listen_port = ? WHERE id = 1")
            .bind(i64::from(port))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Rename this machine.
    ///
    /// # Errors
    /// [`crate::StorageError::Invalid`] for an unusable name.
    pub async fn set_machine_name(&self, name: &str) -> Result<()> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(crate::StorageError::Invalid {
                field: "machine_name",
                reason: "must not be empty",
            });
        }
        if trimmed.len() > 255 {
            return Err(crate::StorageError::Invalid {
                field: "machine_name",
                reason: "is too long",
            });
        }
        if trimmed.chars().any(char::is_control) {
            return Err(crate::StorageError::Invalid {
                field: "machine_name",
                reason: "must not contain control characters",
            });
        }

        self.ensure_row_exists().await?;
        sqlx::query("UPDATE host_settings SET machine_name = ? WHERE id = 1")
            .bind(trimmed)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Set or clear the unattended-access password.
    ///
    /// Passing `None` always writes [`PermissionSet::NONE`] for the permissions too,
    /// regardless of what was asked for — this is what makes the schema's
    /// `CHECK (unattended_phc IS NOT NULL OR unattended_permissions = 0)` unreachable
    /// from this repository rather than merely guarded by it.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn set_unattended(
        &self,
        credential: Option<&PasswordCredential>,
        permissions: PermissionSet,
    ) -> Result<()> {
        let (phc, permissions) = match credential {
            Some(credential) => (
                Some(credential.expose_phc_for_storage().to_owned()),
                permissions,
            ),
            None => (None, PermissionSet::NONE),
        };

        self.ensure_row_exists().await?;
        sqlx::query(
            "UPDATE host_settings SET unattended_phc = ?, unattended_permissions = ? WHERE id = 1",
        )
        .bind(phc)
        .bind(i64::from(permissions.bits()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Insert the default row if it is not there yet.
    async fn ensure_row_exists(&self) -> Result<()> {
        let machine_name = rc_platform::HostInfo::detect().hostname;
        sqlx::query(
            "INSERT INTO host_settings (id, machine_name, listen_port)
             VALUES (1, ?, ?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(machine_name)
        .bind(i64::from(DEFAULT_LISTEN_PORT))
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Raw column mapping, converted into [`HostSettings`] — but never carrying the PHC
/// string past this module, since [`HostSettings`] has no field for it.
#[derive(Debug, sqlx::FromRow)]
struct HostSettingsRaw {
    accepting: i64,
    listen_port: i64,
    machine_name: String,
    unattended_permissions: i64,
}

impl TryFrom<HostSettingsRaw> for HostSettings {
    type Error = crate::StorageError;

    fn try_from(raw: HostSettingsRaw) -> Result<Self> {
        let listen_port =
            u16::try_from(raw.listen_port).map_err(|_| crate::StorageError::MalformedColumn {
                column: "listen_port",
            })?;

        let bits = u8::try_from(raw.unattended_permissions).map_err(|_| {
            crate::StorageError::MalformedColumn {
                column: "unattended_permissions",
            }
        })?;
        let unattended_permissions =
            PermissionSet::from_bits(bits).ok_or(crate::StorageError::MalformedColumn {
                column: "unattended_permissions",
            })?;

        Ok(Self {
            accepting: raw.accepting != 0,
            listen_port,
            machine_name: raw.machine_name,
            unattended_permissions,
        })
    }
}

#[cfg(test)]
mod tests {
    use rc_security::{HashingPolicy, OsRandom, PasswordCredential, Permission, PermissionSet};

    use super::*;
    use crate::test_support::temp_database;

    #[tokio::test]
    async fn defaults_accept_connections_with_no_unattended_password() {
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        let settings = repository.load().await.unwrap();

        assert!(settings.accepting);
        assert_eq!(settings.listen_port, 7443);
        assert!(settings.unattended_permissions.is_empty());
        assert!(repository.unattended_credential().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn setting_a_password_stores_a_verifiable_credential() {
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        let credential = PasswordCredential::create(
            "correct horse battery",
            HashingPolicy::FAST_FOR_TESTS,
            &OsRandom,
        )
        .unwrap();

        repository
            .set_unattended(
                Some(&credential),
                PermissionSet::NONE.with(Permission::ViewMetrics),
            )
            .await
            .unwrap();

        let stored = repository.unattended_credential().await.unwrap().unwrap();
        assert!(stored.verify("correct horse battery").is_ok());
        assert!(stored.verify("wrong").is_err());
        assert_eq!(
            repository.load().await.unwrap().unattended_permissions,
            PermissionSet::NONE.with(Permission::ViewMetrics)
        );
    }

    #[tokio::test]
    async fn clearing_the_password_clears_its_permissions() {
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        let credential = PasswordCredential::create(
            "correct horse battery",
            HashingPolicy::FAST_FOR_TESTS,
            &OsRandom,
        )
        .unwrap();
        repository
            .set_unattended(Some(&credential), PermissionSet::ALL)
            .await
            .unwrap();

        repository
            .set_unattended(None, PermissionSet::ALL)
            .await
            .unwrap();

        assert!(repository.unattended_credential().await.unwrap().is_none());
        assert!(
            repository
                .load()
                .await
                .unwrap()
                .unattended_permissions
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_password_hash_is_not_part_of_the_loaded_settings() {
        // HostSettings is the type that reaches the frontend. A password is configured
        // first, so this fails if the hash ever gains a path into the DTO — the test
        // would pass trivially against an empty database.
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        let credential = PasswordCredential::create(
            "correct horse battery",
            HashingPolicy::FAST_FOR_TESTS,
            &OsRandom,
        )
        .unwrap();
        repository
            .set_unattended(Some(&credential), PermissionSet::ALL)
            .await
            .unwrap();

        let json = serde_json::to_string(&repository.load().await.unwrap()).unwrap();

        let phc = credential.expose_phc_for_storage();
        assert!(
            !json.contains(phc),
            "the stored hash reached the settings DTO"
        );
        assert!(!json.contains("argon2"));
    }

    #[tokio::test]
    async fn a_port_outside_the_valid_range_is_refused() {
        let database = temp_database().await;
        let repository = SettingsRepository::new(&database);
        assert!(repository.set_listen_port(0).await.is_err());
    }
}
