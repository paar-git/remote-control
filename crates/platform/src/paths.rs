//! Where the agent and client keep their configuration, data and logs.
//!
//! Directory choice is centralised here so that the installers, the service unit
//! files and the running processes cannot drift apart.

use std::path::{Path, PathBuf};

use crate::error::{PlatformError, Result};

/// Vendor/application name used to build per-user directories.
const APP_NAME: &str = "remote-control";

/// The set of directories one component uses.
// The shared `_dir` suffix is the point: these are three parallel directories, and
// dropping it would leave fields named `config`, `data` and `log` that read as
// contents rather than locations.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    config_dir: PathBuf,
    data_dir: PathBuf,
    log_dir: PathBuf,
}

impl AppPaths {
    /// Directories for the desktop client, which runs as the logged-in user.
    ///
    /// * Windows: `%APPDATA%\remote-control\{config,data,logs}`
    /// * Linux: `$XDG_CONFIG_HOME/remote-control`, `$XDG_DATA_HOME/remote-control`,
    ///   `$XDG_STATE_HOME/remote-control/logs`
    ///
    /// # Errors
    /// Fails if the platform exposes no home directory.
    pub fn for_client() -> Result<Self> {
        let dirs =
            directories::ProjectDirs::from("", "", APP_NAME).ok_or(PlatformError::Unsupported {
                operation: "resolve per-user application directories",
            })?;

        Ok(Self {
            config_dir: dirs.config_dir().to_path_buf(),
            data_dir: dirs.data_dir().to_path_buf(),
            log_dir: dirs.data_local_dir().join("logs"),
        })
    }

    /// Directories for the host agent, which runs as a system service.
    ///
    /// These are fixed machine-wide locations rather than per-user ones, because the
    /// service account must reach them regardless of who is logged in:
    ///
    /// * Windows: `%ProgramData%\remote-control\{config,data,logs}`
    /// * Linux: `/etc/remote-control`, `/var/lib/remote-control`, `/var/log/remote-control`
    ///
    /// # Errors
    /// Fails on Windows if `ProgramData` is not set in the environment.
    pub fn for_agent() -> Result<Self> {
        #[cfg(windows)]
        {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .ok_or(PlatformError::Unsupported {
                    operation: "resolve %ProgramData%",
                })?
                .join(APP_NAME);
            Ok(Self {
                config_dir: base.join("config"),
                data_dir: base.join("data"),
                log_dir: base.join("logs"),
            })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {
                config_dir: PathBuf::from("/etc").join(APP_NAME),
                data_dir: PathBuf::from("/var/lib").join(APP_NAME),
                log_dir: PathBuf::from("/var/log").join(APP_NAME),
            })
        }
    }

    /// Build an explicit set, for tests and for a `--data-dir` override.
    #[must_use]
    pub fn with_root(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            config_dir: root.join("config"),
            data_dir: root.join("data"),
            log_dir: root.join("logs"),
        }
    }

    /// Directory holding `agent.toml` / `client.toml`.
    #[must_use]
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    /// Directory holding the `SQLite` database and key material.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Directory holding rotating logs.
    #[must_use]
    pub fn log_dir(&self) -> &Path {
        &self.log_dir
    }

    /// Path of the `SQLite` database.
    #[must_use]
    pub fn database_file(&self) -> PathBuf {
        self.data_dir.join("remote-control.db")
    }

    /// Path of the TLS/identity certificate in PEM form. The matching private key is
    /// held by the platform keystore, not next to this file.
    #[must_use]
    pub fn certificate_file(&self) -> PathBuf {
        self.data_dir.join("device-identity.pem")
    }

    /// Create every directory, applying restrictive permissions.
    ///
    /// On Unix the config and data directories are set to `0700` because they hold
    /// pinned identities and key material. On Windows the ACL is inherited from the
    /// parent, which the installer configures.
    ///
    /// # Errors
    /// Fails if a directory cannot be created.
    pub fn create_all(&self) -> Result<()> {
        for dir in [&self.config_dir, &self.data_dir, &self.log_dir] {
            std::fs::create_dir_all(dir).map_err(|source| PlatformError::Os {
                operation: "create application directory",
                source,
            })?;
        }
        Self::restrict(&self.config_dir)?;
        Self::restrict(&self.data_dir)?;
        Ok(())
    }

    #[allow(unused_variables, clippy::unnecessary_wraps)]
    fn restrict(dir: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let perms = std::fs::Permissions::from_mode(0o700);
            if let Err(err) = std::fs::set_permissions(dir, perms) {
                tracing::warn!(?err, ?dir, "could not restrict directory permissions");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_paths_resolve_and_are_distinct() {
        let paths = AppPaths::for_client().unwrap();
        assert_ne!(paths.config_dir(), paths.log_dir());
        assert!(paths.database_file().ends_with("remote-control.db"));
    }

    #[test]
    fn agent_paths_resolve() {
        let paths = AppPaths::for_agent().unwrap();
        assert!(paths.data_dir().is_absolute());
        assert!(paths.config_dir().is_absolute());
    }

    #[test]
    fn agent_and_client_do_not_share_a_data_directory() {
        // The agent runs as a service and the client as the desktop user; sharing a
        // directory would mean one of them needs rights it should not have.
        let agent = AppPaths::for_agent().unwrap();
        let client = AppPaths::for_client().unwrap();
        assert_ne!(agent.data_dir(), client.data_dir());
    }

    #[test]
    fn create_all_makes_every_directory() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_root(dir.path());
        paths.create_all().unwrap();

        assert!(paths.config_dir().is_dir());
        assert!(paths.data_dir().is_dir());
        assert!(paths.log_dir().is_dir());
    }

    #[test]
    fn create_all_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_root(dir.path());
        paths.create_all().unwrap();
        paths.create_all().unwrap();
        assert!(paths.data_dir().is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn data_directory_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_root(dir.path());
        paths.create_all().unwrap();

        let mode = std::fs::metadata(paths.data_dir())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "data dir must not be group- or world-accessible"
        );
    }
}
