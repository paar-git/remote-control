//! Agent configuration: parsing, validation and defaults.
//!
//! Configuration is read from a TOML file and validated eagerly. Validation is
//! **fail-closed**: a malformed or unsafe value stops the agent from starting rather
//! than being silently corrected, so a typo can never quietly widen exposure.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Errors raised while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The file could not be read.
    #[error("could not read configuration file")]
    Read(#[source] std::io::Error),

    /// The file was not valid TOML, or did not match the expected shape.
    #[error("configuration file is not valid: {0}")]
    Parse(String),

    /// The file could not be written.
    #[error("could not write configuration file")]
    Write(#[source] std::io::Error),

    /// A value was syntactically fine but semantically unsafe or unusable.
    #[error("invalid configuration: `{field}` {reason}")]
    Invalid {
        /// Which field.
        field: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
}

/// How often the operator must confirm a dangerous action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationPolicy {
    /// Confirm every single time. The default, and the safest.
    #[default]
    EveryTime,
    /// Confirm once per session, then remember for that session only.
    OncePerSession,
    /// Re-enter the local application password.
    RequirePassword,
    /// Defer to an operating-system confirmation prompt (UAC / polkit).
    RequireOsPrompt,
}

/// Verbosity of the agent's own logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Errors and warnings.
    Warn,
    /// Normal operational detail. The default.
    #[default]
    Info,
    /// Verbose detail for troubleshooting.
    Debug,
    /// Everything, including per-frame detail. Never appropriate in production.
    Trace,
}

impl LogLevel {
    /// The `tracing` filter directive for this level.
    #[must_use]
    pub const fn as_filter(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

/// Network settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Address to bind the QUIC listener to.
    ///
    /// Defaults to `0.0.0.0` so the agent is reachable on the LAN. This is safe only
    /// because every connection requires a pinned client certificate; see
    /// `docs/threat-model.md`.
    pub listen_address: IpAddr,
    /// UDP port for QUIC.
    pub listen_port: u16,
    /// Whether to advertise the agent over mDNS on the local network.
    pub discovery_enabled: bool,
    /// Whether to register with a coordination server for connections from outside
    /// the LAN. Off by default: remote reachability must be a deliberate choice.
    pub remote_access_enabled: bool,
    /// Coordination server URL. Required when `remote_access_enabled` is set.
    pub coordination_url: Option<String>,
    /// Relay URL used when a direct peer-to-peer path cannot be established.
    pub relay_url: Option<String>,
    /// TCP port for the unauthenticated local health endpoint, or `0` to disable it.
    ///
    /// Always bound to `127.0.0.1`; the address is deliberately not configurable, so no
    /// configuration mistake can expose it to the network.
    pub health_port: u16,
    /// Maximum concurrent authenticated sessions.
    pub max_sessions: u16,
    /// Failed authentication attempts permitted per source address per minute.
    pub auth_attempts_per_minute: u16,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            listen_port: rc_protocol::DEFAULT_AGENT_PORT,
            health_port: rc_protocol::DEFAULT_AGENT_HEALTH_PORT,
            discovery_enabled: true,
            remote_access_enabled: false,
            coordination_url: None,
            relay_url: None,
            max_sessions: 4,
            auth_attempts_per_minute: 10,
        }
    }
}

/// Session lifetime and locking behaviour.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    /// Seconds of inactivity before a session is closed. `0` disables the timeout.
    pub idle_timeout_secs: u32,
    /// Lifetime of a short-lived access token, in seconds.
    pub access_token_ttl_secs: u32,
    /// Lifetime of a refresh token, in seconds.
    pub refresh_token_ttl_secs: u32,
    /// How dangerous actions must be confirmed.
    pub confirmation_policy: ConfirmationPolicy,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 1800,
            access_token_ttl_secs: 900,
            refresh_token_ttl_secs: 30 * 24 * 3600,
            confirmation_policy: ConfirmationPolicy::default(),
        }
    }
}

/// Feature toggles. Everything a remote peer can do is opt-out-able here, so an
/// operator can run a monitoring-only agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent, individually named feature switches.
pub struct FeatureConfig {
    /// Allow screen capture and input injection.
    pub remote_desktop: bool,
    /// Allow PTY sessions.
    pub terminal: bool,
    /// Allow file browsing and transfer.
    pub file_transfer: bool,
    /// Allow process termination.
    pub process_management: bool,
    /// Allow service control.
    pub service_management: bool,
    /// Allow power actions.
    pub power_control: bool,
    /// Allow clipboard synchronisation.
    pub clipboard_sync: bool,
    /// Roots the file manager is confined to. Empty means the whole filesystem, which
    /// is appropriate for a server you administer but is stated explicitly.
    pub file_transfer_roots: Vec<String>,
    /// Largest single file that may be transferred, in bytes.
    pub max_transfer_bytes: u64,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            remote_desktop: true,
            terminal: true,
            file_transfer: true,
            process_management: true,
            service_management: true,
            power_control: true,
            clipboard_sync: true,
            file_transfer_roots: Vec::new(),
            max_transfer_bytes: 64 * 1024 * 1024 * 1024,
        }
    }
}

/// The agent's full configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// Name shown to clients. Purely cosmetic.
    pub device_name: String,
    /// Network settings.
    pub network: NetworkConfig,
    /// Session settings.
    pub session: SessionConfig,
    /// Feature toggles.
    pub features: FeatureConfig,
    /// Log verbosity.
    pub log_level: LogLevel,
    /// Number of rotated log files to retain.
    pub log_retention_days: u16,
    /// Whether the agent starts at boot. Applied by the installer; recorded here so
    /// the UI can display and change it.
    pub start_at_boot: bool,
    /// Update channel to check for signed updates on.
    pub update_channel: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            device_name: default_device_name(),
            network: NetworkConfig::default(),
            session: SessionConfig::default(),
            features: FeatureConfig::default(),
            log_level: LogLevel::default(),
            log_retention_days: 14,
            start_at_boot: true,
            update_channel: "stable".to_string(),
        }
    }
}

fn default_device_name() -> String {
    rc_platform::HostInfo::detect().hostname
}

impl AgentConfig {
    /// Load and validate configuration from a TOML file.
    ///
    /// # Errors
    /// Fails if the file cannot be read, is not valid TOML, contains unknown keys, or
    /// fails [`AgentConfig::validate`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Read)?;
        Self::from_toml(&text)
    }

    /// Load configuration from a file, or produce validated defaults if it is absent.
    ///
    /// A file that exists but is broken is still an error: silently falling back to
    /// defaults could disable a restriction the operator intended.
    ///
    /// # Errors
    /// Fails for any reason other than the file not existing.
    pub fn load_or_default(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let config = Self::default();
                config.validate()?;
                Ok(config)
            }
            Err(err) => Err(ConfigError::Read(err)),
        }
    }

    /// Parse and validate configuration from TOML text.
    ///
    /// # Errors
    /// Fails on malformed TOML, unknown keys, or failed validation.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self =
            toml::from_str(text).map_err(|err| ConfigError::Parse(err.message().to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Serialise to TOML.
    ///
    /// # Errors
    /// Fails only if the configuration is not representable, which indicates a bug.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        toml::to_string_pretty(self).map_err(|err| ConfigError::Parse(err.to_string()))
    }

    /// Write to disk, creating the parent directory if needed.
    ///
    /// # Errors
    /// Fails if the file cannot be written.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(ConfigError::Write)?;
        }
        std::fs::write(path, self.to_toml()?).map_err(ConfigError::Write)
    }

    /// The socket the QUIC listener binds to.
    #[must_use]
    pub const fn listen_socket(&self) -> SocketAddr {
        SocketAddr::new(self.network.listen_address, self.network.listen_port)
    }

    /// Reject unsafe or unusable values.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] naming the first offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |field, reason| Err(ConfigError::Invalid { field, reason });

        if self.device_name.trim().is_empty() {
            return invalid("device_name", "must not be empty");
        }
        if self.device_name.len() > rc_protocol::limits::MAX_DEVICE_NAME_BYTES {
            return invalid("device_name", "is too long");
        }
        // Control characters would corrupt terminal output and log lines.
        if self.device_name.chars().any(char::is_control) {
            return invalid("device_name", "must not contain control characters");
        }

        if self.network.listen_port == 0 {
            return invalid("network.listen_port", "must not be 0");
        }
        if self.network.listen_port < 1024 {
            return invalid(
                "network.listen_port",
                "must be above 1023; the agent must not need root to bind",
            );
        }
        // `0` disables the endpoint; any other value must be bindable without root.
        if self.network.health_port != 0 && self.network.health_port < 1024 {
            return invalid(
                "network.health_port",
                "must be 0 to disable it, or above 1023",
            );
        }
        if self.network.health_port != 0 && self.network.health_port == self.network.listen_port {
            return invalid(
                "network.health_port",
                "must differ from the QUIC listener port",
            );
        }
        if self.network.max_sessions == 0 {
            return invalid("network.max_sessions", "must be at least 1");
        }
        if self.network.auth_attempts_per_minute == 0 {
            return invalid("network.auth_attempts_per_minute", "must be at least 1");
        }
        if self.network.auth_attempts_per_minute > 120 {
            return invalid(
                "network.auth_attempts_per_minute",
                "is too permissive to throttle brute-force attempts",
            );
        }

        // Remote access without a coordination server would silently do nothing.
        if self.network.remote_access_enabled {
            match &self.network.coordination_url {
                None => {
                    return invalid(
                        "network.coordination_url",
                        "is required when remote access is enabled",
                    );
                }
                Some(url) => validate_url(url, "network.coordination_url")?,
            }
        }
        if let Some(url) = &self.network.relay_url {
            validate_url(url, "network.relay_url")?;
        }

        if self.session.access_token_ttl_secs == 0 {
            return invalid("session.access_token_ttl_secs", "must be greater than 0");
        }
        if self.session.access_token_ttl_secs > 86_400 {
            return invalid(
                "session.access_token_ttl_secs",
                "must be at most 24 hours; access tokens are meant to be short-lived",
            );
        }
        if self.session.refresh_token_ttl_secs <= self.session.access_token_ttl_secs {
            return invalid(
                "session.refresh_token_ttl_secs",
                "must be longer than the access-token lifetime",
            );
        }

        if self.features.max_transfer_bytes == 0 {
            return invalid("features.max_transfer_bytes", "must be greater than 0");
        }
        for root in &self.features.file_transfer_roots {
            if !Path::new(root).is_absolute() {
                return invalid(
                    "features.file_transfer_roots",
                    "entries must be absolute paths",
                );
            }
            if root.contains("..") {
                return invalid(
                    "features.file_transfer_roots",
                    "entries must not contain `..` components",
                );
            }
        }

        if !matches!(self.update_channel.as_str(), "stable" | "beta" | "none") {
            return invalid("update_channel", "must be one of: stable, beta, none");
        }

        Ok(())
    }
}

/// Accept only `https://` or `wss://` URLs, so signalling traffic is never sent in
/// the clear even though session payloads are separately end-to-end encrypted.
fn validate_url(url: &str, field: &'static str) -> Result<(), ConfigError> {
    if !(url.starts_with("https://") || url.starts_with("wss://")) {
        return Err(ConfigError::Invalid {
            field,
            reason: "must be an https:// or wss:// URL",
        });
    }
    if url.len() > 2048 {
        return Err(ConfigError::Invalid {
            field,
            reason: "is too long",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        AgentConfig::default().validate().unwrap();
    }

    #[test]
    fn defaults_are_conservative() {
        let config = AgentConfig::default();
        assert!(
            !config.network.remote_access_enabled,
            "remote access must be opt-in"
        );
        assert_eq!(
            config.session.confirmation_policy,
            ConfirmationPolicy::EveryTime,
            "the safest confirmation policy must be the default"
        );
        assert!(
            config.session.idle_timeout_secs > 0,
            "sessions must expire when idle"
        );
    }

    #[test]
    fn config_roundtrips_through_toml() {
        let original = AgentConfig::default();
        let parsed = AgentConfig::from_toml(&original.to_toml().unwrap()).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        // A typo must be loud, not silently ignored.
        let err = AgentConfig::from_toml("device_name = \"x\"\nnot_a_real_key = 1").unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)), "got {err:?}");
    }

    #[test]
    fn partial_files_fill_in_defaults() {
        let config = AgentConfig::from_toml("device_name = \"home-server\"").unwrap();
        assert_eq!(config.device_name, "home-server");
        assert_eq!(config.network.listen_port, rc_protocol::DEFAULT_AGENT_PORT);
    }

    #[test]
    fn empty_device_name_is_rejected() {
        assert!(AgentConfig::from_toml("device_name = \"   \"").is_err());
    }

    #[test]
    fn control_characters_in_device_name_are_rejected() {
        let err = AgentConfig::from_toml("device_name = \"evil\\u0007name\"").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    field: "device_name",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn privileged_ports_are_rejected() {
        let err = AgentConfig::from_toml("[network]\nlisten_port = 443").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    field: "network.listen_port",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn remote_access_without_a_coordination_url_is_rejected() {
        let err = AgentConfig::from_toml("[network]\nremote_access_enabled = true").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    field: "network.coordination_url",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn plaintext_signalling_urls_are_rejected() {
        let err = AgentConfig::from_toml(
            "[network]\nremote_access_enabled = true\ncoordination_url = \"http://example.com\"",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    field: "network.coordination_url",
                    ..
                }
            ),
            "got {err:?}"
        );

        AgentConfig::from_toml(
            "[network]\nremote_access_enabled = true\ncoordination_url = \"https://example.com\"",
        )
        .unwrap();
    }

    #[test]
    fn unthrottled_authentication_is_rejected() {
        for value in ["0", "1000"] {
            let toml = format!("[network]\nauth_attempts_per_minute = {value}");
            assert!(
                AgentConfig::from_toml(&toml).is_err(),
                "{value} must be rejected"
            );
        }
    }

    #[test]
    fn long_lived_access_tokens_are_rejected() {
        let err = AgentConfig::from_toml("[session]\naccess_token_ttl_secs = 604800").unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    field: "session.access_token_ttl_secs",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn refresh_tokens_must_outlive_access_tokens() {
        let err = AgentConfig::from_toml(
            "[session]\naccess_token_ttl_secs = 900\nrefresh_token_ttl_secs = 60",
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    field: "session.refresh_token_ttl_secs",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn traversal_in_transfer_roots_is_rejected() {
        let err = AgentConfig::from_toml("[features]\nfile_transfer_roots = [\"/srv/../../etc\"]")
            .unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    field: "features.file_transfer_roots",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn relative_transfer_roots_are_rejected() {
        assert!(
            AgentConfig::from_toml("[features]\nfile_transfer_roots = [\"srv/data\"]").is_err()
        );
    }

    #[test]
    fn unknown_update_channels_are_rejected() {
        assert!(AgentConfig::from_toml("update_channel = \"nightly\"").is_err());
        AgentConfig::from_toml("update_channel = \"beta\"").unwrap();
    }

    #[test]
    fn a_missing_file_yields_defaults_but_a_broken_one_errors() {
        let dir = tempfile::tempdir().unwrap();

        let absent = dir.path().join("absent.toml");
        assert_eq!(
            AgentConfig::load_or_default(&absent).unwrap(),
            AgentConfig::default()
        );

        let broken = dir.path().join("broken.toml");
        std::fs::write(&broken, "device_name = ").unwrap();
        assert!(
            AgentConfig::load_or_default(&broken).is_err(),
            "a broken file must not silently fall back to defaults"
        );
    }

    #[test]
    fn config_survives_a_save_and_load_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("agent.toml");

        let config = AgentConfig {
            device_name: "home-server".into(),
            features: FeatureConfig {
                terminal: false,
                ..FeatureConfig::default()
            },
            ..AgentConfig::default()
        };
        config.save(&path).unwrap();

        assert_eq!(AgentConfig::load(&path).unwrap(), config);
    }
}
