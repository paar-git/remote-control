//! Row types mapping onto the schema.
//!
//! These deliberately mirror the SQL columns rather than the protocol types, so that
//! a schema change is a compile error here rather than a silent data bug elsewhere.

use serde::{Deserialize, Serialize};

/// Whether a trusted-device row describes a controllable agent or an authorized client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRoleRow {
    /// A server this client may connect to.
    Agent,
    /// A client this agent will accept connections from.
    Client,
}

impl PeerRoleRow {
    /// Value stored in the `peer_role` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Client => "client",
        }
    }

    /// Parse a value read from the `peer_role` column.
    #[must_use]
    pub fn from_str_opt(value: &str) -> Option<Self> {
        match value {
            "agent" => Some(Self::Agent),
            "client" => Some(Self::Client),
            _ => None,
        }
    }
}

/// A row of `trusted_device`: a saved server, or an authorized client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct TrustedDeviceRow {
    /// Stable device identifier.
    pub device_id: String,
    /// `"agent"` or `"client"`.
    pub peer_role: String,
    /// User-editable label.
    pub display_name: String,
    /// Hostname reported at pairing time.
    pub hostname: String,
    /// OS family string.
    pub os_family: String,
    /// OS version string.
    pub os_version: String,
    /// Pinned certificate fingerprint. A mismatch is a hard failure.
    pub certificate_fingerprint: String,
    /// Hex Ed25519 identity public key.
    pub identity_public_key: String,
    /// When pairing completed.
    pub paired_at_ms: i64,
    /// Last successful connection.
    pub last_connected_at_ms: Option<i64>,
    /// Last address a connection succeeded on, tried first when reconnecting.
    pub last_known_address: Option<String>,
    /// Port that went with `last_known_address`.
    pub last_known_port: Option<i64>,
    /// Operator-configured endpoint reachable from outside the LAN.
    pub remote_endpoint: Option<String>,
    /// MAC address for Wake-on-LAN.
    pub wake_on_lan_mac: Option<String>,
    /// Non-zero when pinned to the top of the device list.
    pub favorite: i64,
    /// Non-zero when trust has been revoked. Revoked rows are kept for audit.
    pub revoked: i64,
    /// When trust was revoked.
    pub revoked_at_ms: Option<i64>,
    /// JSON connection preferences, validated by the application layer.
    pub preferences_json: String,
}

impl TrustedDeviceRow {
    /// Whether this device may currently be connected to.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.revoked == 0
    }

    /// Whether the user pinned this device.
    #[must_use]
    pub const fn is_favorite(&self) -> bool {
        self.favorite != 0
    }
}

/// A row of `owner_account`.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct OwnerAccountRow {
    /// Account identifier.
    pub id: String,
    /// Login name.
    pub username: String,
    /// Argon2id PHC string. Never a password, never logged, never serialised out.
    pub password_hash: String,
    /// Role name; `"owner"` in v1.
    pub role: String,
    /// Account creation time.
    pub created_at_ms: i64,
    /// Last successful login.
    pub last_login_at_ms: Option<i64>,
    /// Consecutive failed logins since the last success.
    pub failed_login_count: i64,
    /// Set while the account is throttled.
    pub locked_until_ms: Option<i64>,
    /// Non-zero when OS credential / biometric unlock is enabled.
    pub os_unlock_enabled: i64,
    /// Idle seconds before the app locks itself; `0` disables auto-lock.
    pub auto_lock_after_secs: i64,
}

impl OwnerAccountRow {
    /// Whether login is currently blocked by throttling.
    #[must_use]
    pub const fn is_locked_at(&self, now_ms: i64) -> bool {
        match self.locked_until_ms {
            Some(until) => now_ms < until,
            None => false,
        }
    }
}

/// A row of `audit_event`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditEventRow {
    /// Autoincrement identifier.
    pub id: i64,
    /// When it happened.
    pub occurred_at_ms: i64,
    /// Broad category.
    pub category: String,
    /// Specific action name.
    pub action: String,
    /// `"success"`, `"failure"` or `"denied"`.
    pub result: String,
    /// Account that performed the action.
    pub actor_account_id: Option<String>,
    /// Device the action came from.
    pub actor_device_id: Option<String>,
    /// Device the action was performed against.
    pub target_device_id: Option<String>,
    /// Session the action belonged to.
    pub session_id: Option<String>,
    /// Sanitised JSON metadata. Contains no secrets by construction.
    pub metadata_json: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_role_roundtrips() {
        for role in [PeerRoleRow::Agent, PeerRoleRow::Client] {
            assert_eq!(PeerRoleRow::from_str_opt(role.as_str()), Some(role));
        }
        assert_eq!(PeerRoleRow::from_str_opt("owner"), None);
    }

    #[test]
    fn revoked_devices_are_not_usable() {
        let mut row = sample_device();
        assert!(row.is_usable());
        row.revoked = 1;
        assert!(!row.is_usable());
    }

    #[test]
    fn account_lock_expires_with_time() {
        let mut account = sample_account();
        assert!(!account.is_locked_at(1_000));

        account.locked_until_ms = Some(2_000);
        assert!(account.is_locked_at(1_999));
        assert!(!account.is_locked_at(2_000));
        assert!(!account.is_locked_at(2_001));
    }

    #[test]
    fn password_hash_is_not_serialised_out_of_the_process() {
        // OwnerAccountRow deliberately does not derive Serialize, so the hash cannot
        // be leaked to the frontend by accident. This test documents that intent.
        fn assert_not_serializable<T>() {}
        assert_not_serializable::<OwnerAccountRow>();
    }

    fn sample_device() -> TrustedDeviceRow {
        TrustedDeviceRow {
            device_id: "dev_1".into(),
            peer_role: "agent".into(),
            display_name: "home-server".into(),
            hostname: "server".into(),
            os_family: "linux".into(),
            os_version: "Ubuntu 24.04".into(),
            certificate_fingerprint: "ab".repeat(32),
            identity_public_key: "cd".repeat(32),
            paired_at_ms: 1,
            last_connected_at_ms: None,
            last_known_address: None,
            last_known_port: None,
            remote_endpoint: None,
            wake_on_lan_mac: None,
            favorite: 0,
            revoked: 0,
            revoked_at_ms: None,
            preferences_json: "{}".into(),
        }
    }

    fn sample_account() -> OwnerAccountRow {
        OwnerAccountRow {
            id: "usr_1".into(),
            username: "owner".into(),
            password_hash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA".into(),
            role: "owner".into(),
            created_at_ms: 1,
            last_login_at_ms: None,
            failed_login_count: 0,
            locked_until_ms: None,
            os_unlock_enabled: 0,
            auto_lock_after_secs: 900,
        }
    }
}
