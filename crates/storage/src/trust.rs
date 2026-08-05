//! The trusted-device repository.
//!
//! This is the authority on which devices may connect and what they may do. Phase 3's
//! connection handler must consult [`TrustRepository::authorize`] on **every**
//! connection and must not cache the result across connections — revocation has to
//! take effect immediately, not at the next restart.
//!
//! # Identity versus credential
//!
//! Two fingerprints are stored per device:
//!
//! * `identity_fingerprint` — SHA-256 of the Ed25519 identity public key. **Pinned.**
//!   A change here is [`SecurityError::IdentityMismatch`] and is never accepted
//!   automatically.
//! * `certificate_fingerprint` — SHA-256 of the current certificate. Expected to
//!   change when the peer renews. [`TrustRepository::record_certificate_rotation`]
//!   updates it, but only for a device whose identity fingerprint still matches.

use rc_protocol::DeviceId;
use rc_security::Fingerprint;
use rc_security::error::SecurityError;
use rc_security::pairing::RequestedPermissions;
use rc_security::permissions::{AuthorizationContext, Capability, Role};

use crate::error::{Result, StorageError};
use crate::models::PeerRoleRow;

/// A device this installation trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDevice {
    /// Stable device identifier.
    pub device_id: DeviceId,
    /// Whether this is a controllable agent or an authorized client.
    pub peer_role: PeerRoleRow,
    /// User-editable label. Untrusted at the point it was recorded.
    pub display_name: String,
    /// Hostname recorded at pairing time.
    pub hostname: String,
    /// Ed25519 identity public key.
    pub identity_public_key: [u8; 32],
    /// Pinned identity fingerprint. Never changes for a given device.
    pub identity_fingerprint: Fingerprint,
    /// Current certificate fingerprint. Changes on renewal.
    pub certificate_fingerprint: Fingerprint,
    /// Certificate generation counter.
    pub certificate_version: u32,
    /// Permission role granted.
    pub role: Role,
    /// Capabilities granted at pairing time.
    pub granted_capabilities: Vec<Capability>,
    /// When pairing completed.
    pub paired_at_ms: i64,
    /// Last successful mutual authentication.
    pub last_authenticated_at_ms: Option<i64>,
    /// Whether trust has been withdrawn.
    pub revoked: bool,
    /// When trust was withdrawn.
    pub revoked_at_ms: Option<i64>,
    /// Short transcript digest of the pairing that created this trust.
    pub pairing_transcript_digest: Option<String>,
    /// The address the last successful connection used.
    ///
    /// Tried first on the next connect: on a home network it is nearly always still
    /// right, which avoids a discovery round trip. It is only ever a *hint* — the
    /// connection still pins the certificate — so a stale value costs one failed dial.
    pub last_known_address: Option<std::net::SocketAddr>,
    /// An operator-configured endpoint, used when neither the saved address nor
    /// discovery finds the device.
    pub remote_endpoint: Option<String>,
    /// When a connection last succeeded.
    pub last_connected_at_ms: Option<i64>,
    /// MAC address for Wake-on-LAN, if one was recorded.
    pub wake_on_lan_mac: Option<String>,
    /// Whether the operator pinned this device to the top of the list.
    pub favorite: bool,
}

impl TrustedDevice {
    /// The authorization context for this device.
    ///
    /// A revoked device yields a context that grants nothing, regardless of its role.
    #[must_use]
    pub fn authorization(&self) -> AuthorizationContext {
        if self.revoked {
            AuthorizationContext::revoked(self.role)
        } else {
            AuthorizationContext::new(self.role)
        }
    }

    /// Whether this device currently holds `capability`.
    ///
    /// Requires *both* that the role grants it and that it was granted at pairing
    /// time, so widening a role later cannot retroactively widen an existing device.
    #[must_use]
    pub fn holds(&self, capability: Capability) -> bool {
        !self.revoked
            && self.role.grants(capability)
            && self.granted_capabilities.contains(&capability)
    }
}

/// What the caller presented at connection time, to be checked against stored trust.
#[derive(Debug, Clone, Copy)]
pub struct PresentedIdentity {
    /// Device id the peer claims.
    pub device_id: DeviceId,
    /// Identity fingerprint derived from the key it authenticated with.
    pub identity_fingerprint: Fingerprint,
    /// Certificate fingerprint observed on its TLS connection.
    pub certificate_fingerprint: Fingerprint,
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

    /// Record a newly paired device.
    ///
    /// # Errors
    /// [`StorageError::Conflict`] if the identity is already registered — including
    /// under a *different* device id, which would otherwise let one key masquerade as
    /// two devices.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_paired_device(
        &self,
        device_id: DeviceId,
        peer_role: PeerRoleRow,
        display_name: &str,
        hostname: &str,
        identity_public_key: &[u8; 32],
        identity_fingerprint: Fingerprint,
        certificate_fingerprint: Fingerprint,
        permissions: &RequestedPermissions,
        transcript_digest: Option<&str>,
        now_ms: i64,
    ) -> Result<()> {
        // Checked explicitly rather than relying on a unique index, so the error is
        // the specific one the caller can act on.
        if let Some(existing) = self.find_by_identity(identity_fingerprint).await?
            && existing.device_id != device_id
        {
            return Err(StorageError::Conflict);
        }

        let capabilities = permissions
            .capabilities
            .iter()
            .map(|c| c.name())
            .collect::<Vec<_>>()
            .join(",");

        sqlx::query(
            "INSERT INTO trusted_device (
                 device_id, peer_role, display_name, hostname,
                 certificate_fingerprint, identity_public_key, identity_fingerprint,
                 permission_role, granted_capabilities, certificate_version,
                 paired_at_ms, pairing_transcript_digest
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)",
        )
        .bind(device_id.to_canonical_string())
        .bind(peer_role.as_str())
        .bind(display_name)
        .bind(hostname)
        .bind(certificate_fingerprint.to_hex())
        .bind(hex::encode(identity_public_key))
        .bind(identity_fingerprint.to_hex())
        .bind(permissions.role.name())
        .bind(capabilities)
        .bind(now_ms)
        .bind(transcript_digest)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Every trusted device, revoked ones included, in a stable display order.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn list(&self, peer_role: PeerRoleRow) -> Result<Vec<TrustedDevice>> {
        let rows = sqlx::query_as::<_, TrustedDeviceRaw>(
            "SELECT * FROM trusted_device
             WHERE peer_role = ?
             ORDER BY revoked ASC, favorite DESC, last_authenticated_at_ms DESC, display_name ASC",
        )
        .bind(peer_role.as_str())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Look up a device by id.
    ///
    /// # Errors
    /// Propagates query failures. A missing device yields `Ok(None)`.
    pub async fn find(&self, device_id: DeviceId) -> Result<Option<TrustedDevice>> {
        let row = sqlx::query_as::<_, TrustedDeviceRaw>(
            "SELECT * FROM trusted_device WHERE device_id = ?",
        )
        .bind(device_id.to_canonical_string())
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Look up a device by its pinned identity fingerprint.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn find_by_identity(
        &self,
        identity_fingerprint: Fingerprint,
    ) -> Result<Option<TrustedDevice>> {
        let row = sqlx::query_as::<_, TrustedDeviceRaw>(
            "SELECT * FROM trusted_device WHERE identity_fingerprint = ?",
        )
        .bind(identity_fingerprint.to_hex())
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Look a device up by its **current** certificate fingerprint.
    ///
    /// This is the lookup the transport handshake performs, because a certificate
    /// fingerprint is what a TLS connection actually observes. A device that renewed
    /// its certificate without the agent recording the rotation will not be found here
    /// and is refused — re-pinning a renewed certificate is a deliberate step, never
    /// something a connection attempt performs for itself.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn find_by_certificate(
        &self,
        certificate_fingerprint: Fingerprint,
    ) -> Result<Option<TrustedDevice>> {
        let row = sqlx::query_as::<_, TrustedDeviceRaw>(
            "SELECT * FROM trusted_device WHERE certificate_fingerprint = ?",
        )
        .bind(certificate_fingerprint.to_hex())
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Record the address a connection succeeded on.
    ///
    /// Stored so the next connect can try it before searching. It is written only after
    /// a connection has *authenticated*, so an address that merely accepted a TCP
    /// handshake never displaces a good one.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] if the device is unknown.
    pub async fn record_successful_address(
        &self,
        device_id: DeviceId,
        address: std::net::SocketAddr,
    ) -> Result<()> {
        let affected = sqlx::query(
            "UPDATE trusted_device
                SET last_known_address = ?, last_known_port = ?
              WHERE device_id = ? AND revoked = 0",
        )
        .bind(address.ip().to_string())
        .bind(i64::from(address.port()))
        .bind(device_id.to_canonical_string())
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            Err(StorageError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Set or clear the operator-configured endpoint.
    ///
    /// # Errors
    /// [`StorageError::Invalid`] for an unusable value, [`StorageError::NotFound`] if
    /// the device is unknown.
    pub async fn set_remote_endpoint(
        &self,
        device_id: DeviceId,
        endpoint: Option<&str>,
    ) -> Result<()> {
        // Bounded and free of control characters: the value is echoed back into the UI
        // and into log lines.
        if let Some(value) = endpoint {
            if value.len() > 255 {
                return Err(StorageError::Invalid {
                    field: "remote_endpoint",
                    reason: "is too long",
                });
            }
            if value.chars().any(char::is_control) {
                return Err(StorageError::Invalid {
                    field: "remote_endpoint",
                    reason: "must not contain control characters",
                });
            }
        }

        let affected =
            sqlx::query("UPDATE trusted_device SET remote_endpoint = ? WHERE device_id = ?")
                .bind(endpoint)
                .bind(device_id.to_canonical_string())
                .execute(&self.pool)
                .await?
                .rows_affected();

        if affected == 0 {
            Err(StorageError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Decide whether a presenting peer may proceed, and with what authority.
    ///
    /// This is the single authorization entry point. It reads live state every time:
    /// callers must not cache the result across connections, or revocation would not
    /// take effect until restart.
    ///
    /// # Errors
    /// * [`SecurityError::IdentityMismatch`] — unknown identity, or an identity that
    ///   does not match the claimed device id. Never resolved automatically.
    /// * [`SecurityError::DeviceRevoked`] — known but revoked.
    pub async fn authorize(
        &self,
        presented: PresentedIdentity,
    ) -> Result<std::result::Result<(TrustedDevice, AuthorizationContext), SecurityError>> {
        let Some(device) = self
            .find_by_identity(presented.identity_fingerprint)
            .await?
        else {
            return Ok(Err(SecurityError::IdentityMismatch));
        };

        // The claimed device id must belong to the identity that authenticated.
        if device.device_id != presented.device_id {
            return Ok(Err(SecurityError::IdentityMismatch));
        }
        if device.revoked {
            return Ok(Err(SecurityError::DeviceRevoked));
        }

        let context = device.authorization();
        Ok(Ok((device, context)))
    }

    /// Record a successful authentication.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] if the device is unknown.
    pub async fn record_authentication(&self, device_id: DeviceId, now_ms: i64) -> Result<()> {
        let affected = sqlx::query(
            "UPDATE trusted_device
             SET last_authenticated_at_ms = ?, last_connected_at_ms = ?
             WHERE device_id = ? AND revoked = 0",
        )
        .bind(now_ms)
        .bind(now_ms)
        .bind(device_id.to_canonical_string())
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            Err(StorageError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Update a device's certificate after it renewed.
    ///
    /// Only permitted when the identity fingerprint still matches, which is what
    /// distinguishes a legitimate renewal from a different device.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] if no device matches that identity.
    pub async fn record_certificate_rotation(
        &self,
        identity_fingerprint: Fingerprint,
        new_certificate_fingerprint: Fingerprint,
        new_version: u32,
    ) -> Result<()> {
        let affected = sqlx::query(
            "UPDATE trusted_device
             SET certificate_fingerprint = ?, certificate_version = ?
             WHERE identity_fingerprint = ?",
        )
        .bind(new_certificate_fingerprint.to_hex())
        .bind(i64::from(new_version))
        .bind(identity_fingerprint.to_hex())
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            Err(StorageError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Rename a device.
    ///
    /// # Errors
    /// [`StorageError::Invalid`] for an unusable name, [`StorageError::NotFound`] if
    /// the device is unknown.
    pub async fn rename(&self, device_id: DeviceId, new_name: &str) -> Result<()> {
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            return Err(StorageError::Invalid {
                field: "display_name",
                reason: "must not be empty",
            });
        }
        if trimmed.len() > rc_protocol::limits::MAX_DEVICE_NAME_BYTES {
            return Err(StorageError::Invalid {
                field: "display_name",
                reason: "is too long",
            });
        }
        if trimmed.chars().any(char::is_control) {
            return Err(StorageError::Invalid {
                field: "display_name",
                reason: "must not contain control characters",
            });
        }

        let affected =
            sqlx::query("UPDATE trusted_device SET display_name = ? WHERE device_id = ?")
                .bind(trimmed)
                .bind(device_id.to_canonical_string())
                .execute(&self.pool)
                .await?
                .rows_affected();

        if affected == 0 {
            Err(StorageError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Revoke a device's trust.
    ///
    /// The row is kept rather than deleted, so the audit trail stays intact and a
    /// later connection from the same identity is recognised as revoked rather than
    /// unknown. Revoking an already-revoked device succeeds without changing anything.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] if the device is unknown.
    pub async fn revoke(&self, device_id: DeviceId, now_ms: i64) -> Result<()> {
        let affected = sqlx::query(
            "UPDATE trusted_device
             SET revoked = 1, revoked_at_ms = COALESCE(revoked_at_ms, ?)
             WHERE device_id = ?",
        )
        .bind(now_ms)
        .bind(device_id.to_canonical_string())
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            Err(StorageError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Set or clear the favourite flag.
    ///
    /// # Errors
    /// [`StorageError::NotFound`] if the device is unknown.
    pub async fn set_favorite(&self, device_id: DeviceId, favorite: bool) -> Result<()> {
        let affected = sqlx::query("UPDATE trusted_device SET favorite = ? WHERE device_id = ?")
            .bind(i64::from(favorite))
            .bind(device_id.to_canonical_string())
            .execute(&self.pool)
            .await?
            .rows_affected();

        if affected == 0 {
            Err(StorageError::NotFound)
        } else {
            Ok(())
        }
    }
}

/// Raw column mapping. Converted into [`TrustedDevice`] so malformed stored values
/// surface as errors rather than propagating as nonsense.
#[derive(Debug, sqlx::FromRow)]
struct TrustedDeviceRaw {
    device_id: String,
    peer_role: String,
    display_name: String,
    hostname: String,
    certificate_fingerprint: String,
    identity_public_key: String,
    identity_fingerprint: String,
    permission_role: String,
    granted_capabilities: String,
    certificate_version: i64,
    paired_at_ms: i64,
    last_authenticated_at_ms: Option<i64>,
    revoked: i64,
    revoked_at_ms: Option<i64>,
    pairing_transcript_digest: Option<String>,
    last_known_address: Option<String>,
    last_known_port: Option<i64>,
    remote_endpoint: Option<String>,
    last_connected_at_ms: Option<i64>,
    wake_on_lan_mac: Option<String>,
    favorite: i64,
}

impl TryFrom<TrustedDeviceRaw> for TrustedDevice {
    type Error = StorageError;

    fn try_from(raw: TrustedDeviceRaw) -> Result<Self> {
        let device_id =
            raw.device_id
                .parse::<DeviceId>()
                .map_err(|_| StorageError::MalformedColumn {
                    column: "device_id",
                })?;

        let peer_role =
            PeerRoleRow::from_str_opt(&raw.peer_role).ok_or(StorageError::MalformedColumn {
                column: "peer_role",
            })?;

        // An unrecognised role fails closed rather than defaulting to something
        // permissive.
        let role = Role::from_name(&raw.permission_role).ok_or(StorageError::MalformedColumn {
            column: "permission_role",
        })?;

        let identity_fingerprint =
            raw.identity_fingerprint
                .parse::<Fingerprint>()
                .map_err(|_| StorageError::MalformedColumn {
                    column: "identity_fingerprint",
                })?;

        let certificate_fingerprint =
            raw.certificate_fingerprint
                .parse::<Fingerprint>()
                .map_err(|_| StorageError::MalformedColumn {
                    column: "certificate_fingerprint",
                })?;

        let key_bytes =
            hex::decode(&raw.identity_public_key).map_err(|_| StorageError::MalformedColumn {
                column: "identity_public_key",
            })?;
        let identity_public_key: [u8; 32] =
            key_bytes
                .try_into()
                .map_err(|_| StorageError::MalformedColumn {
                    column: "identity_public_key",
                })?;

        // Unknown capability names are dropped rather than rejected: a database
        // written by a newer build must still be readable by an older one, and
        // dropping an unknown capability fails closed.
        let granted_capabilities = raw
            .granted_capabilities
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|name| Capability::all().iter().copied().find(|c| c.name() == name))
            .collect();

        Ok(Self {
            device_id,
            peer_role,
            display_name: raw.display_name,
            hostname: raw.hostname,
            identity_public_key,
            identity_fingerprint,
            certificate_fingerprint,
            certificate_version: u32::try_from(raw.certificate_version).unwrap_or(1),
            role,
            granted_capabilities,
            paired_at_ms: raw.paired_at_ms,
            last_authenticated_at_ms: raw.last_authenticated_at_ms,
            revoked: raw.revoked != 0,
            revoked_at_ms: raw.revoked_at_ms,
            pairing_transcript_digest: raw.pairing_transcript_digest,
            // A stored address that no longer parses is dropped rather than rejected:
            // it is a hint, and losing it costs one discovery round trip, whereas
            // refusing to load the row would make the server unreachable entirely.
            last_known_address: parse_stored_address(
                raw.last_known_address.as_deref(),
                raw.last_known_port,
            ),
            remote_endpoint: raw.remote_endpoint,
            last_connected_at_ms: raw.last_connected_at_ms,
            wake_on_lan_mac: raw.wake_on_lan_mac,
            favorite: raw.favorite != 0,
        })
    }
}

/// Rebuild a socket address from its stored parts.
///
/// Returns `None` unless both parts are present and valid. A half-written pair is not
/// guessed at: dialling a remembered host on a default port would silently contact
/// something other than what was recorded.
fn parse_stored_address(host: Option<&str>, port: Option<i64>) -> Option<std::net::SocketAddr> {
    let host = host?;
    let port = u16::try_from(port?).ok()?;
    if port == 0 {
        return None;
    }
    let ip = host.parse::<std::net::IpAddr>().ok()?;
    Some(std::net::SocketAddr::new(ip, port))
}
