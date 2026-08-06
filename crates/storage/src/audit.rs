//! The audit log.
//!
//! # What is recorded, and what is not
//!
//! Every security-relevant action produces a row: authentication outcomes, pairing
//! lifecycle, trust changes. Each row carries who, what, when and the result.
//!
//! **Never recorded:** passwords, password hashes, pairing codes, code verifiers,
//! private keys, DPAPI blobs, session tokens, full cryptographic proofs, clipboard
//! contents, file contents or terminal I/O.
//!
//! This is enforced two ways: [`AuditEvent::metadata`] takes a typed key/value list
//! rather than free-form text, and [`sanitise_metadata`] drops any pair whose key
//! looks like a secret. The dropping is a backstop, not the primary control — the
//! primary control is not passing secrets in the first place.

use serde::Serialize;

use crate::error::Result;
use crate::models::AuditEventRow;

/// Broad category of an audited action. Matches the `CHECK` constraint on the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditCategory {
    /// Owner authentication.
    Auth,
    /// Pairing lifecycle.
    Pairing,
    /// Connection lifecycle.
    Connection,
    /// File transfers.
    FileTransfer,
    /// Privileged operating-system actions.
    PrivilegedAction,
    /// Power operations.
    Power,
    /// Permission changes.
    Permission,
    /// Trust revocation.
    DeviceRevocation,
    /// Agent updates.
    AgentUpdate,
    /// Configuration changes.
    Config,
}

impl AuditCategory {
    /// Stored column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Pairing => "pairing",
            Self::Connection => "connection",
            Self::FileTransfer => "file_transfer",
            Self::PrivilegedAction => "privileged_action",
            Self::Power => "power",
            Self::Permission => "permission",
            Self::DeviceRevocation => "device_revocation",
            Self::AgentUpdate => "agent_update",
            Self::Config => "config",
        }
    }
}

/// Outcome of an audited action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    /// The action completed.
    Success,
    /// The action was attempted and failed.
    Failure,
    /// The action was refused by an authorization or safety control.
    Denied,
}

impl AuditResult {
    /// Stored column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

/// Stable action names. Using constants rather than free strings keeps the log
/// queryable and stops two call sites spelling the same event differently.
pub mod actions {
    /// A device identity was generated.
    pub const IDENTITY_CREATED: &str = "identity.created";
    /// A device certificate was renewed.
    pub const CERTIFICATE_RENEWED: &str = "identity.certificate_renewed";
    /// A pairing window was opened and a code issued.
    pub const PAIRING_CODE_CREATED: &str = "pairing.code_created";
    /// A pairing attempt failed.
    pub const PAIRING_ATTEMPT_FAILED: &str = "pairing.attempt_failed";
    /// A pairing attempt was refused by throttling.
    pub const PAIRING_THROTTLED: &str = "pairing.throttled";
    /// Pairing completed and trust was recorded.
    pub const PAIRING_COMPLETED: &str = "pairing.completed";
    /// A pairing window closed unused.
    pub const PAIRING_EXPIRED: &str = "pairing.expired";
    /// A pairing window was cancelled by the operator.
    pub const PAIRING_CANCELLED: &str = "pairing.cancelled";
    /// A trusted device was renamed.
    pub const DEVICE_RENAMED: &str = "device.renamed";
    /// A trusted device was revoked.
    pub const DEVICE_REVOKED: &str = "device.revoked";
    /// Owner login succeeded.
    pub const LOGIN_SUCCEEDED: &str = "auth.login_succeeded";
    /// Owner login failed.
    pub const LOGIN_FAILED: &str = "auth.login_failed";
    /// Owner login was refused by throttling.
    pub const LOGIN_THROTTLED: &str = "auth.login_throttled";
    /// The owner account was created.
    pub const OWNER_CREATED: &str = "auth.owner_created";
    /// The owner's password hash was upgraded to stronger parameters.
    pub const PASSWORD_HASH_UPGRADED: &str = "auth.password_hash_upgraded";
    /// The agent bound its listener and began accepting connections.
    pub const LISTENER_STARTED: &str = "connection.listener_started";
    /// A client authenticated and a session began.
    pub const SESSION_STARTED: &str = "connection.session_started";
    /// A session ended, for any reason.
    pub const SESSION_ENDED: &str = "connection.session_ended";
    /// A connection was refused before a session began.
    pub const CONNECTION_REFUSED: &str = "connection.refused";
    /// A connection was refused because the session limit was already reached.
    pub const CONNECTION_LIMIT_REACHED: &str = "connection.limit_reached";
    /// A client reconnected to an agent it had previously been connected to.
    pub const RECONNECTED: &str = "connection.reconnected";
    /// A terminal session was opened.
    pub const TERMINAL_OPENED: &str = "terminal.opened";
    /// A terminal session was closed.
    pub const TERMINAL_CLOSED: &str = "terminal.closed";
    /// A client subscribed to periodic system metrics.
    pub const METRICS_SUBSCRIBED: &str = "monitoring.subscribed";
    /// A file was uploaded to the server.
    pub const FILE_UPLOADED: &str = "file.uploaded";
    /// A file was downloaded from the server.
    pub const FILE_DOWNLOADED: &str = "file.downloaded";
    /// A file or directory was deleted.
    pub const FILE_DELETED: &str = "file.deleted";
    /// A file or directory was renamed or moved.
    pub const FILE_RENAMED: &str = "file.renamed";
    /// A file was copied.
    pub const FILE_COPIED: &str = "file.copied";
    /// A directory was created.
    pub const DIRECTORY_CREATED: &str = "file.directory_created";
}

/// Metadata keys that must never appear in an audit record.
///
/// Matching is on a lowercase substring, so `client_password` and `PasswordHash` are
/// both caught.
const FORBIDDEN_METADATA_SUBSTRINGS: &[&str] = &[
    "password",
    "secret",
    "token",
    "key",
    "code",
    "verifier",
    "proof",
    "signature",
    "hash",
    "credential",
    "blob",
    "cookie",
    "session_token",
    "clipboard",
];

/// One event to append.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Broad category.
    pub category: AuditCategory,
    /// Specific action; use a constant from [`actions`].
    pub action: &'static str,
    /// Outcome.
    pub result: AuditResult,
    /// Account that acted.
    pub actor_account_id: Option<String>,
    /// Device the action came from.
    pub actor_device_id: Option<String>,
    /// Device acted upon.
    pub target_device_id: Option<String>,
    /// Session the action belonged to.
    pub session_id: Option<String>,
    /// Safe key/value metadata. Filtered by [`sanitise_metadata`] before storage.
    pub metadata: Vec<(&'static str, String)>,
}

impl AuditEvent {
    /// A minimal event.
    #[must_use]
    pub fn new(category: AuditCategory, action: &'static str, result: AuditResult) -> Self {
        Self {
            category,
            action,
            result,
            actor_account_id: None,
            actor_device_id: None,
            target_device_id: None,
            session_id: None,
            metadata: Vec::new(),
        }
    }

    /// Attach the device the action came from.
    #[must_use]
    pub fn actor_device(mut self, device_id: impl std::fmt::Display) -> Self {
        self.actor_device_id = Some(device_id.to_string());
        self
    }

    /// Attach the device acted upon.
    #[must_use]
    pub fn target_device(mut self, device_id: impl std::fmt::Display) -> Self {
        self.target_device_id = Some(device_id.to_string());
        self
    }

    /// Attach the acting account.
    #[must_use]
    pub fn actor_account(mut self, account_id: impl Into<String>) -> Self {
        self.actor_account_id = Some(account_id.into());
        self
    }

    /// Attach a metadata pair. Rejected at write time if the key looks like a secret.
    #[must_use]
    pub fn meta(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
        self.metadata.push((key, value.to_string()));
        self
    }
}

/// Drop metadata pairs whose key suggests a secret.
///
/// A backstop. The primary control is that callers pass metadata, not secrets.
#[must_use]
pub fn sanitise_metadata(metadata: &[(&'static str, String)]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in metadata {
        let lowered = key.to_ascii_lowercase();
        if FORBIDDEN_METADATA_SUBSTRINGS
            .iter()
            .any(|f| lowered.contains(f))
        {
            // Recording that something was dropped is more useful than dropping it
            // silently, and the key name alone is not sensitive.
            map.insert(
                (*key).to_string(),
                serde_json::Value::String("<redacted>".into()),
            );
            continue;
        }
        // Bound the value so a long untrusted string cannot bloat the log.
        let truncated: String = value.chars().take(512).collect();
        map.insert((*key).to_string(), serde_json::Value::String(truncated));
    }
    serde_json::Value::Object(map)
}

/// Appends to and reads the audit log.
#[derive(Debug, Clone)]
pub struct AuditRepository {
    pool: sqlx::Pool<sqlx::Sqlite>,
}

impl AuditRepository {
    /// A repository over `database`.
    #[must_use]
    pub fn new(database: &crate::Database) -> Self {
        Self {
            pool: database.pool().clone(),
        }
    }

    /// Append an event.
    ///
    /// # Errors
    /// Propagates query failures. Callers should log and continue rather than failing
    /// the underlying operation: losing an audit row is bad, but aborting a security
    /// action because logging failed is worse.
    pub async fn record(&self, event: &AuditEvent, now_ms: i64) -> Result<i64> {
        let metadata = sanitise_metadata(&event.metadata).to_string();

        let id = sqlx::query(
            "INSERT INTO audit_event (
                 occurred_at_ms, category, action, result,
                 actor_account_id, actor_device_id, target_device_id, session_id, metadata_json
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(now_ms)
        .bind(event.category.as_str())
        .bind(event.action)
        .bind(event.result.as_str())
        .bind(event.actor_account_id.as_deref())
        .bind(event.actor_device_id.as_deref())
        .bind(event.target_device_id.as_deref())
        .bind(event.session_id.as_deref())
        .bind(metadata)
        .execute(&self.pool)
        .await?
        .last_insert_rowid();

        Ok(id)
    }

    /// Most recent events, newest first.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn recent(&self, limit: u32) -> Result<Vec<AuditEventRow>> {
        let rows = sqlx::query_as::<_, AuditEventRow>(
            "SELECT * FROM audit_event ORDER BY occurred_at_ms DESC, id DESC LIMIT ?",
        )
        .bind(i64::from(limit.clamp(1, 1000)))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Most recent events in one category.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn recent_in_category(
        &self,
        category: AuditCategory,
        limit: u32,
    ) -> Result<Vec<AuditEventRow>> {
        let rows = sqlx::query_as::<_, AuditEventRow>(
            "SELECT * FROM audit_event
             WHERE category = ?
             ORDER BY occurred_at_ms DESC, id DESC
             LIMIT ?",
        )
        .bind(category.as_str())
        .bind(i64::from(limit.clamp(1, 1000)))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Total number of recorded events.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn count(&self) -> Result<i64> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_event")
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }
}
