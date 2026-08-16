//! What happened: sessions that ran, and connections that were turned away.
//!
//! # A refusal is a record too
//!
//! `session_id` and `identity_fingerprint` are both optional because a connection that
//! was refused has neither — no session was ever assigned, and a stranger has no trust
//! row. A refusal is exactly the thing an operator most wants to find in this list, so
//! the shape accommodates it rather than excluding it.
//!
//! # The cap is applied by the writer
//!
//! Every insert trims the table back to [`HISTORY_LIMIT`] rows. A machine left
//! accepting connections for a year must not accumulate an unbounded log, and doing it
//! here rather than in a periodic job means there is no window in which the bound does
//! not hold and no job that can fail to run.
//!
//! # Nothing here is a credential
//!
//! The permissions a session held are recorded because they are what an operator needs
//! in order to understand what the session could do. No message content and no secret
//! is recorded, because a session is authenticated by its TLS connection rather than by
//! any stored value.

use rc_security::{Fingerprint, PermissionSet};

use crate::error::Result;

/// How many records are kept before the oldest are dropped.
pub const HISTORY_LIMIT: u32 = 500;

/// Which way a session went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDirection {
    /// Someone connected to this machine.
    Incoming,
    /// This machine connected to someone.
    Outgoing,
}

impl SessionDirection {
    /// The stored form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Outgoing => "outgoing",
        }
    }

    /// Parse the stored form.
    fn parse(value: &str) -> Result<Self> {
        match value {
            "incoming" => Ok(Self::Incoming),
            "outgoing" => Ok(Self::Outgoing),
            _ => Err(crate::StorageError::MalformedColumn {
                column: "direction",
            }),
        }
    }
}

/// How a session finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOutcome {
    /// It ran and ended.
    Completed,
    /// It was never admitted.
    Refused,
    /// It broke rather than ended.
    Failed,
}

impl SessionOutcome {
    /// The stored form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }

    /// Parse the stored form.
    fn parse(value: &str) -> Result<Self> {
        match value {
            "completed" => Ok(Self::Completed),
            "refused" => Ok(Self::Refused),
            "failed" => Ok(Self::Failed),
            _ => Err(crate::StorageError::MalformedColumn { column: "outcome" }),
        }
    }
}

/// One recorded session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Row identifier, used to finish a session that is still running.
    pub id: i64,
    /// The session id assigned at admission, or `None` if none ever was.
    pub session_id: Option<String>,
    /// The device's identity, or `None` for a device that was never trusted.
    pub identity_fingerprint: Option<Fingerprint>,
    /// The name displayed at the time. Untrusted text.
    pub device_name: String,
    /// Which way it went.
    pub direction: SessionDirection,
    /// The address involved.
    pub address: String,
    /// When it started.
    pub started_ms: i64,
    /// When it ended, or `None` while it is still running.
    pub ended_ms: Option<i64>,
    /// What it held.
    pub permissions: PermissionSet,
    /// How it finished.
    pub outcome: SessionOutcome,
    /// A `DisconnectReason` name, when one applies.
    pub end_reason: Option<String>,
}

/// A session about to be recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSessionRecord {
    /// The session id assigned at admission, if one was.
    pub session_id: Option<String>,
    /// The device's identity, if it has a trust row.
    pub identity_fingerprint: Option<Fingerprint>,
    /// The name to display.
    pub device_name: String,
    /// Which way it went.
    pub direction: SessionDirection,
    /// The address involved.
    pub address: String,
    /// When it started.
    pub started_ms: i64,
    /// What it holds.
    pub permissions: PermissionSet,
    /// How it finished, or [`SessionOutcome::Completed`] for one still running.
    pub outcome: SessionOutcome,
    /// A `DisconnectReason` name, when one applies.
    pub end_reason: Option<String>,
}

/// Reads and writes session history.
#[derive(Debug, Clone)]
pub struct SessionHistoryRepository {
    pool: sqlx::Pool<sqlx::Sqlite>,
}

impl SessionHistoryRepository {
    /// A repository over `database`.
    #[must_use]
    pub fn new(database: &crate::Database) -> Self {
        Self {
            pool: database.pool().clone(),
        }
    }

    /// Record a session, returning the row id so it can be finished later.
    ///
    /// Trims the table to [`HISTORY_LIMIT`] rows in the same call.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn record(&self, entry: &NewSessionRecord) -> Result<i64> {
        let id = sqlx::query(
            "INSERT INTO session_history
                 (session_id, identity_fingerprint, device_name, direction, address,
                  started_ms, ended_ms, permissions, outcome, end_reason)
             VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
        )
        .bind(entry.session_id.as_deref())
        .bind(entry.identity_fingerprint.map(|f| f.to_hex()))
        .bind(&entry.device_name)
        .bind(entry.direction.as_str())
        .bind(&entry.address)
        .bind(entry.started_ms)
        .bind(i64::from(entry.permissions.bits()))
        .bind(entry.outcome.as_str())
        .bind(entry.end_reason.as_deref())
        .execute(&self.pool)
        .await?
        .last_insert_rowid();

        // Trimmed on every insert rather than by a job: there is then no window in
        // which the bound does not hold, and no job that can fail to run.
        sqlx::query(
            "DELETE FROM session_history
             WHERE id NOT IN (
                 SELECT id FROM session_history ORDER BY started_ms DESC, id DESC LIMIT ?
             )",
        )
        .bind(i64::from(HISTORY_LIMIT))
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    /// Note that a recorded session has ended.
    ///
    /// Silently does nothing for a row that has since been trimmed away: a very long
    /// session on a very busy machine can outlive its own record, and that is not a
    /// failure worth propagating to a disconnect path.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn finish(
        &self,
        id: i64,
        ended_ms: i64,
        outcome: SessionOutcome,
        end_reason: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE session_history
             SET ended_ms = ?, outcome = ?, end_reason = ?
             WHERE id = ?",
        )
        .bind(ended_ms)
        .bind(outcome.as_str())
        .bind(end_reason)
        .bind(id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// The most recent `limit` records, newest first.
    ///
    /// # Errors
    /// Propagates query failures.
    pub async fn list(&self, limit: u32) -> Result<Vec<SessionRecord>> {
        let rows = sqlx::query_as::<_, SessionRecordRaw>(
            "SELECT * FROM session_history ORDER BY started_ms DESC, id DESC LIMIT ?",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }
}

/// Raw column mapping, converted so a malformed stored value surfaces as an error.
#[derive(Debug, sqlx::FromRow)]
struct SessionRecordRaw {
    id: i64,
    session_id: Option<String>,
    identity_fingerprint: Option<String>,
    device_name: String,
    direction: String,
    address: String,
    started_ms: i64,
    ended_ms: Option<i64>,
    permissions: i64,
    outcome: String,
    end_reason: Option<String>,
}

impl TryFrom<SessionRecordRaw> for SessionRecord {
    type Error = crate::StorageError;

    fn try_from(raw: SessionRecordRaw) -> Result<Self> {
        let identity_fingerprint = raw
            .identity_fingerprint
            .map(|hex| {
                hex.parse::<Fingerprint>()
                    .map_err(|_| crate::StorageError::MalformedColumn {
                        column: "identity_fingerprint",
                    })
            })
            .transpose()?;

        let bits =
            u8::try_from(raw.permissions).map_err(|_| crate::StorageError::MalformedColumn {
                column: "permissions",
            })?;
        let permissions =
            PermissionSet::from_bits(bits).ok_or(crate::StorageError::MalformedColumn {
                column: "permissions",
            })?;

        Ok(Self {
            id: raw.id,
            session_id: raw.session_id,
            identity_fingerprint,
            device_name: raw.device_name,
            direction: SessionDirection::parse(&raw.direction)?,
            address: raw.address,
            started_ms: raw.started_ms,
            ended_ms: raw.ended_ms,
            permissions,
            outcome: SessionOutcome::parse(&raw.outcome)?,
            end_reason: raw.end_reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use rc_security::{Fingerprint, Permission, PermissionSet};

    use super::*;
    use crate::test_support::temp_database;

    fn entry(started_ms: i64) -> NewSessionRecord {
        NewSessionRecord {
            session_id: Some("ses-1".to_owned()),
            identity_fingerprint: Some(Fingerprint::from_bytes([7u8; 32])),
            device_name: "Gaming PC".to_owned(),
            direction: SessionDirection::Incoming,
            address: "192.168.1.77:7443".to_owned(),
            started_ms,
            permissions: PermissionSet::NONE.with(Permission::ViewMetrics),
            outcome: SessionOutcome::Completed,
            end_reason: None,
        }
    }

    #[tokio::test]
    async fn a_recorded_session_comes_back_with_what_it_held() {
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        repository.record(&entry(1_700_000_000_000)).await.unwrap();

        let all = repository.list(50).await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].device_name, "Gaming PC");
        assert_eq!(all[0].direction, SessionDirection::Incoming);
        assert_eq!(
            all[0].permissions,
            PermissionSet::NONE.with(Permission::ViewMetrics)
        );
        assert!(all[0].ended_ms.is_none(), "a live session has not ended");
    }

    #[tokio::test]
    async fn finishing_a_session_records_when_and_why() {
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        let id = repository.record(&entry(1_700_000_000_000)).await.unwrap();

        repository
            .finish(
                id,
                1_700_000_060_000,
                SessionOutcome::Completed,
                Some("user_requested"),
            )
            .await
            .unwrap();

        let record = &repository.list(50).await.unwrap()[0];
        assert_eq!(record.ended_ms, Some(1_700_000_060_000));
        assert_eq!(record.end_reason.as_deref(), Some("user_requested"));
    }

    #[tokio::test]
    async fn finishing_a_record_that_was_trimmed_away_is_not_an_error() {
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        repository
            .finish(9_999, 1_700_000_060_000, SessionOutcome::Failed, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_refused_connection_is_recorded_without_a_session_or_an_identity() {
        // A stranger that was turned away has no session id and no trust row, and the
        // Sessions page still has to be able to show that it happened.
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        let mut refused = entry(1_700_000_000_000);
        refused.session_id = None;
        refused.identity_fingerprint = None;
        refused.outcome = SessionOutcome::Refused;
        refused.permissions = PermissionSet::NONE;

        repository.record(&refused).await.unwrap();

        let record = &repository.list(50).await.unwrap()[0];
        assert_eq!(record.outcome, SessionOutcome::Refused);
        assert!(record.identity_fingerprint.is_none());
        assert!(record.session_id.is_none());
    }

    #[tokio::test]
    async fn the_list_is_most_recent_first() {
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        for (started, name) in [(1_000_i64, "OLDEST"), (3_000, "NEWEST"), (2_000, "MIDDLE")] {
            let mut record = entry(started);
            record.device_name = name.to_owned();
            repository.record(&record).await.unwrap();
        }

        let names: Vec<String> = repository
            .list(50)
            .await
            .unwrap()
            .into_iter()
            .map(|record| record.device_name)
            .collect();
        assert_eq!(names, vec!["NEWEST", "MIDDLE", "OLDEST"]);
    }

    #[tokio::test]
    async fn history_is_capped_so_an_unattended_machine_does_not_grow_forever() {
        let database = temp_database().await;
        let repository = SessionHistoryRepository::new(&database);
        for index in 0..(HISTORY_LIMIT + 20) {
            repository
                .record(&entry(1_000 + i64::from(index)))
                .await
                .unwrap();
        }

        let all = repository.list(HISTORY_LIMIT + 100).await.unwrap();
        assert_eq!(u32::try_from(all.len()).unwrap(), HISTORY_LIMIT);
        assert_eq!(
            all.last().unwrap().started_ms,
            1_000 + 20,
            "the oldest rows are the ones dropped"
        );
    }

    #[tokio::test]
    async fn a_malformed_direction_is_reported_rather_than_guessed_at() {
        let database = temp_database().await;
        // The schema's CHECK refuses this, so the value has to be written past it to
        // prove the reader does not guess. Dropping the constraint is not possible in
        // SQLite, so the parse is exercised directly.
        assert!(SessionDirection::parse("sideways").is_err());
        assert!(SessionOutcome::parse("probably").is_err());
        let _ = database;
    }
}
