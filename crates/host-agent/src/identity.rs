//! Agent identity and pairing entry points.
//!
//! These back the `identity` and `pair` subcommands.
//!
//! Pairing sessions live in the *running agent's* memory and die with that process, so
//! `pair` cannot open a window for itself: a client's proof would arrive at the agent,
//! whose manager had never heard of it. Instead the command asks the running agent over
//! its loopback control endpoint and prints what comes back — the one sanctioned path
//! by which a code becomes visible. The code is never written to the log.

use anyhow::Context as _;
use rc_protocol::{DeviceId, PairingSessionId};
use rc_security::{Clock, DeviceIdentity, Keystore, SystemClock};
use rc_storage::audit::{AuditCategory, AuditEvent, AuditRepository, AuditResult, actions};

use crate::config::AgentConfig;
use crate::local_api::TOKEN_HEADER;

/// How the identity returned by [`load_identity`] came to be.
///
/// The caller needs this to audit correctly: creating an identity is a one-time,
/// security-significant event, whereas loading one happens on every start and would
/// drown the trail if recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOrigin {
    /// No keystore existed; a new identity was generated.
    Created,
    /// An existing identity was loaded unchanged.
    Loaded,
    /// An existing identity was loaded and its certificate reissued. The device id and
    /// identity fingerprint are unchanged, so trust is preserved.
    CertificateRenewed,
}

/// Load the agent's identity, creating it on first run.
///
/// Returns the identity together with how it was obtained, so the caller can write the
/// matching audit record once the database is open.
///
/// # Errors
/// Fails if the keystore is corrupt, has unsafe permissions, or was written under a
/// different OS identity. It never silently regenerates: doing so would change the
/// agent's identity and break every existing pairing.
pub fn load_identity(
    paths: &rc_platform::AppPaths,
    config: &AgentConfig,
) -> anyhow::Result<(DeviceIdentity, IdentityOrigin)> {
    let keystore = Keystore::in_data_dir(paths.data_dir());
    let clock = SystemClock;

    // Sampled before `load_or_create`, which is what makes creation distinguishable
    // from an ordinary load.
    let existed = keystore.exists();

    let identity = keystore
        .load_or_create(&config.device_name, &clock)
        .context("could not load or create the agent identity")?;

    // A certificate that has expired, or is about to, is renewed in place. The device
    // id and identity fingerprint are preserved, so paired clients are unaffected.
    let public = identity.public();
    if existed && public.needs_renewal_at(clock.now_ms()) {
        tracing::info!(
            expires_at_ms = public.certificate_not_after_ms,
            "certificate is due for renewal; issuing a new one"
        );
        let renewed = identity
            .renew_certificate(&config.device_name, &clock)
            .context("could not renew the device certificate")?;
        keystore
            .store(&renewed, &config.device_name, &clock)
            .context("could not persist the renewed certificate")?;
        return Ok((renewed, IdentityOrigin::CertificateRenewed));
    }

    let origin = if existed {
        IdentityOrigin::Loaded
    } else {
        IdentityOrigin::Created
    };
    Ok((identity, origin))
}

/// Write the audit record for how the identity was obtained.
///
/// A plain load produces no record: it happens on every start, and a trail that logs
/// every boot buries the events that matter. Only creation and renewal are recorded,
/// and neither carries key material — the device id and identity fingerprint are both
/// public values a client is expected to see.
///
/// # Errors
/// Propagates a failure to write the audit row. Identity creation that cannot be
/// audited is treated as a failure rather than proceeding silently.
pub async fn record_identity_event(
    audit: &AuditRepository,
    origin: IdentityOrigin,
    identity: &DeviceIdentity,
    clock: &dyn Clock,
) -> anyhow::Result<()> {
    let action = match origin {
        IdentityOrigin::Loaded => return Ok(()),
        IdentityOrigin::Created => actions::IDENTITY_CREATED,
        IdentityOrigin::CertificateRenewed => actions::CERTIFICATE_RENEWED,
    };

    let public = identity.public();
    audit
        .record(
            &AuditEvent::new(AuditCategory::Config, action, AuditResult::Success)
                .actor_device(public.device_id)
                .meta("identity_fingerprint", public.identity_fingerprint)
                .meta("certificate_version", public.certificate_version),
            clock.now_ms(),
        )
        .await
        .context("could not write the identity audit record")?;

    Ok(())
}

/// Print this agent's identity for the operator to compare during pairing.
pub fn print_identity(identity: &DeviceIdentity) {
    let public = identity.public();
    println!("Device ID:              {}", public.device_id);
    println!(
        "Identity fingerprint:   {}",
        public.identity_fingerprint.to_display_groups()
    );
    println!(
        "Certificate fingerprint: {}",
        public.certificate_fingerprint.to_display_groups()
    );
    println!("Certificate version:    {}", public.certificate_version);
    println!(
        "Certificate valid until: {}",
        format_timestamp(public.certificate_not_after_ms)
    );
    println!();
    println!("The identity fingerprint is what a client pins. It does not change when the");
    println!("certificate is renewed. Compare it with what your client displays.");
}

/// Ask the running agent to open a pairing window, and display the code.
///
/// # Why this is a request rather than an action
///
/// Pairing sessions live in the agent process's memory, by design: a code shown before
/// a crash must not still be usable afterwards. This command is a *different process*,
/// so a window it opened for itself would be a window no client could ever complete —
/// the proof would arrive at the agent, whose manager has never heard of it.
///
/// So it asks, over the agent's loopback control endpoint, presenting the local-control
/// token. Being able to read that token is the authorization: it lives in the agent's
/// data directory under the same protection as the keystore.
///
/// # Errors
/// Fails with an operator-facing explanation if no agent is running, if this user may
/// not read the control token, or if the agent refuses the request.
pub async fn request_pairing_window(
    paths: &rc_platform::AppPaths,
    config: &AgentConfig,
    ttl_secs: u64,
) -> anyhow::Result<()> {
    let port = config.network.health_port;
    anyhow::ensure!(
        port != 0,
        "the agent's local control endpoint is disabled (network.health_port = 0), \
         so a pairing window cannot be opened from this command"
    );

    let token_path = crate::local_api::token_path(paths);
    let token = crate::local_api::LocalControlToken::read_from(&token_path).with_context(|| {
        format!(
            "could not read the local control token at {}. Is the agent running, and \
             are you running this as the same user (or an administrator)?",
            token_path.display()
        )
    })?;

    let response = post_open_pairing(port, &token, ttl_secs).await?;

    println!();
    println!("  Pairing code:  {}", response.code);
    println!();
    println!("  This server:   {}", response.device_id);
    println!("  Fingerprint:   {}", response.identity_fingerprint);
    println!();
    println!("  Enter the code on your client and check that the fingerprint matches.");
    println!(
        "  The code expires in {} seconds and can be used once.",
        response.ttl_secs
    );
    println!();

    // The code is deliberately absent from this record.
    tracing::info!(
        pairing_session_id = %response.pairing_session_id,
        ttl_secs = response.ttl_secs,
        "pairing window opened by operator request"
    );
    Ok(())
}

/// Perform the loopback request that opens a window.
///
/// Written against `tokio` directly rather than pulling in an HTTP client: the request
/// is one fixed shape to one fixed address, and a dependency whose only job is to build
/// it would be more surface than the code it replaced.
async fn post_open_pairing(
    port: u16,
    token: &crate::local_api::LocalControlToken,
    ttl_secs: u64,
) -> anyhow::Result<crate::local_api::OpenPairingResponse> {
    use std::fmt::Write as _;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let body = serde_json::to_string(&crate::local_api::OpenPairingRequest { ttl_secs })?;

    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| {
            format!("could not reach the agent on 127.0.0.1:{port}. Is the agent running?")
        })?;

    // Written out by hand because HTTP requires CRLF line endings and a blank line
    // before the body; a source-formatted multi-line string would send spaces instead.
    let mut request = String::new();
    request.push_str("POST /pairing HTTP/1.1\r\n");
    request.push_str("Host: 127.0.0.1\r\n");
    request.push_str("Content-Type: application/json\r\n");
    // Writing into a `String` cannot fail; the results are discarded rather than
    // unwrapped so this stays panic-free.
    let _ = write!(request, "Content-Length: {}\r\n", body.len());
    let _ = write!(request, "{TOKEN_HEADER}: {}\r\n", token.header_value());
    // Asking the server to close tells us where the response ends without having to
    // parse chunked encoding or keep-alive framing.
    request.push_str("Connection: close\r\n\r\n");
    request.push_str(&body);

    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // Bounded: the response is a small JSON document, and an unbounded read from a
    // socket is an unbounded allocation.
    let mut raw = Vec::new();
    stream
        .take(64 * 1024)
        .read_to_end(&mut raw)
        .await
        .context("could not read the agent's reply")?;

    let text = String::from_utf8_lossy(&raw);
    let (headers, payload) = text
        .split_once("\r\n\r\n")
        .context("the agent sent a malformed reply")?;

    let status_ok = headers.starts_with("HTTP/1.1 200");
    let parsed: serde_json::Value =
        serde_json::from_str(payload.trim()).context("the agent sent a reply that is not JSON")?;

    if !status_ok {
        let message = parsed
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("the agent refused the request");
        anyhow::bail!("{message}");
    }

    serde_json::from_value(parsed).context("the agent's reply was not in the expected shape")
}

/// Record that a pairing window was used successfully.
///
/// Guarded on `outcome = 'open'`, so a second completion cannot rewrite the row. That
/// keeps the persisted trail consistent with the in-memory single-use guarantee rather
/// than merely agreeing with it most of the time.
pub async fn mark_window_consumed(
    database: &rc_storage::Database,
    session_id: PairingSessionId,
    paired_device: DeviceId,
    now_ms: i64,
) {
    let result = sqlx::query(
        "UPDATE pairing_code
            SET outcome = 'consumed', consumed_at_ms = ?, paired_device_id = ?
          WHERE pairing_session_id = ? AND outcome = 'open'",
    )
    .bind(now_ms)
    .bind(paired_device.to_canonical_string())
    .bind(session_id.to_canonical_string())
    .execute(database.pool())
    .await;

    if let Err(err) = result {
        tracing::warn!(%err, "could not record the pairing window as consumed");
    }
}

/// Sweep pairing rows left `open` by a previous process run.
///
/// Sessions are in-memory, so any row still marked open after a restart describes a
/// window that can no longer be used. Recording that explicitly keeps the audit trail
/// honest rather than leaving rows that imply a live code.
pub async fn expire_stale_windows(database: &rc_storage::Database) -> anyhow::Result<u64> {
    let affected =
        sqlx::query("UPDATE pairing_code SET outcome = 'expired' WHERE outcome = 'open'")
            .execute(database.pool())
            .await
            .context("could not expire stale pairing windows")?
            .rows_affected();

    if affected > 0 {
        tracing::info!(
            count = affected,
            "expired pairing windows left open by a previous run"
        );
    }
    Ok(affected)
}

/// Format a millisecond timestamp for console output.
fn format_timestamp(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map_or_else(
        || "unknown".to_string(),
        |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use rc_storage::audit::AuditCategory;

    use super::*;

    /// The pairing exchange itself is covered end-to-end over real QUIC endpoints in
    /// `rc-transport`'s `pairing_e2e` suite, against the same `PairingService` the
    /// agent uses. What is left here is the agent's own bookkeeping.
    async fn database_with_open_window(session_id: PairingSessionId) -> rc_storage::Database {
        let db = rc_storage::Database::open_in_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO pairing_code
                 (id, code_hash, code_salt, created_at_ms, expires_at_ms, outcome)
             VALUES (?, 'hash', 'salt', 1, 2, 'open')",
        )
        .bind(session_id.to_canonical_string())
        .execute(db.pool())
        .await
        .unwrap();

        sqlx::query("UPDATE pairing_code SET pairing_session_id = id")
            .execute(db.pool())
            .await
            .unwrap();
        db
    }

    async fn outcome_of(db: &rc_storage::Database, session_id: PairingSessionId) -> String {
        let (outcome,): (String,) =
            sqlx::query_as("SELECT outcome FROM pairing_code WHERE pairing_session_id = ?")
                .bind(session_id.to_canonical_string())
                .fetch_one(db.pool())
                .await
                .unwrap();
        outcome
    }

    #[tokio::test]
    async fn a_completed_window_is_recorded_as_consumed() {
        let session_id = PairingSessionId::generate();
        let device_id = DeviceId::generate();
        let db = database_with_open_window(session_id).await;

        mark_window_consumed(&db, session_id, device_id, 42).await;

        assert_eq!(outcome_of(&db, session_id).await, "consumed");
    }

    #[tokio::test]
    async fn a_window_cannot_be_consumed_twice() {
        // The persisted trail has to agree with the in-memory single-use guarantee,
        // not merely resemble it: a replay must not rewrite the row.
        let session_id = PairingSessionId::generate();
        let first = DeviceId::generate();
        let second = DeviceId::generate();
        let db = database_with_open_window(session_id).await;

        mark_window_consumed(&db, session_id, first, 42).await;
        mark_window_consumed(&db, session_id, second, 99).await;

        let (device, consumed_at): (String, i64) = sqlx::query_as(
            "SELECT paired_device_id, consumed_at_ms FROM pairing_code
             WHERE pairing_session_id = ?",
        )
        .bind(session_id.to_canonical_string())
        .fetch_one(db.pool())
        .await
        .unwrap();

        assert_eq!(device, first.to_canonical_string());
        assert_eq!(consumed_at, 42);
    }

    #[tokio::test]
    async fn creating_an_identity_is_audited_but_loading_one_is_not() {
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        let audit = AuditRepository::new(&database);
        let clock = SystemClock;
        let identity = DeviceIdentity::generate("test-agent", &clock).unwrap();

        record_identity_event(&audit, IdentityOrigin::Loaded, &identity, &clock)
            .await
            .unwrap();
        assert_eq!(
            audit.count().await.unwrap(),
            0,
            "an ordinary load must not write a record on every boot"
        );

        record_identity_event(&audit, IdentityOrigin::Created, &identity, &clock)
            .await
            .unwrap();
        record_identity_event(
            &audit,
            IdentityOrigin::CertificateRenewed,
            &identity,
            &clock,
        )
        .await
        .unwrap();
        assert_eq!(audit.count().await.unwrap(), 2);

        // Neither record may carry key material.
        let rendered = format!("{:?}", audit.recent(10).await.unwrap());
        assert!(
            !rendered.contains("PRIVATE"),
            "no key material in the trail"
        );
        assert_eq!(
            audit
                .recent_in_category(AuditCategory::Pairing, 10)
                .await
                .unwrap()
                .len(),
            0,
            "identity events belong to the config category, not pairing"
        );
    }

    #[test]
    fn timestamps_render_readably() {
        let rendered = format_timestamp(1_700_000_000_000);
        assert!(rendered.starts_with("2023-11-14"), "got {rendered}");
        assert!(rendered.ends_with("UTC"));
    }

    #[test]
    fn an_impossible_timestamp_does_not_panic() {
        assert_eq!(format_timestamp(i64::MAX), "unknown");
    }

    #[tokio::test]
    async fn stale_windows_are_expired_on_startup() {
        let db = rc_storage::Database::open_in_memory().await.unwrap();

        sqlx::query(
            "INSERT INTO pairing_code
                 (id, code_hash, code_salt, created_at_ms, expires_at_ms, outcome)
             VALUES ('p1', 'hash', 'salt', 1, 2, 'open')",
        )
        .execute(db.pool())
        .await
        .unwrap();

        assert_eq!(expire_stale_windows(&db).await.unwrap(), 1);

        let (outcome,): (String,) =
            sqlx::query_as("SELECT outcome FROM pairing_code WHERE id = 'p1'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            outcome, "expired",
            "a code from a previous run must not stay usable"
        );

        // Running again is a no-op.
        assert_eq!(expire_stale_windows(&db).await.unwrap(), 0);
    }
}
