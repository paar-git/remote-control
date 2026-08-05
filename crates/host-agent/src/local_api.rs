//! The agent's loopback control endpoint.
//!
//! # Why this exists
//!
//! `rc-agent pair` runs in a different process from the agent. Pairing windows live in
//! the running agent's memory — by design, so a code displayed before a crash cannot
//! still be usable afterwards — which means the command cannot simply open one for
//! itself. It has to ask the process that is actually listening.
//!
//! # Two routes, two very different access rules
//!
//! | Route | Auth | Why |
//! |---|---|---|
//! | `GET /health` | none | Service managers and monitoring need it, and it discloses nothing |
//! | `POST /pairing` | local-control token | Opening a pairing window is the one action that can create trust |
//!
//! # The local-control token is a filesystem capability, not a password
//!
//! At startup the agent writes 32 random bytes to `local-control.token` in its data
//! directory, with the same protection as the keystore: mode `0600` inside a `0700`
//! directory on Unix, and an Administrators-only directory on Windows. A caller proves
//! it may open a pairing window by *reading that file*.
//!
//! So the real access-control decision is made by the operating system's file
//! permissions, and the token is only how that decision is carried over a socket. The
//! set of processes that can pair is exactly the set that can already read the agent's
//! data directory — which is to say, the ones that could read its keystore anyway. It
//! does not widen anything.
//!
//! The token is regenerated on every start, so a copy taken from a previous run is
//! useless, and it is compared in constant time.
//!
//! # Everything binds loopback
//!
//! The address is `127.0.0.1` and is not configurable, so no configuration mistake can
//! put either route on the network.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

use crate::sessions::SessionRegistry;

/// Header carrying the local-control token.
pub const TOKEN_HEADER: &str = "x-rc-local-token";

/// Longest pairing window an operator may ask for, in seconds.
const MAX_PAIRING_TTL_SECS: u64 = 900;

/// Shortest pairing window an operator may ask for, in seconds.
const MIN_PAIRING_TTL_SECS: u64 = 30;

/// The health document, and the whole of what the unauthenticated route discloses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Health {
    /// `"ok"` when every subsystem is working, `"degraded"` otherwise.
    pub status: &'static str,
    /// Agent version.
    pub version: &'static str,
    /// Protocol major version this build speaks.
    pub protocol_major: u16,
    /// Whether the database answered a query just now.
    pub database_ready: bool,
    /// Whether the QUIC listener is bound.
    pub listener_ready: bool,
    /// How many sessions are currently live and authenticated.
    pub active_sessions: usize,
    /// How many connections hold a session slot but have not authenticated yet.
    ///
    /// Reported separately because a persistently non-zero value here is the visible
    /// symptom of something repeatedly connecting and failing the handshake.
    pub connecting: usize,
    /// The configured concurrent-session cap.
    pub max_sessions: usize,
    /// Seconds since the agent started.
    pub uptime_secs: u64,
}

impl Health {
    /// Whether every subsystem reported healthy.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.database_ready && self.listener_ready
    }
}

/// What `rc-agent pair` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPairingRequest {
    /// How long the window should stay open, in seconds.
    pub ttl_secs: u64,
}

/// What it gets back.
///
/// Carries the pairing code in clear. That is the point of the route: the code exists
/// to be shown to the operator, and this is the sanctioned path by which it becomes
/// visible. Reaching this route requires having read the local-control token, which
/// requires the same access as reading the agent's keystore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPairingResponse {
    /// The code to type into the client.
    pub code: String,
    /// Which exchange it belongs to.
    pub pairing_session_id: String,
    /// When the window closes, milliseconds since the Unix epoch.
    pub expires_at_ms: i64,
    /// How long the window is open for.
    pub ttl_secs: u64,
    /// The agent's device id, for the operator to compare.
    pub device_id: String,
    /// The agent's identity fingerprint, grouped for reading aloud.
    pub identity_fingerprint: String,
}

/// Serves the loopback routes.
pub struct LocalEndpoint {
    database: rc_storage::Database,
    sessions: Arc<SessionRegistry>,
    started_at: std::time::Instant,
    listener_ready: Arc<std::sync::atomic::AtomicBool>,
    pairing: Arc<rc_security::PairingManager>,
    identity: Arc<rc_security::DeviceIdentity>,
    token: LocalControlToken,
}

impl LocalEndpoint {
    /// Build an endpoint over the agent's live state.
    #[must_use]
    pub fn new(
        database: rc_storage::Database,
        sessions: Arc<SessionRegistry>,
        listener_ready: Arc<std::sync::atomic::AtomicBool>,
        pairing: Arc<rc_security::PairingManager>,
        identity: Arc<rc_security::DeviceIdentity>,
        token: LocalControlToken,
    ) -> Self {
        Self {
            database,
            sessions,
            started_at: std::time::Instant::now(),
            listener_ready,
            pairing,
            identity,
            token,
        }
    }

    /// Gather the current health.
    ///
    /// The database check is a real query rather than "we opened it once at startup":
    /// a database whose file has been deleted or whose disk has filled still *looks*
    /// open, and reporting that as healthy would be worse than not reporting at all.
    pub async fn health(&self) -> Health {
        let database_ready = self.database.health_check().await.is_ok();
        let listener_ready = self
            .listener_ready
            .load(std::sync::atomic::Ordering::Acquire);
        let active = self.sessions.list().len();

        Health {
            status: if database_ready && listener_ready {
                "ok"
            } else {
                "degraded"
            },
            version: env!("CARGO_PKG_VERSION"),
            protocol_major: rc_protocol::CURRENT_VERSION.major,
            database_ready,
            listener_ready,
            active_sessions: active,
            connecting: self.sessions.reserved_count().saturating_sub(active),
            max_sessions: self.sessions.capacity(),
            uptime_secs: self.started_at.elapsed().as_secs(),
        }
    }

    /// Open a pairing window and return the code.
    ///
    /// # Errors
    /// A message safe to display if the request is out of range or too many windows are
    /// already open.
    pub async fn open_pairing(
        &self,
        request: OpenPairingRequest,
    ) -> Result<OpenPairingResponse, String> {
        if !(MIN_PAIRING_TTL_SECS..=MAX_PAIRING_TTL_SECS).contains(&request.ttl_secs) {
            return Err(format!(
                "the pairing window must be between {MIN_PAIRING_TTL_SECS} and \
                 {MAX_PAIRING_TTL_SECS} seconds"
            ));
        }

        // The window has to live in the *running agent's* manager: a client connects to
        // this process, and only this process's manager can verify the proof.
        let clock = rc_security::SystemClock;
        let opened = self
            .pairing
            .begin_pairing_with_ttl(&clock, &rc_security::OsRandom, request.ttl_secs)
            .map_err(|err| err.to_string())?;

        // Persist the outcome row, never the code. Reading this row does not yield a
        // usable code: it holds an Argon2id output over a 44-bit space.
        let recorded = sqlx::query(
            "INSERT INTO pairing_code (
                 id, code_hash, code_salt, created_at_ms, expires_at_ms,
                 max_attempts, pairing_session_id, outcome
             ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open')",
        )
        .bind(opened.pairing_session_id.to_canonical_string())
        .bind(&opened.verifier_hex)
        .bind(&opened.salt_hex)
        .bind(rc_security::Clock::now_ms(&clock))
        .bind(opened.expires_at_ms)
        .bind(i64::from(self.pairing.policy().max_attempts))
        .bind(opened.pairing_session_id.to_canonical_string())
        .execute(self.database.pool())
        .await;

        if let Err(err) = recorded {
            // The window is live in memory either way; an audit gap is worth a warning
            // but not worth refusing the operator's request.
            tracing::warn!(%err, "could not record the pairing window");
        }

        let public = self.identity.public();
        Ok(OpenPairingResponse {
            code: opened.code.expose_for_display(),
            pairing_session_id: opened.pairing_session_id.to_canonical_string(),
            expires_at_ms: opened.expires_at_ms,
            ttl_secs: request.ttl_secs,
            device_id: public.device_id.to_canonical_string(),
            identity_fingerprint: public.identity_fingerprint.to_display_groups(),
        })
    }

    /// Serve until `shutdown` resolves.
    ///
    /// # Errors
    /// Fails if the port cannot be bound — usually because another agent is already
    /// running. The caller treats that as a warning rather than a fatal error: an agent
    /// that cannot serve this endpoint can still serve clients.
    pub async fn serve(
        self: Arc<Self>,
        port: u16,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> std::io::Result<()> {
        // Loopback, always. See the module documentation.
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener = tokio::net::TcpListener::bind(address).await?;
        let bound = listener.local_addr()?;

        tracing::info!(%bound, "local control endpoint listening on loopback");

        let health_state = Arc::clone(&self);
        let pairing_state = Arc::clone(&self);

        let router = axum::Router::new()
            .route(
                "/health",
                axum::routing::get(move || {
                    let endpoint = Arc::clone(&health_state);
                    async move {
                        let health = endpoint.health().await;
                        let code = if health.is_ok() {
                            axum::http::StatusCode::OK
                        } else {
                            // A monitoring probe must be able to tell the difference
                            // without parsing the body.
                            axum::http::StatusCode::SERVICE_UNAVAILABLE
                        };
                        (code, axum::Json(health))
                    }
                }),
            )
            .route(
                "/pairing",
                axum::routing::post(
                    move |headers: axum::http::HeaderMap,
                          body: axum::Json<OpenPairingRequest>| {
                        let endpoint = Arc::clone(&pairing_state);
                        async move { endpoint.handle_open_pairing(&headers, body.0).await }
                    },
                ),
            )
            // Small, because neither route takes a large body. An endpoint that
            // accepted large bodies would be a memory-exhaustion surface reachable by
            // any local process.
            .layer(tower_http::limit::RequestBodyLimitLayer::new(4096));

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await
    }

    /// Authenticate and run a pairing request.
    async fn handle_open_pairing(
        &self,
        headers: &axum::http::HeaderMap,
        request: OpenPairingRequest,
    ) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
        if !self.token.matches_header(headers) {
            tracing::warn!("a local pairing request presented no valid control token");
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": "a valid local-control token is required"
                })),
            );
        }

        match self.open_pairing(request).await {
            Ok(response) => (
                axum::http::StatusCode::OK,
                axum::Json(serde_json::to_value(response).unwrap_or_default()),
            ),
            Err(message) => (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({ "error": message })),
            ),
        }
    }
}

/// The local-control token: a filesystem capability carried over a socket.
///
/// Neither `Debug` nor `Serialize` renders the value, so it cannot reach a log by
/// accident.
#[derive(Clone)]
pub struct LocalControlToken {
    value: Arc<String>,
}

impl LocalControlToken {
    /// Generate a fresh token.
    ///
    /// Regenerated on every start, so a copy taken from a previous run is useless.
    #[must_use]
    pub fn generate() -> Self {
        use rc_security::RandomSourceExt as _;
        let bytes: [u8; 32] = rc_security::OsRandom.bytes();
        Self {
            value: Arc::new(hex::encode(bytes)),
        }
    }

    /// Write the token where a privileged local caller can read it.
    ///
    /// The file inherits the data directory's protection, which is the actual access
    /// control; see the module documentation.
    ///
    /// # Errors
    /// Propagates the write failure. The caller degrades to serving `/health` only,
    /// rather than serving a pairing route whose token nobody can present.
    pub fn write_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        // Written through the keystore's atomic-write helper so a reader never sees a
        // half-written token, and so the Unix mode is applied before any content is.
        rc_security::keystore::write_protected_file(path, self.value.as_bytes())
    }

    /// Read a token a running agent wrote.
    ///
    /// # Errors
    /// Propagates the read failure, which for the `pair` command means either that no
    /// agent is running or that this user may not administer it.
    pub fn read_from(path: &std::path::Path) -> std::io::Result<Self> {
        let value = std::fs::read_to_string(path)?;
        Ok(Self {
            value: Arc::new(value.trim().to_owned()),
        })
    }

    /// The header value to send.
    #[must_use]
    pub fn header_value(&self) -> &str {
        &self.value
    }

    /// Whether the request carries this token, compared in constant time.
    #[must_use]
    pub fn matches_header(&self, headers: &axum::http::HeaderMap) -> bool {
        let Some(presented) = headers.get(TOKEN_HEADER).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        self.matches(presented)
    }

    /// Whether `presented` equals this token, compared in constant time.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        // Length is compared first and separately: `ct_eq` requires equal lengths, and
        // the length of a fixed-size token is not itself a secret.
        let expected = self.value.as_bytes();
        let presented = presented.as_bytes();
        presented.len() == expected.len() && bool::from(presented.ct_eq(expected))
    }
}

impl std::fmt::Debug for LocalControlToken {
    /// Redacted. A token in a log line is a token in a bug report.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalControlToken(<redacted>)")
    }
}

/// The file the token is written to, inside the agent's data directory.
#[must_use]
pub fn token_path(paths: &rc_platform::AppPaths) -> std::path::PathBuf {
    paths.data_dir().join("local-control.token")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;

    fn token_headers(token: &LocalControlToken) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            TOKEN_HEADER,
            axum::http::HeaderValue::from_str(token.header_value()).unwrap(),
        );
        headers
    }

    async fn endpoint(listener_ready: bool) -> (Arc<LocalEndpoint>, LocalControlToken) {
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        let token = LocalControlToken::generate();
        let endpoint = Arc::new(LocalEndpoint::new(
            database,
            Arc::new(SessionRegistry::new(4)),
            Arc::new(AtomicBool::new(listener_ready)),
            Arc::new(rc_security::PairingManager::with_defaults()),
            Arc::new(
                rc_security::DeviceIdentity::generate("test", &rc_security::SystemClock).unwrap(),
            ),
            token.clone(),
        ));
        (endpoint, token)
    }

    #[tokio::test]
    async fn a_working_agent_reports_ok() {
        let (endpoint, _) = endpoint(true).await;
        let health = endpoint.health().await;

        assert_eq!(health.status, "ok");
        assert!(health.is_ok());
        assert!(health.database_ready);
        assert_eq!(health.active_sessions, 0);
        assert_eq!(health.connecting, 0);
        assert_eq!(health.max_sessions, 4);
    }

    #[tokio::test]
    async fn an_unbound_listener_reports_degraded() {
        // The process being alive is not the same question as the agent working.
        let (endpoint, _) = endpoint(false).await;
        let health = endpoint.health().await;

        assert_eq!(health.status, "degraded");
        assert!(!health.is_ok());
        assert!(health.database_ready, "the database is still fine");
    }

    #[tokio::test]
    async fn the_health_document_names_no_device_session_or_path() {
        let (endpoint, _) = endpoint(true).await;
        let rendered = serde_json::to_string(&endpoint.health().await).unwrap();

        for forbidden in [
            "dev_",
            "ses_",
            "fingerprint",
            "C:\\",
            "/home/",
            ".db",
            "token",
            "key",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "an unauthenticated endpoint must not disclose {forbidden}: {rendered}"
            );
        }
    }

    #[tokio::test]
    async fn live_sessions_are_counted() {
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        let sessions = Arc::new(SessionRegistry::new(4));
        let endpoint = LocalEndpoint::new(
            database,
            Arc::clone(&sessions),
            Arc::new(AtomicBool::new(true)),
            Arc::new(rc_security::PairingManager::with_defaults()),
            Arc::new(
                rc_security::DeviceIdentity::generate("test", &rc_security::SystemClock).unwrap(),
            ),
            LocalControlToken::generate(),
        );

        let slot = sessions.reserve().unwrap();
        slot.activate(
            rc_protocol::SessionId::generate(),
            rc_protocol::DeviceId::generate(),
            rc_security::Role::Owner,
            "10.0.0.2:5000".parse().unwrap(),
            1,
        );

        let snapshot = endpoint.health().await;
        assert_eq!(snapshot.active_sessions, 1);
        assert_eq!(snapshot.connecting, 0);

        drop(slot);
        assert_eq!(endpoint.health().await.active_sessions, 0);
    }

    #[tokio::test]
    async fn a_pairing_request_without_the_token_is_refused() {
        // The whole access-control decision. Without this, any local process could
        // create trust.
        let (endpoint, _token) = endpoint(true).await;

        let (status, _) = endpoint
            .handle_open_pairing(
                &axum::http::HeaderMap::new(),
                OpenPairingRequest { ttl_secs: 180 },
            )
            .await;

        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_pairing_request_with_the_wrong_token_is_refused() {
        let (endpoint, _) = endpoint(true).await;
        let wrong = LocalControlToken::generate();

        let (status, _) = endpoint
            .handle_open_pairing(&token_headers(&wrong), OpenPairingRequest { ttl_secs: 180 })
            .await;

        assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_pairing_request_with_the_token_opens_a_window_in_this_process() {
        // The window must land in the agent's own manager: a client will connect to
        // this process, and only this process can verify the proof.
        let (endpoint, token) = endpoint(true).await;

        let (status, body) = endpoint
            .handle_open_pairing(&token_headers(&token), OpenPairingRequest { ttl_secs: 120 })
            .await;

        assert_eq!(status, axum::http::StatusCode::OK);

        let response: OpenPairingResponse = serde_json::from_value(body.0).unwrap();
        // Displayed with separators for readability; the symbols themselves are what
        // the length is defined over.
        assert_eq!(
            response.code.chars().filter(|c| *c != '-').count(),
            rc_security::pairing::CODE_LENGTH
        );
        assert_eq!(response.ttl_secs, 120);

        assert_eq!(
            endpoint
                .pairing
                .open_session_ids(&rc_security::SystemClock)
                .len(),
            1,
            "the window must be open in the agent's own manager"
        );
    }

    #[tokio::test]
    async fn an_out_of_range_window_is_refused() {
        let (endpoint, token) = endpoint(true).await;

        for ttl in [0, 5, 10_000] {
            let (status, _) = endpoint
                .handle_open_pairing(&token_headers(&token), OpenPairingRequest { ttl_secs: ttl })
                .await;
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "a {ttl}-second window must be refused"
            );
        }
    }

    #[test]
    fn a_token_never_renders_itself() {
        let token = LocalControlToken::generate();
        let rendered = format!("{token:?}");

        assert!(!rendered.contains(token.header_value()));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn tokens_are_distinct_between_runs() {
        // A copy taken from a previous run must be useless.
        let first = LocalControlToken::generate();
        let second = LocalControlToken::generate();
        assert!(!first.matches(second.header_value()));
    }

    #[test]
    fn a_truncated_token_does_not_match() {
        let token = LocalControlToken::generate();
        let prefix = &token.header_value()[..16];

        assert!(!token.matches(prefix));
        assert!(!token.matches(""));
    }

    #[test]
    fn a_token_round_trips_through_a_protected_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("local-control.token");

        let original = LocalControlToken::generate();
        original.write_to(&path).unwrap();

        let read_back = LocalControlToken::read_from(&path).unwrap();
        assert!(original.matches(read_back.header_value()));
    }

    #[cfg(unix)]
    #[test]
    fn the_token_file_is_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("local-control.token");
        LocalControlToken::generate().write_to(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "the token is the capability; anyone who can read it can create trust"
        );
    }
}
