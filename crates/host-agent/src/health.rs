//! The agent's loopback health endpoint.
//!
//! # Why this exists
//!
//! A service manager knows whether the process is running. It cannot see whether the
//! agent is *working* — whether its database answers and its QUIC listener is bound.
//! `GET /health` is how an operator, a monitoring probe or an installer asks that
//! second question.
//!
//! # It is unauthenticated, so it discloses nothing
//!
//! The document carries counts and readiness flags only: no device id, no session id,
//! no fingerprint, no path. There is nothing here worth authenticating, and requiring a
//! credential would make the one thing a probe needs the hardest thing to get.
//!
//! # It binds loopback
//!
//! The address is `127.0.0.1` and is not configurable, so no configuration mistake can
//! put it on the network.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use serde::Serialize;

use crate::sessions::SessionRegistry;

/// The health document, and the whole of what the endpoint discloses.
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

/// Serves the loopback health route.
pub struct HealthEndpoint {
    database: rc_storage::Database,
    sessions: Arc<SessionRegistry>,
    started_at: std::time::Instant,
    listener_ready: Arc<std::sync::atomic::AtomicBool>,
}

impl HealthEndpoint {
    /// Build an endpoint over the agent's live state.
    #[must_use]
    pub fn new(
        database: rc_storage::Database,
        sessions: Arc<SessionRegistry>,
        listener_ready: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            database,
            sessions,
            started_at: std::time::Instant::now(),
            listener_ready,
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

        tracing::info!(%bound, "health endpoint listening on loopback");

        let router = axum::Router::new()
            .route(
                "/health",
                axum::routing::get(move || {
                    let endpoint = Arc::clone(&self);
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
            // Small, because the route takes no body at all. An endpoint that accepted
            // large bodies would be a memory-exhaustion surface reachable by any local
            // process.
            .layer(tower_http::limit::RequestBodyLimitLayer::new(4096));

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;

    async fn endpoint(listener_ready: bool) -> Arc<HealthEndpoint> {
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        Arc::new(HealthEndpoint::new(
            database,
            Arc::new(SessionRegistry::new(4)),
            Arc::new(AtomicBool::new(listener_ready)),
        ))
    }

    #[tokio::test]
    async fn a_working_agent_reports_ok() {
        let endpoint = endpoint(true).await;
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
        let endpoint = endpoint(false).await;
        let health = endpoint.health().await;

        assert_eq!(health.status, "degraded");
        assert!(!health.is_ok());
        assert!(health.database_ready, "the database is still fine");
    }

    #[tokio::test]
    async fn the_health_document_names_no_device_session_or_path() {
        let endpoint = endpoint(true).await;
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
        let endpoint = HealthEndpoint::new(
            database,
            Arc::clone(&sessions),
            Arc::new(AtomicBool::new(true)),
        );

        let slot = sessions.reserve().unwrap();
        slot.activate(
            rc_protocol::SessionId::generate(),
            rc_protocol::DeviceId::generate(),
            rc_security::PermissionSet::ALL,
            "10.0.0.2:5000".parse().unwrap(),
            1,
        );

        let snapshot = endpoint.health().await;
        assert_eq!(snapshot.active_sessions, 1);
        assert_eq!(snapshot.connecting, 0);

        drop(slot);
        assert_eq!(endpoint.health().await.active_sessions, 0);
    }
}
