//! Optional self-hosted coordination service.
//!
//! # Trust model
//!
//! This service is **untrusted with respect to session contents**. Its only job is to
//! help two devices that already trust each other find one another and exchange
//! connection candidates. It never holds a device private key, never terminates a
//! session's encryption, and never sees plaintext screen or file data —
//! those are protected end-to-end between the client and the agent by mutually
//! authenticated TLS 1.3 over QUIC, established *through* whatever path this service
//! helped negotiate.
//!
//! Concretely, a compromised coordinator can deny service and learn metadata (which
//! device ids talk to each other, and when). It cannot impersonate a device, read
//! traffic, or authorise a new client — that requires a pinned certificate the
//! coordinator does not have. See `docs/threat-model.md`.
//!
//! Signalling and relay endpoints are implemented in Phase 8. This phase establishes
//! the service, its listener, its rate limiting and its health endpoint.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Context as _;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use clap::Parser;
use serde::Serialize;

/// Command-line interface.
#[derive(Debug, Parser)]
#[command(
    name = "rc-coordinator",
    version,
    about = "Remote-control coordination service"
)]
struct Cli {
    /// Address to bind to. Defaults to loopback: exposing this service publicly must
    /// be a deliberate act, done behind a TLS-terminating reverse proxy.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST), env = "RC_COORD_ADDRESS")]
    address: IpAddr,

    /// TCP port to listen on.
    #[arg(long, default_value_t = rc_protocol::DEFAULT_COORDINATION_PORT, env = "RC_COORD_PORT")]
    port: u16,

    /// Maximum request body size in bytes. Signalling payloads are small.
    #[arg(long, default_value_t = 64 * 1024)]
    max_body_bytes: usize,
}

/// Shared service state.
#[derive(Debug, Clone)]
struct AppState {
    started_at: std::time::Instant,
}

/// Response of `GET /health`.
#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    version: &'static str,
    protocol_major: u16,
    protocol_minor: u16,
    uptime_secs: u64,
}

/// Liveness and version endpoint.
///
/// Deliberately discloses nothing about registered devices: an unauthenticated caller
/// learns only that a coordinator exists and which protocol it speaks.
async fn health(State(state): State<AppState>) -> (StatusCode, axum::Json<Health>) {
    let body = Health {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        protocol_major: rc_protocol::CURRENT_VERSION.major,
        protocol_minor: rc_protocol::CURRENT_VERSION.minor,
        uptime_secs: state.started_at.elapsed().as_secs(),
    };
    (StatusCode::OK, axum::Json(body))
}

/// Build the HTTP router.
fn build_router(state: AppState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/health", get(health))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            max_body_bytes,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr = SocketAddr::new(cli.address, cli.port);
    let state = AppState {
        started_at: std::time::Instant::now(),
    };
    let app = build_router(state, cli.max_body_bytes);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("could not bind {addr}"))?;

    tracing::info!(
        %addr,
        version = env!("CARGO_PKG_VERSION"),
        "coordination service listening (signalling endpoints arrive in Phase 8)"
    );
    if !cli.address.is_loopback() {
        tracing::warn!(
            "binding a non-loopback address; terminate TLS at a reverse proxy and \
             apply the firewall guidance in docs/installation.md"
        );
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received");
        })
        .await
        .context("server error")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn default_bind_address_is_loopback() {
        // Exposing the coordinator to a network must be an explicit choice.
        let cli = Cli::parse_from(["rc-coordinator"]);
        assert!(cli.address.is_loopback());
        assert_eq!(cli.port, rc_protocol::DEFAULT_COORDINATION_PORT);
    }

    #[test]
    fn body_limit_is_bounded_by_default() {
        let cli = Cli::parse_from(["rc-coordinator"]);
        assert!(cli.max_body_bytes > 0);
        assert!(
            cli.max_body_bytes <= 1024 * 1024,
            "signalling payloads are small"
        );
    }

    #[tokio::test]
    async fn health_reports_ok_and_the_protocol_version() {
        let state = AppState {
            started_at: std::time::Instant::now(),
        };
        let (status, body) = health(State(state)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.0.status, "ok");
        assert_eq!(body.0.protocol_major, rc_protocol::CURRENT_VERSION.major);
    }

    #[tokio::test]
    async fn health_does_not_disclose_registered_devices() {
        let state = AppState {
            started_at: std::time::Instant::now(),
        };
        let (_, body) = health(State(state)).await;
        let json = serde_json::to_string(&body.0).unwrap();

        assert!(!json.contains("dev_"), "health must not list devices");
        assert!(
            !json.contains("device"),
            "health must not mention devices at all"
        );
    }

    #[test]
    fn router_builds() {
        let state = AppState {
            started_at: std::time::Instant::now(),
        };
        let _router = build_router(state, 1024);
    }
}
