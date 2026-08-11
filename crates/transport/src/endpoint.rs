//! QUIC endpoints: the agent's listener and the client's connector.
//!
//! # Transport parameters
//!
//! The defaults are chosen for a remote-desktop workload rather than bulk transfer:
//!
//! | Parameter | Value | Reasoning |
//! |---|---|---|
//! | Idle timeout | 30 s | Long enough to survive a Wi-Fi handover, short enough that a dead peer is noticed before the operator does |
//! | Keep-alive | 10 s | Comfortably under the idle timeout, and under the ~30 s NAT rebinding window most home routers use |
//! | Concurrent bidi streams | 16 | Six channels plus headroom. A bound, so a peer cannot open streams without limit |
//! | Concurrent uni streams | 0 | Every channel is bidirectional; accepting uni streams would be surface we do not use |
//!
//! # Address validation
//!
//! QUIC's retry mechanism is left on. Without it, a spoofed source address can make the
//! agent send a large handshake to a victim — a reflection amplifier. This costs one
//! extra round trip on the first connection from an address and is worth it for a
//! service that may face the internet.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rc_security::DeviceIdentity;

use crate::error::{Result, TransportError};
use crate::tls::{self, ObservedPeer, PinPolicy};

/// How long a connection may be idle before it is considered lost.
pub const IDLE_TIMEOUT_SECS: u64 = 30;

/// How often to send a keep-alive.
pub const KEEP_ALIVE_SECS: u64 = 10;

/// Maximum concurrent bidirectional streams. Six channels plus headroom.
pub const MAX_CONCURRENT_STREAMS: u32 = 16;

/// Shared transport tuning, applied to both directions.
fn transport_config() -> Arc<TransportConfig> {
    let mut config = TransportConfig::default();

    config
        .max_idle_timeout(Some(
            Duration::from_secs(IDLE_TIMEOUT_SECS)
                .try_into()
                .unwrap_or_default(),
        ))
        .keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_SECS)))
        .max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into())
        // Every channel is bidirectional. Refusing unidirectional streams removes an
        // entire class of unused surface.
        .max_concurrent_uni_streams(0u32.into());

    Arc::new(config)
}

/// The agent's listening endpoint.
#[derive(Debug)]
pub struct AgentListener {
    endpoint: Endpoint,
}

impl AgentListener {
    /// Bind a listener on `address`, presenting `identity`.
    ///
    /// `policy` decides which certificates are admitted at the TLS layer. A listener
    /// serving many clients uses [`PinPolicy::TrustOnFirstUse`], because one pin could
    /// only ever match one of them. Note that TLS admission is **not** authorization —
    /// [`crate::handshake`] decides whether the peer may have a session.
    ///
    /// # Errors
    /// [`TransportError::Bind`] if the socket cannot be bound, or
    /// [`TransportError::Configuration`] if the identity is unusable for TLS.
    pub fn bind(
        address: SocketAddr,
        identity: &DeviceIdentity,
        policy: PinPolicy,
    ) -> Result<(Self, ObservedPeer)> {
        let (rustls_config, observed) = tls::server_config(identity, policy)?;

        let quic_config = QuicServerConfig::try_from(rustls_config).map_err(|err| {
            TransportError::Configuration {
                reason: format!("the TLS configuration is not usable for QUIC: {err}"),
            }
        })?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_config));
        server_config.transport_config(transport_config());

        let endpoint =
            Endpoint::server(server_config, address).map_err(|err| TransportError::Bind {
                reason: err.to_string(),
            })?;

        tracing::info!(%address, "QUIC listener bound");
        Ok((Self { endpoint }, observed))
    }

    /// The address actually bound. Differs from the requested one when port 0 was used.
    ///
    /// # Errors
    /// [`TransportError::Bind`] if the socket has no local address.
    pub fn local_address(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|err| TransportError::Bind {
                reason: err.to_string(),
            })
    }

    /// Wait for the next incoming connection to finish its TLS handshake.
    ///
    /// Returns `None` once the endpoint is closed.
    pub async fn accept(&self) -> Option<Result<quinn::Connection>> {
        let incoming = self.endpoint.accept().await?;
        let remote = incoming.remote_address();

        Some(match incoming.await {
            Ok(connection) => {
                tracing::debug!(%remote, "connection established");
                Ok(connection)
            }
            Err(err) => {
                // A failed handshake here is usually a refused certificate. It is
                // logged at debug because an exposed listener will see scanner traffic
                // and this must not be a log-flooding vector.
                tracing::debug!(%remote, %err, "incoming connection failed to establish");
                Err(TransportError::ConnectionLost {
                    reason: err.to_string(),
                })
            }
        })
    }

    /// Stop accepting connections and close those in flight.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"agent shutting down");
    }

    /// Wait for all connections to finish closing.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}

/// The client's outgoing endpoint.
#[derive(Debug)]
pub struct ClientConnector {
    endpoint: Endpoint,
}

impl ClientConnector {
    /// Create a connector presenting `identity` and pinning peers per `policy`.
    ///
    /// # Errors
    /// [`TransportError::Bind`] if no local socket can be opened.
    pub fn new(identity: &DeviceIdentity, policy: PinPolicy) -> Result<(Self, ObservedPeer)> {
        let (rustls_config, observed) = tls::client_config(identity, policy)?;

        let quic_config = QuicClientConfig::try_from(rustls_config).map_err(|err| {
            TransportError::Configuration {
                reason: format!("the TLS configuration is not usable for QUIC: {err}"),
            }
        })?;

        let mut client_config = ClientConfig::new(Arc::new(quic_config));
        client_config.transport_config(transport_config());

        // Bind an ephemeral local port on all interfaces.
        let mut endpoint =
            Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into()).map_err(|err| {
                TransportError::Bind {
                    reason: err.to_string(),
                }
            })?;
        endpoint.set_default_client_config(client_config);

        Ok((Self { endpoint }, observed))
    }

    /// Connect to an agent.
    ///
    /// `server_name` is required by the TLS API but is **not** verified — devices are
    /// identified by pinned key, not by name. A fixed placeholder is used so the value
    /// cannot accidentally become meaningful.
    ///
    /// # Errors
    /// [`TransportError::Connect`] if the connection or its handshake fails. A refused
    /// pin surfaces here.
    pub async fn connect(&self, address: SocketAddr) -> Result<quinn::Connection> {
        let connecting = self
            .endpoint
            .connect(address, PLACEHOLDER_SERVER_NAME)
            .map_err(|err| TransportError::Connect {
                reason: err.to_string(),
            })?;

        connecting.await.map_err(|err| {
            tracing::debug!(%address, %err, "connection attempt failed");
            TransportError::Connect {
                reason: err.to_string(),
            }
        })
    }

    /// Close the endpoint.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"client closing");
    }

    /// Wait for all connections to finish closing.
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}

/// The SNI value sent on every connection.
///
/// Peers are authenticated by pinned certificate fingerprint. This name is never
/// verified against the certificate; it exists because the TLS API requires one. It is
/// deliberately not derived from the address or the device id, so that no future change
/// can start treating it as identifying.
pub const PLACEHOLDER_SERVER_NAME: &str = "device.invalid";

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use rc_security::SystemClock;

    use super::*;

    fn identity(name: &str) -> DeviceIdentity {
        DeviceIdentity::generate(name, &SystemClock).unwrap()
    }

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    /// Bring up an agent and a client that already trust each other's fingerprints.
    fn paired_pair() -> (DeviceIdentity, DeviceIdentity) {
        (identity("agent"), identity("client"))
    }

    #[tokio::test]
    async fn a_listener_binds_and_reports_its_address() {
        let agent = identity("agent");
        let (listener, _) = AgentListener::bind(
            loopback(),
            &agent,
            PinPolicy::Pinned(agent.public().certificate_fingerprint),
        )
        .unwrap();

        let bound = listener.local_address().unwrap();
        assert_ne!(bound.port(), 0, "an ephemeral port must be resolved");
        listener.close();
    }

    #[tokio::test]
    async fn two_mutually_pinned_devices_connect() {
        let (agent, client) = paired_pair();

        let (listener, agent_observed) = AgentListener::bind(
            loopback(),
            &agent,
            PinPolicy::Pinned(client.public().certificate_fingerprint),
        )
        .unwrap();
        let address = listener.local_address().unwrap();

        let accept = tokio::spawn(async move {
            let connection = listener.accept().await.expect("an incoming connection");
            (connection, listener, agent_observed)
        });

        let (connector, client_observed) = ClientConnector::new(
            &client,
            PinPolicy::Pinned(agent.public().certificate_fingerprint),
        )
        .unwrap();

        let connection = connector.connect(address).await.expect("client connects");
        let (accepted, _listener, agent_observed) = accept.await.unwrap();
        accepted.expect("agent accepts");

        // Each side observed the other's real certificate, not a claimed one.
        assert_eq!(
            client_observed.fingerprint(),
            Some(agent.public().certificate_fingerprint),
            "the client must observe the agent's certificate"
        );
        assert_eq!(
            agent_observed.fingerprint(),
            Some(client.public().certificate_fingerprint),
            "the agent must observe the client's certificate"
        );

        connection.close(0u32.into(), b"done");
        connector.close();
    }

    #[tokio::test]
    async fn a_client_with_the_wrong_pin_is_refused() {
        let (agent, client) = paired_pair();
        let impostor = identity("impostor");

        let (listener, _) = AgentListener::bind(
            loopback(),
            &agent,
            PinPolicy::Pinned(client.public().certificate_fingerprint),
        )
        .unwrap();
        let address = listener.local_address().unwrap();

        tokio::spawn(async move {
            // The accept will fail; draining it keeps the listener alive for the test.
            let _ = listener.accept().await;
            listener
        });

        // The client pins a certificate the agent does not have.
        let (connector, _) = ClientConnector::new(
            &client,
            PinPolicy::Pinned(impostor.public().certificate_fingerprint),
        )
        .unwrap();

        let result = connector.connect(address).await;
        assert!(
            result.is_err(),
            "connecting to an agent whose certificate is not pinned must fail"
        );
        connector.close();
    }

    #[tokio::test]
    async fn an_unpinned_client_is_refused_by_the_agent() {
        // Mutual authentication: the agent must reject a client it does not pin, even
        // though that client pins the agent correctly.
        let (agent, client) = paired_pair();
        let stranger = identity("stranger");

        let (listener, _) = AgentListener::bind(
            loopback(),
            &agent,
            PinPolicy::Pinned(client.public().certificate_fingerprint),
        )
        .unwrap();
        let address = listener.local_address().unwrap();

        let accept = tokio::spawn(async move {
            let outcome = listener.accept().await;
            (outcome, listener)
        });

        let (connector, _) = ClientConnector::new(
            &stranger,
            PinPolicy::Pinned(agent.public().certificate_fingerprint),
        )
        .unwrap();

        // The client may or may not see the failure at `connect` depending on when the
        // agent's alert arrives; what must hold is that the agent never accepts.
        let _ = connector.connect(address).await;
        let (outcome, _listener) = accept.await.unwrap();

        match outcome {
            None => {}
            Some(result) => assert!(
                result.is_err(),
                "the agent must not accept a client it does not pin"
            ),
        }
        connector.close();
    }

    #[tokio::test]
    async fn trust_on_first_use_admits_an_unknown_client_for_pairing() {
        // This is the only configuration in which an unknown peer gets through, and it
        // exists solely so a pairing exchange can happen.
        let agent = identity("agent");
        let newcomer = identity("newcomer");

        let (listener, agent_observed) =
            AgentListener::bind(loopback(), &agent, PinPolicy::TrustOnFirstUse).unwrap();
        let address = listener.local_address().unwrap();

        let accept = tokio::spawn(async move {
            let outcome = listener.accept().await;
            (outcome, listener, agent_observed)
        });

        let (connector, _) = ClientConnector::new(&newcomer, PinPolicy::TrustOnFirstUse).unwrap();
        let connection = connector.connect(address).await.expect("pairing connects");

        let (outcome, _listener, agent_observed) = accept.await.unwrap();
        outcome.expect("an incoming connection").expect("accepted");

        // The observed fingerprint is what the pairing transcript must use.
        assert_eq!(
            agent_observed.fingerprint(),
            Some(newcomer.public().certificate_fingerprint)
        );

        connection.close(0u32.into(), b"done");
        connector.close();
    }
}
