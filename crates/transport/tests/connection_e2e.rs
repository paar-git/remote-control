//! End-to-end connection tests.
//!
//! These drive two real QUIC endpoints over loopback through the complete sequence a
//! production connection follows: mutual TLS with pinned certificates, the control
//! channel, and the application handshake.
//!
//! Nothing is stubbed. In this build the handshake has no way to authorise a peer — the
//! pairing protocol has been deleted and the accept path that replaces it is not here
//! yet — so what these tests assert is that the agent refuses *everyone*, cleanly and
//! visibly, rather than admitting whoever completes TLS.

// Integration tests assert against known-good values, so `unwrap` and `panic` are the
// clearest way to fail. The workspace denies them in library code, where a panic would
// take down an agent; here a panic *is* the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rc_protocol::control::{Capabilities, DeviceDescriptor, OsFamily, PeerRole};
use rc_protocol::frame::Channel;
use rc_security::{DeviceIdentity, SystemClock};

use rc_transport::endpoint::{AgentListener, ClientConnector};
use rc_transport::handshake;
use rc_transport::{PinPolicy, TransportError};

fn identity(name: &str) -> DeviceIdentity {
    DeviceIdentity::generate(name, &SystemClock).unwrap()
}

fn descriptor(identity: &DeviceIdentity, name: &str) -> DeviceDescriptor {
    DeviceDescriptor {
        device_id: identity.device_id(),
        display_name: name.to_owned(),
        hostname: "test-host".to_owned(),
        os_family: OsFamily::Windows,
        os_version: "test".to_owned(),
        app_version: "0.1.0".to_owned(),
        certificate_fingerprint: identity.public().certificate_fingerprint.to_hex(),
    }
}

fn capabilities() -> Capabilities {
    Capabilities {
        remote_desktop: true,
        file_transfer: true,
        monitoring: true,
        power_control: true,
        display_count: 1,
        ..Capabilities::default()
    }
}

/// Everything needed to run one connection attempt.
struct Harness {
    agent: DeviceIdentity,
    client: DeviceIdentity,
}

impl Harness {
    fn new() -> Self {
        Self {
            agent: identity("agent"),
            client: identity("client"),
        }
    }

    /// Run a full connection and return what each side concluded.
    async fn connect(
        &self,
    ) -> (
        rc_transport::Result<handshake::AuthenticatedPeer>,
        rc_transport::Result<rc_protocol::control::HelloAck>,
    ) {
        let (listener, _endpoint_observed) = AgentListener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &self.agent,
            // TLS admits any well-formed peer here; admission is the handshake's job,
            // which is exactly the separation being tested.
            PinPolicy::TrustOnFirstUse,
        )
        .unwrap();
        let address = listener.local_address().unwrap();

        let client_descriptor = descriptor(&self.client, "Client");

        // The connection is returned alongside the result so it stays alive until both
        // halves of the `join!` have finished. Dropping it as soon as the handshake
        // returns would tear the link down before the client had read the reply.
        let agent_side = async {
            let connection = match listener.accept().await.unwrap() {
                Ok(connection) => connection,
                Err(err) => return (Err(err), None),
            };

            // Read from the connection, not from the endpoint: the endpoint-wide
            // record is shared by every concurrent handshake.
            let observed = rc_transport::peer_certificate_fingerprint(&connection)
                .expect("TLS must have recorded the client certificate");

            let outcome = async {
                let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await?;
                handshake::accept_handshake(&mut reader, &mut writer, observed).await
            }
            .await;

            (outcome, Some(connection))
        };

        let client_side = async {
            let (connector, _) = ClientConnector::new(&self.client, PinPolicy::TrustOnFirstUse)?;
            let connection = connector.connect(address).await?;

            let (mut writer, mut reader) =
                rc_transport::open_channel(&connection, Channel::Control).await?;

            let ack = handshake::begin_handshake(
                &mut reader,
                &mut writer,
                client_descriptor,
                capabilities(),
                0,
            )
            .await;

            // Hold the connection open until the agent has finished.
            std::mem::forget(connector);
            ack
        };

        // The agent half yields its connection alongside the result purely to keep the
        // link open; it is dropped here, once both halves have finished.
        let ((agent_outcome, _connection), client_outcome) = tokio::join!(agent_side, client_side);
        (agent_outcome, client_outcome)
    }
}

#[tokio::test]
async fn a_client_that_completes_tls_is_still_not_admitted() {
    // The property that matters most in this build: finishing mutual TLS gets a peer a
    // control stream and nothing else. If this ever returns `Ok`, the agent is running
    // with no authorisation step at all.
    let harness = Harness::new();

    let (agent_result, client_result) = harness.connect().await;

    assert!(
        matches!(agent_result, Err(TransportError::AuthorizationUnavailable)),
        "completing TLS must not admit a peer, got {agent_result:?}"
    );
    assert!(
        client_result.is_err(),
        "the client must be told it was refused, got {client_result:?}"
    );
}

#[tokio::test]
async fn a_refused_peer_is_told_it_was_refused_and_nothing_more() {
    // The refusal reaches the peer as an ordinary rejection. It must not carry the
    // agent's descriptor, capabilities or a session id, all of which travel on the
    // acknowledgement a peer only gets after being admitted.
    let harness = Harness::new();

    let (_, client_result) = harness.connect().await;

    let err = client_result.unwrap_err();
    assert!(
        matches!(err, TransportError::NotTrusted),
        "a refused client sees a plain refusal, got {err:?}"
    );
}

#[tokio::test]
async fn the_agent_refuses_a_peer_claiming_to_be_an_agent() {
    // Only clients connect inward. A peer announcing PeerRole::Agent is not something
    // to accommodate, and the check exists so a future agent-to-agent path has to be
    // added deliberately rather than by accident.
    let harness = Harness::new();

    let (listener, _endpoint_observed) = AgentListener::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &harness.agent,
        PinPolicy::TrustOnFirstUse,
    )
    .unwrap();
    let address = listener.local_address().unwrap();

    let agent_side = async {
        let connection = listener.accept().await.unwrap()?;
        let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await?;
        let observed = rc_transport::peer_certificate_fingerprint(&connection).unwrap();

        handshake::accept_handshake(&mut reader, &mut writer, observed).await
    };

    let client_side = async {
        let (connector, _) =
            ClientConnector::new(&harness.client, PinPolicy::TrustOnFirstUse).unwrap();
        let connection = connector.connect(address).await.unwrap();
        let (mut writer, _reader) = rc_transport::open_channel(&connection, Channel::Control)
            .await
            .unwrap();

        // Claim to be an agent.
        writer
            .send(&rc_protocol::control::Opening::Hello(Box::new(
                rc_protocol::control::Hello {
                    version: rc_protocol::CURRENT_VERSION,
                    role: PeerRole::Agent,
                    descriptor: descriptor(&harness.client, "Client"),
                    capabilities: capabilities(),
                    sent_at_ms: 0,
                },
            )))
            .await
            .unwrap();

        std::mem::forget(connector);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };

    let (agent_result, ()) = tokio::join!(agent_side, client_side);
    assert!(
        matches!(agent_result, Err(TransportError::UnexpectedMessage { .. })),
        "a peer claiming to be an agent must be refused, got {agent_result:?}"
    );
}

#[tokio::test]
async fn a_silent_client_hits_the_handshake_deadline() {
    // A peer that completes TLS and then says nothing must not hold the slot forever.
    // The deadline is 15 s in production; this asserts the timeout path is wired,
    // using tokio's clock rather than waiting.
    tokio::time::pause();

    let harness = Harness::new();

    let (listener, _endpoint_observed) = AgentListener::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &harness.agent,
        PinPolicy::TrustOnFirstUse,
    )
    .unwrap();
    let address = listener.local_address().unwrap();

    let agent_side = async {
        let connection = listener.accept().await.unwrap()?;
        let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await?;
        let observed = rc_transport::peer_certificate_fingerprint(&connection).unwrap();

        handshake::accept_handshake(&mut reader, &mut writer, observed).await
    };

    let client_side = async {
        let (connector, _) =
            ClientConnector::new(&harness.client, PinPolicy::TrustOnFirstUse).unwrap();
        let connection = connector.connect(address).await.unwrap();
        // Open the control stream and then send nothing at all.
        let _channel = rc_transport::open_channel(&connection, Channel::Control)
            .await
            .unwrap();

        // Let the agent reach its await, then run the clock past the deadline.
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        tokio::time::advance(std::time::Duration::from_secs(
            handshake::HANDSHAKE_TIMEOUT_SECS + 5,
        ))
        .await;

        std::mem::forget(connector);
        std::mem::forget(connection);
    };

    let (agent_result, ()) = tokio::join!(agent_side, client_side);
    assert!(
        matches!(agent_result, Err(TransportError::HandshakeTimeout)),
        "a silent peer must hit the deadline, got {agent_result:?}"
    );
}
