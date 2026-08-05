//! End-to-end connection tests.
//!
//! These drive two real QUIC endpoints over loopback through the complete sequence a
//! production connection follows: mutual TLS with pinned certificates, the control
//! channel, the application handshake, and the trust and revocation checks.
//!
//! Nothing is stubbed except the trust store, which is a trait precisely so revocation
//! can be made to land at an arbitrary moment.

// Integration tests assert against known-good values, so `unwrap` and `panic` are the
// clearest way to fail. The workspace denies them in library code, where a panic would
// take down an agent; here a panic *is* the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use rc_protocol::control::{Capabilities, DeviceDescriptor, OsFamily, PeerRole};
use rc_protocol::frame::Channel;
use rc_security::{DeviceIdentity, Fingerprint, Role, SystemClock};

use rc_transport::endpoint::{AgentListener, ClientConnector};
use rc_transport::handshake::{self, TrustDirectory, TrustRecord};
use rc_transport::{PinPolicy, TransportError};

/// A trust store whose contents can change between connections.
#[derive(Debug, Default)]
struct Directory {
    records: Mutex<HashMap<String, TrustRecord>>,
}

impl Directory {
    fn trusting(identity: &DeviceIdentity, role: Role) -> Self {
        let directory = Self::default();
        directory.records.lock().unwrap().insert(
            identity.public().certificate_fingerprint.to_hex(),
            TrustRecord {
                device_id: identity.device_id(),
                display_name: "Paired Client".to_owned(),
                role,
                revoked: false,
                certificate_fingerprint: identity.public().certificate_fingerprint,
            },
        );
        directory
    }

    fn revoke_all(&self) {
        for record in self.records.lock().unwrap().values_mut() {
            record.revoked = true;
        }
    }
}

#[async_trait::async_trait]
impl TrustDirectory for Directory {
    async fn find_by_certificate(&self, fingerprint: Fingerprint) -> Option<TrustRecord> {
        self.records
            .lock()
            .unwrap()
            .get(&fingerprint.to_hex())
            .cloned()
    }
}

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
        terminal: true,
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
        directory: &Directory,
    ) -> (
        rc_transport::Result<handshake::AuthenticatedPeer>,
        rc_transport::Result<rc_protocol::control::HelloAck>,
    ) {
        let (listener, _endpoint_observed) = AgentListener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &self.agent,
            // TLS admits any well-formed peer here; authorization is the handshake's
            // job, which is exactly the separation being tested.
            PinPolicy::TrustOnFirstUse,
        )
        .unwrap();
        let address = listener.local_address().unwrap();

        let agent_descriptor = descriptor(&self.agent, "Agent");
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
                handshake::accept_handshake(
                    &mut reader,
                    &mut writer,
                    directory,
                    observed,
                    agent_descriptor,
                    capabilities(),
                    0,
                )
                .await
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
async fn a_paired_client_completes_the_full_connection() {
    let harness = Harness::new();
    let directory = Directory::trusting(&harness.client, Role::Operator);

    let (agent_result, client_result) = harness.connect(&directory).await;

    let peer = agent_result.expect("the agent admits a trusted client");
    assert_eq!(peer.device_id, harness.client.device_id());
    assert_eq!(peer.role, Role::Operator);
    assert_eq!(
        peer.certificate_fingerprint,
        harness.client.public().certificate_fingerprint,
        "the agent must record the observed certificate"
    );

    let ack = client_result.expect("the client receives an acknowledgement");
    assert!(ack.already_paired);
    assert_eq!(ack.negotiated_version, rc_protocol::CURRENT_VERSION);
}

#[tokio::test]
async fn an_unpaired_client_is_refused_by_the_handshake() {
    // TLS lets it through — there is no pin yet — and the handshake is what stops it.
    let harness = Harness::new();
    let directory = Directory::default();

    let (agent_result, client_result) = harness.connect(&directory).await;

    assert!(
        matches!(agent_result, Err(TransportError::NotTrusted)),
        "an unknown device must be refused, got {agent_result:?}"
    );
    assert!(
        matches!(client_result, Err(TransportError::NotTrusted)),
        "the client must be told it is not trusted, got {client_result:?}"
    );
}

#[tokio::test]
async fn revoking_a_device_blocks_its_next_connection_immediately() {
    // The property Phase 3 was required not to break.
    let harness = Harness::new();
    let directory = Directory::trusting(&harness.client, Role::Owner);

    let (first, _) = harness.connect(&directory).await;
    first.expect("the device connects while trusted");

    directory.revoke_all();

    let (second, client_result) = harness.connect(&directory).await;
    assert!(
        matches!(
            second,
            Err(TransportError::Revoked | TransportError::NotTrusted)
        ),
        "a revoked device must be refused on its next connection, got {second:?}"
    );
    assert!(client_result.is_err());
}

#[tokio::test]
async fn a_revoked_client_learns_nothing_that_an_unknown_one_does_not() {
    // The peer-visible outcome must be identical, so the port cannot be used to
    // enumerate which devices an agent knows.
    let harness = Harness::new();

    let revoked = Directory::trusting(&harness.client, Role::Owner);
    revoked.revoke_all();
    let (_, revoked_client) = harness.connect(&revoked).await;

    let unknown = Directory::default();
    let (_, unknown_client) = harness.connect(&unknown).await;

    let revoked_message = revoked_client.unwrap_err().to_string();
    let unknown_message = unknown_client.unwrap_err().to_string();

    assert_eq!(
        revoked_message, unknown_message,
        "revoked and unknown must be indistinguishable to the peer"
    );
}

#[tokio::test]
async fn a_client_cannot_be_admitted_under_another_devices_id() {
    // The client presents its own certificate but claims a different device id. The
    // lookup is by observed fingerprint, so the claim must not carry it through.
    let harness = Harness::new();
    let impostor_target = identity("someone-else");

    let directory = Directory::default();
    directory.records.lock().unwrap().insert(
        harness.client.public().certificate_fingerprint.to_hex(),
        TrustRecord {
            // The stored record names a different device than the client will claim.
            device_id: impostor_target.device_id(),
            display_name: "Real Device".to_owned(),
            role: Role::Owner,
            revoked: false,
            certificate_fingerprint: harness.client.public().certificate_fingerprint,
        },
    );

    let (agent_result, _) = harness.connect(&directory).await;
    assert!(
        agent_result.is_err(),
        "a mismatched device-id claim must be refused, got {agent_result:?}"
    );
}

#[tokio::test]
async fn the_agent_refuses_a_peer_claiming_to_be_an_agent() {
    // Only clients connect inward. A peer announcing PeerRole::Agent is not something
    // to accommodate, and the check exists so a future agent-to-agent path has to be
    // added deliberately rather than by accident.
    let harness = Harness::new();
    let directory = Directory::trusting(&harness.client, Role::Owner);

    let (listener, _endpoint_observed) = AgentListener::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &harness.agent,
        PinPolicy::TrustOnFirstUse,
    )
    .unwrap();
    let address = listener.local_address().unwrap();
    let agent_descriptor = descriptor(&harness.agent, "Agent");

    let agent_side = async {
        let connection = listener.accept().await.unwrap()?;
        let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await?;
        let observed = rc_transport::peer_certificate_fingerprint(&connection).unwrap();

        handshake::accept_handshake(
            &mut reader,
            &mut writer,
            &directory,
            observed,
            agent_descriptor,
            capabilities(),
            0,
        )
        .await
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
    let directory = Directory::trusting(&harness.client, Role::Owner);

    let (listener, _endpoint_observed) = AgentListener::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &harness.agent,
        PinPolicy::TrustOnFirstUse,
    )
    .unwrap();
    let address = listener.local_address().unwrap();
    let agent_descriptor = descriptor(&harness.agent, "Agent");

    let agent_side = async {
        let connection = listener.accept().await.unwrap()?;
        let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await?;
        let observed = rc_transport::peer_certificate_fingerprint(&connection).unwrap();

        handshake::accept_handshake(
            &mut reader,
            &mut writer,
            &directory,
            observed,
            agent_descriptor,
            capabilities(),
            0,
        )
        .await
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
