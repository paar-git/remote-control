//! End-to-end connection tests.
//!
//! These drive two real QUIC endpoints over loopback through the complete sequence a
//! production connection follows: mutual TLS with pinned certificates, the control
//! channel, and the application handshake.
//!
//! Nothing is stubbed. The admission *rule* lives in `rc-host-agent` and is not this
//! crate's business, so these tests supply the decision directly and assert that the
//! handshake carries it faithfully in both directions: a granted peer arrives with
//! exactly the permissions that were granted, a refused peer learns only the coarse
//! [`WireRefusal`], and completing TLS by itself decides nothing.

// Integration tests assert against known-good values, so `unwrap` and `panic` are the
// clearest way to fail. The workspace denies them in library code, where a panic would
// take down an agent; here a panic *is* the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use rc_protocol::control::{
    Capabilities, DeviceDescriptor, OsFamily, PeerRole, SessionAuthorization, WireRefusal,
};
use rc_protocol::frame::Channel;
use rc_security::{DeviceIdentity, Permission, PermissionSet, SystemClock};

use rc_transport::endpoint::{AgentListener, ClientConnector};
use rc_transport::handshake;
use rc_transport::{PeerAddress, PinPolicy, TransportError};

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

    /// Run a full connection, refusing the peer, and return what each side concluded.
    async fn connect(
        &self,
    ) -> (
        rc_transport::Result<handshake::AuthenticatedPeer>,
        rc_transport::Result<handshake::AdmittedSession>,
    ) {
        let (agent, client, _) = self
            .connect_deciding(
                handshake::HandshakeAuthorization::Refused(WireRefusal::Rejected),
                None,
            )
            .await;
        (agent, client)
    }

    /// Run a full connection whose admission decision is `decision`, offering
    /// `unattended_password`.
    ///
    /// Also returns what the `authorize` callback was handed, so a test can assert on
    /// the inputs the decision would have been made from. Those inputs are the part no
    /// unit test upstream can check: the dialled address in particular is assembled by
    /// the client and re-parsed by the agent, so only a real exchange proves it survives.
    async fn connect_deciding(
        &self,
        decision: handshake::HandshakeAuthorization,
        unattended_password: Option<String>,
    ) -> (
        rc_transport::Result<handshake::AuthenticatedPeer>,
        rc_transport::Result<handshake::AdmittedSession>,
        Option<SeenByAuthorize>,
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
                Err(err) => return (Err(err), None, None),
            };

            // Read from the connection, not from the endpoint: the endpoint-wide
            // record is shared by every concurrent handshake.
            let observed = rc_transport::peer_certificate_fingerprint(&connection)
                .expect("TLS must have recorded the client certificate");

            let seen = Arc::new(Mutex::new(None));
            let recorder = Arc::clone(&seen);
            // The peer's source port, which is emphatically not the port it dialled.
            let remote_address = connection.remote_address();

            let outcome = async {
                let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await?;
                handshake::accept_handshake(
                    &mut reader,
                    &mut writer,
                    observed,
                    descriptor(&self.agent, "Agent"),
                    capabilities(),
                    0,
                    move |fingerprint, dialed_address, machine_name, password| async move {
                        *recorder.lock().unwrap() = Some(SeenByAuthorize {
                            fingerprint,
                            dialed_address,
                            machine_name,
                            unattended_password: password,
                            listening_on: address,
                            peer_source: remote_address,
                        });
                        decision
                    },
                )
                .await
            }
            .await;

            let seen = seen.lock().unwrap().clone();
            (outcome, seen, Some(connection))
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
                address.to_string().parse::<PeerAddress>().unwrap(),
                unattended_password,
                0,
            )
            .await;

            // Hold the connection open until the agent has finished.
            std::mem::forget(connector);
            ack
        };

        // The agent half yields its connection alongside the result purely to keep the
        // link open; it is dropped here, once both halves have finished.
        let ((agent_outcome, seen, _connection), client_outcome) =
            tokio::join!(agent_side, client_side);
        (agent_outcome, client_outcome, seen)
    }

    /// Every frame a refused peer receives, undecoded.
    ///
    /// Drives the client half by hand rather than through [`handshake::begin_handshake`],
    /// which decodes and discards. What is asserted is what actually crossed the wire.
    async fn frames_a_refused_peer_receives(&self) -> Vec<rc_protocol::frame::Frame> {
        let (listener, _endpoint_observed) = AgentListener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &self.agent,
            PinPolicy::TrustOnFirstUse,
        )
        .unwrap();
        let address = listener.local_address().unwrap();

        let agent_side = async {
            let connection = listener.accept().await.unwrap().unwrap();
            let observed = rc_transport::peer_certificate_fingerprint(&connection).unwrap();
            let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await.unwrap();
            let _ = handshake::accept_handshake(
                &mut reader,
                &mut writer,
                observed,
                descriptor(&self.agent, "Agent"),
                capabilities(),
                0,
                |_fingerprint, _dialed_address, _machine_name, _password| async {
                    handshake::HandshakeAuthorization::Refused(WireRefusal::Rejected)
                },
            )
            .await;
            connection
        };

        let raw_client = async {
            let (connector, _) = ClientConnector::new(&self.client, PinPolicy::TrustOnFirstUse)?;
            let connection = connector.connect(address).await?;
            let (mut writer, mut reader) =
                rc_transport::open_channel(&connection, Channel::Control).await?;

            writer
                .send(&rc_protocol::control::Opening::Hello(Box::new(
                    rc_protocol::control::Hello {
                        version: rc_protocol::CURRENT_VERSION,
                        role: PeerRole::Client,
                        descriptor: descriptor(&self.client, "Client"),
                        capabilities: capabilities(),
                        sent_at_ms: 0,
                    },
                )))
                .await?;

            let ack = reader.next_frame().await?.unwrap();

            writer
                .send(&rc_protocol::control::Authenticate {
                    dialed_address: address.to_string(),
                    unattended_password: None,
                })
                .await?;

            let refusal = reader.next_frame().await?.unwrap();

            std::mem::forget(connector);
            Ok::<_, TransportError>(vec![ack, refusal])
        };

        let (_connection, received) = tokio::join!(agent_side, raw_client);
        received.unwrap()
    }
}

/// What the `authorize` callback was handed for one connection.
#[derive(Debug, Clone)]
struct SeenByAuthorize {
    fingerprint: rc_security::Fingerprint,
    dialed_address: PeerAddress,
    machine_name: String,
    unattended_password: Option<String>,
    /// Where the agent was listening — the address the client actually dialled.
    listening_on: SocketAddr,
    /// The peer's source address on the QUIC connection, whose port is ephemeral.
    peer_source: SocketAddr,
}

#[tokio::test]
async fn a_client_that_completes_tls_is_still_not_admitted() {
    // The property that matters most in this build: finishing mutual TLS gets a peer a
    // control stream and nothing else. If this ever returns `Ok`, the agent is running
    // with no authorisation step at all.
    let harness = Harness::new();

    let (agent_result, client_result) = harness.connect().await;

    assert!(
        matches!(
            agent_result,
            Err(TransportError::SessionRefused {
                reason: WireRefusal::Rejected
            })
        ),
        "completing TLS must not admit a peer, got {agent_result:?}"
    );
    assert!(
        client_result.is_err(),
        "the client must be told it was refused, got {client_result:?}"
    );
}

#[tokio::test]
async fn a_refused_peer_learns_only_the_coarse_reason() {
    // What a refused peer is told about *why* is exactly one `WireRefusal` value. The
    // agent's own finer-grained reason — dismissed, wrong password, locked out — never
    // reaches this side, so the refusal cannot be used as an oracle for whether
    // unattended access is configured.
    let harness = Harness::new();

    let (_, client_result) = harness.connect().await;

    let err = client_result.unwrap_err();
    assert!(
        matches!(
            err,
            TransportError::SessionRefused {
                reason: WireRefusal::Rejected
            }
        ),
        "a refused client sees a coarse refusal, got {err:?}"
    );
}

#[tokio::test]
async fn a_refused_peer_never_learns_what_machine_it_reached() {
    // The acknowledgement is sent before the accept decision, so everything on it is
    // disclosed to anyone who can reach the port and complete TLS — which, under
    // trust-on-first-use, is anyone at all. This asserts against the raw bytes both
    // frames actually put on the wire, rather than against the shape of a struct: a
    // refused peer must not be able to learn the machine's hostname, display name, OS
    // version or application version from what it received.
    let harness = Harness::new();
    let received = harness.frames_a_refused_peer_receives().await;

    for disclosure in ["test-host", "Agent", "0.1.0", "Windows"] {
        assert!(
            !contains(&received, disclosure.as_bytes()),
            "a refused peer received {disclosure:?}; \
             nothing identifying the machine may precede the accept decision"
        );
    }

    // Not vacuous: the exchange really did happen and really did end in a refusal.
    let refusal: SessionAuthorization = received.last().unwrap().decode_body().unwrap();
    assert_eq!(
        refusal,
        SessionAuthorization::Refused {
            reason: WireRefusal::Rejected
        }
    );
}

/// Whether any frame's body contains `needle`.
fn contains(frames: &[rc_protocol::frame::Frame], needle: &[u8]) -> bool {
    frames
        .iter()
        .any(|frame| frame.body.windows(needle.len()).any(|w| w == needle))
}

#[tokio::test]
async fn a_granted_peer_is_admitted_with_exactly_the_permissions_that_were_granted() {
    // The counterpart to every refusal test above, and the reason this task exists: the
    // accept path now has a success branch. `PermissionSet::ALL` would pass even if the
    // set were being replaced wholesale somewhere in the exchange, so this grants a
    // strict subset and asserts it arrives unwidened on *both* sides.
    let granted = PermissionSet::NONE.with(Permission::ViewMetrics);
    let harness = Harness::new();

    let (agent_result, client_result, _) = harness
        .connect_deciding(handshake::HandshakeAuthorization::Granted(granted), None)
        .await;

    let peer = agent_result.expect("a granted peer must be admitted");
    assert_eq!(
        peer.permissions, granted,
        "the agent must run the session against exactly what it granted"
    );
    assert!(
        !peer.permissions.contains(Permission::TransferFiles),
        "a metrics-only grant must not carry file access"
    );
    assert_eq!(
        peer.certificate_fingerprint,
        harness.client.public().certificate_fingerprint,
        "the admitted identity is the one TLS observed, never the one claimed"
    );
    assert_eq!(peer.display_name, "Client");

    let session = client_result.expect("a granted client must be told it was admitted");
    assert_eq!(
        session.permissions, granted,
        "the client must be told the same set the agent is enforcing"
    );
    assert_eq!(
        session.descriptor.display_name, "Agent",
        "the responder's name travels with the grant, for the Recent list"
    );
    assert_eq!(
        session.descriptor.hostname, "test-host",
        "and so does the rest of its identity, which a refused peer never sees"
    );
    assert_eq!(session.session_id, peer.session_id);
}

#[tokio::test]
async fn the_dialled_address_reaches_the_decision_unchanged() {
    // The agent keys pinned identities on the address the *user* dialled, not on the
    // QUIC remote socket address, whose source port is ephemeral. If the two were ever
    // confused, the pin would miss on every reconnect and a peer presenting a changed
    // certificate would fall through to the human dialog instead of being refused.
    // Only a real exchange can catch that: the client assembles this value and the
    // agent re-parses it.
    let harness = Harness::new();

    let (_, _, seen) = harness
        .connect_deciding(
            handshake::HandshakeAuthorization::Granted(PermissionSet::ALL),
            None,
        )
        .await;

    let seen = seen.expect("the decision must have been asked for");
    assert_eq!(
        seen.fingerprint,
        harness.client.public().certificate_fingerprint,
        "the decision is made from the observed fingerprint, never a claim"
    );
    assert_eq!(
        seen.dialed_address.to_string(),
        seen.listening_on.to_string(),
        "the decision must see the address that was dialled"
    );
    assert_ne!(
        seen.dialed_address.port,
        seen.peer_source.port(),
        "the two really are different ports, so this test is not passing by coincidence"
    );
    assert_eq!(seen.machine_name, "Client");
    assert_eq!(
        seen.unattended_password, None,
        "no password was offered, so none must be invented"
    );
}

#[tokio::test]
async fn an_offered_password_reaches_the_decision_and_is_not_read_before_the_ack() {
    // The password rides on `Authenticate`, which is sent only after `HelloAck` — a
    // peer that has not yet seen who it is talking to must not have sent a secret.
    // Reaching the callback at all proves it was carried; the ordering is what the
    // separate frame buys.
    let harness = Harness::new();

    let (_, _, seen) = harness
        .connect_deciding(
            handshake::HandshakeAuthorization::Refused(WireRefusal::Rejected),
            Some("correct horse battery staple".to_owned()),
        )
        .await;

    let seen = seen.expect("the decision must have been asked for");
    assert_eq!(
        seen.unattended_password.as_deref(),
        Some("correct horse battery staple"),
        "the offered password must reach the decision verbatim"
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

        handshake::accept_handshake(
            &mut reader,
            &mut writer,
            observed,
            descriptor(&harness.agent, "Agent"),
            capabilities(),
            0,
            |_fingerprint, _dialed_address, _machine_name, _password| async {
                handshake::HandshakeAuthorization::Granted(PermissionSet::ALL)
            },
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

        handshake::accept_handshake(
            &mut reader,
            &mut writer,
            observed,
            descriptor(&harness.agent, "Agent"),
            capabilities(),
            0,
            |_fingerprint, _dialed_address, _machine_name, _password| async {
                handshake::HandshakeAuthorization::Granted(PermissionSet::ALL)
            },
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
