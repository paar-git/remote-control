//! End-to-end pairing over two real QUIC endpoints.
//!
//! These drive the complete four-message exchange across loopback: trust-on-first-use
//! TLS, the request, the challenge, the proof and the confirmation, with the
//! certificate fingerprints taken from the live connections on both sides.
//!
//! Nothing is stubbed but the recorder, which is a trait so the ordering guarantee —
//! trust is persisted *before* the client is told it is paired — can be tested by
//! making persistence fail.

// Integration tests assert against known-good values, so `unwrap` and `panic` are the
// clearest way to fail. The workspace denies them in library code, where a panic would
// take down an agent; here a panic *is* the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use rc_protocol::control::{DeviceDescriptor, Opening, OsFamily};
use rc_protocol::pairing::{PairRequest, PairingMessage};
use rc_security::pairing::{
    PairingCode, PairingManager, PairingOutcome, PairingPolicy, RequestedPermissions,
};
use rc_security::permissions::{Capability, Role};
use rc_security::{DeviceIdentity, OsRandom, SystemClock};
use rc_transport::endpoint::{AgentListener, ClientConnector};
use rc_transport::{PairingRecorder, PinPolicy, TransportError};

/// Captures what the agent persisted, and can be made to fail.
#[derive(Debug, Default)]
struct Recorder {
    recorded: Mutex<Vec<String>>,
    fail: bool,
}

impl Recorder {
    fn failing() -> Self {
        Self {
            recorded: Mutex::new(Vec::new()),
            fail: true,
        }
    }

    fn device_ids(&self) -> Vec<String> {
        self.recorded.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl PairingRecorder for Recorder {
    async fn record(&self, outcome: &PairingOutcome) -> Result<(), String> {
        if self.fail {
            return Err("the trust store is unavailable".to_owned());
        }
        self.recorded
            .lock()
            .unwrap()
            .push(outcome.client_device_id.to_canonical_string());
        Ok(())
    }
}

fn identity(name: &str) -> DeviceIdentity {
    DeviceIdentity::generate(name, &SystemClock).unwrap()
}

fn descriptor(identity: &DeviceIdentity, name: &str) -> DeviceDescriptor {
    let public = identity.public();
    DeviceDescriptor {
        device_id: public.device_id,
        display_name: name.to_owned(),
        hostname: "test-host".to_owned(),
        os_family: OsFamily::Linux,
        os_version: "test".to_owned(),
        app_version: "0.1.0".to_owned(),
        certificate_fingerprint: public.certificate_fingerprint.to_hex(),
    }
}

/// One agent, one client, and a pairing window that is open unless told otherwise.
struct Harness {
    agent: DeviceIdentity,
    client: DeviceIdentity,
    manager: PairingManager,
}

impl Harness {
    fn new() -> Self {
        Self {
            agent: identity("agent"),
            client: identity("client"),
            manager: PairingManager::new(PairingPolicy::default()),
        }
    }

    /// Open a window and return the code the operator would read off the console.
    fn open_window(&self) -> PairingCode {
        self.manager
            .begin_pairing(&SystemClock, &OsRandom)
            .unwrap()
            .code
    }

    /// Run one complete attempt with `code`, returning both sides' outcomes.
    async fn attempt(
        &self,
        code: &PairingCode,
        requested: RequestedPermissions,
        recorder: &Recorder,
    ) -> (
        rc_transport::Result<PairingOutcome>,
        rc_transport::Result<rc_security::pairing::PairedAgent>,
    ) {
        let (listener, _) = AgentListener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &self.agent,
            // No pin exists yet. This is the one configuration in which that is right.
            PinPolicy::TrustOnFirstUse,
        )
        .unwrap();
        let address = listener.local_address().unwrap();
        let agent_descriptor = descriptor(&self.agent, "Agent");

        let agent_side = async {
            let connection = listener.accept().await.unwrap()?;
            let observed = rc_transport::peer_certificate_fingerprint(&connection)?;
            let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await?;

            let opening = rc_transport::handshake::read_opening(&mut reader).await?;
            let request = match opening {
                Opening::Pairing(message) => match *message {
                    PairingMessage::Request(request) => request,
                    _ => panic!("the client must open with a pairing request"),
                },
                Opening::Hello(_) | _ => panic!("the client must open with pairing"),
            };

            let outcome = rc_transport::PairingService {
                manager: &self.manager,
                identity: &self.agent,
                descriptor: agent_descriptor,
                clock: &SystemClock,
                recorder,
            }
            .serve(&mut reader, &mut writer, &request, observed)
            .await;

            // Hold the connection until the client has read the reply.
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            drop(connection);
            outcome
        };

        let client_side = async {
            let (connector, _) = ClientConnector::new(&self.client, PinPolicy::TrustOnFirstUse)?;
            let connection = connector.connect(address).await?;

            let paired = rc_transport::pair_as_client(
                &connection,
                &self.client,
                descriptor(&self.client, "Client"),
                code,
                requested,
                None,
            )
            .await;

            std::mem::forget(connector);
            paired
        };

        tokio::join!(agent_side, client_side)
    }
}

#[tokio::test]
async fn a_correct_code_pairs_both_sides() {
    let harness = Harness::new();
    let code = harness.open_window();
    let recorder = Recorder::default();

    let (agent_result, client_result) = harness
        .attempt(&code, RequestedPermissions::full(Role::Owner), &recorder)
        .await;

    let outcome = agent_result.expect("the agent completes the exchange");
    let paired = client_result.expect("the client completes the exchange");

    // Each side ends up holding the other's real identity.
    assert_eq!(outcome.client_device_id, harness.client.device_id());
    assert_eq!(paired.device_id, harness.agent.device_id());
    assert_eq!(
        paired.identity_fingerprint,
        harness.agent.public().identity_fingerprint,
        "the client must pin the agent's identity fingerprint"
    );
    assert_eq!(
        outcome.client_identity_fingerprint,
        harness.client.public().identity_fingerprint
    );

    // Both computed the same transcript, which is what the proofs are over.
    assert_eq!(outcome.transcript_digest, paired.transcript_digest);

    // Trust was persisted, and persisted before the client was told.
    assert_eq!(
        recorder.device_ids(),
        vec![harness.client.device_id().to_canonical_string()]
    );
}

#[tokio::test]
async fn a_wrong_code_pairs_nothing() {
    let harness = Harness::new();
    let _real_code = harness.open_window();
    let wrong = PairingCode::generate(&OsRandom);
    let recorder = Recorder::default();

    let (agent_result, client_result) = harness
        .attempt(&wrong, RequestedPermissions::full(Role::Owner), &recorder)
        .await;

    assert!(agent_result.is_err(), "a wrong code must not pair");
    assert!(client_result.is_err(), "the client must be told it failed");
    assert!(
        recorder.device_ids().is_empty(),
        "a rejected proof must not record trust"
    );
}

#[tokio::test]
async fn the_client_learns_only_that_it_was_refused() {
    // The message must not distinguish a wrong code from a wrong transcript, or the
    // agent becomes an oracle for guessing codes.
    let harness = Harness::new();
    let _code = harness.open_window();
    let recorder = Recorder::default();

    let (_, first) = harness
        .attempt(
            &PairingCode::generate(&OsRandom),
            RequestedPermissions::full(Role::Owner),
            &recorder,
        )
        .await;

    let harness2 = Harness::new();
    let _code2 = harness2.open_window();
    let (_, second) = harness2
        .attempt(
            &PairingCode::generate(&OsRandom),
            RequestedPermissions::full(Role::Owner),
            &recorder,
        )
        .await;

    assert_eq!(
        first.unwrap_err().to_string(),
        second.unwrap_err().to_string()
    );
}

#[tokio::test]
async fn pairing_with_no_window_open_is_refused() {
    let harness = Harness::new();
    // Deliberately no `open_window`.
    let recorder = Recorder::default();

    let (agent_result, client_result) = harness
        .attempt(
            &PairingCode::generate(&OsRandom),
            RequestedPermissions::full(Role::Owner),
            &recorder,
        )
        .await;

    assert!(
        matches!(agent_result, Err(TransportError::PairingClosed)),
        "got {agent_result:?}"
    );
    let message = client_result.unwrap_err().to_string();
    assert!(
        message.contains("pairing mode"),
        "the operator needs to be told what to do, got: {message}"
    );
}

#[tokio::test]
async fn a_code_pairs_exactly_once() {
    let harness = Harness::new();
    let code = harness.open_window();
    let recorder = Recorder::default();

    harness
        .attempt(&code, RequestedPermissions::full(Role::Owner), &recorder)
        .await
        .0
        .expect("the first attempt succeeds");

    let (agent_result, client_result) = harness
        .attempt(&code, RequestedPermissions::full(Role::Owner), &recorder)
        .await;

    assert!(
        agent_result.is_err(),
        "a consumed code must not pair a second time"
    );
    assert!(client_result.is_err());
    assert_eq!(
        recorder.device_ids().len(),
        1,
        "replay must not add a second trust record"
    );
}

#[tokio::test]
async fn a_client_is_not_told_it_paired_when_the_agent_could_not_record_it() {
    // The ordering guarantee. If the confirmation went out first, a storage failure
    // would leave the client believing in a pairing the agent has no record of.
    let harness = Harness::new();
    let code = harness.open_window();
    let recorder = Recorder::failing();

    let (agent_result, client_result) = harness
        .attempt(&code, RequestedPermissions::full(Role::Owner), &recorder)
        .await;

    assert!(agent_result.is_err(), "recording failed, so pairing failed");
    assert!(
        client_result.is_err(),
        "the client must not believe it is paired"
    );
    assert!(recorder.device_ids().is_empty());
}

#[tokio::test]
async fn a_narrower_role_is_carried_through_to_both_sides() {
    let harness = Harness::new();
    let code = harness.open_window();
    let recorder = Recorder::default();

    let requested = RequestedPermissions {
        role: Role::ViewOnly,
        capabilities: vec![Capability::RemoteDesktopView],
    };

    let (agent_result, client_result) = harness.attempt(&code, requested, &recorder).await;

    let outcome = agent_result.unwrap();
    let paired = client_result.unwrap();

    assert_eq!(outcome.granted_permissions.role, Role::ViewOnly);
    assert_eq!(paired.granted_permissions.role, Role::ViewOnly);
    assert_eq!(
        paired.granted_permissions.capabilities,
        vec![Capability::RemoteDesktopView],
        "the client must record what it was granted, not what a role implies"
    );
}

#[tokio::test]
async fn a_request_claiming_another_devices_id_is_refused() {
    // The device id must be derived from the presented key. Sending a mismatched pair
    // is the attack this rejects.
    let harness = Harness::new();
    let _code = harness.open_window();
    let impostor_target = identity("someone-else");

    let (listener, _) = AgentListener::bind(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        &harness.agent,
        PinPolicy::TrustOnFirstUse,
    )
    .unwrap();
    let address = listener.local_address().unwrap();
    let agent_descriptor = descriptor(&harness.agent, "Agent");
    let recorder = Recorder::default();

    let agent_side = async {
        let connection = listener.accept().await.unwrap().unwrap();
        let observed = rc_transport::peer_certificate_fingerprint(&connection).unwrap();
        let (mut writer, mut reader) = rc_transport::accept_channel(&connection).await.unwrap();

        let request = match rc_transport::handshake::read_opening(&mut reader)
            .await
            .unwrap()
        {
            Opening::Pairing(message) => match *message {
                PairingMessage::Request(request) => request,
                _ => panic!("expected a request"),
            },
            _ => panic!("expected pairing"),
        };

        let outcome = rc_transport::PairingService {
            manager: &harness.manager,
            identity: &harness.agent,
            descriptor: agent_descriptor,
            clock: &SystemClock,
            recorder: &recorder,
        }
        .serve(&mut reader, &mut writer, &request, observed)
        .await;
        drop(connection);
        outcome
    };

    let client_side = async {
        let (connector, _) =
            ClientConnector::new(&harness.client, PinPolicy::TrustOnFirstUse).unwrap();
        let connection = connector.connect(address).await.unwrap();
        let (mut writer, _reader) =
            rc_transport::open_channel(&connection, rc_protocol::Channel::Control)
                .await
                .unwrap();

        // A well-formed request whose descriptor names a device the key does not derive.
        let mut request = PairRequest {
            pairing_session_id: None,
            descriptor: descriptor(&harness.client, "Client"),
            identity_public_key: harness.client.public().identity_public_key,
            client_nonce: [1u8; 32],
            protocol_version: rc_protocol::CURRENT_VERSION,
            requested_permissions: RequestedPermissions::full(Role::Owner).to_wire(),
        };
        request.descriptor.device_id = impostor_target.device_id();

        writer
            .send(&Opening::Pairing(Box::new(PairingMessage::Request(
                Box::new(request),
            ))))
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        std::mem::forget(connector);
    };

    let (agent_result, ()) = tokio::join!(agent_side, client_side);

    assert!(
        agent_result.is_err(),
        "a claim the key does not support must be refused, got {agent_result:?}"
    );
    assert!(recorder.device_ids().is_empty());
}
