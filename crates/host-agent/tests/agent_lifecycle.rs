//! Two-process integration tests against a real `rc-agent`.
//!
//! These spawn the actual agent binary — its own process, its own database, its own
//! keystore — and drive a real client against it over QUIC. Nothing is stubbed.
//!
//! What they are here to prove is the sequence the product specification calls the
//! definition of done for this phase: the agent starts, a client pairs with it, the
//! server stays saved, the client connects, disconnects, and reconnects, and a client
//! that was never paired is refused.
//!
//! # Why the agent is spawned rather than called
//!
//! Pairing windows live in the agent process's memory. A test that called the pairing
//! code in-process would prove that the functions compose, not that two processes can
//! actually reach each other — which is the only question worth asking here.

// Integration tests assert against known-good values, so `unwrap` and `panic` are the
// clearest way to fail. The workspace denies them in library code, where a panic would
// take down an agent; here a panic *is* the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rc_protocol::control::{ControlRequestPayload, ControlResult, DeviceDescriptor, OsFamily};
use rc_security::pairing::RequestedPermissions;
use rc_security::permissions::Role;
use rc_security::{DeviceIdentity, PairingCode, SystemClock};
use rc_transport::{ClientConnector, PinPolicy};

/// A running agent, torn down when the handle is dropped.
struct RunningAgent {
    child: Child,
    /// The temporary root, removed on drop.
    ///
    /// An `Option` so the restart test can stop the process while *keeping* the data
    /// directory: an agent that lost its keystore on restart would trivially pass a
    /// test that deleted it.
    root: Option<tempfile::TempDir>,
    root_path: PathBuf,
    data_dir: PathBuf,
    quic_port: u16,
    local_port: u16,
}

impl RunningAgent {
    /// Start an agent on free ports under a temporary root.
    async fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let quic_port = free_udp_port();
        let local_port = free_tcp_port();

        // Discovery is off: the tests dial a known address, and a responder joining a
        // multicast group is exactly the kind of thing a build agent forbids.
        let config = format!(
            "device_name = \"integration-agent\"\n\
             \n\
             [network]\n\
             listen_address = \"127.0.0.1\"\n\
             listen_port = {quic_port}\n\
             health_port = {local_port}\n\
             discovery_enabled = false\n\
             remote_access_enabled = false\n"
        );

        let config_dir = root.path().join("config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("agent.toml");
        std::fs::write(&config_path, config).unwrap();

        let child = Command::new(env!("CARGO_BIN_EXE_rc-agent"))
            .arg("--root")
            .arg(root.path())
            .arg("--config")
            .arg(&config_path)
            .arg("run")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("the agent binary must start");

        let agent = Self {
            child,
            data_dir: root.path().join("data"),
            root_path: root.path().to_path_buf(),
            root: Some(root),
            quic_port,
            local_port,
        };

        agent.wait_until_healthy().await;
        agent
    }

    /// Block until the agent reports itself healthy, or fail the test.
    ///
    /// The budget is generous because these tests run in parallel and each one spawns a
    /// real agent process: on a loaded machine, startup competes with a dozen siblings
    /// for CPU. A tight deadline here would make the suite fail for reasons that have
    /// nothing to do with the code under test.
    async fn wait_until_healthy(&self) {
        const ATTEMPTS: u32 = 600;
        const INTERVAL_MS: u64 = 100;

        for _ in 0..ATTEMPTS {
            if let Some(body) = self.get("/health").await
                && body.contains("\"status\":\"ok\"")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(INTERVAL_MS)).await;
        }

        panic!(
            "the agent did not become healthy within {} seconds",
            u64::from(ATTEMPTS) * INTERVAL_MS / 1000
        );
    }

    /// The address a client dials.
    fn address(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.quic_port))
    }

    /// Ask the running agent to open a pairing window, and return the code.
    async fn open_pairing_window(&self) -> PairingCode {
        let token = std::fs::read_to_string(self.data_dir.join("local-control.token"))
            .expect("the agent must publish a local control token");

        let body = "{\"ttl_secs\":300}";
        let request = format!(
            "POST /pairing HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             x-rc-local-token: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len(),
            token.trim(),
        );

        let response = self
            .send(&request)
            .await
            .expect("the local endpoint must answer");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "opening a window must succeed, got: {response}"
        );

        let payload = response.split_once("\r\n\r\n").unwrap().1;
        let parsed: serde_json::Value = serde_json::from_str(payload.trim()).unwrap();
        let code = parsed["code"].as_str().unwrap();

        PairingCode::parse(code).expect("the agent must issue a well-formed code")
    }

    /// A `GET` against the local endpoint.
    async fn get(&self, path: &str) -> Option<String> {
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
        self.send(&request).await
    }

    /// Send a raw HTTP request to the local endpoint.
    async fn send(&self, request: &str) -> Option<String> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, self.local_port))
            .await
            .ok()?;
        stream.write_all(request.as_bytes()).await.ok()?;
        stream.flush().await.ok()?;

        let mut raw = Vec::new();
        stream.take(64 * 1024).read_to_end(&mut raw).await.ok()?;
        Some(String::from_utf8_lossy(&raw).into_owned())
    }
}

impl Drop for RunningAgent {
    fn drop(&mut self) {
        // The temporary directory cannot be removed while the process still holds its
        // database open, so the child is killed and reaped before the root is dropped.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl RunningAgent {
    /// Stop the process but keep the data directory, for a restart test.
    fn stop_keeping_data(mut self) -> PathBuf {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Leaked deliberately: dropping it would delete the keystore the restart needs.
        if let Some(root) = self.root.take() {
            std::mem::forget(root);
        }
        self.root_path.clone()
    }
}

/// A free UDP port, released before the agent claims it.
fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket.local_addr().unwrap().port()
}

/// A free TCP port, released before the agent claims it.
fn free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.local_addr().unwrap().port()
}

/// A fresh client identity, as a real installation would have.
fn client_identity(name: &str) -> DeviceIdentity {
    DeviceIdentity::generate(name, &SystemClock).unwrap()
}

fn descriptor(identity: &DeviceIdentity) -> DeviceDescriptor {
    let public = identity.public();
    DeviceDescriptor {
        device_id: public.device_id,
        display_name: "Integration Client".to_owned(),
        hostname: "test-client".to_owned(),
        os_family: OsFamily::Linux,
        os_version: "test".to_owned(),
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        certificate_fingerprint: public.certificate_fingerprint.to_hex(),
    }
}

/// Pair a client with the running agent, returning what the client should pin.
async fn pair(
    agent: &RunningAgent,
    identity: &DeviceIdentity,
) -> rc_security::pairing::PairedAgent {
    let code = agent.open_pairing_window().await;

    let (connector, _) = ClientConnector::new(identity, PinPolicy::TrustOnFirstUse).unwrap();
    let connection = connector.connect(agent.address()).await.unwrap();

    let paired = rc_transport::pair_as_client(
        &connection,
        identity,
        descriptor(identity),
        &code,
        RequestedPermissions::full(Role::Owner),
        None,
    )
    .await
    .expect("pairing with a live agent must succeed");

    connection.close(0u32.into(), b"paired");
    paired
}

/// Open an authenticated session against the agent.
/// The control streams are returned alongside the connection because dropping them
/// ends the session: the agent treats the control channel closing as the session
/// ending, which is correct — it is the channel the session is defined by — and a test
/// that let them fall out of scope would tear down the very connection it was about to
/// use.
async fn connect(
    agent: &RunningAgent,
    identity: &DeviceIdentity,
    paired: &rc_security::pairing::PairedAgent,
) -> rc_transport::Result<(
    quinn::Connection,
    rc_protocol::control::HelloAck,
    rc_transport::ChannelWriter,
    rc_transport::ChannelReader,
)> {
    let (connector, _) =
        ClientConnector::new(identity, PinPolicy::Pinned(paired.certificate_fingerprint))?;
    let connection = connector.connect(agent.address()).await?;

    let (mut writer, mut reader) =
        rc_transport::open_channel(&connection, rc_protocol::Channel::Control).await?;

    let ack = rc_transport::handshake::begin_handshake(
        &mut reader,
        &mut writer,
        descriptor(identity),
        rc_protocol::control::Capabilities::default(),
        rc_protocol::now_ms(),
    )
    .await?;

    // The connector owns the socket the connection runs on.
    std::mem::forget(connector);
    Ok((connection, ack, writer, reader))
}

#[tokio::test]
async fn an_agent_starts_and_reports_itself_healthy() {
    let agent = RunningAgent::start().await;

    let body = agent.get("/health").await.expect("health must answer");
    assert!(body.starts_with("HTTP/1.1 200"), "got: {body}");
    assert!(body.contains("\"listener_ready\":true"), "got: {body}");
    assert!(body.contains("\"database_ready\":true"), "got: {body}");
}

#[tokio::test]
async fn a_client_pairs_connects_disconnects_and_reconnects() {
    // The whole Phase 3 sequence, across two processes.
    let agent = RunningAgent::start().await;
    let identity = client_identity("client");

    let paired = pair(&agent, &identity).await;

    // Connect.
    let (first, ack, first_writer, first_reader) = connect(&agent, &identity, &paired)
        .await
        .expect("a paired client must be admitted");
    assert!(ack.already_paired);
    assert_eq!(ack.descriptor.device_id, paired.device_id);

    // The agent counts it as a live session.
    let health = agent.get("/health").await.unwrap();
    assert!(
        health.contains("\"active_sessions\":1"),
        "the agent must see one session, got: {health}"
    );

    // Disconnect.
    drop(first_writer);
    drop(first_reader);
    first.close(0u32.into(), b"done");
    drop(first);

    // Reconnect, with no code and no further operator action. This is the property the
    // saved server exists for.
    let (second, second_ack, _second_writer, _second_reader) = connect(&agent, &identity, &paired)
        .await
        .expect("reconnecting must not need the code again");
    assert!(second_ack.already_paired);
    assert_ne!(
        second_ack.session_id, ack.session_id,
        "each connection is its own session"
    );

    second.close(0u32.into(), b"done");
}

#[tokio::test]
async fn an_unpaired_client_is_refused() {
    let agent = RunningAgent::start().await;

    // Pair one client so the agent has a trusted device that is *not* this one.
    let paired_identity = client_identity("paired-client");
    let paired = pair(&agent, &paired_identity).await;

    // A different client, pinning the agent correctly but never having paired.
    let stranger = client_identity("stranger");
    let result = connect(&agent, &stranger, &paired).await;

    assert!(
        result.is_err(),
        "a client the agent has never trusted must be refused, got a session"
    );
}

#[tokio::test]
async fn a_pairing_window_is_used_once() {
    let agent = RunningAgent::start().await;

    let code = agent.open_pairing_window().await;
    let first = client_identity("first");
    let second = client_identity("second");

    // The first client consumes the window.
    let (connector, _) = ClientConnector::new(&first, PinPolicy::TrustOnFirstUse).unwrap();
    let connection = connector.connect(agent.address()).await.unwrap();
    rc_transport::pair_as_client(
        &connection,
        &first,
        descriptor(&first),
        &code,
        RequestedPermissions::full(Role::Owner),
        None,
    )
    .await
    .expect("the first pairing succeeds");
    connection.close(0u32.into(), b"paired");

    // The same code cannot pair a second device.
    let (connector, _) = ClientConnector::new(&second, PinPolicy::TrustOnFirstUse).unwrap();
    let connection = connector.connect(agent.address()).await.unwrap();
    let replay = rc_transport::pair_as_client(
        &connection,
        &second,
        descriptor(&second),
        &code,
        RequestedPermissions::full(Role::Owner),
        None,
    )
    .await;

    assert!(replay.is_err(), "a consumed code must not pair again");
}

#[tokio::test]
async fn pairing_is_refused_when_no_window_is_open() {
    // The agent is listening, but the operator has not started pairing.
    let agent = RunningAgent::start().await;
    let identity = client_identity("hopeful");

    let (connector, _) = ClientConnector::new(&identity, PinPolicy::TrustOnFirstUse).unwrap();
    let connection = connector.connect(agent.address()).await.unwrap();

    let result = rc_transport::pair_as_client(
        &connection,
        &identity,
        descriptor(&identity),
        &PairingCode::generate(&rc_security::OsRandom),
        RequestedPermissions::full(Role::Owner),
        None,
    )
    .await;

    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("pairing mode"),
        "the operator must be told what to do, got: {message}"
    );
}

#[tokio::test]
async fn a_local_pairing_request_without_the_token_is_refused() {
    // The token is the whole access-control decision for creating trust.
    let agent = RunningAgent::start().await;

    let body = "{\"ttl_secs\":300}";
    let request = format!(
        "POST /pairing HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );

    let response = agent.send(&request).await.unwrap();
    assert!(
        response.starts_with("HTTP/1.1 401"),
        "an untokened request must be refused, got: {response}"
    );
}

#[tokio::test]
async fn the_agent_answers_a_ping_on_the_session_stream() {
    let agent = RunningAgent::start().await;
    let identity = client_identity("client");
    let paired = pair(&agent, &identity).await;

    let (connector, _) =
        ClientConnector::new(&identity, PinPolicy::Pinned(paired.certificate_fingerprint)).unwrap();
    let connection = connector.connect(agent.address()).await.unwrap();

    let (mut writer, mut reader) =
        rc_transport::open_channel(&connection, rc_protocol::Channel::Control)
            .await
            .unwrap();

    let ack = rc_transport::handshake::begin_handshake(
        &mut reader,
        &mut writer,
        descriptor(&identity),
        rc_protocol::control::Capabilities::default(),
        rc_protocol::now_ms(),
    )
    .await
    .unwrap();

    let request_id = rc_protocol::RequestId::generate();
    writer
        .send(&rc_protocol::control::ControlRequest {
            request_id,
            session_id: ack.session_id,
            sent_at_ms: rc_protocol::now_ms(),
            nonce: [1u8; 16],
            payload: ControlRequestPayload::Ping { token: 987 },
        })
        .await
        .unwrap();

    let response: rc_protocol::control::ControlResponse =
        reader.next_message().await.unwrap().unwrap();

    assert_eq!(response.request_id, request_id);
    match response.result {
        ControlResult::Ok(rc_protocol::control::ControlResponsePayload::Pong { token, .. }) => {
            assert_eq!(token, 987, "the pong must echo the token it was sent");
        }
        other => panic!("expected a pong, got {other:?}"),
    }

    std::mem::forget(connector);
    connection.close(0u32.into(), b"done");
}

#[tokio::test]
async fn an_agent_keeps_its_identity_across_a_restart() {
    // A restart that changed the agent's identity would break every existing pairing.
    // This is the property the keystore exists to hold.
    let agent = RunningAgent::start().await;
    let identity = client_identity("client");
    let paired = pair(&agent, &identity).await;

    let quic_port = agent.quic_port;
    let local_port = agent.local_port;

    // Stop the agent, keeping its data directory.
    let root = agent.stop_keeping_data();
    let config_path = root.join("config").join("agent.toml");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let restarted = restart_at(&root, &config_path, quic_port, local_port).await;

    // The same pin still works, with no re-pairing.
    let (connection, ack, _writer, _reader) = connect(&restarted, &identity, &paired)
        .await
        .expect("trust must survive an agent restart");
    assert_eq!(ack.descriptor.device_id, paired.device_id);

    connection.close(0u32.into(), b"done");
}

/// Start an agent again over an existing data directory.
async fn restart_at(
    root: &Path,
    config_path: &Path,
    quic_port: u16,
    local_port: u16,
) -> RunningAgent {
    let child = Command::new(env!("CARGO_BIN_EXE_rc-agent"))
        .arg("--root")
        .arg(root)
        .arg("--config")
        .arg(config_path)
        .arg("run")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the agent binary must restart");

    let agent = RunningAgent {
        child,
        root: None,
        root_path: root.to_path_buf(),
        data_dir: root.join("data"),
        quic_port,
        local_port,
    };
    agent.wait_until_healthy().await;
    agent
}

#[tokio::test]
async fn a_session_gets_real_measured_metrics() {
    // The dashboard's figures come from the operating system, not from a placeholder.
    let agent = RunningAgent::start().await;
    let identity = client_identity("client");
    let paired = pair(&agent, &identity).await;

    let (connector, _) =
        ClientConnector::new(&identity, PinPolicy::Pinned(paired.certificate_fingerprint)).unwrap();
    let connection = connector.connect(agent.address()).await.unwrap();

    let (mut writer, mut reader) =
        rc_transport::open_channel(&connection, rc_protocol::Channel::Control)
            .await
            .unwrap();

    let ack = rc_transport::handshake::begin_handshake(
        &mut reader,
        &mut writer,
        descriptor(&identity),
        rc_protocol::control::Capabilities::default(),
        rc_protocol::now_ms(),
    )
    .await
    .unwrap();

    let request_id = rc_protocol::RequestId::generate();
    writer
        .send(&rc_protocol::control::ControlRequest {
            request_id,
            session_id: ack.session_id,
            sent_at_ms: rc_protocol::now_ms(),
            nonce: [2u8; 16],
            payload: ControlRequestPayload::SystemSnapshot,
        })
        .await
        .unwrap();

    let response: rc_protocol::control::ControlResponse =
        reader.next_message().await.unwrap().unwrap();

    match response.result {
        ControlResult::Ok(rc_protocol::control::ControlResponsePayload::Snapshot(snapshot)) => {
            assert!(snapshot.cpu.logical_cores >= 1, "a real host has cores");
            assert!(snapshot.memory.total_bytes > 0, "a real host has memory");
            assert!(
                !snapshot.cpu.model.is_empty(),
                "the processor model must be reported"
            );
            assert!(
                !snapshot.top_processes.is_empty(),
                "a running host has processes"
            );
            assert_eq!(
                snapshot.cpu.per_core_percent.len(),
                snapshot.cpu.logical_cores,
                "one reading per core"
            );
        }
        other => panic!("expected a snapshot, got {other:?}"),
    }

    std::mem::forget(connector);
    connection.close(0u32.into(), b"done");
}

#[tokio::test]
async fn a_session_can_open_a_real_terminal_and_run_a_command() {
    // End to end across two processes: a PTY on the agent, driven from a client, with
    // the command's output coming back over QUIC.
    use rc_protocol::terminal::{
        PrivilegeLevel, ShellKind, TerminalAgentMessage, TerminalClientMessage, TerminalSize,
    };

    let agent = RunningAgent::start().await;
    let identity = client_identity("client");
    let paired = pair(&agent, &identity).await;

    // The control streams are held for the life of the test; dropping them would end
    // the session and take the terminal channel with it.
    let (connection, _ack, _control_writer, _control_reader) =
        connect(&agent, &identity, &paired).await.unwrap();

    let (mut writer, mut reader) =
        rc_transport::open_channel(&connection, rc_protocol::Channel::Terminal)
            .await
            .unwrap();

    let terminal_id = rc_protocol::TerminalId::generate();
    writer
        .send(&TerminalClientMessage::Open {
            terminal_id,
            shell: ShellKind::SystemDefault,
            privilege: PrivilegeLevel::Standard,
            size: TerminalSize { cols: 80, rows: 24 },
            working_directory: None,
        })
        .await
        .unwrap();

    let probe = "rc-integration-probe";
    let mut opened = false;
    let mut typed = false;
    let mut collected = Vec::new();

    let saw_output = tokio::time::timeout(Duration::from_secs(40), async {
        while let Ok(Some(message)) = reader.next_message::<TerminalAgentMessage>().await {
            match message {
                TerminalAgentMessage::Opened { pid, .. } => {
                    assert!(pid > 0, "a real shell has a process id");
                    opened = true;
                }
                TerminalAgentMessage::Output { data, .. } => {
                    // A shell asks the terminal where its cursor is before drawing a
                    // prompt; a client that never answers leaves it waiting forever.
                    if data.windows(4).any(|w| w == b"\x1b[6n") {
                        writer
                            .send(&TerminalClientMessage::Input {
                                terminal_id,
                                data: b"\x1b[1;1R".to_vec(),
                            })
                            .await
                            .unwrap();
                    }

                    collected.extend_from_slice(&data);
                    let text = String::from_utf8_lossy(&collected);

                    if opened && !typed && collected.len() > 8 {
                        typed = true;
                        let command: &[u8] = if cfg!(windows) {
                            b"echo rc-integration-probe\r\n"
                        } else {
                            b"echo rc-integration-probe\n"
                        };
                        writer
                            .send(&TerminalClientMessage::Input {
                                terminal_id,
                                data: command.to_vec(),
                            })
                            .await
                            .unwrap();
                        continue;
                    }

                    // Twice: once echoed as it is typed, once as the command's output.
                    if text.matches(probe).count() >= 2 {
                        return true;
                    }
                }
                TerminalAgentMessage::Error { message, .. } => {
                    panic!("the agent refused the terminal: {message}");
                }
                TerminalAgentMessage::Exited { .. } => return false,
                _ => {}
            }
        }
        false
    })
    .await;

    assert_eq!(
        saw_output,
        Ok(true),
        "a command typed into the remote shell must run and return its output"
    );

    writer
        .send(&TerminalClientMessage::Close { terminal_id })
        .await
        .unwrap();

    connection.close(0u32.into(), b"done");
}

/// Open the file channel on an authenticated connection.
async fn open_file_channel(
    connection: &quinn::Connection,
) -> (rc_transport::ChannelWriter, rc_transport::ChannelReader) {
    rc_transport::open_channel(connection, rc_protocol::Channel::FileTransfer)
        .await
        .expect("the agent must serve the file channel")
}

/// Read the next file message, failing the test if none arrives.
async fn next_file_message(
    reader: &mut rc_transport::ChannelReader,
) -> rc_protocol::files::FileAgentMessage {
    tokio::time::timeout(Duration::from_secs(20), reader.next_message())
        .await
        .expect("the agent must answer within the deadline")
        .expect("the file channel must stay open")
        .expect("the agent must send a message")
}

#[tokio::test]
async fn a_session_can_browse_the_servers_files() {
    use rc_protocol::files::{FileAgentMessage, FileClientMessage};

    let agent = RunningAgent::start().await;
    let identity = client_identity("client");
    let paired = pair(&agent, &identity).await;

    let (connection, _ack, _control_writer, _control_reader) =
        connect(&agent, &identity, &paired).await.unwrap();
    let (mut writer, mut reader) = open_file_channel(&connection).await;

    // A directory the test owns, with known contents.
    let workspace = tempfile::tempdir().unwrap();
    std::fs::write(workspace.path().join("readme.txt"), b"hello").unwrap();
    std::fs::create_dir(workspace.path().join("subdir")).unwrap();

    writer
        .send(&FileClientMessage::List {
            path: workspace.path().to_string_lossy().into_owned(),
            include_hidden: false,
        })
        .await
        .unwrap();

    match next_file_message(&mut reader).await {
        FileAgentMessage::Listing { entries, .. } => {
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains(&"readme.txt"), "got {names:?}");
            assert!(names.contains(&"subdir"), "got {names:?}");
        }
        other => panic!("expected a listing, got {other:?}"),
    }

    connection.close(0u32.into(), b"done");
}

#[tokio::test]
async fn a_file_uploads_and_downloads_with_its_checksum_verified() {
    // The round trip across two processes: bytes go up, come back, and match.
    use rc_protocol::files::{
        Checksum, ChecksumAlgorithm, ConflictPolicy, FileAgentMessage, FileClientMessage,
    };

    let agent = RunningAgent::start().await;
    let identity = client_identity("client");
    let paired = pair(&agent, &identity).await;

    let (connection, _ack, _control_writer, _control_reader) =
        connect(&agent, &identity, &paired).await.unwrap();
    let (mut writer, mut reader) = open_file_channel(&connection).await;

    let workspace = tempfile::tempdir().unwrap();
    let destination = workspace.path().join("uploaded.bin");
    let content: Vec<u8> = (0..5000u32).map(|index| (index % 251) as u8).collect();
    let checksum = Checksum {
        algorithm: ChecksumAlgorithm::Blake3,
        digest: blake3::hash(&content).as_bytes().to_vec(),
    };

    // ---- upload ----
    let transfer_id = rc_protocol::TransferId::generate();
    writer
        .send(&FileClientMessage::UploadBegin {
            transfer_id,
            destination: destination.to_string_lossy().into_owned(),
            total_bytes: content.len() as u64,
            checksum: checksum.clone(),
            conflict: ConflictPolicy::Overwrite,
        })
        .await
        .unwrap();

    match next_file_message(&mut reader).await {
        FileAgentMessage::UploadReady { resume_offset, .. } => {
            assert_eq!(resume_offset, 0, "a fresh upload starts at the beginning");
        }
        other => panic!("expected the agent to be ready, got {other:?}"),
    }

    let mut offset = 0u64;
    for chunk in content.chunks(1024) {
        writer
            .send(&FileClientMessage::UploadChunk {
                transfer_id,
                offset,
                data: chunk.to_vec(),
            })
            .await
            .unwrap();
        offset += chunk.len() as u64;
    }

    writer
        .send(&FileClientMessage::UploadEnd { transfer_id })
        .await
        .unwrap();

    match next_file_message(&mut reader).await {
        FileAgentMessage::TransferComplete {
            bytes_transferred, ..
        } => {
            assert_eq!(bytes_transferred, content.len() as u64);
        }
        other => panic!("expected the upload to complete, got {other:?}"),
    }

    // The file is really on disk, with the right bytes.
    assert_eq!(std::fs::read(&destination).unwrap(), content);

    // ---- download it back ----
    let download_id = rc_protocol::TransferId::generate();
    writer
        .send(&FileClientMessage::DownloadBegin {
            transfer_id: download_id,
            source: destination.to_string_lossy().into_owned(),
            start_offset: 0,
        })
        .await
        .unwrap();

    let mut received = Vec::new();
    let mut announced = None;

    loop {
        match next_file_message(&mut reader).await {
            FileAgentMessage::DownloadBegin {
                total_bytes,
                checksum,
                ..
            } => {
                assert_eq!(total_bytes, content.len() as u64);
                announced = Some(checksum);
            }
            FileAgentMessage::DownloadChunk { offset, data, .. } => {
                assert_eq!(offset, received.len() as u64, "chunks must arrive in order");
                received.extend_from_slice(&data);
            }
            FileAgentMessage::TransferComplete { .. } => break,
            other => panic!("unexpected message during download: {other:?}"),
        }
    }

    assert_eq!(received, content, "the round trip must be byte-exact");
    assert_eq!(
        announced
            .expect("the agent must announce a checksum")
            .digest,
        checksum.digest,
        "the announced digest must match what was uploaded"
    );

    connection.close(0u32.into(), b"done");
}

#[tokio::test]
async fn an_upload_that_fails_its_checksum_is_discarded() {
    // A file that is silently wrong is worse than a transfer that failed.
    use rc_protocol::files::{
        Checksum, ChecksumAlgorithm, ConflictPolicy, FileAgentMessage, FileClientMessage,
    };

    let agent = RunningAgent::start().await;
    let identity = client_identity("client");
    let paired = pair(&agent, &identity).await;

    let (connection, _ack, _control_writer, _control_reader) =
        connect(&agent, &identity, &paired).await.unwrap();
    let (mut writer, mut reader) = open_file_channel(&connection).await;

    let workspace = tempfile::tempdir().unwrap();
    let destination = workspace.path().join("corrupt.bin");
    let transfer_id = rc_protocol::TransferId::generate();

    writer
        .send(&FileClientMessage::UploadBegin {
            transfer_id,
            destination: destination.to_string_lossy().into_owned(),
            total_bytes: 4,
            // A digest of something else entirely.
            checksum: Checksum {
                algorithm: ChecksumAlgorithm::Blake3,
                digest: blake3::hash(b"good").as_bytes().to_vec(),
            },
            conflict: ConflictPolicy::Overwrite,
        })
        .await
        .unwrap();

    assert!(matches!(
        next_file_message(&mut reader).await,
        FileAgentMessage::UploadReady { .. }
    ));

    writer
        .send(&FileClientMessage::UploadChunk {
            transfer_id,
            offset: 0,
            data: b"BAD!".to_vec(),
        })
        .await
        .unwrap();
    writer
        .send(&FileClientMessage::UploadEnd { transfer_id })
        .await
        .unwrap();

    match next_file_message(&mut reader).await {
        FileAgentMessage::TransferFailed { .. } => {}
        other => panic!("a corrupt upload must fail, got {other:?}"),
    }

    assert!(
        !destination.exists(),
        "nothing must be left at the destination"
    );

    connection.close(0u32.into(), b"done");
}

#[tokio::test]
async fn a_path_traversal_is_refused_over_the_wire() {
    // The path checks are library-tested; this proves they are actually reached by a
    // real message on a real connection.
    use rc_protocol::files::{FileAgentMessage, FileClientMessage};

    let agent = RunningAgent::start().await;
    let identity = client_identity("client");
    let paired = pair(&agent, &identity).await;

    let (connection, _ack, _control_writer, _control_reader) =
        connect(&agent, &identity, &paired).await.unwrap();
    let (mut writer, mut reader) = open_file_channel(&connection).await;

    for hostile in ["relative/path", "", "/tmp/CON"] {
        writer
            .send(&FileClientMessage::List {
                path: hostile.to_owned(),
                include_hidden: false,
            })
            .await
            .unwrap();

        match next_file_message(&mut reader).await {
            FileAgentMessage::Error { message, .. } => {
                assert!(
                    !message.contains(hostile) || hostile.is_empty(),
                    "an error must not echo the path it was given: {message}"
                );
            }
            other => panic!("{hostile:?} must be refused, got {other:?}"),
        }
    }

    connection.close(0u32.into(), b"done");
}
