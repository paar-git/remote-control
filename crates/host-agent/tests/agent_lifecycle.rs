//! Two-process integration tests against a real `rc-agent`.
//!
//! These spawn the actual agent binary — its own process, its own database, its own
//! keystore — and drive a real client against it over QUIC. Nothing is stubbed.
//!
//! # What is provable in this build
//!
//! Completing TLS still admits nothing. These tests hold the properties that do not
//! depend on a grant: the agent starts and reports itself healthy, it keeps its
//! device identity across a restart, and a client that only completes TLS is refused
//! rather than admitted. Session-level behaviour — admission, ping, metrics, file
//! transfer — is covered in `access_e2e.rs`.
//!
//! # Why the agent is spawned rather than called
//!
//! A test that called the agent's own functions in-process would prove that they
//! compose, not that two processes can actually reach each other — which is the only
//! question worth asking here.

// Integration tests assert against known-good values, so `unwrap` and `panic` are the
// clearest way to fail. The workspace denies them in library code, where a panic would
// take down an agent; here a panic *is* the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rc_protocol::control::{DeviceDescriptor, OsFamily};
use rc_security::{DeviceIdentity, SystemClock};
use rc_transport::{ClientConnector, PeerAddress, PinPolicy};

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
    quic_port: u16,
    local_port: u16,
}

impl RunningAgent {
    /// Start an agent on free ports under a temporary root.
    async fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let quic_port = free_udp_port();
        let local_port = free_tcp_port();

        let config = format!(
            "device_name = \"integration-agent\"\n\
             \n\
             [network]\n\
             listen_address = \"127.0.0.1\"\n\
             listen_port = {quic_port}\n\
             health_port = {local_port}\n\
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

/// What `rc-agent identity` prints for the installation under `root`.
fn reported_device_id(root: &Path, config_path: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_rc-agent"))
        .arg("--root")
        .arg(root)
        .arg("--config")
        .arg(config_path)
        .arg("identity")
        .output()
        .expect("the agent binary must report its identity");

    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| line.strip_prefix("Device ID:"))
        .map(|value| value.trim().to_owned())
        .expect("the identity output must name a device id")
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
async fn a_client_that_completes_tls_is_not_given_a_session() {
    // The agent listens, TLS admits the peer, and admission still refuses: this
    // fixture has incoming access switched off, so completing TLS is not enough.
    // If this test ever sees a session, the agent is admitting peers it never
    // authorised.
    let agent = RunningAgent::start().await;
    let identity = client_identity("hopeful");

    let (connector, _) = ClientConnector::new(&identity, PinPolicy::TrustOnFirstUse).unwrap();
    let connection = connector.connect(agent.address()).await.unwrap();

    let (mut writer, mut reader) =
        rc_transport::open_channel(&connection, rc_protocol::Channel::Control)
            .await
            .unwrap();

    let result = rc_transport::handshake::begin_handshake(
        &mut reader,
        &mut writer,
        descriptor(&identity),
        rc_protocol::control::Capabilities::default(),
        agent.address().to_string().parse::<PeerAddress>().unwrap(),
        None,
        rc_protocol::now_ms(),
    )
    .await;

    assert!(
        result.is_err(),
        "a client that only completes TLS must not be given a session, got {result:?}"
    );

    // And the agent must not be holding a session open for it.
    let health = agent.get("/health").await.unwrap();
    assert!(
        health.contains("\"active_sessions\":0"),
        "a refused peer must not leave a live session, got: {health}"
    );

    connection.close(0u32.into(), b"refused");
}

#[tokio::test]
async fn an_agent_keeps_its_identity_across_a_restart() {
    // A restart that changed the agent's identity would make every client that pinned
    // it refuse to connect. This is the property the keystore exists to hold.
    let agent = RunningAgent::start().await;

    let quic_port = agent.quic_port;
    let local_port = agent.local_port;

    // Stop the agent, keeping its data directory.
    let root = agent.stop_keeping_data();
    let config_path = root.join("config").join("agent.toml");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let before = reported_device_id(&root, &config_path);

    let restarted = restart_at(&root, &config_path, quic_port, local_port).await;
    let health = restarted.get("/health").await.expect("health must answer");
    assert!(health.contains("\"status\":\"ok\""), "got: {health}");
    drop(restarted);

    let after = reported_device_id(&root, &config_path);
    assert_eq!(
        before, after,
        "the device identity must survive a restart unchanged"
    );
    assert!(before.starts_with("dev_"), "got: {before}");
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
        quic_port,
        local_port,
    };
    agent.wait_until_healthy().await;
    agent
}
