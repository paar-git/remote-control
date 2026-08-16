//! The video channel end to end, over a real QUIC link.
//!
//! Follows `access_e2e.rs`: a real `rc-agent` process, seeded with an unattended
//! trusted device, dialled by a real client. The point is not that `VideoService`
//! decides correctly in isolation — that has its own unit tests — but that a client
//! opening `Channel::Video` on a live agent actually gets frames back, and that they
//! reconstruct the picture the agent captured.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use rc_protocol::control::{Capabilities, DeviceDescriptor, OsFamily};
use rc_protocol::desktop::{
    DesktopAgentMessage, DesktopClientMessage, InteractionMode, QualityPreset, VideoCodec,
};
use rc_security::{DeviceIdentity, Permission, PermissionSet, SystemClock};
use rc_storage::{Database, TrustRepository};
use rc_transport::{ChannelReader, ChannelWriter, ClientConnector, PinPolicy};

/// A running agent, torn down when the handle is dropped.
struct RunningAgent {
    child: Child,
    // Never read again; held only so the temporary directory is not removed while
    // the agent still has it open.
    _root: tempfile::TempDir,
    quic_port: u16,
    local_port: u16,
}

impl RunningAgent {
    /// Start an agent with one trusted, unattended device granted `permissions`.
    async fn start_with(identity: &DeviceIdentity, permissions: PermissionSet) -> Self {
        let root = tempfile::tempdir().unwrap();
        let quic_port = free_udp_port();
        let local_port = free_tcp_port();
        let config_path = write_config(root.path(), quic_port, local_port);

        seed_database(root.path(), quic_port, identity, permissions).await;

        let child = spawn(root.path(), &config_path);
        let agent = Self {
            child,
            _root: root,
            quic_port,
            local_port,
        };
        agent.wait_until_healthy().await;
        agent
    }

    fn address(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.quic_port))
    }

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
        panic!("the agent did not become healthy in time");
    }

    async fn get(&self, path: &str) -> Option<String> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let request =
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
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
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(root: &Path, config_path: &Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_rc-agent"))
        .arg("--root")
        .arg(root)
        .arg("--config")
        .arg(config_path)
        .arg("run")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the agent binary must start")
}

fn write_config(root: &Path, quic_port: u16, local_port: u16) -> PathBuf {
    let config = format!(
        "device_name = \"integration-agent\"\n\
         \n\
         [network]\n\
         listen_address = \"127.0.0.1\"\n\
         listen_port = {quic_port}\n\
         health_port = {local_port}\n\
         remote_access_enabled = false\n"
    );
    let config_dir = root.join("config");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("agent.toml");
    std::fs::write(&config_path, config).unwrap();
    config_path
}

/// Seed one trusted, unattended device before the agent opens the database.
async fn seed_database(
    root: &Path,
    quic_port: u16,
    identity: &DeviceIdentity,
    permissions: PermissionSet,
) {
    let paths = rc_platform::AppPaths::with_root(root);
    paths.create_all().unwrap();

    let database = Database::open(paths.database_file()).await.unwrap();
    let trust = TrustRepository::new(&database);
    trust
        .trust(&rc_storage::NewTrustedDevice {
            identity_fingerprint: identity.public().identity_fingerprint,
            device_id: "dev-video-integration".to_owned(),
            display_name: "Video Integration Client".to_owned(),
            os_family: "linux".to_owned(),
            address: format!("127.0.0.1:{quic_port}"),
            permissions,
            unattended: true,
            now_ms: 1_700_000_000_000,
        })
        .await
        .unwrap();

    database.close().await;
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn descriptor(identity: &DeviceIdentity) -> DeviceDescriptor {
    let public = identity.public();
    DeviceDescriptor {
        device_id: public.device_id,
        display_name: "Video Integration Client".to_owned(),
        hostname: "test-client".to_owned(),
        os_family: OsFamily::Linux,
        os_version: "test".to_owned(),
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        certificate_fingerprint: public.certificate_fingerprint.to_hex(),
    }
}

/// One connection, held open with its control channel and its video channel both
/// live: the control channel must not close, or the agent tears the whole session
/// down and takes the video channel with it.
struct Connected {
    // Never read again, but must outlive the video channel: dropping it closes the
    // control stream, which ends the session and aborts every other channel on it.
    _connection: quinn::Connection,
    _control_writer: ChannelWriter,
    _control_reader: ChannelReader,
    video_writer: ChannelWriter,
    video_reader: ChannelReader,
}

/// Connect, complete the handshake, and open the video channel.
async fn connect_and_open_video(agent: &RunningAgent, identity: &DeviceIdentity) -> Connected {
    let (connector, _) = ClientConnector::new(identity, PinPolicy::TrustOnFirstUse).unwrap();
    let connection = connector.connect(agent.address()).await.unwrap();
    let (mut control_writer, mut control_reader) =
        rc_transport::open_channel(&connection, rc_protocol::Channel::Control)
            .await
            .unwrap();

    rc_transport::handshake::begin_handshake(
        &mut control_reader,
        &mut control_writer,
        descriptor(identity),
        Capabilities::default(),
        agent.address().to_string().parse().unwrap(),
        None,
        rc_protocol::now_ms(),
    )
    .await
    .expect("the seeded, unattended device must be admitted");

    // The endpoint is held by the connection; dropping it would close the link.
    std::mem::forget(connector);

    let (video_writer, video_reader) =
        rc_transport::open_channel(&connection, rc_protocol::Channel::Video)
            .await
            .unwrap();

    Connected {
        _connection: connection,
        _control_writer: control_writer,
        _control_reader: control_reader,
        video_writer,
        video_reader,
    }
}

async fn send(writer: &mut ChannelWriter, message: &DesktopClientMessage) {
    writer
        .send(message)
        .await
        .expect("the video channel must accept a message");
}

async fn recv(reader: &mut ChannelReader) -> DesktopAgentMessage {
    tokio::time::timeout(Duration::from_secs(10), reader.next_message())
        .await
        .expect("the agent must answer within the budget")
        .expect("the channel must not error")
        .expect("the channel must not close before answering")
}

#[tokio::test]
async fn a_client_can_start_a_stream_and_receive_a_keyframe() {
    let identity = DeviceIdentity::generate("video-client", &SystemClock).unwrap();
    let agent =
        RunningAgent::start_with(&identity, PermissionSet::NONE.with(Permission::ViewScreen)).await;
    let mut connected = connect_and_open_video(&agent, &identity).await;

    send(
        &mut connected.video_writer,
        &DesktopClientMessage::StartStream {
            display_index: 0,
            accepted_codecs: vec![VideoCodec::TiledZstd],
            quality: QualityPreset::Balanced,
            max_fps: 10,
            interaction: InteractionMode::ViewOnly,
        },
    )
    .await;

    let started = recv(&mut connected.video_reader).await;
    let DesktopAgentMessage::StreamStarted {
        codec,
        width,
        height,
        ..
    } = started
    else {
        panic!("expected StreamStarted, got {started:?}");
    };
    assert_eq!(codec, VideoCodec::TiledZstd);

    let frame = loop {
        if let DesktopAgentMessage::Frame(frame) = recv(&mut connected.video_reader).await {
            break frame;
        }
    };
    assert!(frame.keyframe, "the first frame must stand alone");

    // The picture the agent sent must reconstruct exactly.
    let mut decoder = rc_video::decode::Decoder::new(codec, width, height).expect("decoder");
    decoder.apply(&frame).expect("apply");
    assert!(decoder.complete());
}

#[tokio::test]
async fn a_session_without_view_permission_gets_an_error_not_silence() {
    // A session admitted with no permissions at all is refused outright, before it
    // ever reaches a channel (see `access::grant_or_refuse`). What this test proves
    // is the finer-grained case: a session admitted for something else entirely is
    // still refused, specifically, on the video channel.
    let identity = DeviceIdentity::generate("video-client-refused", &SystemClock).unwrap();
    let agent =
        RunningAgent::start_with(&identity, PermissionSet::NONE.with(Permission::ViewMetrics))
            .await;
    let mut connected = connect_and_open_video(&agent, &identity).await;

    send(
        &mut connected.video_writer,
        &DesktopClientMessage::ListDisplays,
    )
    .await;
    let reply = recv(&mut connected.video_reader).await;
    assert!(
        matches!(reply, DesktopAgentMessage::Error { .. }),
        "got {reply:?}"
    );
}
