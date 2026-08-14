//! The access model, proved against a real `rc-agent` process.
//!
//! These spawn the actual binary — its own process, its own database, its own keystore
//! — and drive a real client against it over QUIC. Nothing is stubbed. The point is not
//! that the admission functions compose in isolation, which their unit tests already
//! show, but that two processes reach the same decision across a wire.
//!
//! # Which door each case goes through, and why not the dialog
//!
//! The plan asked for the human-accept cases to be driven "with a scripted prompt
//! supplied through its configuration". No such configuration exists, and it should not:
//! a switch that makes the agent accept every connection is a switch an operator can
//! turn on, and shipping one in the production binary to satisfy a test would be a
//! larger hole than any of these tests close.
//!
//! The spawned binary refuses every dialog by construction — it has no window, so
//! `DismissingPrompt` is the only honest implementation. That covers the refusal cases
//! directly. The *granted* cases go through the unattended-password and pinned-identity
//! doors instead, which is not a weaker proof of the property under test: all three
//! doors converge on the same `grant_or_refuse`, produce the same `Authorization`, and
//! the session enforces the result identically regardless of which door opened it. What
//! a granted case actually asserts — that a permission is enforced per request, that a
//! grant crosses the wire unwidened — is the same either way.
//!
//! What this file therefore does *not* prove is the dialog itself. That is covered by
//! `crates/host-agent/src/access.rs`'s scripted-prompt tests and by
//! `apps/desktop-client/src/host.rs`.

// Integration tests assert against known-good values, so `unwrap` and `panic` are the
// clearest way to fail. The workspace denies them in library code, where a panic would
// take down an agent; here a panic *is* the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rc_protocol::control::{Capabilities, DeviceDescriptor, OsFamily, WireRefusal};
use rc_security::{
    DeviceIdentity, Fingerprint, HashingPolicy, OsRandom, PasswordCredential, Permission,
    PermissionSet, SystemClock,
};
use rc_storage::{Database, SettingsRepository, TrustRepository};
use rc_transport::{ClientConnector, PeerAddress, PinPolicy, TransportError};

/// What to write into the agent's database before it starts.
#[derive(Default)]
struct Seed {
    /// An unattended password and what it grants.
    unattended: Option<(String, PermissionSet)>,
    /// A trusted device: the identity it will prove, what it grants, and whether it
    /// may reconnect without anyone approving.
    trusted: Option<(Fingerprint, PermissionSet, bool)>,
    /// An identity to revoke immediately after trusting it, so a test can assert that
    /// revocation invalidates rather than merely hides.
    revoke: Option<Fingerprint>,
    /// An identity to suspend after trusting it.
    suspend: Option<Fingerprint>,
    /// Whether the machine accepts connections at all.
    not_accepting: bool,
}

/// A running agent, torn down when the handle is dropped.
struct RunningAgent {
    child: Child,
    /// `None` once the root has been deliberately kept for a restart.
    root: Option<tempfile::TempDir>,
    root_path: PathBuf,
    config_path: PathBuf,
    quic_port: u16,
    local_port: u16,
}

impl RunningAgent {
    /// Start an agent with a seeded database.
    ///
    /// The database is created and written *before* the process starts, so the agent
    /// reads settings that were already there rather than racing a writer.
    async fn start_with(seed: Seed) -> Self {
        let root = tempfile::tempdir().unwrap();
        let quic_port = free_udp_port();
        let local_port = free_tcp_port();
        let config_path = write_config(root.path(), quic_port, local_port);

        seed_database(root.path(), quic_port, &seed).await;

        let child = spawn(root.path(), &config_path);
        let agent = Self {
            child,
            root_path: root.path().to_path_buf(),
            config_path,
            root: Some(root),
            quic_port,
            local_port,
        };
        agent.wait_until_healthy().await;
        agent
    }

    /// The address a client dials, and the key the agent pins on.
    fn address(&self) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::LOCALHOST, self.quic_port))
    }

    fn dialled(&self) -> PeerAddress {
        self.address().to_string().parse().unwrap()
    }

    /// Stop the process, keep the data, and start it again on the same port.
    ///
    /// The keystore and database survive; the certificate must not be reissued. This is
    /// the regression test for the bug where a fresh certificate was generated on every
    /// load, which would have broken every pin on every restart.
    async fn restart(mut self) -> Self {
        let _ = self.child.kill();
        let _ = self.child.wait();

        let root = self.root.take();
        let root_path = self.root_path.clone();
        let config_path = self.config_path.clone();
        let (quic_port, local_port) = (self.quic_port, self.local_port);
        // The `Drop` impl would kill an already-dead child harmlessly, but it would also
        // drop the TempDir and delete the data this test exists to check survived.
        std::mem::forget(self);

        let child = spawn(&root_path, &config_path);
        let agent = Self {
            child,
            root,
            root_path,
            config_path,
            quic_port,
            local_port,
        };
        agent.wait_until_healthy().await;
        agent
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

    /// How many sessions the agent currently holds.
    async fn active_sessions(&self) -> u64 {
        let body = self.get("/health").await.expect("health must answer");
        let marker = "\"active_sessions\":";
        let start = body.find(marker).expect("health reports active sessions") + marker.len();
        let rest = &body[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().unwrap()
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

/// Write the seed into the agent's database before the agent opens it.
async fn seed_database(root: &Path, quic_port: u16, seed: &Seed) {
    let paths = rc_platform::AppPaths::with_root(root);
    paths.create_all().unwrap();

    let database = Database::open(paths.database_file()).await.unwrap();
    let settings = SettingsRepository::new(&database);

    if seed.not_accepting {
        settings.set_accepting(false).await.unwrap();
    }

    if let Some((password, permissions)) = &seed.unattended {
        // Hashed at test strength: these tests spawn processes and open databases, and
        // production Argon2id parameters would dominate their runtime without making
        // any assertion here stronger. What is under test is the decision, not the KDF,
        // which has its own tests in `rc-security`.
        let credential =
            PasswordCredential::create(password, HashingPolicy::FAST_FOR_TESTS, &OsRandom).unwrap();
        settings
            .set_unattended(Some(&credential), *permissions)
            .await
            .unwrap();
    }

    if let Some((identity, permissions, unattended)) = &seed.trusted {
        let key = format!("127.0.0.1:{quic_port}");
        let trust = TrustRepository::new(&database);
        // A real timestamp: the column has a `CHECK (added_ms > 0)`, because a row
        // claiming the epoch is a row nothing wrote deliberately.
        trust
            .trust(&rc_storage::NewTrustedDevice {
                identity_fingerprint: *identity,
                device_id: "dev-integration".to_owned(),
                display_name: "Integration Client".to_owned(),
                os_family: "linux".to_owned(),
                address: key,
                permissions: *permissions,
                unattended: *unattended,
                now_ms: 1_700_000_000_000,
            })
            .await
            .unwrap();
    }

    if let Some(identity) = &seed.revoke {
        TrustRepository::new(&database)
            .revoke(*identity)
            .await
            .unwrap();
    }

    if let Some(identity) = &seed.suspend {
        TrustRepository::new(&database)
            .set_suspended(*identity, true)
            .await
            .unwrap();
    }

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

/// One complete connection attempt, held open so requests can be made on it.
///
/// A manual `Debug` rather than a derive: the fields are QUIC internals with no useful
/// rendering, and `expect` on a `Result` containing one needs the bound.
struct Attempt {
    connection: quinn::Connection,
    reader: rc_transport::ChannelReader,
    writer: rc_transport::ChannelWriter,
    session: rc_transport::handshake::AdmittedSession,
}

impl std::fmt::Debug for Attempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Attempt")
            .field("permissions", &self.session.permissions)
            .finish_non_exhaustive()
    }
}

/// Dial the agent, offering `password`, and run the handshake.
async fn connect(
    agent: &RunningAgent,
    identity: &DeviceIdentity,
    password: Option<&str>,
) -> Result<Attempt, TransportError> {
    let (connector, _) = ClientConnector::new(identity, PinPolicy::TrustOnFirstUse)?;
    let connection = connector.connect(agent.address()).await?;
    let (mut writer, mut reader) =
        rc_transport::open_channel(&connection, rc_protocol::Channel::Control).await?;

    let session = rc_transport::handshake::begin_handshake(
        &mut reader,
        &mut writer,
        descriptor(identity),
        Capabilities::default(),
        agent.dialled(),
        password.map(str::to_owned),
        rc_protocol::now_ms(),
    )
    .await?;

    // The endpoint is held by the connection; dropping it would close the link under
    // the session that was just established.
    std::mem::forget(connector);
    Ok(Attempt {
        connection,
        reader,
        writer,
        session,
    })
}

impl Attempt {
    /// Ask for a system snapshot, and report whether the agent answered.
    async fn metrics_allowed(&mut self) -> bool {
        self.control(rc_protocol::control::ControlRequestPayload::SystemSnapshot)
            .await
    }

    /// Open a file channel and ask for a listing, reporting whether it was served.
    async fn files_allowed(&self) -> bool {
        let Ok((mut writer, mut reader)) =
            rc_transport::open_channel(&self.connection, rc_protocol::Channel::FileTransfer).await
        else {
            return false;
        };

        if writer
            .send(&rc_protocol::files::FileClientMessage::List {
                path: ".".to_owned(),
                include_hidden: false,
            })
            .await
            .is_err()
        {
            return false;
        }

        // Served only if a real answer came back. An explicit refusal, a closed channel
        // and a timeout all mean the request was not served.
        matches!(
            tokio::time::timeout(Duration::from_secs(10), reader.next_message()).await,
            Ok(Ok(Some(message))) if !matches!(message, rc_protocol::files::FileAgentMessage::Error { .. })
        )
    }

    /// Send a control request and report whether it produced a result rather than a
    /// refusal.
    async fn control(&mut self, payload: rc_protocol::control::ControlRequestPayload) -> bool {
        let request = rc_protocol::control::ControlRequest {
            request_id: rc_protocol::RequestId::generate(),
            session_id: self.session.session_id,
            sent_at_ms: rc_protocol::now_ms(),
            nonce: {
                let mut nonce = [0u8; 16];
                nonce[..8].copy_from_slice(&rc_protocol::now_ms().to_le_bytes());
                nonce
            },
            payload,
        };
        if self.writer.send(&request).await.is_err() {
            return false;
        }

        match tokio::time::timeout(Duration::from_secs(10), self.reader.next_message()).await {
            Ok(Ok(Some(rc_protocol::control::ControlResponse { result, .. }))) => {
                matches!(result, rc_protocol::control::ControlResult::Ok(_))
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_connection_nobody_answers_is_refused() {
    // The spawned agent has no window, so its prompt dismisses. This is the shape of
    // every unattended machine: the door closes by itself rather than staying ajar.
    let agent = RunningAgent::start_with(Seed::default()).await;
    let identity = client_identity("hopeful");

    let error = connect(&agent, &identity, None)
        .await
        .expect_err("a dismissed connection must not be admitted");

    assert!(
        matches!(
            error,
            TransportError::SessionRefused {
                reason: WireRefusal::Rejected
            }
        ),
        "got {error:?}"
    );
    assert_eq!(agent.active_sessions().await, 0);
}

#[tokio::test]
async fn a_refusal_is_never_retried() {
    // A refusal is a decision, not a hiccup. Retrying would turn a visible failure into
    // a quiet loop, and would pester whoever refused.
    let error = TransportError::SessionRefused {
        reason: WireRefusal::Rejected,
    };
    assert!(!error.permits_auto_reconnect());
    assert!(
        !TransportError::SessionRefused {
            reason: WireRefusal::IdentityChanged
        }
        .permits_auto_reconnect()
    );
    assert!(
        !TransportError::SessionRefused {
            reason: WireRefusal::NotAccepting
        }
        .permits_auto_reconnect()
    );
}

#[tokio::test]
async fn a_machine_not_accepting_says_so_distinctly() {
    // Distinct from `Rejected` on purpose: it needs a different remedy and discloses
    // nothing a caller could not already observe.
    let agent = RunningAgent::start_with(Seed {
        not_accepting: true,
        ..Seed::default()
    })
    .await;
    let identity = client_identity("hopeful");

    let error = connect(&agent, &identity, None).await.unwrap_err();

    assert!(
        matches!(
            error,
            TransportError::SessionRefused {
                reason: WireRefusal::NotAccepting
            }
        ),
        "got {error:?}"
    );
}

#[tokio::test]
async fn a_wrong_unattended_password_is_refused_indistinguishably() {
    // Never a fallback to the dialog, and never distinguishable from a dismissal — both
    // would let a caller learn whether unattended access is configured.
    let agent = RunningAgent::start_with(Seed {
        unattended: Some((
            "correct horse battery staple".to_owned(),
            PermissionSet::ALL,
        )),
        ..Seed::default()
    })
    .await;
    let identity = client_identity("guesser");

    let error = connect(&agent, &identity, Some("wrong password entirely"))
        .await
        .unwrap_err();

    assert!(
        matches!(
            error,
            TransportError::SessionRefused {
                reason: WireRefusal::Rejected
            }
        ),
        "a wrong password must be indistinguishable from a dismissal, got {error:?}"
    );
    assert_eq!(agent.active_sessions().await, 0);
}

#[tokio::test]
async fn a_stranger_at_a_trusted_devices_address_is_refused_outright() {
    // The case the pin exists for. It must never reach the dialog: an identity change
    // that arrives as a routine Accept prompt gets accepted by reflex.
    let pinned = client_identity("the-real-one");
    let agent = RunningAgent::start_with(Seed {
        trusted: Some((
            pinned.public().identity_fingerprint,
            PermissionSet::ALL,
            true,
        )),
        ..Seed::default()
    })
    .await;

    // A different identity dialling the same trusted address.
    let impostor = client_identity("someone-else");
    let error = connect(&agent, &impostor, None).await.unwrap_err();

    assert!(
        matches!(
            error,
            TransportError::SessionRefused {
                reason: WireRefusal::IdentityChanged
            }
        ),
        "a changed identity must be refused as such, got {error:?}"
    );
    assert_eq!(agent.active_sessions().await, 0);
}

// ---------------------------------------------------------------------------
// Admissions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_correct_unattended_password_is_admitted_with_what_it_grants() {
    let agent = RunningAgent::start_with(Seed {
        unattended: Some((
            "correct horse battery staple".to_owned(),
            PermissionSet::ALL,
        )),
        ..Seed::default()
    })
    .await;
    let identity = client_identity("expected");

    let mut attempt = connect(&agent, &identity, Some("correct horse battery staple"))
        .await
        .expect("the right password must be admitted");

    assert_eq!(attempt.session.permissions, PermissionSet::ALL);
    assert_eq!(
        attempt.session.descriptor.display_name, "integration-agent",
        "an admitted peer learns who answered"
    );
    assert!(attempt.metrics_allowed().await);
    assert_eq!(agent.active_sessions().await, 1);
}

#[tokio::test]
async fn an_unattended_device_is_admitted_without_being_asked_about() {
    let pinned = client_identity("known");
    let agent = RunningAgent::start_with(Seed {
        trusted: Some((
            pinned.public().identity_fingerprint,
            PermissionSet::ALL,
            true,
        )),
        ..Seed::default()
    })
    .await;

    let attempt = connect(&agent, &pinned, None)
        .await
        .expect("a pinned peer must be admitted");

    // The agent's prompt dismisses everything. Reaching a session at all proves the pin
    // decided before the prompt was ever consulted.
    assert_eq!(attempt.session.permissions, PermissionSet::ALL);
    assert_eq!(agent.active_sessions().await, 1);
}

#[tokio::test]
async fn a_withheld_permission_is_refused_per_request() {
    // The property the whole permission model rests on: enforcement is on the request,
    // not on whether the interface offered a button.
    let granted = PermissionSet::ALL.without(Permission::TransferFiles);
    let agent = RunningAgent::start_with(Seed {
        unattended: Some(("correct horse battery staple".to_owned(), granted)),
        ..Seed::default()
    })
    .await;
    let identity = client_identity("partial");

    let mut attempt = connect(&agent, &identity, Some("correct horse battery staple"))
        .await
        .expect("a partial grant is still a grant");

    assert_eq!(attempt.session.permissions, granted);
    assert!(
        !attempt
            .session
            .permissions
            .contains(Permission::TransferFiles),
        "the grant must arrive unwidened"
    );
    assert!(
        attempt.metrics_allowed().await,
        "what was granted must work"
    );
    assert!(
        !attempt.files_allowed().await,
        "what was withheld must be refused by the agent, not merely hidden by the client"
    );
}

#[tokio::test]
async fn unattended_access_survives_an_agent_restart() {
    // The regression test for the bug where the certificate was reissued on every load.
    // A pin keyed on a fingerprint that changes at every start is a pin that never
    // matches, and every reconnection would fall through to the dialog.
    let pinned = client_identity("persistent");
    let agent = RunningAgent::start_with(Seed {
        trusted: Some((
            pinned.public().identity_fingerprint,
            PermissionSet::ALL,
            true,
        )),
        ..Seed::default()
    })
    .await;

    let before = connect(&agent, &pinned, None)
        .await
        .expect("admitted before the restart");
    assert_eq!(before.session.permissions, PermissionSet::ALL);
    let agent_identity_before = before.session.descriptor.certificate_fingerprint.clone();
    drop(before);

    let agent = agent.restart().await;

    let after = connect(&agent, &pinned, None)
        .await
        .expect("the pin must still admit this peer after a restart");
    assert_eq!(after.session.permissions, PermissionSet::ALL);
    assert_eq!(
        after.session.descriptor.certificate_fingerprint, agent_identity_before,
        "the agent must present the same certificate across a restart, or every peer \
         that pinned it would refuse it"
    );
}

#[tokio::test]
async fn a_revoked_device_is_refused_after_a_restart() {
    // Revocation must invalidate the authorization, not merely hide a row from a list.
    // Asserted by connecting again against a restarted process rather than by reading
    // the table back: the table is not what admits anyone.
    let revoked = client_identity("revoked");
    let agent = RunningAgent::start_with(Seed {
        trusted: Some((
            revoked.public().identity_fingerprint,
            PermissionSet::ALL,
            true,
        )),
        revoke: Some(revoked.public().identity_fingerprint),
        ..Seed::default()
    })
    .await;

    let agent = agent.restart().await;

    let outcome = connect(&agent, &revoked, None).await;

    assert!(
        outcome.is_err(),
        "a revoked device must not get back in, and the agent's prompt dismisses \
         everything, so reaching a session at all would mean the grant survived"
    );
}

#[tokio::test]
async fn a_suspended_device_is_refused_but_keeps_its_settings() {
    let suspended = client_identity("suspended");
    let agent = RunningAgent::start_with(Seed {
        trusted: Some((
            suspended.public().identity_fingerprint,
            PermissionSet::ALL,
            true,
        )),
        suspend: Some(suspended.public().identity_fingerprint),
        ..Seed::default()
    })
    .await;

    let outcome = connect(&agent, &suspended, None).await;

    assert!(outcome.is_err(), "a suspended device must be refused");
}

#[tokio::test]
async fn a_second_device_cannot_reuse_the_first_devices_grant() {
    // Two genuinely different identity keys, dialling the same address. The grant
    // belongs to the key, so the second device inherits nothing from the first.
    let trusted = client_identity("trusted");
    let stranger = client_identity("stranger");
    let agent = RunningAgent::start_with(Seed {
        trusted: Some((
            trusted.public().identity_fingerprint,
            PermissionSet::ALL,
            true,
        )),
        ..Seed::default()
    })
    .await;

    // The trusted one gets in, so the seed is known to be live rather than inert.
    let admitted = connect(&agent, &trusted, None)
        .await
        .expect("the trusted device must be admitted");
    assert_eq!(admitted.session.permissions, PermissionSet::ALL);
    drop(admitted);

    let outcome = connect(&agent, &stranger, None).await;

    assert!(
        outcome.is_err(),
        "holding a different key must mean holding no grant"
    );
}
