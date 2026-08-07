//! End-to-end tests across the privilege split.
//!
//! A real helper server on a real loopback socket, driven by the real client. What these
//! prove is the property the whole split exists for:
//!
//! > A caller that bypasses the client's own checks — as a compromised agent would —
//! > is still refused by the helper.
//!
//! Every test that asks for a refusal sends its request as raw bytes rather than through
//! `PrivilegedClient`, precisely so the client's convenience checks are not what is being
//! measured.

// Integration tests assert against known-good values, so `unwrap` and `panic` are the
// clearest way to fail. The workspace denies them in library code, where a panic would
// take down a privileged process; here a panic *is* the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::sync::Arc;

use rc_privileged::{HelperError, HelperResponse, HelperServer, PrivilegedClient, Token};
use rc_protocol::system::ServiceAction;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// A helper listening on a free loopback port.
struct RunningHelper {
    port: u16,
    token: Token,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RunningHelper {
    async fn start() -> Self {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let token = Token::generate();
        let server = Arc::new(HelperServer::new(token.clone()));
        let (stop, wait) = tokio::sync::oneshot::channel();

        let task = tokio::spawn(async move {
            let _ = server
                .serve(port, async {
                    let _ = wait.await;
                })
                .await;
        });

        // Wait for the socket to be accepting rather than sleeping a fixed amount: a
        // loaded machine takes longer, and a fixed sleep would be flaky in one direction
        // and slow in the other.
        for _ in 0..200 {
            if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        Self {
            port,
            token,
            stop: Some(stop),
            task: Some(task),
        }
    }

    /// A client holding the right token.
    fn client(&self) -> PrivilegedClient {
        PrivilegedClient::with_token(self.port, self.token.clone())
    }

    /// Send a raw request, bypassing every check the client would perform.
    ///
    /// This is what a compromised agent would be able to do, so it is how the helper's
    /// own enforcement is measured.
    async fn send_raw(&self, body: &str) -> HelperResponse {
        let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, self.port))
            .await
            .expect("the helper must be listening");

        stream.write_all(body.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();

        serde_json::from_slice(&raw).expect("the helper must send a well-formed reply")
    }

    /// A raw request carrying the correct token.
    async fn send_authorised(&self, operation_json: &str) -> HelperResponse {
        self.send_raw(&format!(
            r#"{{"token":"{}","operation":{operation_json}}}"#,
            self.token.expose()
        ))
        .await
    }
}

impl Drop for RunningHelper {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[tokio::test]
async fn a_client_with_the_token_reaches_the_helper() {
    let helper = RunningHelper::start().await;

    let (version, _elevated) = helper
        .client()
        .ping()
        .await
        .expect("a ping with the right token must be answered");

    assert!(!version.is_empty());
}

#[tokio::test]
async fn a_client_without_the_token_is_refused() {
    // Being able to read the token file is the whole authorization.
    let helper = RunningHelper::start().await;
    let impostor = PrivilegedClient::with_token(helper.port, Token::generate());

    assert_eq!(impostor.ping().await, Err(HelperError::NotAuthorized));
}

#[tokio::test]
async fn the_helper_refuses_a_protected_service_even_when_the_client_is_bypassed() {
    // The property the split exists for. A compromised agent can send whatever it
    // likes; the helper decides.
    let helper = RunningHelper::start().await;

    for name in ["sshd", "remote-control-agent", "SSHD.service"] {
        let response = helper
            .send_authorised(&format!(
                r#"{{"operation":"service","name":"{name}","action":"stop"}}"#
            ))
            .await;

        match response {
            HelperResponse::Failed { error, .. } => {
                assert_eq!(error, HelperError::Refused, "{name} must be refused");
            }
            other => panic!("{name} must be refused, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_helper_refuses_shell_syntax_in_a_service_name() {
    // It could not inject anything even if accepted — arguments are a vector, not a
    // command line — but a name like this is not a service name, and accepting it would
    // hide a bug.
    let helper = RunningHelper::start().await;

    for hostile in [
        "spooler; rm -rf /",
        "spooler && shutdown -h now",
        "../../etc/passwd",
        "spooler|tee",
    ] {
        let response = helper
            .send_authorised(&format!(
                r#"{{"operation":"service","name":"{hostile}","action":"start"}}"#
            ))
            .await;

        match response {
            HelperResponse::Failed { error, .. } => {
                assert_eq!(error, HelperError::Refused, "{hostile:?} must be refused");
            }
            other => panic!("{hostile:?} must be refused, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_helper_refuses_an_operation_it_does_not_know() {
    // A newer agent talking to an older helper is refused rather than approximated.
    let helper = RunningHelper::start().await;

    let response = helper
        .send_authorised(r#"{"operation":"run_arbitrary_command","command":"rm -rf /"}"#)
        .await;

    match response {
        HelperResponse::Failed { error, .. } => assert_eq!(error, HelperError::BadRequest),
        other => panic!("an unknown operation must be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn a_request_naming_a_program_directly_is_not_understood() {
    // There is no field for a program, so a request that invents one does not parse as
    // an operation at all.
    let helper = RunningHelper::start().await;

    let response = helper
        .send_authorised(r#"{"program":"/bin/sh","args":["-c","id"]}"#)
        .await;

    match response {
        HelperResponse::Failed { error, .. } => assert_eq!(error, HelperError::BadRequest),
        other => panic!("a command-shaped request must be refused, got {other:?}"),
    }
}

#[tokio::test]
async fn garbage_is_refused_without_the_helper_falling_over() {
    let helper = RunningHelper::start().await;

    for body in ["", "not json at all", "{", r#"{"token":123}"#] {
        let response = helper.send_raw(body).await;
        assert!(
            matches!(response, HelperResponse::Failed { .. }),
            "{body:?} must be refused, got {response:?}"
        );
    }

    // Still serving afterwards.
    assert!(helper.client().ping().await.is_ok());
}

#[tokio::test]
async fn an_oversized_request_does_not_take_the_helper_down() {
    // The read is bounded, so a caller streaming without end cannot make the helper
    // allocate without end.
    let helper = RunningHelper::start().await;

    let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, helper.port))
        .await
        .unwrap();
    // Deliberately larger than the helper's request ceiling.
    let flood = vec![b'a'; 256 * 1024];
    let _ = stream.write_all(&flood).await;
    let _ = stream.shutdown().await;

    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw).await;

    assert!(
        helper.client().ping().await.is_ok(),
        "the helper must still be serving"
    );
}

#[tokio::test]
async fn the_client_refuses_a_protected_service_before_asking() {
    // Belt and braces: the client's check is a convenience, and this confirms it is
    // wired up. The helper's own refusal is covered separately above.
    let helper = RunningHelper::start().await;

    assert_eq!(
        helper.client().service("sshd", ServiceAction::Stop).await,
        Err(HelperError::Refused)
    );
}

#[tokio::test]
async fn a_lock_request_is_accepted_by_the_allowlist() {
    // Locking the console is the one power action that needs no elevation, so it is the
    // only one safe to let reach execution in a test. What is asserted is that the
    // request was *understood and permitted* — not that the desktop actually locked,
    // which a build agent has no desktop to do.
    let helper = RunningHelper::start().await;

    let response = helper
        .send_authorised(r#"{"operation":"power","action":"lock"}"#)
        .await;

    match response {
        // Either outcome proves the point: the request was resolved and attempted. On a
        // machine with no interactive session the command itself may fail, which is not
        // what this test is about.
        HelperResponse::Ok { executed, .. } => assert_eq!(executed, "power.lock"),
        HelperResponse::Failed { error, .. } => {
            assert_eq!(
                error,
                HelperError::ExecutionFailed,
                "a lock must be permitted; only its execution may fail here"
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[tokio::test]
async fn the_helper_reports_whether_it_is_elevated_rather_than_pretending() {
    // An agent that could not tell would report a confusing OS error for every
    // privileged operation instead of the real cause.
    let helper = RunningHelper::start().await;

    let (_version, elevated) = helper.client().ping().await.unwrap();
    assert_eq!(
        elevated,
        rc_platform::is_elevated(),
        "the helper must report its actual state"
    );
}
