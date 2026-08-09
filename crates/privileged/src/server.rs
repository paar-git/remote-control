//! The helper's listener.
//!
//! # The rule this file exists to enforce
//!
//! **Every request is re-validated here.** The agent validates too, but that check is a
//! convenience for reporting a mistake early and well. This one is the control.
//!
//! Concretely, for every request, regardless of what the caller claims to have checked:
//!
//! 1. The token is compared in constant time.
//! 2. A service name is validated against [`rc_platform::privileged::validate_service_name`].
//! 3. The protected-services deny-list is consulted.
//! 4. The operation is resolved into `(program, argv)` from constants.
//! 5. The resolved program is executed with an argument *vector*, never a shell string.
//!
//! Step 4 is why there is no injection surface: nothing the caller sent becomes part of
//! a command line. The only caller-supplied value that reaches an argv element is a
//! service name, and it has already survived steps 2 and 3.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rc_platform::privileged::{self, PrivilegedCommand};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::protocol::{
    HelperError, HelperRequest, HelperResponse, MAX_REQUEST_BYTES, PrivilegedOperation, Token,
};

/// How long a caller has to send its request once connected.
///
/// A connection that opens and says nothing holds a slot. The deadline is generous for a
/// local process and still bounded.
const REQUEST_TIMEOUT_SECS: u64 = 10;

/// How long a resolved command may run before the helper gives up waiting.
///
/// A power action typically returns immediately, having scheduled the real work; a
/// service restart can take longer. Neither should be able to hold the helper forever.
const COMMAND_TIMEOUT_SECS: u64 = 60;

/// The privileged helper's server.
pub struct HelperServer {
    token: Token,
    /// Whether this process actually holds Administrator or root.
    ///
    /// Reported to the agent rather than assumed: a helper running unelevated can still
    /// answer, and saying so plainly is better than failing every operation with an
    /// obscure OS error.
    elevated: bool,
}

impl HelperServer {
    /// A server using `token`.
    #[must_use]
    pub fn new(token: Token) -> Self {
        Self {
            token,
            elevated: rc_platform::is_elevated(),
        }
    }

    /// Serve on loopback until `shutdown` resolves.
    ///
    /// The address is `127.0.0.1` and is not configurable, so no configuration mistake
    /// can put a privileged endpoint on the network.
    ///
    /// # Errors
    /// Fails if the port cannot be bound.
    pub async fn serve(
        self: Arc<Self>,
        port: u16,
        shutdown: impl Future<Output = ()> + Send,
    ) -> std::io::Result<()> {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener = tokio::net::TcpListener::bind(address).await?;
        self.serve_listener(listener, shutdown).await
    }

    /// Serve using an already-bound loopback listener until `shutdown` resolves.
    ///
    /// This is primarily useful for tests and launchers that need to bind port `0`
    /// atomically and then communicate the actual selected port without dropping the
    /// socket in between.
    ///
    /// # Errors
    /// Fails if the listener address cannot be inspected.
    pub async fn serve_listener(
        self: Arc<Self>,
        listener: tokio::net::TcpListener,
        shutdown: impl Future<Output = ()> + Send,
    ) -> std::io::Result<()> {
        tracing::info!(
            bound = %listener.local_addr()?,
            elevated = self.elevated,
            "privileged helper listening on loopback"
        );

        if !self.elevated {
            tracing::warn!(
                "the privileged helper is not running elevated; operations that need \
                 Administrator or root will fail"
            );
        }

        let accepting = async {
            loop {
                match listener.accept().await {
                    Ok((stream, _peer)) => {
                        let server = Arc::clone(&self);
                        // One task per connection so a caller that stalls cannot delay
                        // the next request.
                        tokio::spawn(async move {
                            server.handle_connection(stream).await;
                        });
                    }
                    Err(err) => {
                        tracing::debug!(%err, "a local connection failed to accept");
                    }
                }
            }
        };

        tokio::select! {
            () = accepting => {}
            () = shutdown => tracing::info!("privileged helper shutting down"),
        }

        Ok(())
    }

    /// Read one request, answer it, and close.
    async fn handle_connection(&self, mut stream: tokio::net::TcpStream) {
        let deadline = std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS);

        let raw = match tokio::time::timeout(deadline, read_request(&mut stream)).await {
            Ok(Ok(raw)) => raw,
            Ok(Err(err)) => {
                tracing::debug!(%err, "could not read a privileged request");
                return;
            }
            Err(_) => {
                tracing::debug!("a caller connected and sent nothing");
                return;
            }
        };

        let response = self.answer(&raw).await;

        let encoded = serde_json::to_vec(&response).unwrap_or_else(|_| {
            // Unreachable: `HelperResponse` always serialises. Answering with a
            // hand-written refusal is still better than dropping the connection, which
            // the caller could not distinguish from the helper being absent.
            br#"{"result":"failed","error":"execution_failed","message":"internal error"}"#.to_vec()
        });

        if let Err(err) = stream.write_all(&encoded).await {
            tracing::debug!(%err, "could not send a privileged response");
        }
        let _ = stream.shutdown().await;
    }

    /// Decide and perform.
    async fn answer(&self, raw: &[u8]) -> HelperResponse {
        let Ok(request) = serde_json::from_slice::<HelperRequest>(raw) else {
            // Covers a malformed body and an operation this build does not know. Both
            // are refused rather than approximated.
            return refuse(HelperError::BadRequest);
        };

        // Check 1: the caller could read the token file.
        if !self.token.matches(&request.token) {
            tracing::warn!("a privileged request presented no valid token");
            return refuse(HelperError::NotAuthorized);
        }

        if matches!(request.operation, PrivilegedOperation::Ping) {
            return HelperResponse::Alive {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                elevated: self.elevated,
            };
        }

        // Checks 2, 3 and 4 all happen inside `resolve`, from constants.
        let command = match resolve(&request.operation) {
            Ok(command) => command,
            Err(error) => {
                tracing::warn!(
                    operation = request.operation.audit_name(),
                    ?error,
                    "refusing a privileged request"
                );
                return refuse(error);
            }
        };

        if command.requires_elevation && !self.elevated {
            tracing::error!(
                audit = command.audit_name,
                "cannot perform a privileged operation: the helper is not elevated"
            );
            return HelperResponse::Failed {
                error: HelperError::ExecutionFailed,
                message: "the privileged helper on this server is not running with \
                          Administrator or root privileges"
                    .to_owned(),
            };
        }

        execute(&command).await
    }
}

/// Read a request, bounded.
async fn read_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    // `take` bounds the read: a caller that streams without end must not make the
    // helper allocate without end.
    stream
        .take(MAX_REQUEST_BYTES as u64)
        .read_to_end(&mut buffer)
        .await?;
    Ok(buffer)
}

/// Resolve an operation into a command, from constants.
///
/// This is the whole security decision. Every path through it goes to
/// [`rc_platform::privileged`], which validates the service name, consults the
/// protected-services deny-list, and returns a fixed program with an explicit argument
/// vector.
fn resolve(operation: &PrivilegedOperation) -> Result<PrivilegedCommand, HelperError> {
    use rc_platform::error::PlatformError;

    let outcome = match operation {
        PrivilegedOperation::Power { action } => privileged::resolve_power_action(*action),
        PrivilegedOperation::Service { name, action } => {
            privileged::resolve_service_action(name, *action)
        }
        // Handled before this is called; reaching it is a routing bug.
        PrivilegedOperation::Ping => return Err(HelperError::BadRequest),
    };

    outcome.map_err(|err| match err {
        PlatformError::Unsupported { .. } => HelperError::Unsupported,
        // A malformed name and a protected service are both "the rules here say no".
        // Distinguishing them to the caller would describe which services exist.
        PlatformError::InvalidArgument { .. } | PlatformError::BlockedBySafetyRule { .. } => {
            HelperError::Refused
        }
        _ => HelperError::ExecutionFailed,
    })
}

/// Run a resolved command.
///
/// The program and every argument are passed as separate values, so quoting, `&&`, `|`,
/// `;`, `$(…)` and newlines in a service name are inert data rather than syntax.
async fn execute(command: &PrivilegedCommand) -> HelperResponse {
    tracing::info!(
        audit = command.audit_name,
        program = %command.program,
        "performing a privileged operation"
    );

    let mut process = tokio::process::Command::new(&command.program);
    process.args(&command.args);
    // Output is not captured. It would carry OS text into the agent's log and, from
    // there, to a client — and there is nothing in it the operator needs that the exit
    // code does not already say.
    process.stdout(std::process::Stdio::null());
    process.stderr(std::process::Stdio::null());
    process.stdin(std::process::Stdio::null());

    let deadline = std::time::Duration::from_secs(COMMAND_TIMEOUT_SECS);

    let status = match tokio::time::timeout(deadline, process.status()).await {
        Ok(Ok(status)) => status,
        Ok(Err(err)) => {
            tracing::error!(
                audit = command.audit_name,
                %err,
                "a privileged command could not be started"
            );
            return HelperResponse::Failed {
                error: HelperError::ExecutionFailed,
                message: HelperError::ExecutionFailed.describe().to_owned(),
            };
        }
        Err(_) => {
            tracing::error!(
                audit = command.audit_name,
                "a privileged command did not finish within its deadline"
            );
            return HelperResponse::Failed {
                error: HelperError::ExecutionFailed,
                message: "the operation is taking longer than expected on the server".to_owned(),
            };
        }
    };

    if status.success() {
        HelperResponse::Ok {
            // The constant the helper resolved to, never caller input.
            executed: command.audit_name.to_owned(),
            exit_code: status.code(),
        }
    } else {
        tracing::warn!(
            audit = command.audit_name,
            code = status.code(),
            "a privileged command exited unsuccessfully"
        );
        HelperResponse::Failed {
            error: HelperError::ExecutionFailed,
            message: HelperError::ExecutionFailed.describe().to_owned(),
        }
    }
}

/// A refusal carrying the error's own safe description.
///
/// The message is populated rather than left empty: it is the only part of a refusal an
/// operator ever sees, and a blank one turns "that operation is blocked by a safety rule
/// on this server" into a silent failure they cannot act on.
fn refuse(error: HelperError) -> HelperResponse {
    HelperResponse::Failed {
        error,
        message: error.describe().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use rc_protocol::system::{PowerAction, ServiceAction};

    use super::*;

    /// A server whose token is known to the test.
    fn server() -> (Arc<HelperServer>, Token) {
        let token = Token::generate();
        (Arc::new(HelperServer::new(token.clone())), token)
    }

    fn request(token: &str, operation: PrivilegedOperation) -> Vec<u8> {
        serde_json::to_vec(&HelperRequest {
            token: token.to_owned(),
            operation,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn a_request_without_the_token_is_refused() {
        // This is the whole access-control decision.
        let (server, _token) = server();

        let response = server
            .answer(&request("not-the-token", PrivilegedOperation::Ping))
            .await;

        assert!(matches!(
            response,
            HelperResponse::Failed {
                error: HelperError::NotAuthorized,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn an_empty_token_is_refused() {
        let (server, _token) = server();
        let response = server.answer(&request("", PrivilegedOperation::Ping)).await;

        assert!(matches!(
            response,
            HelperResponse::Failed {
                error: HelperError::NotAuthorized,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_ping_with_the_token_reports_the_helpers_state() {
        let (server, token) = server();
        let response = server
            .answer(&request(token.expose(), PrivilegedOperation::Ping))
            .await;

        match response {
            HelperResponse::Alive { version, .. } => {
                assert_eq!(version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("expected an alive response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_malformed_request_is_refused_without_being_guessed_at() {
        let (server, _token) = server();

        for raw in [b"".as_slice(), b"not json", br#"{"token":"x"}"#] {
            let response = server.answer(raw).await;
            assert!(
                matches!(
                    response,
                    HelperResponse::Failed {
                        error: HelperError::BadRequest,
                        ..
                    }
                ),
                "got {response:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_operation_this_build_does_not_know_is_refused() {
        // A newer agent talking to an older helper is refused rather than having its
        // request approximated into a different operation.
        let (server, token) = server();
        let raw = format!(
            r#"{{"token":"{}","operation":{{"operation":"format_the_disk"}}}}"#,
            token.expose()
        );

        let response = server.answer(raw.as_bytes()).await;
        assert!(matches!(
            response,
            HelperResponse::Failed {
                error: HelperError::BadRequest,
                ..
            }
        ));
    }

    // -- the helper re-validates, whatever the caller claims --------------------

    #[test]
    fn a_protected_service_is_refused_by_the_helper_itself() {
        // The agent checks too, but that check is a convenience. This one is the
        // control: a compromised agent asking directly must still be refused.
        for name in ["sshd", "SSHD.service", "remote-control-agent"] {
            let refusal = resolve(&PrivilegedOperation::Service {
                name: name.to_owned(),
                action: ServiceAction::Stop,
            });

            assert_eq!(
                refusal.err(),
                Some(HelperError::Refused),
                "{name} must be refused by the helper"
            );
        }
    }

    #[test]
    fn a_service_name_carrying_shell_syntax_is_refused() {
        // It could not inject anything even if it were accepted — it would be a single
        // argv element — but it is refused anyway, because a name like this is not a
        // service name and pretending otherwise hides a bug.
        for hostile in [
            "spooler; rm -rf /",
            "spooler && shutdown",
            "spooler`whoami`",
            "spooler\nshutdown",
            "spooler|tee",
            "../../etc/passwd",
            "",
        ] {
            let refusal = resolve(&PrivilegedOperation::Service {
                name: hostile.to_owned(),
                action: ServiceAction::Start,
            });

            assert_eq!(
                refusal.err(),
                Some(HelperError::Refused),
                "{hostile:?} must be refused"
            );
        }
    }

    #[test]
    fn an_over_long_service_name_is_refused() {
        let refusal = resolve(&PrivilegedOperation::Service {
            name: "a".repeat(1000),
            action: ServiceAction::Start,
        });
        assert_eq!(refusal.err(), Some(HelperError::Refused));
    }

    #[test]
    fn an_ordinary_service_name_resolves_to_a_fixed_program_and_argv() {
        let command = resolve(&PrivilegedOperation::Service {
            name: "spooler".to_owned(),
            action: ServiceAction::Restart,
        })
        .expect("an ordinary service name resolves");

        // The program is a constant, and the name appears only as an argv element.
        assert!(!command.program.is_empty());
        assert!(
            command.args.iter().any(|arg| arg.contains("spooler")),
            "the service name must reach argv: {:?}",
            command.args
        );
        assert!(
            !command.program.contains("spooler"),
            "the name must never become part of the program path"
        );
    }

    #[test]
    fn a_power_action_resolves_to_a_fixed_program() {
        let command = resolve(&PrivilegedOperation::Power {
            action: PowerAction::Restart,
        })
        .expect("restart is supported on every platform this builds for");

        assert!(!command.program.is_empty());
        assert!(command.requires_elevation, "a restart needs elevation");
        assert_eq!(command.audit_name, "power.restart");
    }

    #[test]
    fn nothing_the_caller_sent_becomes_part_of_a_command_line() {
        // The structural property: the program is a constant, and arguments are a
        // vector rather than a string, so there is no command line to inject into.
        let command = resolve(&PrivilegedOperation::Service {
            name: "my-app".to_owned(),
            action: ServiceAction::Stop,
        })
        .unwrap();

        for arg in &command.args {
            assert!(!arg.contains('\n'), "no argument may carry a newline");
        }
        assert!(!command.program.contains(' '), "the program is a bare path");
    }

    #[test]
    fn a_refusal_does_not_say_which_check_rejected_it() {
        // A malformed name and a protected service report identically: distinguishing
        // them would tell a caller which services exist on the host.
        let malformed = resolve(&PrivilegedOperation::Service {
            name: "not a name".to_owned(),
            action: ServiceAction::Stop,
        });
        let protected = resolve(&PrivilegedOperation::Service {
            name: "sshd".to_owned(),
            action: ServiceAction::Stop,
        });

        assert_eq!(malformed.err(), protected.err());
    }

    #[tokio::test]
    async fn every_refusal_reaches_the_caller_with_something_to_read() {
        // The message is the only part of a refusal an operator sees. An empty one is a
        // silent failure wearing an error's clothes.
        let (server, token) = server();

        let refusals = [
            server
                .answer(&request("wrong-token", PrivilegedOperation::Ping))
                .await,
            server.answer(b"not json").await,
            server
                .answer(&request(
                    token.expose(),
                    PrivilegedOperation::Service {
                        name: "sshd".to_owned(),
                        action: ServiceAction::Stop,
                    },
                ))
                .await,
        ];

        for response in refusals {
            match response {
                HelperResponse::Failed { error, message } => {
                    assert!(!message.is_empty(), "{error:?} refused with no message");
                    assert_eq!(message, error.describe());
                }
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }

    #[test]
    fn resolving_a_ping_is_a_routing_bug_rather_than_an_operation() {
        assert_eq!(
            resolve(&PrivilegedOperation::Ping).err(),
            Some(HelperError::BadRequest)
        );
    }
}
