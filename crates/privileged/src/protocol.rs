//! What the agent and the helper say to each other.
//!
//! JSON over a loopback socket, one request and one response per connection. JSON
//! rather than the binary wire format used on the network because this is a local
//! control channel between two processes of the same build, and being able to read a
//! captured exchange while debugging a privilege problem is worth more here than
//! compactness.
//!
//! # The request names an operation, not a command
//!
//! There is deliberately no field for a program, an argument vector or a shell string.
//! The helper resolves an operation into `(program, argv)` from constants in
//! [`rc_platform::privileged`], so there is nothing an injection could be injected into.

use rc_protocol::system::{PowerAction, ServiceAction};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq as _;

/// Name of the token file inside the helper's data directory.
pub const TOKEN_FILE_NAME: &str = "privileged-helper.token";

/// Largest request the helper will read.
///
/// A request is a few hundred bytes. Anything larger is not a request, and reading it
/// would be an allocation chosen by whoever connected.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Something the helper is willing to do.
///
/// `#[non_exhaustive]` so a newer agent talking to an older helper is refused rather
/// than having its request approximated into a different operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
#[non_exhaustive]
pub enum PrivilegedOperation {
    /// Perform a power action on the host.
    Power {
        /// Which action.
        action: PowerAction,
    },
    /// Start, stop, restart, enable or disable a service.
    Service {
        /// Service or unit name. Validated by the helper before use.
        name: String,
        /// Which action.
        action: ServiceAction,
    },
    /// Confirm the helper is alive and elevated, without doing anything.
    ///
    /// Used at agent startup so a missing or unelevated helper is reported once, in the
    /// log, rather than discovered by an operator when a power button does nothing.
    Ping,
}

impl PrivilegedOperation {
    /// Stable name for audit records and logs.
    #[must_use]
    pub const fn audit_name(&self) -> &'static str {
        match self {
            Self::Power { .. } => "privileged.power",
            Self::Service { .. } => "privileged.service",
            Self::Ping => "privileged.ping",
        }
    }

    /// Whether this operation changes the state of the host.
    ///
    /// A ping does not, and is not audited as though it did — a trail full of pings is
    /// a trail nobody reads.
    #[must_use]
    pub const fn is_stateful(&self) -> bool {
        !matches!(self, Self::Ping)
    }
}

/// What the agent sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperRequest {
    /// Proof that the caller could read the helper's token file.
    pub token: String,
    /// What to do.
    pub operation: PrivilegedOperation,
}

/// What the helper sends back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "result")]
#[non_exhaustive]
pub enum HelperResponse {
    /// The operation ran.
    Ok {
        /// What was actually executed, for the audit trail. Never caller input: this is
        /// the constant the helper resolved to.
        executed: String,
        /// The process exit code, when one was produced.
        exit_code: Option<i32>,
    },
    /// The helper is alive.
    Alive {
        /// Helper version, so a mismatched pair is visible rather than mysterious.
        version: String,
        /// Whether the helper actually holds Administrator or root.
        elevated: bool,
    },
    /// The operation was refused or failed.
    Failed {
        /// Machine-readable reason.
        error: HelperError,
        /// A sentence safe to show an operator.
        message: String,
    },
}

/// Why the helper refused or failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HelperError {
    /// The token was absent, malformed or wrong.
    NotAuthorized,
    /// The request did not parse, or named an operation this helper does not know.
    BadRequest,
    /// The allowlist refused it — a protected service, or a malformed service name.
    Refused,
    /// The platform has no equivalent of this operation.
    Unsupported,
    /// The command was resolved and run, and failed.
    ExecutionFailed,
}

impl HelperError {
    /// A sentence safe to show an operator.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            // Deliberately identical whether the token was missing, malformed or simply
            // wrong: a caller that cannot read the token file learns only that it may
            // not ask.
            Self::NotAuthorized => "this process is not permitted to request privileged operations",
            Self::BadRequest => "the privileged helper did not understand that request",
            Self::Refused => "that operation is blocked by a safety rule on this server",
            Self::Unsupported => "this server's operating system has no equivalent of that action",
            Self::ExecutionFailed => "the operation was attempted and did not complete",
        }
    }
}

/// The helper's shared secret.
///
/// Neither `Debug` nor `Serialize` renders the value, so it cannot reach a log by
/// accident.
#[derive(Clone)]
pub struct Token {
    value: std::sync::Arc<String>,
}

impl Token {
    /// Generate a fresh token.
    ///
    /// Regenerated every time the helper starts, so a copy taken from a previous run is
    /// useless.
    #[must_use]
    pub fn generate() -> Self {
        use rc_security::RandomSourceExt as _;
        let bytes: [u8; 32] = rc_security::OsRandom.bytes();
        Self {
            value: std::sync::Arc::new(hex::encode(bytes)),
        }
    }

    /// The value to send.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// Whether `presented` is this token, compared in constant time.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        let expected = self.value.as_bytes();
        let presented = presented.as_bytes();
        // Length is compared separately because `ct_eq` requires equal lengths, and the
        // length of a fixed-size token is not itself a secret.
        presented.len() == expected.len() && bool::from(presented.ct_eq(expected))
    }

    /// Write the token where the agent's account can read it.
    ///
    /// # Errors
    /// Propagates the write failure. A helper whose token cannot be published is a
    /// helper nothing can talk to, so the caller treats this as fatal.
    pub fn write_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        // The same atomic, mode-0600 write the keystore uses: a token that is briefly
        // world-readable is a token that was world-readable.
        rc_security::keystore::write_protected_file(path, self.value.as_bytes())
    }

    /// Read a token the helper published.
    ///
    /// # Errors
    /// Propagates the read failure, which for the agent means the helper is not running
    /// or this account may not talk to it.
    pub fn read_from(path: &std::path::Path) -> std::io::Result<Self> {
        let value = std::fs::read_to_string(path)?;
        Ok(Self {
            value: std::sync::Arc::new(value.trim().to_owned()),
        })
    }
}

impl std::fmt::Debug for Token {
    /// Redacted. A token in a log line is a token in a bug report.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_carries_an_operation_and_never_a_command() {
        // The property that makes injection structurally impossible: there is no field
        // to inject into.
        let request = HelperRequest {
            token: "t".to_owned(),
            operation: PrivilegedOperation::Service {
                name: "spooler".to_owned(),
                action: ServiceAction::Restart,
            },
        };

        let json = serde_json::to_value(&request).unwrap();
        let rendered = json.to_string();

        assert!(!rendered.contains("program"));
        assert!(!rendered.contains("args"));
        assert!(!rendered.contains("command"));
        assert!(rendered.contains("spooler"));
    }

    #[test]
    fn every_operation_round_trips() {
        for operation in [
            PrivilegedOperation::Ping,
            PrivilegedOperation::Power {
                action: PowerAction::Restart,
            },
            PrivilegedOperation::Service {
                name: "sshd".to_owned(),
                action: ServiceAction::Stop,
            },
        ] {
            let json = serde_json::to_string(&operation).unwrap();
            let back: PrivilegedOperation = serde_json::from_str(&json).unwrap();
            assert_eq!(operation, back);
        }
    }

    #[test]
    fn an_operation_this_build_does_not_know_fails_to_parse() {
        // Refused rather than approximated into a different operation.
        let unknown = r#"{"operation":"format_the_disk"}"#;
        assert!(serde_json::from_str::<PrivilegedOperation>(unknown).is_err());
    }

    #[test]
    fn a_ping_is_not_treated_as_a_state_change() {
        // A trail full of pings is a trail nobody reads.
        assert!(!PrivilegedOperation::Ping.is_stateful());
        assert!(
            PrivilegedOperation::Power {
                action: PowerAction::Shutdown
            }
            .is_stateful()
        );
    }

    #[test]
    fn every_operation_has_a_distinct_audit_name() {
        let names = [
            PrivilegedOperation::Ping.audit_name(),
            PrivilegedOperation::Power {
                action: PowerAction::Lock,
            }
            .audit_name(),
            PrivilegedOperation::Service {
                name: "x".to_owned(),
                action: ServiceAction::Start,
            }
            .audit_name(),
        ];
        let unique: std::collections::HashSet<_> = names.iter().collect();
        assert_eq!(unique.len(), names.len());
    }

    #[test]
    fn a_token_never_renders_itself() {
        let token = Token::generate();
        let rendered = format!("{token:?}");

        assert!(!rendered.contains(token.expose()));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn tokens_differ_between_runs() {
        // A copy taken from a previous run must be useless.
        assert!(!Token::generate().matches(Token::generate().expose()));
    }

    #[test]
    fn a_truncated_or_empty_token_does_not_match() {
        let token = Token::generate();

        assert!(!token.matches(""));
        assert!(!token.matches(&token.expose()[..16]));
        assert!(token.matches(token.expose()));
    }

    #[test]
    fn a_token_round_trips_through_a_protected_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);

        let original = Token::generate();
        original.write_to(&path).unwrap();

        assert!(original.matches(Token::read_from(&path).unwrap().expose()));
    }

    #[cfg(unix)]
    #[test]
    fn the_token_file_is_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE_NAME);
        Token::generate().write_to(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "reading this file is the authorization; anyone who can read it can act as root"
        );
    }

    #[test]
    fn no_refusal_message_says_which_check_rejected_it() {
        // A caller that cannot read the token learns only that it may not ask.
        let message = HelperError::NotAuthorized.describe();

        assert!(!message.contains("token"));
        assert!(!message.contains("missing"));
        assert!(!message.is_empty());
    }

    #[test]
    fn every_error_describes_itself_safely() {
        for error in [
            HelperError::NotAuthorized,
            HelperError::BadRequest,
            HelperError::Refused,
            HelperError::Unsupported,
            HelperError::ExecutionFailed,
        ] {
            let message = error.describe();
            assert!(!message.is_empty());
            assert!(!message.contains("C:\\"), "{message}");
            assert!(!message.contains("/usr/"), "{message}");
        }
    }

    #[test]
    fn a_request_is_bounded() {
        // A request is a few hundred bytes; anything larger is not a request.
        const { assert!(MAX_REQUEST_BYTES <= 64 * 1024) }
        const { assert!(MAX_REQUEST_BYTES >= 1024) }
    }
}
