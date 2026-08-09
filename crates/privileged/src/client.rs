//! The agent's side of the privileged channel.
//!
//! # This is not where the security decision happens
//!
//! The checks here exist to fail early and report well: an operator who asks to stop a
//! protected service should be told so immediately, not after a round trip. But the
//! helper re-checks everything, and *its* check is the control. If this file were
//! removed entirely, nothing about what the helper permits would change.
//!
//! # A missing helper is reported, not papered over
//!
//! If the helper is not running, or is running unelevated, that is reported plainly.
//! The alternative — silently degrading to "the button did nothing" — is the failure
//! mode an operator cannot diagnose.

use std::net::Ipv4Addr;
use std::path::Path;

use rc_protocol::system::{PowerAction, ServiceAction};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::protocol::{
    HelperError, HelperRequest, HelperResponse, MAX_REQUEST_BYTES, PrivilegedOperation, Token,
};

/// How long to wait for the helper to answer.
///
/// Longer than the helper's own command deadline would be pointless; shorter would
/// report a timeout for an operation that then completes.
const REPLY_TIMEOUT_SECS: u64 = 90;

/// Talks to the privileged helper.
pub struct PrivilegedClient {
    port: u16,
    token: Token,
}

impl std::fmt::Debug for PrivilegedClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivilegedClient")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl PrivilegedClient {
    /// Connect using the token the helper published.
    ///
    /// # Errors
    /// The token file cannot be read, which means either that the helper is not running
    /// or that this account may not talk to it.
    pub fn from_token_file(port: u16, token_path: &Path) -> std::io::Result<Self> {
        Ok(Self {
            port,
            token: Token::read_from(token_path)?,
        })
    }

    /// A client with a token already in hand. Used by tests and by an in-process helper.
    #[must_use]
    pub const fn with_token(port: u16, token: Token) -> Self {
        Self { port, token }
    }

    /// Confirm the helper is running, and learn whether it is elevated.
    ///
    /// # Errors
    /// [`HelperError::ExecutionFailed`] when the helper cannot be reached.
    pub async fn ping(&self) -> Result<(String, bool), HelperError> {
        match self.send(PrivilegedOperation::Ping).await? {
            HelperResponse::Alive { version, elevated } => Ok((version, elevated)),
            HelperResponse::Failed { error, .. } => Err(error),
            // An `Ok` in answer to a ping means the two builds disagree about what a
            // ping is, which is a protocol error rather than a success.
            HelperResponse::Ok { .. } => Err(HelperError::BadRequest),
        }
    }

    /// Perform a power action.
    ///
    /// # Errors
    /// Whatever the helper decided, or [`HelperError::ExecutionFailed`] if it could not
    /// be reached.
    pub async fn power(&self, action: PowerAction) -> Result<(), HelperError> {
        // Checked here so an unsupported action is reported without a round trip. The
        // helper checks again regardless.
        rc_platform::privileged::resolve_power_action(action)
            .map_err(|_| HelperError::Unsupported)?;

        self.perform(PrivilegedOperation::Power { action }).await
    }

    /// Start, stop, restart, enable or disable a service.
    ///
    /// # Errors
    /// [`HelperError::Refused`] for a protected service or a malformed name — reported
    /// here without a round trip, and enforced again by the helper.
    pub async fn service(&self, name: &str, action: ServiceAction) -> Result<(), HelperError> {
        rc_platform::privileged::resolve_service_action(name, action)
            .map_err(|_| HelperError::Refused)?;

        self.perform(PrivilegedOperation::Service {
            name: name.to_owned(),
            action,
        })
        .await
    }

    /// Send an operation and require that it succeeded.
    async fn perform(&self, operation: PrivilegedOperation) -> Result<(), HelperError> {
        match self.send(operation).await? {
            HelperResponse::Ok { .. } => Ok(()),
            HelperResponse::Failed { error, .. } => Err(error),
            // An `Alive` in answer to an operation means the helper did not perform
            // it, so reporting success would be a lie.
            HelperResponse::Alive { .. } => Err(HelperError::BadRequest),
        }
    }

    /// One request, one response, one connection.
    async fn send(&self, operation: PrivilegedOperation) -> Result<HelperResponse, HelperError> {
        let request = HelperRequest {
            token: self.token.expose().to_owned(),
            operation,
        };
        let encoded = serde_json::to_vec(&request).map_err(|_| HelperError::BadRequest)?;

        let deadline = std::time::Duration::from_secs(REPLY_TIMEOUT_SECS);

        tokio::time::timeout(deadline, self.exchange(&encoded))
            .await
            .map_err(|_| {
                tracing::error!("the privileged helper did not answer within its deadline");
                HelperError::ExecutionFailed
            })?
    }

    /// Write the request and read the reply.
    async fn exchange(&self, encoded: &[u8]) -> Result<HelperResponse, HelperError> {
        let mut stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, self.port))
            .await
            .map_err(|err| {
                // The common cause is that the helper is not installed or not running,
                // which is worth saying loudly once rather than failing silently.
                tracing::error!(%err, port = self.port, "could not reach the privileged helper");
                HelperError::ExecutionFailed
            })?;

        stream
            .write_all(encoded)
            .await
            .map_err(|_| HelperError::ExecutionFailed)?;
        // The helper reads to end of stream, so the write side must be closed for it to
        // see the whole request.
        stream
            .shutdown()
            .await
            .map_err(|_| HelperError::ExecutionFailed)?;

        let mut raw = Vec::new();
        stream
            .take(MAX_REQUEST_BYTES as u64)
            .read_to_end(&mut raw)
            .await
            .map_err(|_| HelperError::ExecutionFailed)?;

        serde_json::from_slice(&raw).map_err(|_| {
            tracing::error!("the privileged helper sent a reply this build cannot read");
            HelperError::BadRequest
        })
    }
}

/// Where the helper publishes its token.
#[must_use]
pub fn token_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(crate::protocol::TOKEN_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client pointed at a port nothing is listening on.
    fn unreachable_client() -> PrivilegedClient {
        // Port 1 on loopback: privileged, and nothing in this test binary binds it.
        PrivilegedClient::with_token(1, Token::generate())
    }

    #[tokio::test]
    async fn a_protected_service_is_refused_without_a_round_trip() {
        // The client is pointed at a port nothing answers on, so a refusal here proves
        // the check happened locally rather than at the helper.
        let client = unreachable_client();

        assert_eq!(
            client.service("sshd", ServiceAction::Stop).await,
            Err(HelperError::Refused)
        );
    }

    #[tokio::test]
    async fn a_malformed_service_name_is_refused_without_a_round_trip() {
        let client = unreachable_client();

        for hostile in ["spooler; rm -rf /", "", "../../etc/passwd"] {
            assert_eq!(
                client.service(hostile, ServiceAction::Start).await,
                Err(HelperError::Refused),
                "{hostile:?} must be refused locally"
            );
        }
    }

    #[tokio::test]
    async fn an_unreachable_helper_is_reported_rather_than_silently_ignored() {
        // The failure mode this avoids: a power button that does nothing and says
        // nothing.
        let client = unreachable_client();

        assert_eq!(
            client.power(PowerAction::Lock).await,
            Err(HelperError::ExecutionFailed)
        );
        assert_eq!(client.ping().await, Err(HelperError::ExecutionFailed));
    }

    #[test]
    fn the_client_debug_line_does_not_carry_the_token() {
        let client = PrivilegedClient::with_token(47814, Token::generate());
        let rendered = format!("{client:?}");

        assert!(!rendered.contains(client.token.expose()));
        assert!(rendered.contains("PrivilegedClient"));
    }

    #[test]
    fn the_token_path_sits_in_the_data_directory() {
        let path = token_path(Path::new("/var/lib/rc"));
        assert!(path.ends_with(crate::protocol::TOKEN_FILE_NAME));
        assert!(path.starts_with("/var/lib/rc"));
    }
}
