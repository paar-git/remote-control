//! Typed terminal errors.
//!
//! Every message here is written on the assumption that it will be shown to an
//! operator. None carries a command line, an environment variable or terminal output —
//! all three routinely contain secrets, and a terminal error is exactly the moment
//! someone copies the text into a bug report.

use rc_protocol::control::ErrorCode;

/// Result alias for terminal operations.
pub type Result<T> = std::result::Result<T, TerminalError>;

/// What can go wrong opening or running a terminal session.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TerminalError {
    /// No shell of the requested kind exists on this host.
    #[error("no {kind} shell is installed on this server")]
    ShellNotFound {
        /// Which kind was asked for.
        kind: &'static str,
    },

    /// The pseudo-terminal could not be created.
    #[error("the server could not open a terminal")]
    PtyUnavailable,

    /// The shell process could not be started.
    #[error("the server could not start the shell")]
    SpawnFailed,

    /// The requested working directory is unusable.
    #[error("that working directory does not exist on the server")]
    BadWorkingDirectory,

    /// The session id is not one this connection owns.
    #[error("that terminal session is not open")]
    UnknownSession,

    /// The per-connection session cap is reached.
    #[error("too many terminal sessions are open; close one first")]
    TooManySessions,

    /// Elevation was requested but this build cannot provide it.
    #[error(
        "this server cannot open an elevated terminal; run the agent as a service to \
         enable privileged sessions"
    )]
    ElevationUnavailable,

    /// Writing to or reading from the session failed.
    #[error("the terminal session ended unexpectedly")]
    SessionLost,
}

impl TerminalError {
    /// The wire code a client branches on.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::ShellNotFound { .. } | Self::ElevationUnavailable => ErrorCode::Unsupported,
            Self::BadWorkingDirectory => ErrorCode::InvalidArgument,
            Self::UnknownSession => ErrorCode::NotFound,
            Self::TooManySessions => ErrorCode::ResourceExhausted,
            Self::PtyUnavailable | Self::SpawnFailed | Self::SessionLost => ErrorCode::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_error() -> Vec<TerminalError> {
        vec![
            TerminalError::ShellNotFound { kind: "bash" },
            TerminalError::PtyUnavailable,
            TerminalError::SpawnFailed,
            TerminalError::BadWorkingDirectory,
            TerminalError::UnknownSession,
            TerminalError::TooManySessions,
            TerminalError::ElevationUnavailable,
            TerminalError::SessionLost,
        ]
    }

    #[test]
    fn no_message_carries_a_path_a_command_or_an_environment_value() {
        // A terminal error is exactly the text someone pastes into a bug report.
        for error in every_error() {
            let message = error.to_string();
            assert!(!message.contains("C:\\"), "{message}");
            assert!(!message.contains("/home/"), "{message}");
            assert!(!message.is_empty());
        }
    }

    #[test]
    fn a_missing_shell_says_which_kind_without_naming_a_path() {
        let message = TerminalError::ShellNotFound { kind: "bash" }.to_string();
        assert!(message.contains("bash"));
        assert!(!message.contains("/bin/"));
    }

    #[test]
    fn resource_and_argument_failures_are_distinguishable_from_internal_ones() {
        // The client shows a different thing for "you asked for something impossible"
        // than for "the server broke".
        assert_eq!(
            TerminalError::TooManySessions.code(),
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            TerminalError::BadWorkingDirectory.code(),
            ErrorCode::InvalidArgument
        );
        assert_eq!(TerminalError::UnknownSession.code(), ErrorCode::NotFound);
        assert_eq!(TerminalError::SpawnFailed.code(), ErrorCode::Internal);
    }

    #[test]
    fn an_unavailable_feature_reports_unsupported_rather_than_a_failure() {
        // "Not built" and "broken" call for different responses from the operator.
        assert_eq!(
            TerminalError::ElevationUnavailable.code(),
            ErrorCode::Unsupported
        );
        assert_eq!(
            TerminalError::ShellNotFound { kind: "cmd" }.code(),
            ErrorCode::Unsupported
        );
    }
}
