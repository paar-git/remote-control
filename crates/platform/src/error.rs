//! Typed platform errors.

/// Errors raised by platform operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformError {
    /// The operation is not implemented for this operating system.
    #[error("`{operation}` is not supported on this platform")]
    Unsupported {
        /// Which operation.
        operation: &'static str,
    },

    /// The operation requires elevation that the agent does not currently hold.
    #[error("`{operation}` requires elevated privileges")]
    ElevationRequired {
        /// Which operation.
        operation: &'static str,
    },

    /// The request was rejected by the privileged-command allowlist. This is a
    /// security control, not a transient failure: retrying will not help.
    #[error("`{operation}` is not in the privileged command allowlist")]
    NotAllowlisted {
        /// Which operation.
        operation: &'static str,
    },

    /// A safety deny-rule blocked the request because it would predictably break
    /// the agent or the host.
    #[error("`{operation}` is blocked by a safety rule: {reason}")]
    BlockedBySafetyRule {
        /// Which operation.
        operation: &'static str,
        /// Why it was blocked.
        reason: &'static str,
    },

    /// An argument failed validation.
    #[error("invalid argument for `{operation}`: {reason}")]
    InvalidArgument {
        /// Which operation.
        operation: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },

    /// An underlying OS call failed.
    #[error("`{operation}` failed")]
    Os {
        /// Which operation.
        operation: &'static str,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A spawned helper exited non-zero.
    #[error("`{operation}` exited with status {status}")]
    CommandFailed {
        /// Which operation.
        operation: &'static str,
        /// Process exit status.
        status: i32,
    },
}

/// Convenience result alias for platform operations.
pub type Result<T> = std::result::Result<T, PlatformError>;
