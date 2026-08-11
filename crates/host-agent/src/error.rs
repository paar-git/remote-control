//! Typed errors raised by this crate's own logic.
//!
//! Distinct from `anyhow::Result`, which `main.rs` uses for startup and command
//! dispatch: this is the typed error the access decision propagates, so a caller can
//! match on it rather than parse a string.

/// Errors raised while deciding or serving a connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AccessError {
    /// The persistence layer failed.
    #[error(transparent)]
    Storage(#[from] rc_storage::StorageError),
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, AccessError>;
