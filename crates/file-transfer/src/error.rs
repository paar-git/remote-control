//! Typed file-transfer errors.
//!
//! # These messages are shown to an operator
//!
//! Every one names what happened and, where there is one, what to do about it. None
//! echoes back the path it was given: the caller already knows the path it sent, and a
//! message that repeats attacker-supplied text is a message that carries attacker-
//! supplied text into a log, a toast and a bug report.
//!
//! # Refusals do not describe the filesystem
//!
//! Traversal and symlink escape report the *same* error. Distinguishing them would tell
//! a peer whether a path exists and whether it is a link, which is a map of a filesystem
//! it was refused access to.

use rc_protocol::control::ErrorCode;

/// Result alias for file operations.
pub type Result<T> = std::result::Result<T, FileError>;

/// What can go wrong resolving a path or moving a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FileError {
    /// The path was relative.
    #[error("that path is not absolute; use a full path from the root of the drive")]
    NotAbsolute,

    /// The path resolved outside every permitted root, by traversal or through a
    /// symlink. Deliberately one error for both.
    #[error("that path is outside the folders this server allows access to")]
    OutsideRoot,

    /// A Windows device name, or a name ending in a space or dot.
    #[error("that name is reserved by the operating system and cannot be used for a file")]
    ReservedName,

    /// The path was empty, contained a NUL, or was otherwise unusable.
    #[error("that is not a usable file path")]
    InvalidPath,

    /// A configured root was not absolute.
    #[error("a configured file-transfer root is not an absolute path")]
    BadRoot,

    /// The path does not exist.
    #[error("that file or folder does not exist on the server")]
    NotFound,

    /// The operating system refused access.
    #[error("the server's account does not have permission to access that")]
    PermissionDenied,

    /// The destination exists and the conflict policy said to fail.
    #[error("something already exists at that destination")]
    Conflict,

    /// The destination volume has too little free space.
    #[error("there is not enough free space on the server for that file")]
    InsufficientSpace,

    /// The transfer's checksum did not match.
    #[error(
        "the transferred file does not match its checksum and has been discarded; \
         try again"
    )]
    ChecksumMismatch,

    /// A resume was attempted but the existing prefix does not match.
    #[error("the partial file on the server does not match; restart the transfer")]
    ResumeMismatch,

    /// The transfer id is not one this connection owns.
    #[error("that transfer is not in progress")]
    UnknownTransfer,

    /// Too many transfers are already queued.
    #[error("too many transfers are already in progress; wait for one to finish")]
    TooManyTransfers,

    /// A chunk arrived at an offset the transfer was not expecting.
    #[error("the transfer received data out of order and has been stopped")]
    OutOfOrderChunk,

    /// The file is larger than the configured maximum.
    #[error("that file is larger than this server's transfer limit")]
    TooLarge,

    /// The path is a directory where a file was required, or the reverse.
    #[error("that path is not the kind of item this operation works on")]
    WrongKind,

    /// An I/O failure with no more specific cause.
    #[error("the server could not complete that file operation")]
    Io,
}

impl FileError {
    /// The wire code a client branches on.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // `Conflict` sits with these: from the caller's side it is also "the
            // request as stated cannot be carried out", and the specific variant tells
            // it which.
            Self::NotAbsolute
            | Self::InvalidPath
            | Self::ReservedName
            | Self::WrongKind
            | Self::OutOfOrderChunk
            | Self::Conflict => ErrorCode::InvalidArgument,

            // Both are refusals by policy rather than by the operating system, and both
            // are reported to the peer identically.
            Self::OutsideRoot | Self::BadRoot => ErrorCode::Forbidden,

            Self::NotFound | Self::UnknownTransfer => ErrorCode::NotFound,
            Self::PermissionDenied => ErrorCode::PermissionDenied,

            Self::InsufficientSpace | Self::TooManyTransfers | Self::TooLarge => {
                ErrorCode::ResourceExhausted
            }

            Self::ChecksumMismatch | Self::ResumeMismatch | Self::Io => ErrorCode::Internal,
        }
    }

    /// Classify an I/O failure into something the operator can act on.
    ///
    /// `std::io::Error` distinguishes these; collapsing them all to "I/O failed" would
    /// leave an operator unable to tell a typo from a permissions problem.
    #[must_use]
    pub fn from_io(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            std::io::ErrorKind::AlreadyExists => Self::Conflict,
            std::io::ErrorKind::StorageFull => Self::InsufficientSpace,
            std::io::ErrorKind::IsADirectory | std::io::ErrorKind::NotADirectory => Self::WrongKind,
            _ => {
                // The underlying message goes to the log, where an operator can find it,
                // rather than to the peer, where it could disclose a path.
                tracing::debug!(%error, "unclassified file I/O failure");
                Self::Io
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_error() -> Vec<FileError> {
        vec![
            FileError::NotAbsolute,
            FileError::OutsideRoot,
            FileError::ReservedName,
            FileError::InvalidPath,
            FileError::BadRoot,
            FileError::NotFound,
            FileError::PermissionDenied,
            FileError::Conflict,
            FileError::InsufficientSpace,
            FileError::ChecksumMismatch,
            FileError::ResumeMismatch,
            FileError::UnknownTransfer,
            FileError::TooManyTransfers,
            FileError::OutOfOrderChunk,
            FileError::TooLarge,
            FileError::WrongKind,
            FileError::Io,
        ]
    }

    #[test]
    fn no_message_echoes_a_path_back() {
        // A message that repeats attacker-supplied text carries it into a log, a toast
        // and a bug report.
        for error in every_error() {
            let message = error.to_string();
            assert!(!message.contains("C:\\"), "{message}");
            assert!(!message.contains("/etc/"), "{message}");
            assert!(!message.is_empty());
        }
    }

    #[test]
    fn traversal_and_symlink_escape_are_indistinguishable_to_the_peer() {
        // Telling them apart would map a filesystem the peer was refused access to.
        // Both paths in `PathPolicy::resolve` produce this one error.
        let message = FileError::OutsideRoot.to_string();
        assert!(!message.contains("symlink"));
        assert!(!message.contains("traversal"));
    }

    #[test]
    fn an_operator_can_tell_a_typo_from_a_permissions_problem() {
        assert_eq!(FileError::NotFound.code(), ErrorCode::NotFound);
        assert_eq!(
            FileError::PermissionDenied.code(),
            ErrorCode::PermissionDenied
        );
        assert_ne!(
            FileError::NotFound.code(),
            FileError::PermissionDenied.code()
        );
    }

    #[test]
    fn a_policy_refusal_is_forbidden_not_merely_denied() {
        // `Forbidden` says "a rule here refuses this", which is different from the OS
        // refusing, and calls for a different response from the operator.
        assert_eq!(FileError::OutsideRoot.code(), ErrorCode::Forbidden);
    }

    #[test]
    fn resource_limits_are_reported_as_exhaustion() {
        for error in [
            FileError::InsufficientSpace,
            FileError::TooManyTransfers,
            FileError::TooLarge,
        ] {
            assert_eq!(error.code(), ErrorCode::ResourceExhausted, "{error:?}");
        }
    }

    #[test]
    fn io_kinds_are_classified_rather_than_collapsed() {
        use std::io::{Error, ErrorKind};

        assert_eq!(
            FileError::from_io(&Error::from(ErrorKind::NotFound)),
            FileError::NotFound
        );
        assert_eq!(
            FileError::from_io(&Error::from(ErrorKind::PermissionDenied)),
            FileError::PermissionDenied
        );
        assert_eq!(
            FileError::from_io(&Error::from(ErrorKind::AlreadyExists)),
            FileError::Conflict
        );
        assert_eq!(
            FileError::from_io(&Error::other("something else")),
            FileError::Io
        );
    }

    #[test]
    fn an_unclassified_io_error_does_not_carry_its_message_to_the_peer() {
        let leaky = std::io::Error::other("C:\\Users\\koren\\secret\\file.txt is locked");
        let classified = FileError::from_io(&leaky);

        assert!(!classified.to_string().contains("secret"));
        assert!(!classified.to_string().contains("C:\\"));
    }
}
