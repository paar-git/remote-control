//! Typed security errors.
//!
//! Error text is written on the assumption that it may be shown to the operator and
//! written to logs. No variant carries a password, pairing code, private key, proof
//! or any other secret, and none of them echo attacker-supplied input.

/// Errors raised by identity, keystore, pairing and authentication operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecurityError {
    /// A cryptographic key could not be generated.
    #[error("could not generate a device key")]
    KeyGeneration,

    /// A certificate could not be generated.
    #[error("could not generate a device certificate")]
    CertificateGeneration,

    /// Stored key or certificate material could not be parsed.
    #[error("stored identity material is malformed")]
    MalformedIdentity,

    /// The keystore file exists but its contents failed integrity checking. This is
    /// reported distinctly from "missing" so an operator can tell corruption apart
    /// from a first run.
    #[error("the keystore is corrupt or was tampered with")]
    KeystoreCorrupt,

    /// The keystore was written by a newer build using a format this one cannot read.
    #[error("keystore format version {found} is newer than the supported version {supported}")]
    KeystoreVersionUnsupported {
        /// Version found on disk.
        found: u32,
        /// Highest version this build understands.
        supported: u32,
    },

    /// The keystore could not be decrypted under the current OS identity. On Windows
    /// this usually means the file was created by a different user or service account.
    #[error(
        "the keystore could not be decrypted by this user or service account; it was \
         created under a different identity"
    )]
    KeystoreWrongIdentity,

    /// File permissions on the keystore or its directory are unsafe. This is a hard
    /// failure, not a warning: continuing would leave a private key readable.
    #[error("unsafe permissions on {path}: expected mode {expected:o}, found {found:o}")]
    UnsafePermissions {
        /// Which path.
        path: String,
        /// Required mode.
        expected: u32,
        /// Mode actually found.
        found: u32,
    },

    /// The keystore's parent directory does not exist or is not a directory.
    #[error("the keystore directory is missing")]
    KeystoreDirectoryMissing,

    /// An I/O operation failed.
    #[error("keystore I/O failed during {operation}")]
    Io {
        /// What was being attempted.
        operation: &'static str,
        /// Underlying cause.
        #[source]
        source: std::io::Error,
    },

    /// A signature did not verify.
    #[error("signature verification failed")]
    BadSignature,

    /// A pairing proof did not verify.
    ///
    /// Deliberately indistinguishable from a wrong pairing code, so failures cannot be
    /// used as an oracle to learn whether a guessed code was close.
    #[error("pairing proof rejected")]
    ProofRejected,

    /// The pairing transcript did not match the one the peer signed, meaning some
    /// bound value (identity, permission, expiry, version) differs between the peers.
    #[error("pairing transcript mismatch")]
    TranscriptMismatch,

    /// No pairing session with that identifier is open.
    #[error("no such pairing session")]
    PairingSessionUnknown,

    /// The pairing window has closed.
    #[error("the pairing code has expired")]
    PairingExpired,

    /// The pairing code has already been used successfully.
    #[error("the pairing code has already been used")]
    PairingAlreadyConsumed,

    /// Too many failed attempts; the code has been destroyed.
    #[error("too many failed pairing attempts; the code has been cancelled")]
    PairingAttemptsExhausted,

    /// The pairing session is not in a state where this step is valid.
    #[error("pairing step is not valid in the current state")]
    PairingWrongState,

    /// The peer speaks a protocol version we will not pair with.
    #[error("the peer's protocol version is not supported for pairing")]
    UnsupportedProtocolVersion,

    /// A value that must be fresh was seen before.
    #[error("replayed value rejected")]
    Replay,

    /// The presented device identity does not match the one previously pinned. This is
    /// never resolved automatically.
    #[error("device identity does not match the pinned identity")]
    IdentityMismatch,

    /// A device is known but its trust has been revoked.
    #[error("this device's access has been revoked")]
    DeviceRevoked,

    /// Two different device identifiers presented the same identity key.
    #[error("this identity is already registered under a different device")]
    DuplicateIdentity,

    /// Authentication failed. Intentionally identical whether the account does not
    /// exist or the password was wrong, so it cannot be used to enumerate accounts.
    #[error("incorrect username or password")]
    InvalidCredentials,

    /// Authentication is temporarily blocked after repeated failures.
    #[error("too many failed attempts; try again in {retry_after_secs} seconds")]
    Throttled {
        /// Seconds the caller must wait.
        retry_after_secs: u64,
    },

    /// A password failed policy checks.
    #[error("password is not acceptable: {reason}")]
    WeakPassword {
        /// Why it was rejected. Never contains the password.
        reason: &'static str,
    },

    /// A password hash could not be computed or parsed.
    #[error("password hashing failed")]
    PasswordHashing,

    /// The caller lacks the capability required for an operation.
    #[error("permission denied: this role does not grant `{capability}`")]
    PermissionDenied {
        /// The capability that was required.
        capability: &'static str,
    },

    /// An argument failed validation.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Which field.
        field: &'static str,
        /// Why it was rejected. Never contains the value.
        reason: &'static str,
    },
}

/// Convenience result alias for security operations.
pub type Result<T> = std::result::Result<T, SecurityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_errors_do_not_distinguish_missing_accounts() {
        // Account enumeration protection: there is exactly one variant for both cases.
        let message = SecurityError::InvalidCredentials.to_string();
        assert!(!message.to_lowercase().contains("not found"));
        assert!(!message.to_lowercase().contains("no such"));
        assert!(!message.to_lowercase().contains("unknown user"));
    }

    #[test]
    fn proof_rejection_does_not_reveal_why() {
        let message = SecurityError::ProofRejected.to_string();
        for leak in ["code", "digit", "expected", "guess"] {
            assert!(
                !message.to_lowercase().contains(leak),
                "leaks `{leak}`: {message}"
            );
        }
    }

    #[test]
    fn errors_never_render_secret_values() {
        let errors = [
            SecurityError::BadSignature,
            SecurityError::ProofRejected,
            SecurityError::KeystoreCorrupt,
            SecurityError::KeystoreWrongIdentity,
            SecurityError::InvalidCredentials,
            SecurityError::PasswordHashing,
            SecurityError::WeakPassword {
                reason: "too short",
            },
            SecurityError::Invalid {
                field: "device name",
                reason: "empty",
            },
        ];
        for err in errors {
            let text = err.to_string();
            assert!(!text.contains("0x"), "possible raw bytes in: {text}");
            assert!(text.is_ascii(), "error text should stay log-safe: {text}");
        }
    }
}
