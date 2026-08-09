use std::path::PathBuf;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, UpdateError>;

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error("The release manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("No compatible build is available for {0}.")]
    IncompatiblePlatform(String),
    #[error("This version requires {required}. Your system is {current}.")]
    UnsupportedOs { required: String, current: String },
    #[error("The version string `{0}` is not valid semantic versioning.")]
    InvalidVersion(String),
    #[error(
        "The update would downgrade from {installed} to {available}; automatic downgrades are refused."
    )]
    DowngradeRefused {
        installed: String,
        available: String,
    },
    #[error(
        "This installation is too old to update incrementally. Install the full application package instead."
    )]
    MinimumVersionNotMet { installed: String, minimum: String },
    #[error("The server URL is not allowed: {0}")]
    UnsafeUrl(String),
    #[error("The file name `{0}` is not safe to use on this computer.")]
    UnsafeFileName(String),
    #[error("The destination path is outside the configured download directory: {0}")]
    UnsafePath(PathBuf),
    #[error(
        "There is not enough free space. Required {required_bytes} bytes, available {available_bytes} bytes."
    )]
    InsufficientDiskSpace {
        required_bytes: u64,
        available_bytes: u64,
    },
    #[error("Download failed because the server stopped responding.")]
    StalledDownload,
    #[error("Download failed after {attempts} attempts: {source}")]
    RetriesExhausted {
        attempts: u32,
        source: Box<UpdateError>,
    },
    #[error("Download was paused and can be resumed later.")]
    DownloadPaused,
    #[error("Download was cancelled.")]
    DownloadCancelled,
    #[error("The server does not support resuming this download safely.")]
    ResumeUnsupported,
    #[error("The server returned invalid HTTP range metadata: {0}")]
    InvalidRangeResponse(String),
    #[error(
        "Verification failed. The downloaded file did not match the expected SHA-256 checksum and was deleted."
    )]
    ChecksumMismatch,
    #[error("Digital signature verification failed: {0}")]
    SignatureFailed(String),
    #[error("Release manifest signature verification failed: {0}")]
    ManifestSignatureFailed(String),
    #[error("A signed release manifest is required before checking for production updates.")]
    ManifestSignatureRequired,
    #[error("Required digital signature verification is not supported for this artifact.")]
    SignatureUnsupported,
    #[error("Illegal update state transition from {from} to {to}.")]
    IllegalTransition { from: String, to: String },
    #[error("Another download for this application and version is already active.")]
    DuplicateDownload,
    #[error("Installation failed: {0}")]
    InstallFailed(String),
    #[error("The new application failed its startup health check and rollback was attempted.")]
    HealthCheckFailed,
    #[error("Rollback failed: {0}")]
    RollbackFailed(String),
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),
    #[error("Network failure: {0}")]
    Network(#[from] reqwest::Error),
    #[error("JSON failure: {0}")]
    Json(#[from] serde_json::Error),
    #[error("URL parse failure: {0}")]
    Url(#[from] url::ParseError),
}
