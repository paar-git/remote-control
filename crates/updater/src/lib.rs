//! Production update primitives for the desktop distribution pipeline.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(missing_docs)]

pub mod database;
pub mod disk;
pub mod download;
pub mod error;
pub mod helper;
pub mod installer;
pub mod integrity;
pub mod manifest;
pub mod platform;
pub mod signature;
pub mod state;
pub mod version;

pub use database::{DownloadRecord, UpdateDatabase};
pub use disk::DiskSpaceCheck;
pub use download::{
    DownloadCommand, DownloadConfig, DownloadEvent, DownloadManager, DownloadOutcome,
};
pub use error::{Result, UpdateError};
pub use helper::{HealthCheck, StagedInstallPlan, run_staged_install};
pub use installer::{InstallOutcome, Installer, PackageFormat};
pub use integrity::{Sha256Digest, verify_sha256};
pub use manifest::{
    ArtifactSelection, ManifestPolicy, MinimumOsVersion, ReleaseArtifact, ReleaseIndex,
    ReleaseIndexEntry, ReleaseManifest, ReleasePlatform, ReleasePlatformSummary,
};
pub use platform::{Architecture, InstallationType, OperatingSystem, PlatformInfo, PlatformKey};
pub use signature::{
    ManifestSignaturePolicy, ManifestSignatureVerifier, SignaturePolicy, SignatureStatus,
    SignatureVerifier,
};
pub use state::{DownloadQueueState, UpdateState, UpdateStateMachine};
pub use version::{Version, compare_versions, parse_version};
