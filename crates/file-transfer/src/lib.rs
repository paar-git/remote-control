//! Safe path resolution, directory listing and resumable file transfers.
//!
//! # Everything here treats its input as hostile
//!
//! Paths, file names, offsets and lengths all come from a peer. [`path`] turns an
//! untrusted path into one that is safe to touch; [`listing`] reads a directory without
//! following anything out of bounds; [`transfer`] moves bytes with every size and
//! offset checked against what was agreed.
//!
//! # Transfers are verified, not assumed
//!
//! Every transfer carries a whole-file BLAKE3 checksum agreed before the first byte
//! moves. A completed upload whose checksum does not match is **discarded**, not kept
//! with a warning: a file that is silently wrong is worse than a transfer that failed,
//! because the operator will find out at the moment they depend on it.
//!
//! Resuming verifies the bytes already on disk against the same digest over the same
//! range before continuing. A resume that trusted the offset alone would happily splice
//! two different files together.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod error;
pub mod listing;
pub mod path;
pub mod transfer;

pub use error::{FileError, Result};
pub use listing::{list_directory, stat};
pub use path::{PathPolicy, validate_file_name};
pub use transfer::{
    CHUNK_BYTES, Download, MAX_CONCURRENT_TRANSFERS, TransferRegistry, Upload, checksum_file,
    checksum_range,
};
