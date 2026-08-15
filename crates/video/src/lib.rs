//! Remote desktop video: capture, encode, decode.
//!
//! # Why tiles rather than a video codec
//!
//! This stream carries terminals, config files and log output. Compression artifacts
//! on 9pt text are the failure that matters, not bandwidth, so the default path is
//! lossless: the frame is split into fixed tiles, only tiles whose contents changed are
//! sent, and those are compressed with zstd.
//!
//! Tiling also means the operating system is never asked for dirty regions. Damage is
//! computed here, identically on all three platforms, from data this crate already has.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod capture;
pub mod tile;

/// Anything that can go wrong capturing or coding a frame.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VideoError {
    /// No display carries this index.
    #[error("no display with index {0}")]
    NoSuchDisplay(u8),
    /// This platform or session cannot capture at all, and here is why.
    #[error("capture is not available here: {0}")]
    Unsupported(&'static str),
    /// The capture backend refused or failed.
    #[error("capture failed: {0}")]
    Capture(String),
    /// The frame could not be coded.
    #[error("encode failed: {0}")]
    Encode(String),
    /// A single frame exceeded what the transport will carry.
    #[error("frame of {bytes} bytes exceeds the {limit} byte channel limit")]
    FrameTooLarge {
        /// Size of the offending frame.
        bytes: usize,
        /// The ceiling it broke.
        limit: usize,
    },
}

/// Result carrying a [`VideoError`].
pub type Result<T> = std::result::Result<T, VideoError>;
