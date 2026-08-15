//! Turning a display into frames.
//!
//! [`mock`] is always available and is what the test suite runs against, which is what
//! lets the encoder be tested on a machine with no display server. The real backend is
//! behind the `capture` feature for the same reason.

use rc_protocol::desktop::DisplayInfo;

use crate::Result;

pub mod mock;

#[cfg(feature = "capture")]
pub mod xcap_source;

/// One captured frame, in RGBA order.
///
/// RGBA rather than BGRA throughout: the capture backend produces it and the browser's
/// `putImageData` consumes it, so no layer in this pipeline swizzles bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
    /// `width * height * 4` bytes, row-major, RGBA.
    pub rgba: Vec<u8>,
}

/// A source of frames.
pub trait CaptureSource {
    /// Every display this source can capture.
    ///
    /// # Errors
    /// If the platform cannot enumerate displays.
    fn displays(&self) -> Result<Vec<DisplayInfo>>;

    /// Capture the display at `index`.
    ///
    /// # Errors
    /// If the index is unknown, or the platform refuses or fails the capture.
    fn grab(&mut self, index: u8) -> Result<CapturedFrame>;
}
