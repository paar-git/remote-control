//! The real OS clipboard, behind the `system` feature.
//!
//! Compiled only when that feature is on, so a build without a desktop never links the
//! windowing libraries this needs. Everything decision-shaped lives in
//! [`crate::ClipboardSync`]; this file is the thinnest possible bridge to `arboard`.

use crate::{ClipboardAccess, ClipboardError};

/// The machine's own clipboard.
pub struct SystemClipboard {
    inner: arboard::Clipboard,
}

impl std::fmt::Debug for SystemClipboard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: a derived Debug on the inner handle risks rendering
        // whatever the clipboard currently holds into a log line.
        f.write_str("SystemClipboard")
    }
}

impl SystemClipboard {
    /// Connect to the machine's clipboard.
    ///
    /// # Errors
    /// [`ClipboardError::Unavailable`] where there is no reachable clipboard — a
    /// headless server, or a Wayland session with no portal.
    pub fn open() -> Result<Self, ClipboardError> {
        arboard::Clipboard::new()
            .map(|inner| Self { inner })
            .map_err(|err| {
                tracing::debug!(%err, "no clipboard is reachable");
                ClipboardError::Unavailable
            })
    }
}

impl ClipboardAccess for SystemClipboard {
    fn read_text(&mut self) -> Result<String, ClipboardError> {
        self.inner.get_text().map_err(|err| match err {
            arboard::Error::ContentNotAvailable => ClipboardError::NotText,
            arboard::Error::ClipboardNotSupported => ClipboardError::Unavailable,
            // No detail carried through: this message can reach the operator on the
            // other machine, and clipboard errors can name applications and windows.
            other => {
                tracing::debug!(%other, "the clipboard could not be read");
                ClipboardError::Refused
            }
        })
    }

    fn write_text(&mut self, text: &str) -> Result<(), ClipboardError> {
        self.inner
            .set_text(text.to_owned())
            .map_err(|err| match err {
                arboard::Error::ClipboardNotSupported => ClipboardError::Unavailable,
                other => {
                    tracing::debug!(%other, "the clipboard could not be written");
                    ClipboardError::Refused
                }
            })
    }
}
