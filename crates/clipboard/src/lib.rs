//! Clipboard sharing between two machines.
//!
//! # The problem this crate exists to solve is the loop
//!
//! Copying is not a request; it is something a machine notices happening to it. So both
//! ends watch their own clipboard and publish what they see. Naively, that never
//! settles: A publishes, B writes what A sent, B's own watcher notices the change and
//! publishes it back, A writes it, A's watcher notices — forever, at whatever rate the
//! two poll. [`ClipboardSync`] is the state that stops it, and it is the part of this
//! crate worth testing, which is why it is pure and lives apart from any OS call.
//!
//! # Nothing here retains clipboard text
//!
//! The bookkeeping needs to answer one question — "have I already seen this?" — and a
//! digest answers it as well as the text does. A clipboard routinely holds a password
//! or a private key, so this crate keeps a BLAKE3 digest of what it last saw and never
//! a copy of the text itself. Text passes through and is dropped.
//!
//! For the same reason nothing here is ever logged at a level that records content;
//! `crates/host-agent/src/logging.rs` already names clipboard contents among the things
//! that must never reach a log.
//!
//! # The OS backend is optional
//!
//! Off by default, following `rc-input`'s `inject` feature for the same reason: the
//! logic above must build and run where there is no desktop at all.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod sync;

pub use sync::{ClipboardSync, MAX_CLIPBOARD_BYTES};

#[cfg(feature = "system")]
mod backend;
#[cfg(feature = "system")]
pub use backend::SystemClipboard;

/// Why a clipboard operation could not be carried out.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClipboardError {
    /// No clipboard is reachable: a headless session, or a build without the backend.
    #[error("no clipboard is available on this machine")]
    Unavailable,
    /// The clipboard held something, but not text this build can carry.
    #[error("the clipboard does not currently hold text")]
    NotText,
    /// The platform refused the read or write.
    ///
    /// Carries no detail from the OS on purpose: the message is shown to an operator on
    /// the *other* machine, and clipboard failures can name window titles and
    /// applications.
    #[error("the clipboard could not be read or written")]
    Refused,
}

/// Read and write the machine's clipboard.
///
/// A trait so the sync logic can be exercised against an in-memory clipboard, and so a
/// build without the `system` feature still has a shape to compile against.
pub trait ClipboardAccess {
    /// The clipboard's current text.
    ///
    /// # Errors
    /// The clipboard is unreachable, holds something other than text, or was refused.
    fn read_text(&mut self) -> Result<String, ClipboardError>;

    /// Replace the clipboard's text.
    ///
    /// # Errors
    /// The clipboard is unreachable or the write was refused.
    fn write_text(&mut self, text: &str) -> Result<(), ClipboardError>;
}

/// An in-memory clipboard, for tests and for builds with no OS backend.
///
/// Not a stub that silently does nothing: it behaves like a real clipboard, so a test
/// that drives the sync logic through it exercises the same paths a desktop would.
#[derive(Debug, Default)]
pub struct MemoryClipboard {
    text: Option<String>,
}

impl MemoryClipboard {
    /// An empty clipboard.
    #[must_use]
    pub const fn new() -> Self {
        Self { text: None }
    }

    /// Put text on it, as though a user had pressed Copy.
    pub fn set(&mut self, text: impl Into<String>) {
        self.text = Some(text.into());
    }
}

impl ClipboardAccess for MemoryClipboard {
    fn read_text(&mut self) -> Result<String, ClipboardError> {
        self.text.clone().ok_or(ClipboardError::NotText)
    }

    fn write_text(&mut self, text: &str) -> Result<(), ClipboardError> {
        self.text = Some(text.to_owned());
        Ok(())
    }
}
