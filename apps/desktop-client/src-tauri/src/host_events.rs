//! The one place that connects the accept prompt to a real window.
//!
//! Split out from [`crate::host`] deliberately, and the reason is mechanical rather
//! than stylistic. On Windows, a binary that links Tauri's window code needs an
//! application manifest requesting comctl32 version 6 — `TaskDialogIndirect`,
//! `SetWindowSubclass`, `RemoveWindowSubclass` and `DefSubclassProc` are not exported by
//! the 5.82 copy in System32. `tauri-build` supplies that manifest to the application
//! binary. A `cargo test` harness gets no such manifest, so if the window code reaches
//! it the harness dies with `STATUS_ENTRYPOINT_NOT_FOUND` before running a test.
//!
//! Keeping every Tauri type in this module means the linker can drop it from the test
//! binary, because nothing a test constructs can reach it. Adding a Tauri type to
//! [`crate::host`] would quietly break the whole crate's unit tests.

use tauri::Emitter as _;

use crate::host::{ACCEPT_REQUEST_EVENT, ACCEPT_RESOLVED_EVENT, AcceptRequestDto, DialogChannel};

/// Announces accept requests to the webview as Tauri events.
pub struct WindowChannel {
    app: tauri::AppHandle,
}

impl WindowChannel {
    /// Announce into `app`'s webview.
    #[must_use]
    pub const fn new(app: tauri::AppHandle) -> Self {
        Self { app }
    }

    /// Emit, logging rather than propagating a failure.
    ///
    /// There is nothing to recover: a dialog that is never raised means the request
    /// waits out its timeout and is dismissed, which is the safe direction.
    fn emit(&self, event: &str, payload: Option<&AcceptRequestDto>) {
        if let Err(err) = self.app.emit(event, payload) {
            tracing::warn!(%err, event, "could not tell the window about an accept request");
        }
    }
}

impl DialogChannel for WindowChannel {
    fn raised(&self, request: &AcceptRequestDto) {
        self.emit(ACCEPT_REQUEST_EVENT, Some(request));
    }

    fn resolved(&self) {
        self.emit(ACCEPT_RESOLVED_EVENT, None);
    }
}
