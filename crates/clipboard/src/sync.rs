//! Deciding what to publish and what to write, without the two ends echoing forever.

/// The largest clipboard text this build will carry, in bytes.
///
/// A clipboard can hold a whole document. Sending one over the session's control
/// channel would stall everything else queued behind it — including the operator's own
/// keystrokes — so anything larger is dropped rather than truncated. Truncating would
/// paste half a file and look like corruption on the far end.
pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

/// What this end has most recently seen, so an echo can be recognised.
///
/// Holds a digest, never the text: a clipboard routinely carries a password or a
/// private key, and answering "have I already seen this?" does not require keeping it.
#[derive(Debug, Default)]
pub struct ClipboardSync {
    seen: Option<[u8; 32]>,
}

impl ClipboardSync {
    /// A sync that has seen nothing yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { seen: None }
    }

    /// Decide whether locally-observed clipboard text should be published to the peer.
    ///
    /// Returns `false` for text that arrived *from* the peer and was written here,
    /// which is what stops the two ends echoing forever. Also refuses empty text — a
    /// cleared clipboard is not worth a round trip — and anything over
    /// [`MAX_CLIPBOARD_BYTES`].
    pub fn should_publish(&mut self, text: &str) -> bool {
        if text.is_empty() || text.len() > MAX_CLIPBOARD_BYTES {
            return false;
        }
        self.record_if_new(text)
    }

    /// Decide whether text received from the peer should be written to this clipboard.
    ///
    /// Returns `false` when this end already holds it, so a peer that republishes
    /// unchanged text does not make this machine's own watcher fire.
    pub fn should_apply(&mut self, text: &str) -> bool {
        if text.is_empty() || text.len() > MAX_CLIPBOARD_BYTES {
            return false;
        }
        self.record_if_new(text)
    }

    /// Note text as seen, reporting whether it differed from what was already known.
    fn record_if_new(&mut self, text: &str) -> bool {
        let digest = *blake3::hash(text.as_bytes()).as_bytes();
        if self.seen == Some(digest) {
            return false;
        }
        self.seen = Some(digest);
        true
    }

    /// Forget what was seen, so the next observation is published whatever it is.
    ///
    /// Used when a session ends: the next one starts with its own peer, which has never
    /// been sent anything.
    pub fn reset(&mut self) {
        self.seen = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_written_from_the_peer_is_not_published_back() {
        // The whole reason this type exists. Without it: A publishes, B applies, B's
        // watcher sees the change and publishes it back, A applies, A's watcher fires —
        // forever, as fast as both ends poll.
        let mut sync = ClipboardSync::new();
        assert!(sync.should_apply("hunter2"));
        assert!(!sync.should_publish("hunter2"));
    }

    #[test]
    fn the_peer_republishing_unchanged_text_is_not_reapplied() {
        // The mirror of the case above, and the other half of the loop: applying it
        // again would make this machine's own watcher fire.
        let mut sync = ClipboardSync::new();
        assert!(sync.should_publish("hunter2"));
        assert!(!sync.should_apply("hunter2"));
    }

    #[test]
    fn copying_something_genuinely_new_is_published() {
        let mut sync = ClipboardSync::new();
        assert!(sync.should_publish("first"));
        assert!(sync.should_publish("second"));
    }

    #[test]
    fn copying_the_same_thing_twice_is_published_once() {
        // A poll-based watcher sees the same text on every tick; only a change is news.
        let mut sync = ClipboardSync::new();
        assert!(sync.should_publish("same"));
        assert!(!sync.should_publish("same"));
        assert!(!sync.should_publish("same"));
    }

    #[test]
    fn returning_to_earlier_text_is_published_again() {
        // Only the most recent observation is remembered, so copying A, then B, then A
        // again is three pieces of news. Remembering every value ever seen would be a
        // growing store of other people's passwords.
        let mut sync = ClipboardSync::new();
        assert!(sync.should_publish("alpha"));
        assert!(sync.should_publish("beta"));
        assert!(sync.should_publish("alpha"));
    }

    #[test]
    fn an_empty_clipboard_is_not_worth_a_round_trip() {
        let mut sync = ClipboardSync::new();
        assert!(!sync.should_publish(""));
        assert!(!sync.should_apply(""));
    }

    #[test]
    fn an_oversized_clipboard_is_dropped_rather_than_truncated() {
        // Truncating would paste half a document and read as corruption on the far end.
        let mut sync = ClipboardSync::new();
        let huge = "x".repeat(MAX_CLIPBOARD_BYTES + 1);
        assert!(!sync.should_publish(&huge));
        assert!(!sync.should_apply(&huge));
    }

    #[test]
    fn text_exactly_at_the_limit_still_travels() {
        let mut sync = ClipboardSync::new();
        let exact = "x".repeat(MAX_CLIPBOARD_BYTES);
        assert!(sync.should_publish(&exact));
    }

    #[test]
    fn an_oversized_clipboard_does_not_disturb_what_was_already_seen() {
        // Refusing must not overwrite the digest, or the text before it would be
        // republished the next time the watcher ticks.
        let mut sync = ClipboardSync::new();
        assert!(sync.should_publish("kept"));
        assert!(!sync.should_publish(&"x".repeat(MAX_CLIPBOARD_BYTES + 1)));
        assert!(
            !sync.should_publish("kept"),
            "the earlier text is still known"
        );
    }

    #[test]
    fn a_reset_starts_the_next_session_fresh() {
        // A new session is a new peer, which has never been sent anything.
        let mut sync = ClipboardSync::new();
        assert!(sync.should_publish("carried"));
        sync.reset();
        assert!(sync.should_publish("carried"));
    }

    #[test]
    fn nothing_here_retains_the_text_itself() {
        // A clipboard routinely holds a password. The bookkeeping answers "seen this
        // before?", which a digest answers as well as the text does.
        let mut sync = ClipboardSync::new();
        sync.should_publish("correct horse battery staple");
        let debug = format!("{sync:?}");
        assert!(
            !debug.contains("correct horse"),
            "clipboard text must not be retained: {debug}"
        );
    }
}
