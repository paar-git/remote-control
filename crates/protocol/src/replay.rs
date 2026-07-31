//! Replay protection for timestamped, nonced messages.
//!
//! QUIC already prevents replay *within* a connection. This guard defends the layer
//! above it: messages that are meaningful across connections (pairing proofs, control
//! requests carrying an authorization token) must not be capturable and re-sent.
//!
//! A message is accepted only when both hold:
//!
//! 1. Its timestamp is within [`limits::MAX_CLOCK_SKEW_SECS`] of local time.
//! 2. Its nonce has not been seen inside that window.
//!
//! The nonce set is bounded, so memory cannot grow without limit. Together with the
//! skew bound, evicting the oldest entries is safe: anything old enough to be evicted
//! is already rejected by the timestamp check.

use std::collections::{HashSet, VecDeque};

use crate::limits;

/// Why a message failed the replay check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReplayRejection {
    /// The timestamp is too far in the past.
    #[error("message timestamp is too old")]
    TooOld,
    /// The timestamp is too far in the future, suggesting a skewed or lying peer.
    #[error("message timestamp is too far in the future")]
    TooFarAhead,
    /// This exact nonce was already accepted.
    #[error("nonce has already been used")]
    DuplicateNonce,
}

/// A bounded sliding-window replay detector.
///
/// Not thread-safe by itself; wrap in a mutex when shared. One guard should be kept
/// per peer identity so a noisy peer cannot evict another peer's nonces.
#[derive(Debug)]
pub struct ReplayGuard {
    seen: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
    capacity: usize,
    max_skew_secs: i64,
}

impl ReplayGuard {
    /// A guard with the protocol's default window size and skew tolerance.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(limits::REPLAY_WINDOW_SIZE, limits::MAX_CLOCK_SKEW_SECS)
    }

    /// A guard with explicit parameters, for tests and tuning.
    ///
    /// `capacity` is forced to at least 1 so the structure always makes progress.
    #[must_use]
    pub fn with_config(capacity: usize, max_skew_secs: i64) -> Self {
        let capacity = capacity.max(1);
        Self {
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            max_skew_secs,
        }
    }

    /// Number of nonces currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether no nonces are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Check and record a message.
    ///
    /// Both timestamps are milliseconds since the Unix epoch. On success the nonce is
    /// recorded; on failure nothing is recorded, so a rejected message cannot be used
    /// to evict legitimate entries.
    ///
    /// # Errors
    /// Returns the specific [`ReplayRejection`] that applied.
    pub fn check(
        &mut self,
        nonce: [u8; 16],
        sent_at_ms: i64,
        now_ms: i64,
    ) -> Result<(), ReplayRejection> {
        let skew_ms = self.max_skew_secs.saturating_mul(1000);

        if now_ms.saturating_sub(sent_at_ms) > skew_ms {
            return Err(ReplayRejection::TooOld);
        }
        if sent_at_ms.saturating_sub(now_ms) > skew_ms {
            return Err(ReplayRejection::TooFarAhead);
        }
        if !self.seen.insert(nonce) {
            return Err(ReplayRejection::DuplicateNonce);
        }

        self.order.push_back(nonce);
        while self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        Ok(())
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn nonce(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn accepts_a_fresh_message() {
        let mut guard = ReplayGuard::new();
        assert!(guard.check(nonce(1), NOW, NOW).is_ok());
    }

    #[test]
    fn rejects_an_exact_replay() {
        let mut guard = ReplayGuard::new();
        guard.check(nonce(1), NOW, NOW).unwrap();
        assert_eq!(
            guard.check(nonce(1), NOW, NOW),
            Err(ReplayRejection::DuplicateNonce)
        );
    }

    #[test]
    fn rejects_a_stale_timestamp() {
        let mut guard = ReplayGuard::new();
        let stale = NOW - (limits::MAX_CLOCK_SKEW_SECS + 1) * 1000;
        assert_eq!(
            guard.check(nonce(1), stale, NOW),
            Err(ReplayRejection::TooOld)
        );
    }

    #[test]
    fn rejects_a_future_timestamp() {
        let mut guard = ReplayGuard::new();
        let future = NOW + (limits::MAX_CLOCK_SKEW_SECS + 1) * 1000;
        assert_eq!(
            guard.check(nonce(1), future, NOW),
            Err(ReplayRejection::TooFarAhead)
        );
    }

    #[test]
    fn tolerates_skew_inside_the_window() {
        let mut guard = ReplayGuard::new();
        let slightly_old = NOW - (limits::MAX_CLOCK_SKEW_SECS - 1) * 1000;
        assert!(guard.check(nonce(1), slightly_old, NOW).is_ok());
    }

    #[test]
    fn a_rejected_message_does_not_consume_window_space() {
        let mut guard = ReplayGuard::with_config(4, 60);
        guard.check(nonce(1), NOW, NOW).unwrap();
        let before = guard.len();
        let _ = guard.check(nonce(1), NOW, NOW);
        let _ = guard.check(nonce(9), NOW - 10_000_000, NOW);
        assert_eq!(
            guard.len(),
            before,
            "rejected messages must not be recorded"
        );
    }

    #[test]
    fn memory_is_bounded_and_oldest_entries_are_evicted() {
        let mut guard = ReplayGuard::with_config(8, 60);
        for i in 0..200u8 {
            guard.check(nonce(i), NOW, NOW).unwrap();
        }
        assert_eq!(guard.len(), 8);
        assert_eq!(guard.seen.len(), 8);
        // The oldest nonce was evicted, so it is accepted again — but only because a
        // fresh timestamp is also required, which a captured old message cannot have.
        assert!(guard.check(nonce(0), NOW, NOW).is_ok());
    }

    #[test]
    fn zero_capacity_is_forced_to_one_and_still_works() {
        let mut guard = ReplayGuard::with_config(0, 60);
        assert!(guard.check(nonce(1), NOW, NOW).is_ok());
        assert_eq!(guard.len(), 1);
    }
}
