//! Attempt throttling with bounded exponential lockout.
//!
//! Used for owner login and, in Phase 3, for per-source connection attempts. The
//! design goals are: make online guessing impractical, keep memory bounded so the
//! throttle itself cannot be turned into a denial-of-service vector, and stay
//! deterministic under test by taking time from an injected [`Clock`].
//!
//! # Lockout schedule
//!
//! Failures below the threshold cost nothing, so an operator who fat-fingers a
//! password once is not punished. From the threshold onwards the delay doubles per
//! failure and is capped:
//!
//! | Consecutive failures | Lockout |
//! |---|---|
//! | 1–2 | none |
//! | 3 | 5s |
//! | 4 | 10s |
//! | 5 | 20s |
//! | 6 | 40s |
//! | … | doubling |
//! | 9+ | 300s (cap) |
//!
//! The cap exists so a locked-out operator is never permanently denied access to
//! their own machine — an attacker cannot use failed attempts to lock the owner out
//! indefinitely.

use std::collections::HashMap;

use crate::clock::Clock;
use crate::error::{Result, SecurityError};

/// Tunable throttle parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThrottlePolicy {
    /// Failures allowed before any lockout applies.
    pub free_attempts: u32,
    /// Lockout applied at the first throttled failure, in seconds.
    pub base_lockout_secs: u64,
    /// Ceiling on the lockout, in seconds.
    pub max_lockout_secs: u64,
    /// Consecutive-failure counters older than this are forgotten, in seconds.
    pub failure_window_secs: u64,
    /// Maximum number of tracked keys, bounding memory.
    pub max_tracked_keys: usize,
}

impl Default for ThrottlePolicy {
    fn default() -> Self {
        Self {
            free_attempts: 2,
            base_lockout_secs: 5,
            max_lockout_secs: 300,
            failure_window_secs: 900,
            max_tracked_keys: 1024,
        }
    }
}

impl ThrottlePolicy {
    /// Lockout duration after `failures` consecutive failures.
    #[must_use]
    pub const fn lockout_secs(&self, failures: u32) -> u64 {
        if failures <= self.free_attempts {
            return 0;
        }
        let steps = failures - self.free_attempts - 1;
        // Saturating shift: beyond 63 doublings the cap applies anyway.
        let multiplier = if steps >= 63 { u64::MAX } else { 1u64 << steps };
        let lockout = self.base_lockout_secs.saturating_mul(multiplier);
        if lockout > self.max_lockout_secs {
            self.max_lockout_secs
        } else {
            lockout
        }
    }
}

/// State tracked for one throttle key.
#[derive(Debug, Clone, Copy)]
struct Entry {
    consecutive_failures: u32,
    /// When the current lockout ends. `0` means not locked.
    locked_until_ms: i64,
    last_activity_ms: i64,
}

/// Tracks failed attempts per key and decides when to block.
///
/// The key is caller-defined: a username for login, a source address for connections.
#[derive(Debug)]
pub struct Throttle {
    policy: ThrottlePolicy,
    entries: HashMap<String, Entry>,
}

impl Throttle {
    /// A throttle using `policy`.
    #[must_use]
    pub fn new(policy: ThrottlePolicy) -> Self {
        Self {
            policy,
            entries: HashMap::new(),
        }
    }

    /// A throttle using the default policy.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ThrottlePolicy::default())
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &ThrottlePolicy {
        &self.policy
    }

    /// Number of keys currently tracked.
    #[must_use]
    pub fn tracked_keys(&self) -> usize {
        self.entries.len()
    }

    /// Check whether `key` may attempt right now.
    ///
    /// This does not record anything: call [`Throttle::record_failure`] or
    /// [`Throttle::record_success`] afterwards depending on the outcome.
    ///
    /// # Errors
    /// Returns [`SecurityError::Throttled`] with the remaining wait if locked out.
    pub fn check(&self, key: &str, clock: &dyn Clock) -> Result<()> {
        let now = clock.now_ms();
        let Some(entry) = self.entries.get(key) else {
            return Ok(());
        };

        if entry.locked_until_ms > now {
            let remaining_ms = entry.locked_until_ms - now;
            return Err(SecurityError::Throttled {
                // Round up, so a caller told to wait N seconds is not rejected again
                // for being a few milliseconds early.
                retry_after_secs: remaining_ms.unsigned_abs().div_ceil(1000).max(1),
            });
        }
        Ok(())
    }

    /// Record a failed attempt and return the resulting lockout in seconds.
    pub fn record_failure(&mut self, key: &str, clock: &dyn Clock) -> u64 {
        let now = clock.now_ms();
        self.expire_stale(now);

        let window_ms =
            i64::try_from(self.policy.failure_window_secs.saturating_mul(1000)).unwrap_or(i64::MAX);

        let entry = self.entries.entry(key.to_string()).or_insert(Entry {
            consecutive_failures: 0,
            locked_until_ms: 0,
            last_activity_ms: now,
        });

        // A long-idle counter has decayed; start over rather than punishing a user
        // for a typo they made hours ago.
        if now.saturating_sub(entry.last_activity_ms) > window_ms {
            entry.consecutive_failures = 0;
        }

        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_activity_ms = now;

        let lockout = self.policy.lockout_secs(entry.consecutive_failures);
        entry.locked_until_ms =
            now.saturating_add(i64::try_from(lockout.saturating_mul(1000)).unwrap_or(i64::MAX));

        // Applied *after* insertion: enforcing the ceiling beforehand would leave the
        // map one over the limit on every call.
        self.enforce_ceiling(now);

        lockout
    }

    /// Record a successful attempt, clearing the counter for `key`.
    ///
    /// Only the successful key is cleared. A success for one account never resets
    /// another account's counter.
    pub fn record_success(&mut self, key: &str, clock: &dyn Clock) {
        self.entries.remove(key);
        self.expire_stale(clock.now_ms());
    }

    /// Consecutive failures currently recorded for `key`.
    #[must_use]
    pub fn failure_count(&self, key: &str) -> u32 {
        self.entries.get(key).map_or(0, |e| e.consecutive_failures)
    }

    /// When `key`'s lockout ends, if it is locked.
    #[must_use]
    pub fn locked_until_ms(&self, key: &str, clock: &dyn Clock) -> Option<i64> {
        self.entries
            .get(key)
            .filter(|e| e.locked_until_ms > clock.now_ms())
            .map(|e| e.locked_until_ms)
    }

    /// Drop entries whose failure window has elapsed and which are not locked.
    fn expire_stale(&mut self, now_ms: i64) {
        let window_ms =
            i64::try_from(self.policy.failure_window_secs.saturating_mul(1000)).unwrap_or(i64::MAX);

        self.entries.retain(|_, entry| {
            entry.locked_until_ms > now_ms
                || now_ms.saturating_sub(entry.last_activity_ms) <= window_ms
        });
    }

    /// Enforce the memory ceiling.
    ///
    /// An attacker cycling through keys must not be able to grow this map without
    /// bound. Currently-locked entries are kept in preference to idle ones, so
    /// flooding cannot be used to clear someone else's active lockout.
    fn enforce_ceiling(&mut self, now_ms: i64) {
        if self.entries.len() > self.policy.max_tracked_keys {
            let mut candidates: Vec<(String, i64, bool)> = self
                .entries
                .iter()
                .map(|(k, e)| (k.clone(), e.last_activity_ms, e.locked_until_ms > now_ms))
                .collect();
            // Unlocked first, then oldest first.
            candidates.sort_by(|a, b| a.2.cmp(&b.2).then(a.1.cmp(&b.1)));

            let excess = self.entries.len() - self.policy.max_tracked_keys;
            for (key, _, _) in candidates.into_iter().take(excess) {
                self.entries.remove(&key);
            }
        }
    }
}

impl Default for Throttle {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;

    #[test]
    fn first_failures_are_free() {
        let clock = TestClock::default();
        let mut throttle = Throttle::with_defaults();

        assert_eq!(throttle.record_failure("owner", &clock), 0);
        assert_eq!(throttle.record_failure("owner", &clock), 0);
        throttle.check("owner", &clock).unwrap();
    }

    #[test]
    fn lockout_engages_after_the_free_attempts() {
        let clock = TestClock::default();
        let mut throttle = Throttle::with_defaults();

        for _ in 0..3 {
            throttle.record_failure("owner", &clock);
        }
        let err = throttle.check("owner", &clock).unwrap_err();
        assert!(
            matches!(err, SecurityError::Throttled { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn lockout_grows_exponentially_and_is_capped() {
        let policy = ThrottlePolicy::default();
        assert_eq!(policy.lockout_secs(1), 0);
        assert_eq!(policy.lockout_secs(2), 0);
        assert_eq!(policy.lockout_secs(3), 5);
        assert_eq!(policy.lockout_secs(4), 10);
        assert_eq!(policy.lockout_secs(5), 20);
        assert_eq!(policy.lockout_secs(6), 40);

        // The cap stops an attacker locking the owner out permanently.
        assert_eq!(policy.lockout_secs(50), policy.max_lockout_secs);
        assert_eq!(policy.lockout_secs(u32::MAX), policy.max_lockout_secs);
    }

    #[test]
    fn lockout_expires_and_access_is_restored() {
        let clock = TestClock::default();
        let mut throttle = Throttle::with_defaults();

        for _ in 0..3 {
            throttle.record_failure("owner", &clock);
        }
        assert!(throttle.check("owner", &clock).is_err());

        clock.advance_secs(5);
        throttle.check("owner", &clock).unwrap();
    }

    #[test]
    fn the_reported_wait_is_accurate_and_never_zero() {
        let clock = TestClock::default();
        let mut throttle = Throttle::with_defaults();

        for _ in 0..4 {
            throttle.record_failure("owner", &clock);
        }
        let Err(SecurityError::Throttled { retry_after_secs }) = throttle.check("owner", &clock)
        else {
            panic!("expected a lockout");
        };
        assert_eq!(retry_after_secs, 10);

        clock.advance_ms(9_500);
        let Err(SecurityError::Throttled { retry_after_secs }) = throttle.check("owner", &clock)
        else {
            panic!("expected a lockout");
        };
        assert_eq!(
            retry_after_secs, 1,
            "a partial second must round up, never to zero"
        );
    }

    #[test]
    fn success_clears_the_counter() {
        let clock = TestClock::default();
        let mut throttle = Throttle::with_defaults();

        for _ in 0..3 {
            throttle.record_failure("owner", &clock);
        }
        assert_eq!(throttle.failure_count("owner"), 3);

        clock.advance_secs(10);
        throttle.record_success("owner", &clock);

        assert_eq!(throttle.failure_count("owner"), 0);
        throttle.check("owner", &clock).unwrap();
    }

    #[test]
    fn success_for_one_key_does_not_reset_another() {
        let clock = TestClock::default();
        let mut throttle = Throttle::with_defaults();

        for _ in 0..3 {
            throttle.record_failure("alice", &clock);
            throttle.record_failure("bob", &clock);
        }
        throttle.record_success("alice", &clock);

        assert_eq!(throttle.failure_count("alice"), 0);
        assert_eq!(
            throttle.failure_count("bob"),
            3,
            "bob's lockout must survive"
        );
        assert!(throttle.check("bob", &clock).is_err());
    }

    #[test]
    fn keys_are_throttled_independently() {
        let clock = TestClock::default();
        let mut throttle = Throttle::with_defaults();

        for _ in 0..5 {
            throttle.record_failure("attacker", &clock);
        }
        assert!(throttle.check("attacker", &clock).is_err());
        throttle.check("owner", &clock).unwrap();
    }

    #[test]
    fn counters_decay_after_the_failure_window() {
        let clock = TestClock::default();
        let mut throttle = Throttle::with_defaults();

        throttle.record_failure("owner", &clock);
        throttle.record_failure("owner", &clock);

        clock.advance_secs(ThrottlePolicy::default().failure_window_secs + 1);

        // The decayed counter restarts, so this is treated as a first failure.
        assert_eq!(throttle.record_failure("owner", &clock), 0);
        assert_eq!(throttle.failure_count("owner"), 1);
    }

    #[test]
    fn memory_stays_bounded_under_key_flooding() {
        let clock = TestClock::default();
        let policy = ThrottlePolicy {
            max_tracked_keys: 16,
            ..ThrottlePolicy::default()
        };
        let mut throttle = Throttle::new(policy);

        for i in 0..1000 {
            throttle.record_failure(&format!("key-{i}"), &clock);
        }
        assert!(
            throttle.tracked_keys() <= 16,
            "throttle must not grow without bound: {} keys",
            throttle.tracked_keys()
        );
    }

    #[test]
    fn flooding_cannot_evict_an_active_lockout() {
        let clock = TestClock::default();
        let policy = ThrottlePolicy {
            max_tracked_keys: 8,
            ..ThrottlePolicy::default()
        };
        let mut throttle = Throttle::new(policy);

        // Lock the real account out.
        for _ in 0..5 {
            throttle.record_failure("owner", &clock);
        }
        assert!(throttle.check("owner", &clock).is_err());

        // Flood with single failures, which are free and therefore not locked.
        for i in 0..500 {
            throttle.record_failure(&format!("noise-{i}"), &clock);
        }

        assert!(
            throttle.check("owner", &clock).is_err(),
            "an active lockout must survive eviction pressure"
        );
    }

    #[test]
    fn unknown_keys_are_always_allowed() {
        let clock = TestClock::default();
        let throttle = Throttle::with_defaults();
        throttle.check("never-seen", &clock).unwrap();
        assert_eq!(throttle.failure_count("never-seen"), 0);
    }

    #[test]
    fn locked_until_reports_only_active_lockouts() {
        let clock = TestClock::default();
        let mut throttle = Throttle::with_defaults();

        assert_eq!(throttle.locked_until_ms("owner", &clock), None);
        for _ in 0..3 {
            throttle.record_failure("owner", &clock);
        }
        assert!(throttle.locked_until_ms("owner", &clock).is_some());

        clock.advance_secs(10);
        assert_eq!(throttle.locked_until_ms("owner", &clock), None);
    }
}
