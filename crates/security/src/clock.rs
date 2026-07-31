//! Injectable time and randomness.
//!
//! Every security decision that depends on "now" or on fresh random bytes takes it
//! through one of these traits. Production wires in the system clock and the OS
//! CSPRNG; tests wire in deterministic implementations so expiry, throttling and
//! lockout can be exercised exactly rather than by sleeping.
//!
//! The test implementations live behind `#[cfg(test)]`-free code on purpose: the
//! agent's own integration tests in other crates need them too. They are documented
//! as test-only and are never constructed by production code paths.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A source of wall-clock time, in milliseconds since the Unix epoch.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Current time in milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64;
}

/// The real system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        rc_protocol::now_ms()
    }
}

/// A clock that only moves when told to.
///
/// **Test support.** Use this to make expiry and lockout deterministic.
#[derive(Debug, Clone)]
pub struct TestClock {
    now_ms: Arc<AtomicU64>,
}

impl TestClock {
    /// A clock starting at `start_ms`.
    #[must_use]
    pub fn new(start_ms: i64) -> Self {
        Self {
            now_ms: Arc::new(AtomicU64::new(start_ms.max(0).unsigned_abs())),
        }
    }

    /// Move the clock forward.
    pub fn advance_ms(&self, delta_ms: u64) {
        self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }

    /// Move the clock forward by whole seconds.
    pub fn advance_secs(&self, delta_secs: u64) {
        self.advance_ms(delta_secs.saturating_mul(1000));
    }

    /// Jump to an absolute time.
    pub fn set_ms(&self, now_ms: i64) {
        self.now_ms
            .store(now_ms.max(0).unsigned_abs(), Ordering::SeqCst);
    }
}

impl Default for TestClock {
    fn default() -> Self {
        // An arbitrary fixed point in 2023, chosen so timestamps look plausible.
        Self::new(1_700_000_000_000)
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> i64 {
        i64::try_from(self.now_ms.load(Ordering::SeqCst)).unwrap_or(i64::MAX)
    }
}

/// A source of cryptographically secure random bytes.
///
/// Implementations used in production **must** be a CSPRNG. The test implementation
/// is deliberately not, and is documented as such at its definition.
pub trait RandomSource: Send + Sync + std::fmt::Debug {
    /// Fill `dst` with random bytes.
    fn fill(&self, dst: &mut [u8]);
}

/// Convenience helpers over any [`RandomSource`].
///
/// These live in a separate, blanket-implemented trait rather than as defaulted
/// methods because a const-generic method would make [`RandomSource`] not
/// dyn-compatible, and the whole point is to pass `&dyn RandomSource` around.
pub trait RandomSourceExt: RandomSource {
    /// Return `N` random bytes.
    fn bytes<const N: usize>(&self) -> [u8; N] {
        let mut buf = [0u8; N];
        self.fill(&mut buf);
        buf
    }

    /// Return `n` random bytes.
    fn byte_vec(&self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        self.fill(&mut buf);
        buf
    }
}

impl<T: RandomSource + ?Sized> RandomSourceExt for T {}

/// The operating system CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, dst: &mut [u8]) {
        // `getrandom` reads the OS entropy source directly. A failure here means the
        // platform cannot provide randomness, which is unrecoverable for a security
        // component: every key, nonce and pairing code depends on it. Aborting is the
        // only safe response — continuing with predictable bytes would silently
        // produce guessable secrets.
        #[allow(clippy::panic)]
        if let Err(err) = getrandom::fill(dst) {
            panic!("the operating system CSPRNG is unavailable: {err}");
        }
    }
}

/// A deterministic, reproducible byte source.
///
/// **Test support only. This is not a CSPRNG and must never be used in production.**
/// It exists so that generated pairing codes, nonces and salts can be asserted on.
#[derive(Debug, Clone)]
pub struct DeterministicRandom {
    state: Arc<AtomicU64>,
}

impl DeterministicRandom {
    /// A source seeded with `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        // Avoid the all-zero state, which is a fixed point for xorshift.
        Self {
            state: Arc::new(AtomicU64::new(if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            })),
        }
    }
}

impl Default for DeterministicRandom {
    fn default() -> Self {
        Self::new(0xDEAD_BEEF)
    }
}

impl RandomSource for DeterministicRandom {
    fn fill(&self, dst: &mut [u8]) {
        for chunk in dst.chunks_mut(8) {
            // xorshift64*, adequate for reproducible test vectors.
            let mut x = self.state.load(Ordering::SeqCst);
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.state.store(x, Ordering::SeqCst);
            let value = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
            chunk.copy_from_slice(&value[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_a_plausible_time() {
        let now = SystemClock.now_ms();
        assert!(now > 1_577_836_800_000, "later than 2020");
        assert!(now < 4_102_444_800_000, "earlier than 2100");
    }

    #[test]
    fn test_clock_only_moves_when_advanced() {
        let clock = TestClock::new(1000);
        assert_eq!(clock.now_ms(), 1000);
        assert_eq!(clock.now_ms(), 1000);

        clock.advance_ms(500);
        assert_eq!(clock.now_ms(), 1500);

        clock.advance_secs(2);
        assert_eq!(clock.now_ms(), 3500);
    }

    #[test]
    fn test_clock_shares_state_across_clones() {
        // Components take their own handle; they must all observe the same time.
        let clock = TestClock::new(0);
        let other = clock.clone();
        clock.advance_secs(10);
        assert_eq!(other.now_ms(), 10_000);
    }

    #[test]
    fn os_random_produces_different_values() {
        let a: [u8; 32] = OsRandom.bytes();
        let b: [u8; 32] = OsRandom.bytes();
        assert_ne!(a, b, "an OS CSPRNG must not repeat");
        assert_ne!(a, [0u8; 32], "must not return all zeroes");
    }

    #[test]
    fn os_random_fills_odd_lengths() {
        for len in [1usize, 7, 15, 33] {
            let mut buf = vec![0u8; len];
            OsRandom.fill(&mut buf);
            assert_eq!(buf.len(), len);
        }
    }

    #[test]
    fn deterministic_random_is_reproducible() {
        let a: [u8; 32] = DeterministicRandom::new(42).bytes();
        let b: [u8; 32] = DeterministicRandom::new(42).bytes();
        assert_eq!(a, b);

        let c: [u8; 32] = DeterministicRandom::new(43).bytes();
        assert_ne!(a, c, "different seeds must diverge");
    }

    #[test]
    fn deterministic_random_advances_between_calls() {
        let rng = DeterministicRandom::new(7);
        let a: [u8; 16] = rng.bytes();
        let b: [u8; 16] = rng.bytes();
        assert_ne!(a, b, "successive draws must differ");
    }
}
