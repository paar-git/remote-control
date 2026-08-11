//! Unattended-access password hashing with Argon2id.
//!
//! # Parameter choice
//!
//! Production uses **Argon2id, m=19456 KiB (19 MiB), t=2, p=1**, which is the first
//! configuration in the OWASP Password Storage Cheat Sheet's recommended set. The
//! reasoning:
//!
//! * **Argon2id**, not Argon2i or Argon2d: it is the variant designed to resist both
//!   side-channel and GPU/ASIC attacks, and is the one RFC 9106 recommends by default.
//! * **19 MiB** is the memory cost that makes GPU cracking uneconomic while still
//!   completing in well under a second on a home server, and — importantly — while
//!   fitting comfortably on the low-memory Linux boxes people actually run agents on.
//! * **t=2, p=1** pairs with that memory figure in the OWASP guidance. Raising `t`
//!   buys less than raising `m` for the same wall-clock cost.
//!
//! Parameters are recorded *inside* the stored PHC string, so a stored hash always
//! carries the settings it was made with. [`PasswordCredential::needs_rehash`] reports
//! when a stored hash was made with weaker settings than current policy, letting the
//! application transparently upgrade it on the next successful login.
//!
//! # What this module guarantees
//!
//! * A unique 16-byte CSPRNG salt per password. No global pepper — a pepper the agent
//!   stores next to the database adds nothing against the attacker who has the
//!   database.
//! * Verification is constant-time within the Argon2 comparison, and the *code path*
//!   is uniform: a missing account still performs a hash before returning the same
//!   [`SecurityError::InvalidCredentials`], so timing does not reveal whether an
//!   account exists.
//! * Password bytes are held in [`Zeroizing`] buffers and wiped as soon as hashing or
//!   verification completes.
//! * No normalisation. The password is hashed as the exact UTF-8 bytes supplied, so a
//!   password set on one platform verifies identically on another. Unicode
//!   normalisation would silently change what the user typed.

use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::clock::{RandomSource, RandomSourceExt as _};
use crate::error::{Result, SecurityError};

/// Minimum accepted password length in bytes.
///
/// This is a personal-administration tool with a throttled local login, not a public
/// web service; 12 characters with lockout is a materially stronger position than a
/// longer minimum with none.
pub const MIN_PASSWORD_BYTES: usize = 12;

/// Maximum accepted password length in bytes.
///
/// Bounded so a very long input cannot be used to make hashing arbitrarily expensive.
/// Argon2's cost is dominated by `m` and `t`, but the bound removes the question.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Salt length in bytes.
const SALT_BYTES: usize = 16;

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashingPolicy {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of iterations.
    pub iterations: u32,
    /// Degree of parallelism.
    pub parallelism: u32,
}

impl HashingPolicy {
    /// The production policy. See the module documentation for the rationale.
    pub const PRODUCTION: Self = Self {
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    };

    /// Deliberately cheap parameters for tests.
    ///
    /// **Never use in production.** Present so the test suite can exercise hashing
    /// logic hundreds of times without spending a second per call.
    pub const FAST_FOR_TESTS: Self = Self {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    /// Whether a hash made with `self` is weaker than `policy` requires.
    #[must_use]
    pub const fn is_weaker_than(&self, policy: &Self) -> bool {
        self.memory_kib < policy.memory_kib
            || self.iterations < policy.iterations
            || self.parallelism < policy.parallelism
    }

    fn to_argon2(self) -> Result<Argon2<'static>> {
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, None)
            .map_err(|_| SecurityError::PasswordHashing)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

impl Default for HashingPolicy {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// An optional unattended-access password: an Argon2id PHC string and nothing else.
///
/// Deliberately implements neither [`serde::Serialize`] nor [`std::fmt::Display`], so
/// it cannot be returned from a Tauri command or interpolated into a log line by
/// accident. [`std::fmt::Debug`] redacts the hash.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordCredential {
    phc: String,
}

impl std::fmt::Debug for PasswordCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordCredential(<redacted>)")
    }
}

impl PasswordCredential {
    /// Hash `password` under `policy`.
    ///
    /// # Errors
    /// [`SecurityError::WeakPassword`] if the password fails policy checks, or
    /// [`SecurityError::PasswordHashing`] if hashing fails.
    pub fn create(password: &str, policy: HashingPolicy, rng: &dyn RandomSource) -> Result<Self> {
        validate_password(password)?;

        let salt_bytes: [u8; SALT_BYTES] = rng.bytes();
        let salt =
            SaltString::encode_b64(&salt_bytes).map_err(|_| SecurityError::PasswordHashing)?;

        // Wiped when this scope ends, so the password bytes do not linger in the heap
        // copy we hand to Argon2.
        let secret = Zeroizing::new(password.as_bytes().to_vec());

        let phc = policy
            .to_argon2()?
            .hash_password(&secret, &salt)
            .map_err(|_| SecurityError::PasswordHashing)?
            .to_string();

        Ok(Self { phc })
    }

    /// Wrap an existing PHC string read from the database.
    ///
    /// # Errors
    /// [`SecurityError::PasswordHashing`] if the string is not a valid PHC encoding.
    pub fn from_phc(phc: impl Into<String>) -> Result<Self> {
        let phc = phc.into();
        PasswordHash::new(&phc).map_err(|_| SecurityError::PasswordHashing)?;
        Ok(Self { phc })
    }

    /// The PHC string, for storage only.
    ///
    /// Named to make a reviewer look twice at any call site that is not the
    /// persistence layer.
    #[must_use]
    pub fn expose_phc_for_storage(&self) -> &str {
        &self.phc
    }

    /// Verify `password` against this credential.
    ///
    /// # Errors
    /// [`SecurityError::InvalidCredentials`] if it does not match.
    pub fn verify(&self, password: &str) -> Result<()> {
        // Over-long input is rejected before hashing, but with the *same* error as a
        // wrong password so it is not distinguishable.
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(SecurityError::InvalidCredentials);
        }

        let parsed = PasswordHash::new(&self.phc).map_err(|_| SecurityError::PasswordHashing)?;
        let secret = Zeroizing::new(password.as_bytes().to_vec());

        Argon2::default()
            .verify_password(&secret, &parsed)
            .map_err(|_| SecurityError::InvalidCredentials)
    }

    /// The parameters this hash was created with.
    ///
    /// # Errors
    /// [`SecurityError::PasswordHashing`] if the stored string cannot be parsed.
    pub fn policy(&self) -> Result<HashingPolicy> {
        let parsed = PasswordHash::new(&self.phc).map_err(|_| SecurityError::PasswordHashing)?;
        let params = Params::try_from(&parsed).map_err(|_| SecurityError::PasswordHashing)?;

        Ok(HashingPolicy {
            memory_kib: params.m_cost(),
            iterations: params.t_cost(),
            parallelism: params.p_cost(),
        })
    }

    /// Whether this hash should be recomputed to meet `policy`.
    ///
    /// Callers rehash on the next successful login, when the plaintext is available.
    #[must_use]
    pub fn needs_rehash(&self, policy: HashingPolicy) -> bool {
        self.policy()
            .is_ok_and(|current| current.is_weaker_than(&policy))
    }

    /// Whether the stored hash uses the Argon2id algorithm.
    ///
    /// A hash in some other format is treated as needing replacement rather than
    /// trusted, which is what makes migrating away from a legacy scheme detectable.
    #[must_use]
    pub fn is_argon2id(&self) -> bool {
        PasswordHash::new(&self.phc).is_ok_and(|parsed| parsed.algorithm.as_str() == "argon2id")
    }
}

/// Reject passwords that fail policy.
///
/// # Errors
/// [`SecurityError::WeakPassword`] describing the problem without echoing the input.
pub fn validate_password(password: &str) -> Result<()> {
    if password.len() < MIN_PASSWORD_BYTES {
        return Err(SecurityError::WeakPassword {
            reason: "must be at least 12 characters",
        });
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(SecurityError::WeakPassword {
            reason: "must be at most 1024 bytes",
        });
    }
    // A password consisting only of whitespace is almost certainly a mistake, and
    // leading/trailing whitespace is impossible to see when re-entering it.
    if password.trim().is_empty() {
        return Err(SecurityError::WeakPassword {
            reason: "must not be only whitespace",
        });
    }
    if password.chars().any(|c| c == '\0') {
        return Err(SecurityError::WeakPassword {
            reason: "must not contain null characters",
        });
    }
    Ok(())
}

/// Spend the same work as a real verification without having a credential.
///
/// Called when authentication is attempted for an account that does not exist, so the
/// response time does not reveal whether it exists. Always returns
/// [`SecurityError::InvalidCredentials`].
///
/// # Errors
/// Always. That is its purpose.
pub fn verify_against_nothing(password: &str, policy: HashingPolicy) -> Result<()> {
    // A fixed salt is fine: the result is discarded, and the point is the work, not
    // the output.
    let salt =
        SaltString::encode_b64(&[0x5A; SALT_BYTES]).map_err(|_| SecurityError::PasswordHashing)?;
    let secret = Zeroizing::new(password.as_bytes().to_vec());

    let _ = policy.to_argon2()?.hash_password(&secret, &salt);
    Err(SecurityError::InvalidCredentials)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::OsRandom;

    const GOOD: &str = "correct horse battery staple";
    const POLICY: HashingPolicy = HashingPolicy::FAST_FOR_TESTS;

    fn credential() -> PasswordCredential {
        PasswordCredential::create(GOOD, POLICY, &OsRandom).unwrap()
    }

    #[test]
    fn the_correct_password_verifies() {
        credential().verify(GOOD).unwrap();
    }

    #[test]
    fn a_wrong_password_is_rejected() {
        let credential = credential();
        for wrong in [
            "correct horse battery stapl",
            "correct horse battery staplee",
            "Correct horse battery staple",
            "",
            "               ",
        ] {
            assert!(
                matches!(
                    credential.verify(wrong),
                    Err(SecurityError::InvalidCredentials)
                ),
                "must reject {wrong:?}"
            );
        }
    }

    #[test]
    fn every_hash_uses_a_unique_salt() {
        // Identical passwords must not produce identical stored hashes, otherwise the
        // database reveals which accounts share a password.
        let a = credential();
        let b = credential();
        assert_ne!(a.expose_phc_for_storage(), b.expose_phc_for_storage());
        a.verify(GOOD).unwrap();
        b.verify(GOOD).unwrap();
    }

    #[test]
    fn the_stored_hash_is_argon2id() {
        let phc = credential().expose_phc_for_storage().to_string();
        assert!(phc.starts_with("$argon2id$"), "got {phc}");
        assert!(credential().is_argon2id());
    }

    #[test]
    fn the_stored_hash_never_contains_the_password() {
        let phc = credential().expose_phc_for_storage().to_string();
        assert!(!phc.contains(GOOD));
        assert!(!phc.contains("staple"));
    }

    #[test]
    fn debug_output_redacts_the_hash() {
        let rendered = format!("{:?}", credential());
        assert_eq!(rendered, "PasswordCredential(<redacted>)");
        assert!(!rendered.contains("argon2"));
    }

    #[test]
    fn short_passwords_are_rejected_at_creation() {
        let err = PasswordCredential::create("short", POLICY, &OsRandom).unwrap_err();
        assert!(
            matches!(err, SecurityError::WeakPassword { .. }),
            "got {err:?}"
        );
        assert!(
            PasswordCredential::create(&"a".repeat(MIN_PASSWORD_BYTES), POLICY, &OsRandom).is_ok()
        );
    }

    #[test]
    fn overlong_passwords_are_rejected_at_creation() {
        let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(matches!(
            PasswordCredential::create(&long, POLICY, &OsRandom),
            Err(SecurityError::WeakPassword { .. })
        ));
    }

    #[test]
    fn overlong_input_at_verification_looks_like_a_wrong_password() {
        // It must not be distinguishable from an ordinary failure.
        let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(matches!(
            credential().verify(&long),
            Err(SecurityError::InvalidCredentials)
        ));
    }

    #[test]
    fn whitespace_only_and_null_bearing_passwords_are_rejected() {
        assert!(validate_password("                 ").is_err());
        assert!(validate_password("has\0null padding here").is_err());
    }

    #[test]
    fn passwords_are_not_normalised() {
        // The composed and decomposed forms of "é" are different byte sequences. A
        // password set as one must not verify as the other, because silently
        // normalising would change what the user actually typed.
        let composed = "passwordé-long-enough";
        let decomposed = "passworde\u{0301}-long-enough";
        assert_ne!(composed.as_bytes(), decomposed.as_bytes());

        let credential = PasswordCredential::create(composed, POLICY, &OsRandom).unwrap();
        credential.verify(composed).unwrap();
        assert!(credential.verify(decomposed).is_err());
    }

    #[test]
    fn leading_and_trailing_whitespace_is_significant() {
        let credential = PasswordCredential::create(" padded password ", POLICY, &OsRandom).unwrap();
        credential.verify(" padded password ").unwrap();
        assert!(credential.verify("padded password").is_err());
    }

    #[test]
    fn unicode_passwords_round_trip() {
        for password in [
            "日本語のパスワードです",
            "пароль-достаточно-длинный",
            "🔐🔐🔐🔐🔐🔐",
        ] {
            let credential = PasswordCredential::create(password, POLICY, &OsRandom).unwrap();
            credential.verify(password).unwrap();
        }
    }

    #[test]
    fn stored_parameters_are_readable() {
        let credential = PasswordCredential::create(GOOD, POLICY, &OsRandom).unwrap();
        assert_eq!(credential.policy().unwrap(), POLICY);
    }

    #[test]
    fn a_hash_made_with_weaker_parameters_is_flagged_for_upgrade() {
        let weak = PasswordCredential::create(GOOD, HashingPolicy::FAST_FOR_TESTS, &OsRandom).unwrap();
        assert!(
            weak.needs_rehash(HashingPolicy::PRODUCTION),
            "a test-strength hash must be flagged against production policy"
        );
    }

    #[test]
    fn a_hash_at_current_strength_is_not_flagged() {
        let current = PasswordCredential::create(GOOD, POLICY, &OsRandom).unwrap();
        assert!(!current.needs_rehash(POLICY));
    }

    #[test]
    fn upgrade_detection_compares_every_parameter() {
        let base = HashingPolicy {
            memory_kib: 1000,
            iterations: 3,
            parallelism: 2,
        };
        assert!(!base.is_weaker_than(&base));
        assert!(
            HashingPolicy {
                memory_kib: 999,
                ..base
            }
            .is_weaker_than(&base)
        );
        assert!(
            HashingPolicy {
                iterations: 2,
                ..base
            }
            .is_weaker_than(&base)
        );
        assert!(
            HashingPolicy {
                parallelism: 1,
                ..base
            }
            .is_weaker_than(&base)
        );
        assert!(
            !HashingPolicy {
                memory_kib: 2000,
                ..base
            }
            .is_weaker_than(&base)
        );
    }

    #[test]
    fn production_policy_meets_owasp_minimums() {
        let policy = HashingPolicy::PRODUCTION;
        assert!(
            policy.memory_kib >= 19_456,
            "OWASP minimum memory for Argon2id t=2 p=1"
        );
        assert!(policy.iterations >= 2);
        assert!(policy.parallelism >= 1);
    }

    #[test]
    fn credentials_round_trip_through_storage() {
        let original = credential();
        let reloaded =
            PasswordCredential::from_phc(original.expose_phc_for_storage().to_string()).unwrap();

        reloaded.verify(GOOD).unwrap();
        assert!(reloaded.verify("wrong password here").is_err());
    }

    #[test]
    fn malformed_stored_hashes_are_rejected() {
        for bad in [
            "",
            "not a phc string",
            "$argon2id$",
            "$unknown$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA",
        ] {
            assert!(
                PasswordCredential::from_phc(bad).is_err(),
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn verifying_against_nothing_always_fails() {
        // The no-such-account path must never accidentally succeed.
        for password in ["", GOOD, "anything at all"] {
            assert!(matches!(
                verify_against_nothing(password, POLICY),
                Err(SecurityError::InvalidCredentials)
            ));
        }
    }

    #[test]
    fn the_no_account_path_returns_the_same_error_as_a_wrong_password() {
        // Account enumeration protection: identical error, identical shape.
        let wrong = credential()
            .verify("definitely wrong password")
            .unwrap_err();
        let missing = verify_against_nothing("definitely wrong password", POLICY).unwrap_err();
        assert_eq!(wrong.to_string(), missing.to_string());
    }
}
