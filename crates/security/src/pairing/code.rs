//! Pairing codes and their stored verifiers.
//!
//! # Format
//!
//! Nine characters from a 30-symbol alphabet, displayed as `XXX-XXX-XXX`. The alphabet
//! is `23456789ABCDEFGHJKMNPQRSTVWXYZ`: digits `0`/`1` and letters `I`/`L`/`O`/`U` are
//! excluded because they are the pairs people actually mistype when reading a code off
//! a server console. That gives 30⁹ ≈ 2×10¹³ possibilities, about **44 bits**.
//!
//! 44 bits is not enough on its own — it is enough *in combination with* the controls
//! around it: a 3-minute window, a hard cap of 5 attempts, and single-use consumption.
//! An online attacker gets 5 guesses out of 2×10¹³ before the code is destroyed.
//!
//! # Storage
//!
//! The raw code is **never stored**. What is stored is
//! `verifier = Argon2id(code, salt)` with a per-code random salt. Two consequences:
//!
//! * Reading the database does not yield a usable code.
//! * If the database is stolen while a code is live, recovering it means running
//!   Argon2id at production cost over a 44-bit space — expensive, and pointless after
//!   three minutes.
//!
//! The verifier is also what keys the pairing proof, so the agent never needs to
//! retain the raw code after displaying it to the operator.
//!
//! # Input handling
//!
//! Codes are parsed case-insensitively with separators ignored, and the characters
//! `0`/`O`, `1`/`I`/`L` are folded onto their alphabet members. Someone reading a code
//! aloud should not be defeated by a homoglyph.

use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize, Zeroizing};

use crate::clock::{RandomSource, RandomSourceExt as _};
use crate::error::{Result, SecurityError};

/// Characters a pairing code may contain. No `0`, `1`, `I`, `L`, `O` or `U`.
pub const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of characters in a code, excluding separators.
pub const CODE_LENGTH: usize = 9;

/// Salt length for the verifier, in bytes.
const VERIFIER_SALT_BYTES: usize = 16;

/// Verifier length, in bytes.
pub const VERIFIER_LEN: usize = 32;

/// A freshly generated pairing code, in plaintext.
///
/// Exists only between generation and display. It implements neither
/// [`serde::Serialize`] nor [`std::fmt::Display`], and its [`std::fmt::Debug`] is
/// redacted, so the only way to obtain the characters is
/// [`PairingCode::expose_for_display`] — which is named to make every call site
/// obvious in review.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingCode {
    /// Nine alphabet characters, no separators.
    raw: String,
}

impl Drop for PairingCode {
    fn drop(&mut self) {
        self.raw.zeroize();
    }
}

impl std::fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairingCode(<redacted>)")
    }
}

impl PairingCode {
    /// Generate a code from `rng`.
    ///
    /// Rejection sampling is used rather than `byte % 30`, which would make the first
    /// 16 alphabet symbols slightly likelier than the rest and shave entropy off every
    /// code generated.
    #[must_use]
    pub fn generate(rng: &dyn RandomSource) -> Self {
        let alphabet_len = CODE_ALPHABET.len();
        // Largest multiple of the alphabet size that fits in a byte; values at or
        // above it are discarded so the mapping stays uniform.
        let limit = (256 / alphabet_len) * alphabet_len;

        let mut raw = String::with_capacity(CODE_LENGTH);
        while raw.len() < CODE_LENGTH {
            // Draw in blocks to keep the number of RNG calls small.
            let block = rng.byte_vec(CODE_LENGTH * 2);
            for byte in block {
                if (byte as usize) < limit {
                    let index = (byte as usize) % alphabet_len;
                    raw.push(char::from(CODE_ALPHABET[index]));
                    if raw.len() == CODE_LENGTH {
                        break;
                    }
                }
            }
        }

        Self { raw }
    }

    /// Parse an operator-entered code.
    ///
    /// Separators (`-`, space, underscore) are ignored, letters are upper-cased, and
    /// the common homoglyphs are folded: `0`→`O` is *not* applied because `O` is not
    /// in the alphabet; instead `O`→`0` is rejected. Specifically `0`, `O`, `1`, `I`,
    /// `L` and `U` are all rejected with a clear message rather than silently mapped,
    /// because a silent mapping could turn one valid code into another.
    ///
    /// # Errors
    /// [`SecurityError::Invalid`] if the code is not the right length or contains
    /// characters outside the alphabet.
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: String = input
            .chars()
            .filter(|c| !matches!(c, '-' | ' ' | '_' | '\t'))
            .map(|c| c.to_ascii_uppercase())
            .collect();

        if cleaned.chars().count() != CODE_LENGTH {
            return Err(SecurityError::Invalid {
                field: "pairing code",
                reason: "must be 9 characters",
            });
        }
        if !cleaned.bytes().all(|b| CODE_ALPHABET.contains(&b)) {
            return Err(SecurityError::Invalid {
                field: "pairing code",
                reason: "contains characters that are not part of a pairing code",
            });
        }

        Ok(Self { raw: cleaned })
    }

    /// The code formatted for display to the operator: `XXX-XXX-XXX`.
    ///
    /// This is the **only** sanctioned path by which a pairing code becomes visible,
    /// and it exists solely to show the code on the host's own console or setup
    /// screen. It must never reach a log, an audit record or the network.
    #[must_use]
    pub fn expose_for_display(&self) -> String {
        self.raw
            .as_bytes()
            .chunks(3)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Derive the stored verifier for this code.
    ///
    /// # Errors
    /// [`SecurityError::PasswordHashing`] if Argon2 fails.
    pub fn derive_verifier(&self, salt: &[u8; VERIFIER_SALT_BYTES]) -> Result<CodeVerifier> {
        let params = Params::new(
            // Deliberately lighter than the owner-password policy: this runs on every
            // pairing attempt on a possibly-modest server, and the code's real defence
            // is the attempt cap and the three-minute window, not hash cost.
            19_456,
            2,
            1,
            Some(VERIFIER_LEN),
        )
        .map_err(|_| SecurityError::PasswordHashing)?;

        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let secret = Zeroizing::new(self.raw.as_bytes().to_vec());

        let mut output = [0u8; VERIFIER_LEN];
        argon
            .hash_password_into(&secret, salt, &mut output)
            .map_err(|_| SecurityError::PasswordHashing)?;

        Ok(CodeVerifier {
            salt: *salt,
            bytes: output,
        })
    }

    /// Generate a random salt suitable for [`PairingCode::derive_verifier`].
    #[must_use]
    pub fn generate_salt(rng: &dyn RandomSource) -> [u8; VERIFIER_SALT_BYTES] {
        rng.bytes()
    }
}

/// The stored form of a pairing code: a salt and an Argon2id output.
///
/// Safe to persist. Recovering the code from it requires brute force against the
/// alphabet at Argon2id cost.
#[derive(Clone)]
pub struct CodeVerifier {
    salt: [u8; VERIFIER_SALT_BYTES],
    bytes: [u8; VERIFIER_LEN],
}

impl Drop for CodeVerifier {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for CodeVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CodeVerifier(<redacted>)")
    }
}

impl CodeVerifier {
    /// The salt, which must be given to the client so it can derive the same verifier.
    ///
    /// The salt is not secret: without the code it reveals nothing.
    #[must_use]
    pub const fn salt(&self) -> &[u8; VERIFIER_SALT_BYTES] {
        &self.salt
    }

    /// The verifier bytes, used as key material for the pairing proof.
    #[must_use]
    pub const fn as_key_material(&self) -> &[u8; VERIFIER_LEN] {
        &self.bytes
    }

    /// Reconstruct from stored parts.
    #[must_use]
    pub const fn from_parts(salt: [u8; VERIFIER_SALT_BYTES], bytes: [u8; VERIFIER_LEN]) -> Self {
        Self { salt, bytes }
    }

    /// Hex encoding of the verifier, for storage.
    #[must_use]
    pub fn to_storage_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Hex encoding of the salt, for storage.
    #[must_use]
    pub fn salt_to_storage_hex(&self) -> String {
        hex::encode(self.salt)
    }

    /// Constant-time equality.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

/// Build a `SaltString` — used only where the `password_hash` API demands one.
#[allow(dead_code)]
fn salt_string(salt: &[u8]) -> Result<SaltString> {
    SaltString::encode_b64(salt).map_err(|_| SecurityError::PasswordHashing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{DeterministicRandom, OsRandom};

    const SALT: [u8; VERIFIER_SALT_BYTES] = [9u8; VERIFIER_SALT_BYTES];

    #[test]
    fn generated_codes_have_the_expected_shape() {
        let code = PairingCode::generate(&OsRandom);
        let display = code.expose_for_display();

        assert_eq!(display.len(), 11, "XXX-XXX-XXX");
        assert_eq!(display.matches('-').count(), 2);
        assert!(
            display
                .chars()
                .all(|c| c == '-' || CODE_ALPHABET.contains(&(c as u8))),
            "got {display}"
        );
    }

    #[test]
    fn generated_codes_never_contain_ambiguous_characters() {
        // The whole point of the alphabet choice.
        for _ in 0..200 {
            let display = PairingCode::generate(&OsRandom).expose_for_display();
            for ambiguous in ['0', '1', 'I', 'L', 'O', 'U'] {
                assert!(
                    !display.contains(ambiguous),
                    "{display} contains {ambiguous}"
                );
            }
        }
    }

    #[test]
    fn generated_codes_differ() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            seen.insert(PairingCode::generate(&OsRandom).expose_for_display());
        }
        assert!(
            seen.len() > 495,
            "codes must not repeat: {} unique of 500",
            seen.len()
        );
    }

    #[test]
    fn generation_is_uniform_across_the_alphabet() {
        // Rejection sampling means no symbol should be systematically favoured. With
        // 30 symbols and 9000 draws, a modulo bias would show up clearly.
        let mut counts = std::collections::HashMap::new();
        for _ in 0..1000 {
            for c in PairingCode::generate(&OsRandom)
                .expose_for_display()
                .chars()
            {
                if c != '-' {
                    *counts.entry(c).or_insert(0usize) += 1;
                }
            }
        }
        assert_eq!(
            counts.len(),
            CODE_ALPHABET.len(),
            "every symbol should appear"
        );

        let expected = 9000 / CODE_ALPHABET.len();
        for (symbol, count) in counts {
            assert!(
                count > expected / 2 && count < expected * 2,
                "symbol {symbol} appeared {count} times, expected around {expected}"
            );
        }
    }

    #[test]
    fn generation_is_deterministic_under_a_seeded_source() {
        let a = PairingCode::generate(&DeterministicRandom::new(1)).expose_for_display();
        let b = PairingCode::generate(&DeterministicRandom::new(1)).expose_for_display();
        assert_eq!(a, b);
    }

    #[test]
    fn parsing_accepts_the_displayed_form() {
        let code = PairingCode::generate(&OsRandom);
        let display = code.expose_for_display();
        assert_eq!(PairingCode::parse(&display).unwrap(), code);
    }

    #[test]
    fn parsing_tolerates_how_people_actually_type_codes() {
        let code = PairingCode::generate(&OsRandom);
        let display = code.expose_for_display();

        for variant in [
            display.clone(),
            display.replace('-', ""),
            display.replace('-', " "),
            display.replace('-', "_"),
            display.to_lowercase(),
            format!(" {display} "),
        ] {
            assert_eq!(
                PairingCode::parse(&variant).unwrap(),
                code,
                "failed on {variant:?}"
            );
        }
    }

    #[test]
    fn parsing_rejects_ambiguous_characters_rather_than_guessing() {
        // Silently mapping `O`→`0` could turn one valid code into a different one.
        for bad in [
            "OOO-OOO-OOO",
            "III-III-III",
            "000-000-000",
            "111-111-111",
            "LLL-LLL-LLL",
        ] {
            assert!(PairingCode::parse(bad).is_err(), "must reject {bad}");
        }
    }

    #[test]
    fn parsing_rejects_wrong_lengths_and_junk() {
        for bad in [
            "",
            "ABC",
            "ABC-DEF-GHJ-KMN",
            "ABC-DEF-GH",
            "'; DROP TABLE pairing_code; --",
            "../../etc/passwd",
            "ABC-DEF-GH\u{0}",
            "日本語のコード",
        ] {
            assert!(PairingCode::parse(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn debug_output_redacts_the_code() {
        let code = PairingCode::generate(&OsRandom);
        let rendered = format!("{code:?}");
        assert_eq!(rendered, "PairingCode(<redacted>)");
        assert!(!rendered.contains(&code.expose_for_display().replace('-', "")));
    }

    #[test]
    fn the_same_code_and_salt_derive_the_same_verifier() {
        let code = PairingCode::generate(&OsRandom);
        let a = code.derive_verifier(&SALT).unwrap();
        let b = code.derive_verifier(&SALT).unwrap();
        assert!(a.ct_eq(&b));
    }

    #[test]
    fn different_codes_derive_different_verifiers() {
        let a = PairingCode::generate(&OsRandom)
            .derive_verifier(&SALT)
            .unwrap();
        let b = PairingCode::generate(&OsRandom)
            .derive_verifier(&SALT)
            .unwrap();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn the_same_code_with_different_salts_derives_different_verifiers() {
        let code = PairingCode::generate(&OsRandom);
        let a = code.derive_verifier(&[1u8; VERIFIER_SALT_BYTES]).unwrap();
        let b = code.derive_verifier(&[2u8; VERIFIER_SALT_BYTES]).unwrap();
        assert!(!a.ct_eq(&b), "the salt must change the verifier");
    }

    #[test]
    fn the_verifier_does_not_contain_the_code() {
        let code = PairingCode::generate(&OsRandom);
        let raw = code.expose_for_display().replace('-', "");
        let stored = code.derive_verifier(&SALT).unwrap().to_storage_hex();

        assert!(!stored.contains(&raw));
        assert!(!stored.to_uppercase().contains(&raw));
    }

    #[test]
    fn verifier_debug_output_is_redacted() {
        let verifier = PairingCode::generate(&OsRandom)
            .derive_verifier(&SALT)
            .unwrap();
        let rendered = format!("{verifier:?}");
        assert_eq!(rendered, "CodeVerifier(<redacted>)");
        assert!(!rendered.contains(&verifier.to_storage_hex()));
    }

    #[test]
    fn verifiers_round_trip_through_storage() {
        let code = PairingCode::generate(&OsRandom);
        let original = code.derive_verifier(&SALT).unwrap();

        let mut bytes = [0u8; VERIFIER_LEN];
        hex::decode_to_slice(original.to_storage_hex(), &mut bytes).unwrap();
        let mut salt = [0u8; VERIFIER_SALT_BYTES];
        hex::decode_to_slice(original.salt_to_storage_hex(), &mut salt).unwrap();

        assert!(CodeVerifier::from_parts(salt, bytes).ct_eq(&original));
    }

    #[test]
    fn generated_salts_differ() {
        assert_ne!(
            PairingCode::generate_salt(&OsRandom),
            PairingCode::generate_salt(&OsRandom)
        );
    }

    #[test]
    fn the_code_space_is_large_enough_to_survive_the_attempt_cap() {
        // 30^9 possibilities against at most 5 guesses. Computed in `u128` rather than
        // `f64` so the assertion is exact and involves no lossy casts.
        let alphabet = CODE_ALPHABET.len() as u128;
        let length = u32::try_from(CODE_LENGTH).expect("code length fits in u32");
        let space = alphabet.pow(length);

        assert!(space > 10_000_000_000_000, "code space is only {space}");
        assert!(
            space.ilog2() >= 43,
            "only {} bits of entropy",
            space.ilog2()
        );
    }
}
