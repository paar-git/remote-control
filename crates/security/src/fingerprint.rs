//! Certificate and public-key fingerprints.
//!
//! A fingerprint is the SHA-256 digest of a DER-encoded certificate or of a raw
//! Ed25519 public key. It is the anchor of device trust: the client pins the agent's
//! fingerprint at pairing time and refuses to talk to anything else.
//!
//! Equality is **constant time**. Fingerprints are not secret, but comparing them in
//! variable time leaks how many leading bytes an attacker has guessed correctly, which
//! turns forging a colliding certificate into an incremental search.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::error::{Result, SecurityError};

/// Length of a SHA-256 digest in bytes.
pub const FINGERPRINT_LEN: usize = 32;

/// A SHA-256 fingerprint of a certificate or public key.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

impl Fingerprint {
    /// Compute the fingerprint of a DER-encoded certificate.
    #[must_use]
    pub fn of_certificate_der(der: &[u8]) -> Self {
        Self(Sha256::digest(der).into())
    }

    /// Compute the fingerprint of a raw Ed25519 public key.
    ///
    /// A domain-separation prefix keeps this in a different space from certificate
    /// fingerprints, so a value from one can never be accepted where the other is
    /// expected even if the underlying bytes coincided.
    #[must_use]
    pub fn of_public_key(public_key: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"rc.fingerprint.ed25519.v1");
        hasher.update(public_key);
        Self(hasher.finalize().into())
    }

    /// Wrap raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; FINGERPRINT_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }

    /// Lowercase hex, the form stored in the database and sent on the wire.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Uppercase groups of four, the form a human compares across two screens.
    ///
    /// Example: `A1B2 C3D4 …`.
    #[must_use]
    pub fn to_display_groups(&self) -> String {
        let hex = hex::encode_upper(self.0);
        hex.as_bytes()
            .chunks(4)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Constant-time equality.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl PartialEq for Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for Fingerprint {}

impl std::hash::Hash for Fingerprint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Renders the hex form. Fingerprints are public values, so this is safe to log.
impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.to_hex())
    }
}

impl FromStr for Fingerprint {
    type Err = SecurityError;

    fn from_str(value: &str) -> Result<Self> {
        // Rejecting uppercase keeps exactly one canonical stored form, so a
        // case-only difference can never masquerade as a different fingerprint.
        if value.len() != FINGERPRINT_LEN * 2 {
            return Err(SecurityError::Invalid {
                field: "fingerprint",
                reason: "must be 64 hex characters",
            });
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SecurityError::Invalid {
                field: "fingerprint",
                reason: "must be lowercase hexadecimal",
            });
        }

        let mut bytes = [0u8; FINGERPRINT_LEN];
        hex::decode_to_slice(value, &mut bytes).map_err(|_| SecurityError::Invalid {
            field: "fingerprint",
            reason: "must be lowercase hexadecimal",
        })?;
        Ok(Self(bytes))
    }
}

impl TryFrom<String> for Fingerprint {
    type Error = SecurityError;

    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl From<Fingerprint> for String {
    fn from(value: Fingerprint) -> Self {
        value.to_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Fingerprint {
        Fingerprint::of_certificate_der(b"certificate bytes")
    }

    #[test]
    fn certificate_fingerprints_are_stable() {
        assert_eq!(sample(), sample());
        assert_eq!(sample().to_hex(), sample().to_hex());
    }

    #[test]
    fn different_input_gives_a_different_fingerprint() {
        assert_ne!(
            Fingerprint::of_certificate_der(b"a"),
            Fingerprint::of_certificate_der(b"b")
        );
    }

    #[test]
    fn a_single_flipped_bit_changes_the_fingerprint() {
        let a = Fingerprint::of_certificate_der(&[0b0000_0000]);
        let b = Fingerprint::of_certificate_der(&[0b0000_0001]);
        assert_ne!(a, b);
    }

    #[test]
    fn public_key_and_certificate_spaces_are_separated() {
        // The same 32 bytes hashed as each kind must not collide.
        let bytes = [7u8; 32];
        assert_ne!(
            Fingerprint::of_public_key(&bytes),
            Fingerprint::of_certificate_der(&bytes),
            "domain separation must keep the two spaces distinct"
        );
    }

    #[test]
    fn hex_roundtrips() {
        let fp = sample();
        assert_eq!(fp.to_hex().parse::<Fingerprint>().unwrap(), fp);
    }

    #[test]
    fn display_groups_are_human_comparable() {
        let display = sample().to_display_groups();
        assert_eq!(display.split(' ').count(), 16);
        assert!(display.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
        assert_eq!(display.to_lowercase().replace(' ', ""), sample().to_hex());
    }

    #[test]
    fn parsing_rejects_malformed_values() {
        for value in [
            "",
            "abc",
            &"a".repeat(63),
            &"a".repeat(65),
            &"g".repeat(64),
            &format!("{}\n", "a".repeat(63)),
            "../../etc/passwd",
        ] {
            assert!(
                value.parse::<Fingerprint>().is_err(),
                "must reject {value:?}"
            );
        }
    }

    #[test]
    fn parsing_rejects_uppercase_to_keep_one_canonical_form() {
        let upper = sample().to_hex().to_uppercase();
        assert!(
            upper.parse::<Fingerprint>().is_err(),
            "a single canonical stored form avoids case-only mismatches"
        );
    }

    #[test]
    fn serde_roundtrips_through_a_hex_string() {
        let fp = sample();
        let json = serde_json::to_string(&fp).unwrap();
        assert_eq!(json, format!("\"{}\"", fp.to_hex()));
        assert_eq!(serde_json::from_str::<Fingerprint>(&json).unwrap(), fp);
    }

    #[test]
    fn serde_rejects_a_malformed_string() {
        assert!(serde_json::from_str::<Fingerprint>("\"nope\"").is_err());
    }

    #[test]
    fn constant_time_equality_agrees_with_ordinary_equality() {
        let a = sample();
        let b = Fingerprint::of_certificate_der(b"different");
        assert!(a.ct_eq(&a));
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn debug_shows_the_hex_and_nothing_else() {
        // Fingerprints are public; the concern is accidental truncation, not secrecy.
        let text = format!("{:?}", sample());
        assert!(text.contains(&sample().to_hex()));
    }
}
