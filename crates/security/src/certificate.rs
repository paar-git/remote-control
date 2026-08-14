//! Reading a device's identity out of the certificate it presented.
//!
//! # Why this is sound
//!
//! Every device in this system generates an Ed25519 identity key and a certificate
//! **self-signed by that key** — see [`crate::identity::DeviceIdentity`]. The
//! certificate's subject public key therefore *is* the identity public key, and a peer
//! that completed a TLS handshake with it has proved possession of the private half.
//!
//! That makes the identity fingerprint of a presented certificate a value the peer
//! cannot lie about, unlike anything it reports in a message body. It is the only
//! sanctioned trust key: `DeviceDescriptor::device_id` is a claim, and is display text.
//!
//! # Why renewal is safe
//!
//! Renewal issues a new certificate from the same key. The certificate's own digest
//! changes; the value computed here does not. Trust anchored on it survives an ordinary
//! maintenance event that would otherwise fail every trusted device at once.
//!
//! # Why this parses rather than scans
//!
//! [`crate::identity`] verifies that a *known* key is present in a certificate by
//! scanning for its SPKI byte sequence, which is sound for a yes/no answer about a key
//! you already hold. Extraction is a different question with a different failure mode:
//! the answer becomes a trust key. A scan would take the first SPKI-shaped sequence
//! anywhere in the DER, including one an attacker planted in an extension, which would
//! let a certificate authenticated by one key claim the identity of another. So the
//! subject public key field is located by parsing the structure, and nothing else in the
//! certificate can be mistaken for it.

use x509_parser::prelude::*;

use crate::error::{Result, SecurityError};
use crate::fingerprint::Fingerprint;

/// Length of a raw Ed25519 public key.
const ED25519_KEY_LEN: usize = 32;

/// The Ed25519 subject public key of a DER-encoded certificate.
///
/// # Errors
/// [`SecurityError::MalformedIdentity`] if the bytes are not a parseable certificate, if
/// its subject public key algorithm is not Ed25519, or if that key is not 32 bytes. All
/// three are refusals rather than approximations: coercing some other key into 32 bytes
/// would mint a stable identity for a device that has none, and that value could then be
/// trusted.
pub fn identity_key_of_certificate(der: &[u8]) -> Result<[u8; ED25519_KEY_LEN]> {
    let (_, certificate) =
        X509Certificate::from_der(der).map_err(|_| SecurityError::MalformedIdentity)?;

    let spki = certificate.public_key();
    if spki.algorithm.algorithm != oid_registry::OID_SIG_ED25519 {
        return Err(SecurityError::MalformedIdentity);
    }

    spki.subject_public_key
        .as_ref()
        .try_into()
        .map_err(|_| SecurityError::MalformedIdentity)
}

/// The identity fingerprint of a DER-encoded certificate. **The trust key.**
///
/// # Errors
/// As [`identity_key_of_certificate`].
pub fn identity_fingerprint_of_certificate(der: &[u8]) -> Result<Fingerprint> {
    identity_key_of_certificate(der).map(|key| Fingerprint::of_public_key(&key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;
    use crate::identity::DeviceIdentity;

    #[test]
    fn a_generated_certificate_yields_the_identity_behind_it() {
        // The whole trust model rests on this: the fingerprint derived from the
        // certificate a peer presents must equal the fingerprint that peer publishes as
        // its own identity. If the two ever diverge, every trusted device stops being
        // recognised at once.
        let clock = TestClock::default();
        let identity = DeviceIdentity::generate("test-device", &clock).unwrap();
        let public = identity.public();

        let derived = identity_fingerprint_of_certificate(&public.certificate_der).unwrap();

        assert_eq!(derived, public.identity_fingerprint);
    }

    #[test]
    fn a_renewed_certificate_yields_the_same_identity() {
        // This is the bug the change exists to fix. Pinning the certificate makes an
        // ordinary renewal look like a substituted machine; pinning the identity does
        // not.
        let clock = TestClock::default();
        let identity = DeviceIdentity::generate("test-device", &clock).unwrap();
        let before = identity_fingerprint_of_certificate(&identity.public().certificate_der)
            .expect("a freshly generated certificate must carry its identity");
        let certificate_before = identity.public().certificate_fingerprint;

        clock.advance_ms(24 * 3600 * 1000);
        let renewed = identity.renew_certificate("test-device", &clock).unwrap();

        let after = identity_fingerprint_of_certificate(&renewed.public().certificate_der).unwrap();
        assert_eq!(before, after, "renewal must not change the identity");
        assert_ne!(
            certificate_before,
            renewed.public().certificate_fingerprint,
            "the test is meaningless unless the certificate actually changed"
        );
    }

    #[test]
    fn two_devices_never_share_an_identity() {
        let clock = TestClock::default();
        let a = DeviceIdentity::generate("a", &clock).unwrap();
        let b = DeviceIdentity::generate("b", &clock).unwrap();

        assert_ne!(
            identity_fingerprint_of_certificate(&a.public().certificate_der).unwrap(),
            identity_fingerprint_of_certificate(&b.public().certificate_der).unwrap()
        );
    }

    #[test]
    fn garbage_is_refused_rather_than_hashed() {
        // Falling back to hashing whatever bytes arrived would mint a stable "identity"
        // for a peer that has no identity key at all, and that value could then be
        // trusted.
        for bad in [b"".as_slice(), b"not a certificate", &[0x30, 0x82, 0x01]] {
            assert!(
                identity_key_of_certificate(bad).is_err(),
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn a_non_ed25519_certificate_is_refused() {
        // An ECDSA certificate's subject public key is not 32 bytes of Ed25519, and must
        // not be coerced into a value that would be treated as one.
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["other".to_owned()]).unwrap();
        let certificate = params.self_signed(&key).unwrap();

        assert!(identity_key_of_certificate(certificate.der()).is_err());
    }

    #[test]
    fn a_planted_spki_sequence_does_not_become_the_identity() {
        // The reason this module parses instead of scanning. A certificate carrying a
        // second, attacker-chosen Ed25519 SPKI byte sequence in an extension must still
        // resolve to the key it actually authenticates with -- otherwise a certificate
        // signed by one key could claim another device's identity.
        const ED25519_SPKI_HEADER: [u8; 12] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let victim_key = [0x77u8; 32];
        let mut planted = Vec::from(ED25519_SPKI_HEADER);
        planted.extend_from_slice(&victim_key);

        let clock = TestClock::default();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["attacker".to_owned()]).unwrap();
        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 99999, 1],
            planted,
        )];
        let certificate = params.self_signed(&key).unwrap();
        let _ = &clock;

        // Without this the test would pass vacuously if the extension were ever dropped
        // during encoding: the planted sequence has to genuinely be in the bytes for its
        // rejection to mean anything.
        let mut needle = Vec::from(ED25519_SPKI_HEADER);
        needle.extend_from_slice(&victim_key);
        assert!(
            certificate
                .der()
                .windows(needle.len())
                .any(|window| window == needle.as_slice()),
            "the planted sequence must actually be present for this test to test anything"
        );

        let derived = identity_key_of_certificate(certificate.der()).unwrap();

        assert_ne!(
            derived, victim_key,
            "the planted sequence must never be read as the certificate's identity"
        );
        assert_eq!(
            Fingerprint::of_public_key(&derived),
            Fingerprint::of_public_key(
                &<[u8; 32]>::try_from(key.public_key_raw()).expect("an Ed25519 key is 32 bytes")
            ),
            "the identity must be the key the certificate actually authenticates with"
        );
    }
}
