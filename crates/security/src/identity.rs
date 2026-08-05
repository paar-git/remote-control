//! Long-lived device identity.
//!
//! # What "identity" means here
//!
//! A device's identity is its **Ed25519 public key**, not its certificate. The
//! certificate is a rotatable credential that the identity key signs for itself. This
//! distinction is what makes certificate renewal safe:
//!
//! | Value | Derived from | Changes on renewal? | Role |
//! |---|---|---|---|
//! | [`DeviceId`] | identity public key | no | stable name |
//! | identity fingerprint | identity public key | no | **trust anchor** |
//! | certificate fingerprint | certificate DER | yes | current credential |
//!
//! A peer pins the *identity* fingerprint. When a renewed certificate arrives, its
//! fingerprint differs but the identity behind it does not, and continuity is provable
//! because the new certificate carries the same public key. A change in the identity
//! fingerprint is never automatically accepted — see [`crate::trust`].
//!
//! # Private key handling
//!
//! The signing key is held in an [`ed25519_dalek::SigningKey`], which zeroizes on
//! drop. It is never logged (the [`std::fmt::Debug`] implementation redacts it), never
//! serialized, and never leaves this crate except as PKCS#8 bytes handed directly to
//! the keystore for encryption.

use std::fmt;

use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rc_protocol::DeviceId;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::error::{Result, SecurityError};
use crate::fingerprint::Fingerprint;

/// Domain-separation label for deriving a device id from an identity key.
const DEVICE_ID_LABEL: &[u8] = b"rc.device-id.v1";

/// Default certificate lifetime in days.
///
/// 398 days is the maximum lifetime public CAs may issue and what browser and TLS
/// stacks are known to tolerate. These certificates are self-signed and pinned rather
/// than publicly trusted, but staying inside the well-trodden range avoids surprises
/// from libraries that enforce it.
pub const CERTIFICATE_LIFETIME_DAYS: i64 = 398;

/// Number of days before expiry at which renewal should happen.
pub const CERTIFICATE_RENEW_BEFORE_DAYS: i64 = 30;

/// The public half of a device identity: everything safe to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentityPublic {
    /// Stable identifier derived from the identity public key.
    pub device_id: DeviceId,
    /// Raw Ed25519 public key.
    pub identity_public_key: [u8; 32],
    /// Fingerprint of the identity public key. **The trust anchor.**
    pub identity_fingerprint: Fingerprint,
    /// Fingerprint of the current certificate. Changes on renewal.
    pub certificate_fingerprint: Fingerprint,
    /// DER-encoded self-signed certificate.
    pub certificate_der: Vec<u8>,
    /// PEM-encoded form of the same certificate.
    pub certificate_pem: String,
    /// When the certificate becomes valid, milliseconds since the Unix epoch.
    pub certificate_not_before_ms: i64,
    /// When the certificate expires, milliseconds since the Unix epoch.
    pub certificate_not_after_ms: i64,
    /// Increments on every certificate renewal. Lets a peer detect an out-of-date
    /// cached credential without comparing bytes.
    pub certificate_version: u32,
}

impl DeviceIdentityPublic {
    /// Whether the certificate is currently within its validity window.
    #[must_use]
    pub fn is_valid_at(&self, now_ms: i64) -> bool {
        now_ms >= self.certificate_not_before_ms && now_ms < self.certificate_not_after_ms
    }

    /// Whether the certificate is close enough to expiry to warrant renewal.
    #[must_use]
    pub fn needs_renewal_at(&self, now_ms: i64) -> bool {
        let threshold = CERTIFICATE_RENEW_BEFORE_DAYS * 24 * 3600 * 1000;
        now_ms.saturating_add(threshold) >= self.certificate_not_after_ms
    }

    /// Verify a signature made by this identity over `message` with `label`.
    ///
    /// # Errors
    /// Returns [`SecurityError::BadSignature`] if verification fails.
    pub fn verify(&self, label: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        let verifying = VerifyingKey::from_bytes(&self.identity_public_key)
            .map_err(|_| SecurityError::MalformedIdentity)?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| SecurityError::BadSignature)?;

        verifying
            .verify(
                &domain_separated(label, message),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| SecurityError::BadSignature)
    }
}

/// A device identity, including its private signing key.
///
/// This type must never be serialized, logged or sent across a process boundary.
pub struct DeviceIdentity {
    signing_key: SigningKey,
    public: DeviceIdentityPublic,
    /// When the identity key itself was created. Unchanged by certificate renewal.
    created_at_ms: i64,
}

/// Redacts the private key. Only public material is shown.
impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.public.device_id)
            .field("identity_fingerprint", &self.public.identity_fingerprint)
            .field(
                "certificate_fingerprint",
                &self.public.certificate_fingerprint,
            )
            .field("certificate_version", &self.public.certificate_version)
            .field("created_at_ms", &self.created_at_ms)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl DeviceIdentity {
    /// Generate a brand-new identity with a fresh key and certificate.
    ///
    /// `subject_name` appears in the certificate's common name. It is cosmetic: trust
    /// comes from the pinned fingerprint, never from the name.
    ///
    /// # Errors
    /// Fails if key or certificate generation fails.
    pub fn generate(subject_name: &str, clock: &dyn Clock) -> Result<Self> {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(|err| {
            tracing::error!(%err, "device key generation failed");
            SecurityError::KeyGeneration
        })?;

        Self::from_key_pair(key_pair, subject_name, clock.now_ms(), clock.now_ms(), 1)
    }

    /// Reconstruct an identity from stored PKCS#8 private key bytes.
    ///
    /// The certificate is regenerated deterministically from the same key, so the
    /// identity fingerprint and device id are unchanged; only the certificate's
    /// validity window is recomputed.
    ///
    /// # Errors
    /// Returns [`SecurityError::MalformedIdentity`] if the bytes are not a usable
    /// Ed25519 PKCS#8 key.
    pub fn from_pkcs8(
        pkcs8_der: &[u8],
        subject_name: &str,
        created_at_ms: i64,
        certificate_version: u32,
        clock: &dyn Clock,
    ) -> Result<Self> {
        let key_pair = rcgen::KeyPair::try_from(pkcs8_der).map_err(|err| {
            tracing::warn!(%err, "stored device key could not be parsed");
            SecurityError::MalformedIdentity
        })?;

        Self::from_key_pair(
            key_pair,
            subject_name,
            created_at_ms,
            clock.now_ms(),
            certificate_version,
        )
    }

    /// Rebuild an identity from a stored key **and its stored certificate**.
    ///
    /// # Why the certificate has to be stored rather than reissued
    ///
    /// Peers pin the certificate fingerprint at the TLS layer. Reissuing the
    /// certificate from the same key on every load produces a *different* certificate
    /// — different validity dates, different serial, different DER — and therefore a
    /// different fingerprint. Every paired peer would then refuse the agent after its
    /// next restart, reporting an identity change, which is the loudest failure the
    /// system has and would fire on an ordinary reboot.
    ///
    /// So the certificate is persisted alongside the key and reused verbatim. Reissuing
    /// is a deliberate act ([`DeviceIdentity::renew_certificate`]), not a side effect of
    /// starting up.
    ///
    /// # Errors
    /// [`SecurityError::MalformedIdentity`] if the key cannot be parsed, or if the
    /// stored certificate does not carry the public key belonging to that private key —
    /// which would mean the two halves came from different identities.
    pub fn from_stored(
        pkcs8_der: &[u8],
        certificate_der: Vec<u8>,
        subject_name: &str,
        created_at_ms: i64,
        certificate_version: u32,
        not_before_ms: i64,
        not_after_ms: i64,
    ) -> Result<Self> {
        validate_subject_name(subject_name)?;

        let signing_key =
            SigningKey::from_pkcs8_der(pkcs8_der).map_err(|_| SecurityError::MalformedIdentity)?;
        let identity_public_key = signing_key.verifying_key().to_bytes();

        // The stored certificate must contain the public key of the stored private key.
        // Without this check, a keystore assembled from two sources could present a
        // certificate whose fingerprint peers pin while holding a different key.
        if !certificate_embeds_public_key(&certificate_der, &identity_public_key) {
            tracing::error!("the stored certificate does not match the stored private key");
            return Err(SecurityError::MalformedIdentity);
        }

        Ok(Self {
            public: DeviceIdentityPublic {
                device_id: derive_device_id(&identity_public_key),
                identity_fingerprint: Fingerprint::of_public_key(&identity_public_key),
                certificate_fingerprint: Fingerprint::of_certificate_der(&certificate_der),
                identity_public_key,
                certificate_pem: pem_of(&certificate_der),
                certificate_der,
                certificate_not_before_ms: not_before_ms,
                certificate_not_after_ms: not_after_ms,
                certificate_version,
            },
            signing_key,
            created_at_ms,
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    fn from_key_pair(
        // Taken by value even though only borrowed: `rcgen::KeyPair` holds private key
        // material, so consuming it here guarantees the caller cannot keep a second
        // handle to it after the identity has been built.
        key_pair: rcgen::KeyPair,
        subject_name: &str,
        created_at_ms: i64,
        issued_at_ms: i64,
        certificate_version: u32,
    ) -> Result<Self> {
        validate_subject_name(subject_name)?;

        // Held in `Zeroizing` so the PKCS#8 bytes are wiped once the dalek key and the
        // certificate have been built from them.
        let pkcs8 = Zeroizing::new(key_pair.serialize_der());
        let signing_key =
            SigningKey::from_pkcs8_der(&pkcs8).map_err(|_| SecurityError::MalformedIdentity)?;
        let identity_public_key = signing_key.verifying_key().to_bytes();

        let not_before_ms = issued_at_ms;
        let not_after_ms =
            issued_at_ms.saturating_add(CERTIFICATE_LIFETIME_DAYS * 24 * 3600 * 1000);

        let mut params = rcgen::CertificateParams::new(vec![subject_name.to_string()])
            .map_err(|_| SecurityError::CertificateGeneration)?;
        params.distinguished_name = {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, subject_name);
            dn.push(rcgen::DnType::OrganizationName, "Remote Control");
            dn
        };
        params.not_before =
            offset_from_ms(not_before_ms).ok_or(SecurityError::CertificateGeneration)?;
        params.not_after =
            offset_from_ms(not_after_ms).ok_or(SecurityError::CertificateGeneration)?;
        // This certificate authenticates exactly one endpoint and signs nothing else.
        params.is_ca = rcgen::IsCa::ExplicitNoCa;

        let certificate = params.self_signed(&key_pair).map_err(|err| {
            tracing::error!(%err, "certificate generation failed");
            SecurityError::CertificateGeneration
        })?;

        let certificate_der = certificate.der().to_vec();
        let certificate_pem = certificate.pem();

        Ok(Self {
            public: DeviceIdentityPublic {
                device_id: derive_device_id(&identity_public_key),
                identity_fingerprint: Fingerprint::of_public_key(&identity_public_key),
                certificate_fingerprint: Fingerprint::of_certificate_der(&certificate_der),
                identity_public_key,
                certificate_der,
                certificate_pem,
                certificate_not_before_ms: not_before_ms,
                certificate_not_after_ms: not_after_ms,
                certificate_version,
            },
            signing_key,
            created_at_ms,
        })
    }

    /// The public half, safe to share, store and display.
    #[must_use]
    pub const fn public(&self) -> &DeviceIdentityPublic {
        &self.public
    }

    /// Stable device identifier.
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.public.device_id
    }

    /// When the identity key was created.
    #[must_use]
    pub const fn created_at_ms(&self) -> i64 {
        self.created_at_ms
    }

    /// Export the private key as PKCS#8 DER, for the keystore to encrypt.
    ///
    /// The result is wrapped in [`Zeroizing`] so it is wiped when dropped. This is the
    /// only way private material leaves this type, and the only intended caller is
    /// [`crate::keystore`].
    ///
    /// # Errors
    /// Fails only if encoding fails, which indicates a bug.
    pub fn export_pkcs8(&self) -> Result<Zeroizing<Vec<u8>>> {
        let document = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|_| SecurityError::MalformedIdentity)?;
        Ok(Zeroizing::new(document.as_bytes().to_vec()))
    }

    /// Sign `message` under a domain-separation `label`.
    ///
    /// The label is bound into the signed bytes, so a signature produced for one
    /// purpose (say, a pairing proof) can never be replayed as a signature for
    /// another (say, a session token).
    #[must_use]
    pub fn sign(&self, label: &[u8], message: &[u8]) -> [u8; 64] {
        self.signing_key
            .sign(&domain_separated(label, message))
            .to_bytes()
    }

    /// Issue a fresh certificate for the same identity key.
    ///
    /// The device id and identity fingerprint are preserved by construction; only the
    /// certificate, its fingerprint and its version change. The returned identity is
    /// therefore still the *same device* as far as any peer is concerned.
    ///
    /// # Errors
    /// Fails if certificate generation fails.
    pub fn renew_certificate(&self, subject_name: &str, clock: &dyn Clock) -> Result<Self> {
        let pkcs8 = self.export_pkcs8()?;
        let renewed = Self::from_pkcs8(
            &pkcs8,
            subject_name,
            self.created_at_ms,
            self.public.certificate_version.saturating_add(1),
            clock,
        )?;

        // An invariant, not a runtime check on untrusted input: if this ever failed it
        // would mean renewal silently changed the device's identity.
        debug_assert_eq!(renewed.public.device_id, self.public.device_id);
        debug_assert_eq!(
            renewed.public.identity_fingerprint,
            self.public.identity_fingerprint
        );

        Ok(renewed)
    }
}

/// Derive a stable device id from an identity public key.
///
/// The public key is hashed with a domain-separation label and the first 16 bytes are
/// shaped into a UUID. This is a one-way derivation of a *public* value: it discloses
/// nothing private, and it guarantees that the same identity key always yields the
/// same device id, across restarts, reinstalls and certificate renewals.
#[must_use]
pub fn derive_device_id(identity_public_key: &[u8; 32]) -> DeviceId {
    let mut hasher = Sha256::new();
    hasher.update(DEVICE_ID_LABEL);
    hasher.update(identity_public_key);
    let digest = hasher.finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Shape as a RFC 9562 version-8 (custom) UUID so tooling reads it as well-formed.
    bytes[6] = (bytes[6] & 0x0F) | 0x80;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    DeviceId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

/// Bind a label to a message before signing, so signatures cannot cross purposes.
///
/// Layout: `label_len (u32 BE) || label || message`. Length-prefixing the label
/// prevents a label/message boundary ambiguity where `("ab", "c")` and `("a", "bc")`
/// would otherwise produce identical signed bytes.
fn domain_separated(label: &[u8], message: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + label.len() + message.len());
    buf.extend_from_slice(&u32::try_from(label.len()).unwrap_or(u32::MAX).to_be_bytes());
    buf.extend_from_slice(label);
    buf.extend_from_slice(message);
    buf
}

/// Reject subject names that would produce an invalid or misleading certificate.
fn validate_subject_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(SecurityError::Invalid {
            field: "subject name",
            reason: "must not be empty",
        });
    }
    if name.len() > 64 {
        return Err(SecurityError::Invalid {
            field: "subject name",
            reason: "must be at most 64 characters",
        });
    }
    if name.chars().any(|c| c.is_control() || c == '\0') {
        return Err(SecurityError::Invalid {
            field: "subject name",
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

/// Convert milliseconds since the Unix epoch into the type `rcgen` expects.
fn offset_from_ms(ms: i64) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok()
}

/// Whether `certificate_der` carries `public_key` as its subject public key.
///
/// An Ed25519 `SubjectPublicKeyInfo` has one canonical DER encoding: the fixed
/// twelve-byte header below, then the 32-byte key. Searching for that exact sequence
/// is therefore an equality test on a structure with no encoding freedom, not a
/// heuristic — a certificate for a different key cannot contain it, and one for this
/// key must.
///
/// This is used instead of a full X.509 parse because the only question being asked is
/// "is this the key I hold", and pulling in a parser to answer it would add an
/// attack surface larger than the check.
fn certificate_embeds_public_key(certificate_der: &[u8], public_key: &[u8; 32]) -> bool {
    /// `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING (256 bit) }`
    const ED25519_SPKI_HEADER: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    let mut expected = Vec::with_capacity(ED25519_SPKI_HEADER.len() + public_key.len());
    expected.extend_from_slice(&ED25519_SPKI_HEADER);
    expected.extend_from_slice(public_key);

    certificate_der
        .windows(expected.len())
        .any(|window| window == expected.as_slice())
}

/// PEM-encode a DER certificate.
fn pem_of(certificate_der: &[u8]) -> String {
    use base64::Engine as _;

    let body = base64::engine::general_purpose::STANDARD.encode(certificate_der);

    let mut pem = String::with_capacity(body.len() + 80);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    // 64 characters per line, as PEM requires.
    for chunk in body.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;

    fn identity(clock: &TestClock) -> DeviceIdentity {
        DeviceIdentity::generate("test-device", clock).unwrap()
    }

    #[test]
    fn generation_produces_a_usable_identity() {
        let clock = TestClock::default();
        let id = identity(&clock);

        assert!(!id.public().certificate_der.is_empty());
        assert!(
            id.public()
                .certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(id.public().is_valid_at(clock.now_ms()));
    }

    #[test]
    fn two_installations_get_different_identities() {
        let clock = TestClock::default();
        let a = identity(&clock);
        let b = identity(&clock);

        assert_ne!(a.device_id(), b.device_id());
        assert_ne!(
            a.public().identity_fingerprint,
            b.public().identity_fingerprint
        );
        assert_ne!(
            a.public().certificate_fingerprint,
            b.public().certificate_fingerprint
        );
        assert_ne!(
            a.public().identity_public_key,
            b.public().identity_public_key
        );
    }

    #[test]
    fn device_id_is_derived_deterministically_from_the_public_key() {
        let key = [3u8; 32];
        assert_eq!(derive_device_id(&key), derive_device_id(&key));
        assert_ne!(derive_device_id(&key), derive_device_id(&[4u8; 32]));
    }

    #[test]
    fn identity_survives_an_export_and_reload() {
        let clock = TestClock::default();
        let original = identity(&clock);
        let pkcs8 = original.export_pkcs8().unwrap();

        let reloaded = DeviceIdentity::from_pkcs8(
            &pkcs8,
            "test-device",
            original.created_at_ms(),
            original.public().certificate_version,
            &clock,
        )
        .unwrap();

        assert_eq!(reloaded.device_id(), original.device_id());
        assert_eq!(
            reloaded.public().identity_fingerprint,
            original.public().identity_fingerprint
        );
        assert_eq!(
            reloaded.public().identity_public_key,
            original.public().identity_public_key
        );
    }

    #[test]
    fn reloading_rejects_malformed_key_material() {
        let clock = TestClock::default();
        for bad in [vec![], vec![0u8; 16], b"-----BEGIN NONSENSE-----".to_vec()] {
            assert!(
                DeviceIdentity::from_pkcs8(&bad, "d", 0, 1, &clock).is_err(),
                "must reject malformed PKCS#8"
            );
        }
    }

    #[test]
    fn renewal_preserves_the_device_identity() {
        let clock = TestClock::default();
        let original = identity(&clock);

        clock.advance_secs(400 * 24 * 3600);
        let renewed = original.renew_certificate("test-device", &clock).unwrap();

        // The trust anchor is unchanged...
        assert_eq!(renewed.device_id(), original.device_id());
        assert_eq!(
            renewed.public().identity_fingerprint,
            original.public().identity_fingerprint
        );
        // ...but the credential is new.
        assert_ne!(
            renewed.public().certificate_fingerprint,
            original.public().certificate_fingerprint
        );
        assert_eq!(
            renewed.public().certificate_version,
            original.public().certificate_version + 1
        );
        assert!(renewed.public().is_valid_at(clock.now_ms()));
    }

    #[test]
    fn certificate_validity_window_is_enforced() {
        let clock = TestClock::default();
        let id = identity(&clock);
        let public = id.public();

        assert!(!public.is_valid_at(public.certificate_not_before_ms - 1));
        assert!(public.is_valid_at(public.certificate_not_before_ms));
        assert!(!public.is_valid_at(public.certificate_not_after_ms));
    }

    #[test]
    fn renewal_is_signalled_before_expiry_not_after() {
        let clock = TestClock::default();
        let id = identity(&clock);
        let public = id.public();

        assert!(!public.needs_renewal_at(clock.now_ms()));

        let day = 24 * 3600 * 1000;
        let just_inside =
            public.certificate_not_after_ms - (CERTIFICATE_RENEW_BEFORE_DAYS + 1) * day;
        assert!(!public.needs_renewal_at(just_inside));

        let inside_window =
            public.certificate_not_after_ms - (CERTIFICATE_RENEW_BEFORE_DAYS - 1) * day;
        assert!(public.needs_renewal_at(inside_window));
    }

    #[test]
    fn signatures_verify_against_the_public_identity() {
        let clock = TestClock::default();
        let id = identity(&clock);

        let signature = id.sign(b"rc.test.v1", b"payload");
        id.public()
            .verify(b"rc.test.v1", b"payload", &signature)
            .unwrap();
    }

    #[test]
    fn signatures_do_not_verify_across_domain_labels() {
        let clock = TestClock::default();
        let id = identity(&clock);

        let signature = id.sign(b"rc.pairing.v1", b"payload");
        assert!(
            id.public()
                .verify(b"rc.session.v1", b"payload", &signature)
                .is_err(),
            "a signature must not be reusable under a different label"
        );
    }

    #[test]
    fn label_length_prefixing_prevents_boundary_confusion() {
        let clock = TestClock::default();
        let id = identity(&clock);

        // Without length-prefixing, ("ab", "c") and ("a", "bc") would sign the same
        // bytes and the signatures would be interchangeable.
        let signature = id.sign(b"ab", b"c");
        assert!(id.public().verify(b"a", b"bc", &signature).is_err());
    }

    #[test]
    fn signatures_do_not_verify_for_a_modified_message() {
        let clock = TestClock::default();
        let id = identity(&clock);

        let signature = id.sign(b"rc.test.v1", b"payload");
        assert!(
            id.public()
                .verify(b"rc.test.v1", b"payloae", &signature)
                .is_err()
        );
    }

    #[test]
    fn signatures_do_not_verify_against_another_identity() {
        let clock = TestClock::default();
        let a = identity(&clock);
        let b = identity(&clock);

        let signature = a.sign(b"rc.test.v1", b"payload");
        assert!(
            b.public()
                .verify(b"rc.test.v1", b"payload", &signature)
                .is_err()
        );
    }

    #[test]
    fn malformed_signatures_are_rejected_without_panicking() {
        let clock = TestClock::default();
        let id = identity(&clock);

        for bad in [vec![], vec![0u8; 63], vec![0u8; 65], vec![0xFF; 64]] {
            assert!(id.public().verify(b"rc.test.v1", b"payload", &bad).is_err());
        }
    }

    #[test]
    fn debug_output_never_contains_private_key_material() {
        let clock = TestClock::default();
        let id = identity(&clock);

        let rendered = format!("{id:?}");
        assert!(rendered.contains("<redacted>"));

        let secret = hex::encode(id.export_pkcs8().unwrap().as_slice());
        assert!(
            !rendered.contains(&secret),
            "debug output must not leak the key"
        );
        assert!(!rendered.to_lowercase().contains("private"));
    }

    #[test]
    fn subject_names_are_validated() {
        let clock = TestClock::default();
        assert!(DeviceIdentity::generate("", &clock).is_err());
        assert!(DeviceIdentity::generate(&"a".repeat(65), &clock).is_err());
        assert!(DeviceIdentity::generate("bad\u{0}name", &clock).is_err());
        assert!(DeviceIdentity::generate("good-name.local", &clock).is_ok());
    }

    #[test]
    fn certificate_fingerprint_matches_the_certificate_bytes() {
        let clock = TestClock::default();
        let id = identity(&clock);
        assert_eq!(
            id.public().certificate_fingerprint,
            Fingerprint::of_certificate_der(&id.public().certificate_der)
        );
    }
}
