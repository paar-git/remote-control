//! Secure, versioned storage for device private key material.
//!
//! # File format
//!
//! The keystore is a single JSON file, `device-identity.keystore`, holding a versioned
//! envelope. JSON is used deliberately: the file must remain *inspectable* by an
//! operator diagnosing a problem, while the one field that matters — `payload` — is
//! either DPAPI-encrypted or protected only by file permissions, never both plaintext
//! and unreadable.
//!
//! ```json
//! {
//!   "format_version": 1,
//!   "protection": "dpapi",
//!   "created_at_ms": 1700000000000,
//!   "device_created_at_ms": 1700000000000,
//!   "certificate_version": 1,
//!   "subject_name": "home-server",
//!   "identity_public_key": "<64 hex chars>",
//!   "payload": "<base64>",
//!   "integrity": "<64 hex chars>"
//! }
//! ```
//!
//! `format_version` exists so a future change can migrate rather than guess. A file
//! written by a newer build is refused outright ([`SecurityError::KeystoreVersionUnsupported`]).
//!
//! The certificate fields were added to this envelope while `format_version` stayed at
//! `1`, so a file written before that change carries an `integrity` tag over the
//! shorter field list. A tag matching that older layout is accepted for an envelope
//! that carries no certificate, which is then upgraded in place; see
//! [`KeystoreEnvelope::verify_integrity`]. Any future field must bump the version
//! instead of relying on the same allowance.
//!
//! `integrity` is a BLAKE3 keyed hash over a canonical encoding of every other field.
//! It detects truncation, bit-rot and partial writes. It is **not** a defence against
//! an attacker who can write the file: the key is a fixed domain constant, not a
//! secret. Confidentiality and authenticity come from the protection mechanism below.
//!
//! # Protection mechanisms
//!
//! | Platform | Mechanism | Protects against |
//! |---|---|---|
//! | Windows | DPAPI, `CurrentUser` scope | Any other local account reading the key, including other services |
//! | Linux/Unix | File mode `0600` in a `0700` directory | Any other local account reading the key |
//!
//! **`CurrentUser` scope is deliberate.** Machine scope would let every process on the
//! host decrypt the key, which defeats the purpose. The consequence is that the
//! keystore is bound to the account that wrote it: changing the agent's service
//! account requires re-running setup, and attempting to read it as a different account
//! produces [`SecurityError::KeystoreWrongIdentity`] rather than a confusing parse
//! failure.
//!
//! On Unix, unsafe permissions are a **hard error**, not a warning. A private key that
//! is group- or world-readable is already compromised; continuing would only hide it.
//!
//! # What this does not protect against
//!
//! An attacker with offline access to an unencrypted disk can read a Unix keystore,
//! and DPAPI material is recoverable given the account's credentials. Full-disk
//! encryption is a documented prerequisite; see `docs/threat-model.md`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::clock::Clock;
use crate::error::{Result, SecurityError};
use crate::identity::DeviceIdentity;

/// Keystore format version this build writes.
pub const KEYSTORE_FORMAT_VERSION: u32 = 1;

/// File name of the keystore inside the data directory.
pub const KEYSTORE_FILE_NAME: &str = "device-identity.keystore";

/// Domain constant keying the integrity hash. Not a secret; see the module docs.
const INTEGRITY_KEY: &[u8; 32] = b"rc.keystore.integrity.v1\0\0\0\0\0\0\0\0";

/// Required file mode on Unix.
#[cfg(unix)]
const REQUIRED_FILE_MODE: u32 = 0o600;

/// Required directory mode on Unix.
#[cfg(unix)]
const REQUIRED_DIR_MODE: u32 = 0o700;

/// How the payload is protected at rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Protection {
    /// Windows DPAPI, `CurrentUser` scope.
    Dpapi,
    /// Unix file permissions only: mode `0600` in a `0700` directory.
    FilePermissions,
}

impl Protection {
    /// The mechanism used on the platform this binary targets.
    #[must_use]
    pub const fn for_this_platform() -> Self {
        if cfg!(windows) {
            Self::Dpapi
        } else {
            Self::FilePermissions
        }
    }
}

/// The on-disk envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystoreEnvelope {
    format_version: u32,
    protection: Protection,
    created_at_ms: i64,
    /// When the identity key was first created. Preserved across certificate renewal.
    device_created_at_ms: i64,
    certificate_version: u32,
    subject_name: String,
    /// Hex identity public key. Stored in the clear so the device id and fingerprint
    /// can be reported without decrypting the private key.
    identity_public_key: String,
    /// Base64 payload: a DPAPI blob, or raw PKCS#8 under file-permission protection.
    payload: String,
    /// Base64 DER of the device's certificate.
    ///
    /// Stored rather than reissued on load. Peers pin the certificate fingerprint, and
    /// a certificate reissued from the same key is a *different* certificate with a
    /// different fingerprint — so regenerating it on every start would make every
    /// paired peer refuse this device after an ordinary reboot, reporting the loudest
    /// failure the system has.
    ///
    /// Absent in a format-version-1 keystore written before this was understood; such
    /// a keystore is upgraded in place on first load.
    #[serde(default)]
    certificate_der: String,
    /// When the stored certificate becomes valid.
    #[serde(default)]
    certificate_not_before_ms: i64,
    /// When the stored certificate expires.
    #[serde(default)]
    certificate_not_after_ms: i64,
    integrity: String,
}

/// Which set of fields an integrity tag covers.
///
/// The certificate fields were added to the envelope without bumping
/// `format_version`, so a file written by an older build carries a tag over the
/// shorter list. Both layouts must be computable to tell "older file" apart from
/// "damaged file".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntegrityLayout {
    /// Every field, including the certificate. What this build writes.
    Current,
    /// Stops before `certificate_der`. What builds predating stored certificates wrote.
    PreCertificate,
}

impl KeystoreEnvelope {
    /// Canonical bytes covered by the integrity hash: every field except `integrity`,
    /// each length-prefixed so no two different envelopes can produce the same input.
    fn integrity_input(&self, layout: IntegrityLayout) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut push = |bytes: &[u8]| {
            buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            buf.extend_from_slice(bytes);
        };
        push(&self.format_version.to_be_bytes());
        push(match self.protection {
            Protection::Dpapi => b"dpapi",
            Protection::FilePermissions => b"file_permissions",
        });
        push(&self.created_at_ms.to_be_bytes());
        push(&self.device_created_at_ms.to_be_bytes());
        push(&self.certificate_version.to_be_bytes());
        push(self.subject_name.as_bytes());
        push(self.identity_public_key.as_bytes());
        push(self.payload.as_bytes());
        if layout == IntegrityLayout::Current {
            push(self.certificate_der.as_bytes());
            push(&self.certificate_not_before_ms.to_be_bytes());
            push(&self.certificate_not_after_ms.to_be_bytes());
        }
        buf
    }

    fn compute_integrity_with(&self, layout: IntegrityLayout) -> String {
        hex::encode(blake3::keyed_hash(INTEGRITY_KEY, &self.integrity_input(layout)).as_bytes())
    }

    fn compute_integrity(&self) -> String {
        self.compute_integrity_with(IntegrityLayout::Current)
    }

    /// Whether this envelope carries no certificate at all — the shape a build
    /// predating stored certificates wrote, and the only shape whose tag may have been
    /// computed over the shorter field list.
    fn predates_stored_certificates(&self) -> bool {
        self.certificate_der.is_empty()
            && self.certificate_not_before_ms == 0
            && self.certificate_not_after_ms == 0
    }

    /// Verify the integrity tag in constant time.
    ///
    /// A tag over the pre-certificate layout is accepted *only* for an envelope that
    /// carries no certificate; `load` then issues one and rewrites the file with a
    /// current tag. Without this an older keystore is indistinguishable from a damaged
    /// one, and the upgrade path below it is unreachable — the operator is told their
    /// key was tampered with when nothing touched it.
    fn verify_integrity(&self) -> Result<()> {
        use subtle::ConstantTimeEq as _;

        let matches = |layout| -> bool {
            self.compute_integrity_with(layout)
                .as_bytes()
                .ct_eq(self.integrity.as_bytes())
                .into()
        };

        if matches(IntegrityLayout::Current) {
            return Ok(());
        }
        if self.predates_stored_certificates() && matches(IntegrityLayout::PreCertificate) {
            tracing::info!(
                "keystore integrity matches the pre-certificate layout; upgrading the file"
            );
            return Ok(());
        }
        Err(SecurityError::KeystoreCorrupt)
    }
}

/// Reads and writes the device identity keystore.
#[derive(Debug, Clone)]
pub struct Keystore {
    path: PathBuf,
}

impl Keystore {
    /// A keystore stored at `path`.
    #[must_use]
    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// A keystore in the standard location inside `data_dir`.
    #[must_use]
    pub fn in_data_dir(data_dir: impl AsRef<Path>) -> Self {
        Self {
            path: data_dir.as_ref().join(KEYSTORE_FILE_NAME),
        }
    }

    /// Path of the keystore file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether a keystore already exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.is_file()
    }

    /// Load the identity, or generate and persist a new one if none exists.
    ///
    /// This is the normal entry point for both the agent and the client.
    ///
    /// # Errors
    /// Fails on corruption, an unsupported format version, unsafe permissions, or a
    /// keystore written under a different OS identity. It never silently regenerates:
    /// a broken keystore is reported so the operator can decide, because regenerating
    /// would change the device identity and break every existing pairing.
    pub fn load_or_create(&self, subject_name: &str, clock: &dyn Clock) -> Result<DeviceIdentity> {
        if self.exists() {
            let identity = self.load(clock)?;

            // A keystore written before certificates were persisted has just had one
            // issued. Writing it back now is what makes the *next* start stable; without
            // this the upgrade would happen again on every boot, and the certificate
            // fingerprint would keep changing.
            if !self.has_stored_certificate() {
                self.store(&identity, subject_name, clock)?;
            }
            Ok(identity)
        } else {
            let identity = DeviceIdentity::generate(subject_name, clock)?;
            self.store(&identity, subject_name, clock)?;
            tracing::info!(
                device_id = %identity.device_id(),
                identity_fingerprint = %identity.public().identity_fingerprint,
                "generated a new device identity"
            );
            Ok(identity)
        }
    }

    /// Whether the keystore on disk already carries a certificate.
    ///
    /// Used to decide whether a load needs writing back. A file that cannot be read or
    /// parsed answers `false`, which at worst causes one redundant write.
    fn has_stored_certificate(&self) -> bool {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|text| serde_json::from_str::<KeystoreEnvelope>(&text).ok())
            .is_some_and(|envelope| !envelope.certificate_der.is_empty())
    }

    /// Load the identity from disk.
    ///
    /// # Errors
    /// See [`Keystore::load_or_create`].
    pub fn load(&self, clock: &dyn Clock) -> Result<DeviceIdentity> {
        self.check_permissions()?;

        let text = std::fs::read_to_string(&self.path).map_err(|source| SecurityError::Io {
            operation: "read keystore",
            source,
        })?;

        let envelope: KeystoreEnvelope = serde_json::from_str(&text).map_err(|err| {
            tracing::warn!(%err, "keystore could not be parsed");
            SecurityError::KeystoreCorrupt
        })?;

        if envelope.format_version > KEYSTORE_FORMAT_VERSION {
            return Err(SecurityError::KeystoreVersionUnsupported {
                found: envelope.format_version,
                supported: KEYSTORE_FORMAT_VERSION,
            });
        }
        envelope.verify_integrity()?;

        let protected = decode_base64(&envelope.payload)?;
        let pkcs8 = unprotect(envelope.protection, &protected)?;

        let identity = if envelope.certificate_der.is_empty() {
            // A keystore written before certificates were persisted. Reissuing here is
            // a one-time event on upgrade, not something that happens on every start;
            // the caller writes the result back, so the next load is stable.
            tracing::info!(
                "keystore has no stored certificate; issuing one and upgrading the file"
            );
            DeviceIdentity::from_pkcs8(
                &pkcs8,
                &envelope.subject_name,
                envelope.device_created_at_ms,
                envelope.certificate_version,
                clock,
            )?
        } else {
            DeviceIdentity::from_stored(
                &pkcs8,
                decode_base64(&envelope.certificate_der)?,
                &envelope.subject_name,
                envelope.device_created_at_ms,
                envelope.certificate_version,
                envelope.certificate_not_before_ms,
                envelope.certificate_not_after_ms,
            )?
        };

        // The plaintext public key recorded in the envelope must match the key we just
        // decrypted. A mismatch means the file was assembled from two different
        // keystores, so the recorded device id could be attributed to the wrong key.
        let recorded = hex::decode(&envelope.identity_public_key)
            .map_err(|_| SecurityError::KeystoreCorrupt)?;
        if recorded != identity.public().identity_public_key {
            tracing::error!("keystore public key does not match its private key");
            return Err(SecurityError::KeystoreCorrupt);
        }

        Ok(identity)
    }

    /// Write an identity to disk, replacing any existing keystore atomically.
    ///
    /// The file is written to a temporary sibling, permissions are applied *before*
    /// any secret is written, the contents are flushed to disk, and only then is it
    /// renamed over the target. A crash therefore leaves either the old keystore or
    /// the new one, never a truncated file.
    ///
    /// # Errors
    /// Fails if the directory is missing or unsafe, or if any I/O step fails.
    pub fn store(
        &self,
        identity: &DeviceIdentity,
        subject_name: &str,
        clock: &dyn Clock,
    ) -> Result<()> {
        let dir = self
            .path
            .parent()
            .ok_or(SecurityError::KeystoreDirectoryMissing)?;
        if !dir.is_dir() {
            return Err(SecurityError::KeystoreDirectoryMissing);
        }
        check_dir_mode(dir)?;

        let pkcs8 = identity.export_pkcs8()?;
        let protection = Protection::for_this_platform();
        let payload = protect(protection, &pkcs8)?;

        let mut envelope = KeystoreEnvelope {
            format_version: KEYSTORE_FORMAT_VERSION,
            protection,
            created_at_ms: clock.now_ms(),
            device_created_at_ms: identity.created_at_ms(),
            certificate_version: identity.public().certificate_version,
            subject_name: subject_name.to_string(),
            identity_public_key: hex::encode(identity.public().identity_public_key),
            payload: encode_base64(&payload),
            certificate_der: encode_base64(&identity.public().certificate_der),
            certificate_not_before_ms: identity.public().certificate_not_before_ms,
            certificate_not_after_ms: identity.public().certificate_not_after_ms,
            integrity: String::new(),
        };
        envelope.integrity = envelope.compute_integrity();

        let json =
            serde_json::to_string_pretty(&envelope).map_err(|_| SecurityError::KeystoreCorrupt)?;

        self.write_atomically(json.as_bytes())?;

        tracing::info!(
            path = %self.path.display(),
            protection = ?protection,
            "device identity keystore written"
        );
        Ok(())
    }

    /// Write `contents` to the keystore path atomically and with restrictive modes.
    fn write_atomically(&self, contents: &[u8]) -> Result<()> {
        write_protected_file(&self.path, contents).map_err(|source| SecurityError::Io {
            operation: "write keystore",
            source,
        })
    }

    /// Verify that the keystore and its directory have safe permissions.
    ///
    /// # Errors
    /// Returns [`SecurityError::UnsafePermissions`] on Unix if either is too open.
    pub fn check_permissions(&self) -> Result<()> {
        let dir = self
            .path
            .parent()
            .ok_or(SecurityError::KeystoreDirectoryMissing)?;
        check_dir_mode(dir)?;
        check_file_mode(&self.path)
    }
}

// ---------------------------------------------------------------------------
// Permission checks
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn mode_of(path: &Path) -> Result<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = std::fs::metadata(path).map_err(|source| SecurityError::Io {
        operation: "stat keystore path",
        source,
    })?;
    Ok(metadata.permissions().mode() & 0o777)
}

/// On Unix, require `0700`: no group or other access at all.
#[cfg(unix)]
fn check_dir_mode(dir: &Path) -> Result<()> {
    let mode = mode_of(dir)?;
    if mode & 0o077 != 0 {
        return Err(SecurityError::UnsafePermissions {
            path: dir.display().to_string(),
            expected: REQUIRED_DIR_MODE,
            found: mode,
        });
    }
    Ok(())
}

/// On Unix, require `0600`: no group or other access at all.
#[cfg(unix)]
fn check_file_mode(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mode = mode_of(path)?;
    if mode & 0o077 != 0 {
        return Err(SecurityError::UnsafePermissions {
            path: path.display().to_string(),
            expected: REQUIRED_FILE_MODE,
            found: mode,
        });
    }
    Ok(())
}

/// Windows has no POSIX modes. Access control is by ACL, which the installer applies
/// to the data directory; DPAPI is the actual confidentiality control here, so a
/// readable file does not by itself expose the key.
#[cfg(not(unix))]
fn check_dir_mode(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        Ok(())
    } else {
        Err(SecurityError::KeystoreDirectoryMissing)
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn check_file_mode(_path: &Path) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Payload protection
// ---------------------------------------------------------------------------

/// Application-specific secondary entropy mixed into DPAPI protection.
///
/// Without it, *any* process running as the same user could recover the key with a
/// bare `CryptUnprotectData` call. With it, a caller must also know this constant, so
/// an unrelated application on the host cannot passively decrypt the keystore. It is
/// not a secret — it is in this source file — but it does raise the bar from "any
/// process" to "a process written against this application".
#[cfg(windows)]
const DPAPI_ENTROPY: &[u8] = b"dev.remotecontrol.keystore.v1";

#[cfg(windows)]
fn protect(protection: Protection, plaintext: &[u8]) -> Result<Vec<u8>> {
    match protection {
        Protection::Dpapi => {
            windows_dpapi::encrypt_data(plaintext, windows_dpapi::Scope::User, Some(DPAPI_ENTROPY))
                .map_err(|err| {
                    tracing::error!(%err, "DPAPI encryption failed");
                    SecurityError::KeystoreWrongIdentity
                })
        }
        // Refuse to write an unprotected key on a platform that offers DPAPI.
        Protection::FilePermissions => Err(SecurityError::Invalid {
            field: "keystore protection",
            reason: "Windows keystores must use DPAPI",
        }),
    }
}

#[cfg(windows)]
fn unprotect(protection: Protection, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    match protection {
        Protection::Dpapi => {
            windows_dpapi::decrypt_data(payload, windows_dpapi::Scope::User, Some(DPAPI_ENTROPY))
                .map(Zeroizing::new)
                .map_err(|err| {
                    // The most common cause by far is a different user or service account,
                    // so that is what the error says rather than "corrupt".
                    tracing::warn!(%err, "DPAPI decryption failed");
                    SecurityError::KeystoreWrongIdentity
                })
        }
        Protection::FilePermissions => Err(SecurityError::KeystoreCorrupt),
    }
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn protect(protection: Protection, plaintext: &[u8]) -> Result<Vec<u8>> {
    match protection {
        Protection::FilePermissions => Ok(plaintext.to_vec()),
        Protection::Dpapi => Err(SecurityError::Invalid {
            field: "keystore protection",
            reason: "DPAPI is only available on Windows",
        }),
    }
}

#[cfg(not(windows))]
fn unprotect(protection: Protection, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    match protection {
        Protection::FilePermissions => Ok(Zeroizing::new(payload.to_vec())),
        // A DPAPI keystore copied to Linux cannot be read, and saying so plainly is
        // more useful than reporting corruption.
        Protection::Dpapi => Err(SecurityError::KeystoreWrongIdentity),
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_base64(text: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| SecurityError::KeystoreCorrupt)
}

/// Write `contents` to `path` atomically, with restrictive permissions from the moment
/// the file exists.
///
/// Used for the keystore and for anything else whose *readability* is the access
/// control — a file that is briefly world-readable while being written is a file that
/// was world-readable.
///
/// Three properties, in the order they matter:
///
/// 1. **Mode at creation, not afterwards.** A separate `chmod` leaves a window in which
///    the content exists on disk under the previous mode.
/// 2. **Durable before rename.** `sync_all` before the rename means a power loss cannot
///    leave an empty file under the real name.
/// 3. **Rename, not truncate-and-write.** A concurrent reader sees either the old
///    content or the new one, never a half-written file.
///
/// # Errors
/// Propagates the underlying I/O failure. A leftover temporary file is removed on every
/// failure path.
pub fn write_protected_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let temp_path = path.with_extension("tmp");

    // Remove any leftover temporary file from a previous crash before creating ours;
    // `create_new` below would otherwise fail against it forever.
    let _ = std::fs::remove_file(&temp_path);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(REQUIRED_FILE_MODE);
    }

    let mut file = options.open(&temp_path)?;

    let result = (|| -> std::io::Result<()> {
        file.write_all(contents)?;
        file.flush()?;
        file.sync_all()
    })();

    if let Err(source) = result {
        drop(file);
        let _ = std::fs::remove_file(&temp_path);
        return Err(source);
    }
    drop(file);

    std::fs::rename(&temp_path, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp_path);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;

    /// A temp directory with the mode the keystore requires.
    fn secure_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    #[test]
    fn creates_an_identity_on_first_use() {
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());

        assert!(!keystore.exists());
        let identity = keystore.load_or_create("home-server", &clock).unwrap();
        assert!(keystore.exists());
        assert!(!identity.public().certificate_der.is_empty());
    }

    #[test]
    fn identity_persists_across_restart() {
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());

        let first = keystore.load_or_create("home-server", &clock).unwrap();
        // A "restart" is simply a fresh Keystore over the same path.
        let second = Keystore::in_data_dir(dir.path())
            .load_or_create("home-server", &clock)
            .unwrap();

        assert_eq!(second.device_id(), first.device_id());
        assert_eq!(
            second.public().identity_fingerprint,
            first.public().identity_fingerprint
        );
        assert_eq!(second.created_at_ms(), first.created_at_ms());
    }

    #[test]
    fn separate_installations_get_separate_identities() {
        let clock = TestClock::default();
        let dir_a = secure_dir();
        let dir_b = secure_dir();

        let a = Keystore::in_data_dir(dir_a.path())
            .load_or_create("host", &clock)
            .unwrap();
        let b = Keystore::in_data_dir(dir_b.path())
            .load_or_create("host", &clock)
            .unwrap();

        assert_ne!(a.device_id(), b.device_id());
        assert_ne!(
            a.public().identity_fingerprint,
            b.public().identity_fingerprint
        );
    }

    #[test]
    fn the_keystore_file_never_contains_the_raw_private_key() {
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        let identity = keystore.load_or_create("host", &clock).unwrap();

        let on_disk = std::fs::read(keystore.path()).unwrap();
        let secret = identity.export_pkcs8().unwrap();

        // On Windows the payload is DPAPI-encrypted, so the raw bytes must be absent.
        // On Unix the payload IS the key, protected by mode 0600 instead — so this
        // assertion is only meaningful where encryption is in play.
        if Protection::for_this_platform() == Protection::Dpapi {
            assert!(
                !on_disk
                    .windows(secret.len())
                    .any(|w| w == secret.as_slice()),
                "DPAPI-protected keystore must not contain the plaintext key"
            );
        }
        // The public key is expected in the clear; the private seed is not adjacent.
        assert!(!on_disk.is_empty());
    }

    #[test]
    fn a_corrupted_payload_is_rejected() {
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();

        let text = std::fs::read_to_string(keystore.path()).unwrap();
        let mut envelope: serde_json::Value = serde_json::from_str(&text).unwrap();
        envelope["payload"] = serde_json::Value::String(encode_base64(b"not a key"));
        std::fs::write(keystore.path(), envelope.to_string()).unwrap();

        let err = keystore.load(&clock).unwrap_err();
        assert!(matches!(err, SecurityError::KeystoreCorrupt), "got {err:?}");
    }

    #[test]
    fn a_tampered_field_fails_the_integrity_check() {
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();

        let text = std::fs::read_to_string(keystore.path()).unwrap();
        let mut envelope: serde_json::Value = serde_json::from_str(&text).unwrap();
        envelope["subject_name"] = serde_json::Value::String("attacker".into());
        std::fs::write(keystore.path(), envelope.to_string()).unwrap();

        assert!(matches!(
            keystore.load(&clock),
            Err(SecurityError::KeystoreCorrupt)
        ));
    }

    /// Rewrite `keystore` as a build predating the stored certificate would have left
    /// it: the three certificate fields absent from the JSON, and the integrity tag
    /// computed over the shorter field list.
    fn downgrade_to_pre_certificate(keystore: &Keystore) {
        let text = std::fs::read_to_string(keystore.path()).unwrap();
        let mut envelope: KeystoreEnvelope = serde_json::from_str(&text).unwrap();
        envelope.certificate_der = String::new();
        envelope.certificate_not_before_ms = 0;
        envelope.certificate_not_after_ms = 0;
        envelope.integrity = envelope.compute_integrity_with(IntegrityLayout::PreCertificate);

        let mut value = serde_json::to_value(&envelope).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("certificate_der");
        object.remove("certificate_not_before_ms");
        object.remove("certificate_not_after_ms");
        std::fs::write(keystore.path(), value.to_string()).unwrap();
    }

    #[test]
    fn a_keystore_written_before_certificates_were_stored_is_upgraded_not_rejected() {
        // The certificate fields joined the integrity input without a format-version
        // bump, so an older file's tag is computed over fewer fields. Recomputing it
        // the current way and calling the difference "corrupt" would strand every
        // existing installation on upgrade.
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        let original = keystore.load_or_create("host", &clock).unwrap();
        downgrade_to_pre_certificate(&keystore);

        let upgraded = keystore.load_or_create("host", &clock).unwrap();

        // The identity must survive. Regenerating would change the device id and break
        // every existing pairing, which is exactly what this path must not do.
        assert_eq!(upgraded.public().device_id, original.public().device_id);
        assert_eq!(
            upgraded.public().identity_public_key,
            original.public().identity_public_key
        );

        // The upgrade must stick: the next start must be an ordinary load, not another
        // upgrade issuing yet another certificate.
        assert!(keystore.has_stored_certificate());
        let reloaded = keystore.load(&clock).unwrap();
        assert_eq!(
            reloaded.public().certificate_fingerprint,
            upgraded.public().certificate_fingerprint
        );
    }

    #[test]
    fn accepting_the_legacy_layout_does_not_accept_a_damaged_legacy_file() {
        // The compatibility path must stay a *layout* allowance, not a hole: a file
        // with no certificate fields and a wrong tag is still corrupt.
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();
        downgrade_to_pre_certificate(&keystore);

        let text = std::fs::read_to_string(keystore.path()).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
        value["subject_name"] = serde_json::Value::String("attacker".into());
        std::fs::write(keystore.path(), value.to_string()).unwrap();

        assert!(matches!(
            keystore.load(&clock),
            Err(SecurityError::KeystoreCorrupt)
        ));
    }

    #[test]
    fn a_swapped_public_key_is_detected() {
        // Splicing another installation's public key into the envelope would let a
        // keystore claim a device id that does not belong to its private key.
        let dir = secure_dir();
        let other_dir = secure_dir();
        let clock = TestClock::default();

        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();
        let other = Keystore::in_data_dir(other_dir.path())
            .load_or_create("other", &clock)
            .unwrap();

        let text = std::fs::read_to_string(keystore.path()).unwrap();
        let mut envelope: KeystoreEnvelope = serde_json::from_str(&text).unwrap();
        envelope.identity_public_key = hex::encode(other.public().identity_public_key);
        envelope.integrity = envelope.compute_integrity(); // recompute so integrity passes
        std::fs::write(keystore.path(), serde_json::to_string(&envelope).unwrap()).unwrap();

        assert!(matches!(
            keystore.load(&clock),
            Err(SecurityError::KeystoreCorrupt)
        ));
    }

    #[test]
    fn truncated_and_empty_files_are_rejected() {
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();

        let text = std::fs::read_to_string(keystore.path()).unwrap();
        for broken in ["", "{", "null", "[]", &text[..text.len() / 2]] {
            std::fs::write(keystore.path(), broken).unwrap();
            assert!(keystore.load(&clock).is_err(), "must reject {broken:?}");
        }
    }

    #[test]
    fn a_newer_format_version_is_refused_rather_than_guessed() {
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();

        let text = std::fs::read_to_string(keystore.path()).unwrap();
        let mut envelope: KeystoreEnvelope = serde_json::from_str(&text).unwrap();
        envelope.format_version = KEYSTORE_FORMAT_VERSION + 1;
        envelope.integrity = envelope.compute_integrity();
        std::fs::write(keystore.path(), serde_json::to_string(&envelope).unwrap()).unwrap();

        let err = keystore.load(&clock).unwrap_err();
        assert!(
            matches!(err, SecurityError::KeystoreVersionUnsupported { found, supported }
                if found == KEYSTORE_FORMAT_VERSION + 1 && supported == KEYSTORE_FORMAT_VERSION),
            "got {err:?}"
        );
    }

    #[test]
    fn loading_never_silently_regenerates_a_broken_keystore() {
        // Regenerating would change the device identity and break every pairing.
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        let original = keystore.load_or_create("host", &clock).unwrap();

        std::fs::write(keystore.path(), "garbage").unwrap();
        assert!(keystore.load_or_create("host", &clock).is_err());

        // The broken file is left in place for the operator to inspect.
        assert_eq!(std::fs::read_to_string(keystore.path()).unwrap(), "garbage");
        drop(original);
    }

    #[test]
    fn storing_is_atomic_and_leaves_no_temporary_file() {
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary file was not cleaned up");
    }

    #[test]
    fn storing_replaces_an_existing_keystore() {
        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());

        let first = keystore.load_or_create("host", &clock).unwrap();
        let renewed = first.renew_certificate("host", &clock).unwrap();
        keystore.store(&renewed, "host", &clock).unwrap();

        let loaded = keystore.load(&clock).unwrap();
        assert_eq!(loaded.device_id(), first.device_id());
        assert_eq!(
            loaded.public().certificate_version,
            first.public().certificate_version + 1
        );
    }

    #[test]
    fn a_missing_directory_is_reported_clearly() {
        let clock = TestClock::default();
        let keystore = Keystore::at_path(
            std::env::temp_dir()
                .join("rc-does-not-exist-xyz")
                .join("k.keystore"),
        );
        let identity = DeviceIdentity::generate("host", &clock).unwrap();

        assert!(matches!(
            keystore.store(&identity, "host", &clock),
            Err(SecurityError::KeystoreDirectoryMissing)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_keystore_is_refused_not_merely_warned_about() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();

        std::fs::set_permissions(keystore.path(), std::fs::Permissions::from_mode(0o640)).unwrap();

        let err = keystore.load(&clock).unwrap_err();
        assert!(
            matches!(err, SecurityError::UnsafePermissions { .. }),
            "got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_world_readable_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = keystore.load(&clock).unwrap_err();
        assert!(
            matches!(err, SecurityError::UnsafePermissions { .. }),
            "got {err:?}"
        );

        // Restore so the temp dir can be cleaned up.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_newly_written_keystore_has_mode_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = secure_dir();
        let clock = TestClock::default();
        let keystore = Keystore::in_data_dir(dir.path());
        keystore.load_or_create("host", &clock).unwrap();

        let mode = std::fs::metadata(keystore.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, REQUIRED_FILE_MODE, "keystore must be owner-only");
    }

    #[test]
    fn a_reloaded_identity_presents_the_very_same_certificate() {
        // The bug this pins: reissuing the certificate on load gives it new validity
        // dates and therefore a new fingerprint, so every paired peer would refuse this
        // device after an ordinary restart — reporting an identity change, the loudest
        // failure the system has.
        let dir = secure_dir();
        let keystore = Keystore::in_data_dir(dir.path());
        let clock = TestClock::default();

        let first = keystore.load_or_create("test-device", &clock).unwrap();
        let second = keystore.load_or_create("test-device", &clock).unwrap();

        assert_eq!(
            first.public().certificate_fingerprint,
            second.public().certificate_fingerprint,
            "the certificate fingerprint must survive a restart"
        );
        assert_eq!(
            first.public().certificate_der,
            second.public().certificate_der,
            "the certificate bytes must be the stored ones, not reissued ones"
        );
        assert_eq!(first.device_id(), second.device_id());
        assert_eq!(
            first.public().certificate_not_after_ms,
            second.public().certificate_not_after_ms,
            "the validity window must not move on load"
        );
    }

    #[test]
    fn a_keystore_without_a_stored_certificate_is_upgraded_once() {
        // Keystores written before certificates were persisted must keep working, and
        // must become stable rather than reissuing on every start.
        let dir = secure_dir();
        let keystore = Keystore::in_data_dir(dir.path());
        let clock = TestClock::default();

        let original = keystore.load_or_create("test-device", &clock).unwrap();

        // Strip the stored certificate, as a version-1 file would be.
        let text = std::fs::read_to_string(keystore.path()).unwrap();
        let mut envelope: KeystoreEnvelope = serde_json::from_str(&text).unwrap();
        envelope.certificate_der = String::new();
        envelope.certificate_not_before_ms = 0;
        envelope.certificate_not_after_ms = 0;
        envelope.integrity = envelope.compute_integrity();
        std::fs::write(
            keystore.path(),
            serde_json::to_string_pretty(&envelope).unwrap(),
        )
        .unwrap();

        let upgraded = keystore.load_or_create("test-device", &clock).unwrap();
        let after = keystore.load_or_create("test-device", &clock).unwrap();

        // The identity is preserved through the upgrade...
        assert_eq!(original.device_id(), upgraded.device_id());
        assert_eq!(
            original.public().identity_fingerprint,
            upgraded.public().identity_fingerprint
        );

        // ...and from then on the certificate is stable.
        assert_eq!(
            upgraded.public().certificate_fingerprint,
            after.public().certificate_fingerprint,
            "the upgrade must happen once, not on every start"
        );
    }

    #[test]
    fn a_keystore_whose_certificate_belongs_to_another_key_is_refused() {
        // A file assembled from two identities could otherwise present a certificate
        // peers pin while holding a different private key.
        let dir = secure_dir();
        let keystore = Keystore::in_data_dir(dir.path());
        let clock = TestClock::default();

        keystore.load_or_create("test-device", &clock).unwrap();
        let stranger = DeviceIdentity::generate("stranger", &clock).unwrap();

        let text = std::fs::read_to_string(keystore.path()).unwrap();
        let mut envelope: KeystoreEnvelope = serde_json::from_str(&text).unwrap();
        envelope.certificate_der = encode_base64(&stranger.public().certificate_der);
        envelope.integrity = envelope.compute_integrity();
        std::fs::write(
            keystore.path(),
            serde_json::to_string_pretty(&envelope).unwrap(),
        )
        .unwrap();

        assert!(
            keystore.load(&clock).is_err(),
            "a certificate that does not match the stored key must be refused"
        );
    }

    #[test]
    fn integrity_input_is_unambiguous_across_field_boundaries() {
        // Length-prefixing means moving a character between adjacent fields changes
        // the hash; simple concatenation would not.
        let base = KeystoreEnvelope {
            format_version: 1,
            protection: Protection::FilePermissions,
            created_at_ms: 0,
            device_created_at_ms: 0,
            certificate_version: 1,
            subject_name: "ab".into(),
            identity_public_key: "c".into(),
            payload: String::new(),
            certificate_der: String::new(),
            certificate_not_before_ms: 0,
            certificate_not_after_ms: 0,
            integrity: String::new(),
        };
        let shifted = KeystoreEnvelope {
            subject_name: "a".into(),
            identity_public_key: "bc".into(),
            ..base.clone()
        };
        assert_ne!(base.compute_integrity(), shifted.compute_integrity());
    }
}
