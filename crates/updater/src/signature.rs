use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{Result, UpdateError};
use crate::installer::PackageFormat;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignaturePolicy {
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    NotRequired,
    Verified,
    Unsupported,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SignatureVerifier;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestSignaturePolicy {
    Required { public_keys_base64: Vec<String> },
    AllowUnsignedForDevelopment,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ManifestSignatureVerifier;

impl ManifestSignatureVerifier {
    pub fn verify(
        self,
        manifest_bytes: &[u8],
        signature_base64: Option<&str>,
        policy: &ManifestSignaturePolicy,
    ) -> Result<SignatureStatus> {
        let ManifestSignaturePolicy::Required { public_keys_base64 } = policy else {
            return Ok(SignatureStatus::NotRequired);
        };
        let signature_base64 = signature_base64.ok_or(UpdateError::ManifestSignatureRequired)?;
        let keys: Vec<_> = public_keys_base64
            .iter()
            .map(String::as_str)
            .map(str::trim)
            .filter(|key| !key.is_empty())
            .collect();
        if keys.is_empty() {
            return Err(UpdateError::ManifestSignatureRequired);
        }
        let signature_bytes = base64::engine::general_purpose::STANDARD
            .decode(signature_base64.trim())
            .map_err(|err| UpdateError::ManifestSignatureFailed(err.to_string()))?;
        let signature_bytes: [u8; 64] = signature_bytes.try_into().map_err(|_| {
            UpdateError::ManifestSignatureFailed("signature must be 64 bytes".to_string())
        })?;
        let signature = Signature::from_bytes(&signature_bytes);
        let mut last_error = None;
        for key in keys {
            let result = verify_with_key(manifest_bytes, &signature, key);
            match result {
                Ok(()) => return Ok(SignatureStatus::Verified),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            UpdateError::ManifestSignatureFailed(
                "no trusted key accepted the signature".to_string(),
            )
        }))
    }
}

fn verify_with_key(manifest_bytes: &[u8], signature: &Signature, key_base64: &str) -> Result<()> {
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(key_base64)
        .map_err(|err| UpdateError::ManifestSignatureFailed(err.to_string()))?;
    let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
        UpdateError::ManifestSignatureFailed("public key must be 32 bytes".to_string())
    })?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|err| UpdateError::ManifestSignatureFailed(err.to_string()))?;
    verifying_key
        .verify(manifest_bytes, signature)
        .map_err(|err| UpdateError::ManifestSignatureFailed(err.to_string()))
}

impl SignatureVerifier {
    pub fn verify(
        self,
        path: &Path,
        format: PackageFormat,
        policy: SignaturePolicy,
    ) -> Result<SignatureStatus> {
        if !policy.required {
            return Ok(SignatureStatus::NotRequired);
        }
        match format {
            PackageFormat::Msi | PackageFormat::Exe => verify_windows_signature(path),
            PackageFormat::Pkg | PackageFormat::Dmg => verify_macos_signature(path, format),
            PackageFormat::Deb | PackageFormat::Rpm => verify_linux_signature(path, format),
            PackageFormat::AppImage | PackageFormat::TarGz => {
                Err(UpdateError::SignatureUnsupported)
            }
        }
    }
}

#[cfg(windows)]
fn verify_windows_signature(path: &Path) -> Result<SignatureStatus> {
    let script = "(Get-AuthenticodeSignature -LiteralPath $args[0]).Status";
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .arg(path)
        .output()?;
    if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "Valid" {
        Ok(SignatureStatus::Verified)
    } else {
        Err(UpdateError::SignatureFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

#[cfg(not(windows))]
fn verify_windows_signature(_path: &Path) -> Result<SignatureStatus> {
    Err(UpdateError::SignatureUnsupported)
}

#[cfg(target_os = "macos")]
fn verify_macos_signature(path: &Path, _format: PackageFormat) -> Result<SignatureStatus> {
    let output = Command::new("spctl")
        .args(["--assess", "--verbose", "--type", "install"])
        .arg(path)
        .output()?;
    if output.status.success() {
        Ok(SignatureStatus::Verified)
    } else {
        Err(UpdateError::SignatureFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

#[cfg(not(target_os = "macos"))]
fn verify_macos_signature(_path: &Path, _format: PackageFormat) -> Result<SignatureStatus> {
    Err(UpdateError::SignatureUnsupported)
}

#[cfg(target_os = "linux")]
fn verify_linux_signature(path: &Path, format: PackageFormat) -> Result<SignatureStatus> {
    let (program, args): (&str, &[&str]) = match format {
        PackageFormat::Deb => ("dpkg-sig", &["--verify"]),
        PackageFormat::Rpm => ("rpm", &["--checksig"]),
        _ => return Err(UpdateError::SignatureUnsupported),
    };
    let output = Command::new(program).args(args).arg(path).output()?;
    if output.status.success() {
        Ok(SignatureStatus::Verified)
    } else {
        Err(UpdateError::SignatureFailed(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}

#[cfg(not(target_os = "linux"))]
fn verify_linux_signature(_path: &Path, _format: PackageFormat) -> Result<SignatureStatus> {
    Err(UpdateError::SignatureUnsupported)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use tempfile::tempdir;

    use super::{
        ManifestSignaturePolicy, ManifestSignatureVerifier, SignaturePolicy, SignatureStatus,
        SignatureVerifier,
    };
    use crate::installer::PackageFormat;

    #[test]
    fn signature_can_be_optional() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("app.tar.gz");
        std::fs::write(&path, b"test").unwrap();
        let status = SignatureVerifier
            .verify(
                &path,
                PackageFormat::TarGz,
                SignaturePolicy { required: false },
            )
            .unwrap();
        assert_eq!(status, SignatureStatus::NotRequired);
    }

    #[test]
    fn manifest_signature_accepts_detached_ed25519_signature() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let public_key = signing_key.verifying_key();
        let manifest = br#"{"version":"2.4.1"}"#;
        let signature = signing_key.sign(manifest);
        let public_key_base64 =
            base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
        let signature_base64 =
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let status = ManifestSignatureVerifier
            .verify(
                manifest,
                Some(&signature_base64),
                &ManifestSignaturePolicy::Required {
                    public_keys_base64: vec![public_key_base64],
                },
            )
            .unwrap();

        assert_eq!(status, SignatureStatus::Verified);
    }

    #[test]
    fn manifest_signature_rejects_tampered_manifest() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let public_key = signing_key.verifying_key();
        let signature = signing_key.sign(b"original");
        let public_key_base64 =
            base64::engine::general_purpose::STANDARD.encode(public_key.as_bytes());
        let signature_base64 =
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        assert!(
            ManifestSignatureVerifier
                .verify(
                    b"tampered",
                    Some(&signature_base64),
                    &ManifestSignaturePolicy::Required {
                        public_keys_base64: vec![public_key_base64],
                    },
                )
                .is_err()
        );
    }
    #[test]
    fn manifest_signature_accepts_authorized_rotated_key() {
        let old_key = SigningKey::from_bytes(&[1; 32]);
        let next_key = SigningKey::from_bytes(&[2; 32]);
        let manifest = br#"{"version":"2.4.2"}"#;
        let signature = next_key.sign(manifest);
        let old_public =
            base64::engine::general_purpose::STANDARD.encode(old_key.verifying_key().as_bytes());
        let next_public =
            base64::engine::general_purpose::STANDARD.encode(next_key.verifying_key().as_bytes());
        let signature_base64 =
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let status = ManifestSignatureVerifier
            .verify(
                manifest,
                Some(&signature_base64),
                &ManifestSignaturePolicy::Required {
                    public_keys_base64: vec![old_public, next_public],
                },
            )
            .unwrap();

        assert_eq!(status, SignatureStatus::Verified);
    }

    #[test]
    fn manifest_signature_rejects_unauthorized_key() {
        let trusted_key = SigningKey::from_bytes(&[3; 32]);
        let attacker_key = SigningKey::from_bytes(&[4; 32]);
        let manifest = br#"{"version":"9.9.9"}"#;
        let signature = attacker_key.sign(manifest);
        let trusted_public = base64::engine::general_purpose::STANDARD
            .encode(trusted_key.verifying_key().as_bytes());
        let signature_base64 =
            base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        assert!(
            ManifestSignatureVerifier
                .verify(
                    manifest,
                    Some(&signature_base64),
                    &ManifestSignaturePolicy::Required {
                        public_keys_base64: vec![trusted_public],
                    },
                )
                .is_err()
        );
    }
}
