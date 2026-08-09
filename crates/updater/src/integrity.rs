use std::fmt::Write as _;
use std::path::Path;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use crate::error::{Result, UpdateError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sha256Digest(pub String);

pub async fn file_sha256(path: &Path) -> Result<Sha256Digest> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}")
            .map_err(|err| UpdateError::InstallFailed(err.to_string()))?;
    }
    Ok(Sha256Digest(output))
}

pub async fn verify_sha256(path: &Path, expected_hex: &str) -> Result<Sha256Digest> {
    let digest = file_sha256(path).await?;
    if digest.0.eq_ignore_ascii_case(expected_hex) {
        Ok(digest)
    } else {
        let _ = tokio::fs::remove_file(path).await;
        Err(UpdateError::ChecksumMismatch)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{file_sha256, verify_sha256};

    #[tokio::test]
    async fn checksum_mismatch_deletes_corrupt_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.bin");
        tokio::fs::write(&path, b"corrupt").await.unwrap();
        assert!(verify_sha256(&path, &"0".repeat(64)).await.is_err());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn checksum_accepts_correct_digest() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ok.bin");
        tokio::fs::write(&path, b"hello").await.unwrap();
        let digest = file_sha256(&path).await.unwrap();
        assert_eq!(verify_sha256(&path, &digest.0).await.unwrap(), digest);
    }
}
