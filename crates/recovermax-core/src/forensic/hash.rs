use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Streaming SHA-256 hasher for disk images.
/// Reads in 8 MiB chunks to handle multi-TB images without loading into memory.
pub struct ImageHasher;

const CHUNK_SIZE: usize = 8 * 1024 * 1024; // 8 MiB

impl ImageHasher {
    /// Compute SHA-256 hash of a file, streaming in chunks.
    pub fn hash_file(path: &Path) -> Result<String> {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open {}", path.display()))?;

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; CHUNK_SIZE];

        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }

    /// Compute SHA-256 hash of a byte slice.
    pub fn hash_bytes(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    /// Verify a file matches an expected SHA-256 hash.
    pub fn verify_file(path: &Path, expected_hash: &str) -> Result<bool> {
        let actual = Self::hash_file(path)?;
        Ok(actual == expected_hash.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes() {
        // SHA-256 of empty string
        let hash = ImageHasher::hash_bytes(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hash_known_string() {
        let hash = ImageHasher::hash_bytes(b"recovermax");
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA-256 is 64 hex chars
    }

    #[test]
    fn test_hash_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"hello world").unwrap();

        let hash = ImageHasher::hash_file(&path).unwrap();
        let expected = ImageHasher::hash_bytes(b"hello world");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_verify_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        std::fs::write(&path, b"test data").unwrap();

        let hash = ImageHasher::hash_file(&path).unwrap();
        assert!(ImageHasher::verify_file(&path, &hash).unwrap());
        assert!(!ImageHasher::verify_file(
            &path,
            "0000000000000000000000000000000000000000000000000000000000000000"
        )
        .unwrap());
    }
}
