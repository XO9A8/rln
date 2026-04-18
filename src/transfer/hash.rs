//! SHA-256 streaming hash verification for P2P file transfers.
//!
//! [`HashVerification`] wraps a running `sha2::Sha256` digest and allows callers
//! to feed data in arbitrary-size chunks before finalizing the hex digest.
//! This mirrors how the transfer protocol works — data arrives in stream chunks
//! and is hashed incrementally without buffering the entire file in memory.
use sha2::{Digest, Sha256};

/// An incremental SHA-256 hasher for verifying in-flight file transfer integrity.
pub struct HashVerification {
    hasher: Sha256,
}

impl HashVerification {
    /// Creates a new hasher ready to accept data.
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Feeds a chunk of bytes into the running digest.
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    /// Consumes the hasher and returns the final SHA-256 digest as a lowercase hex string.
    pub fn finalize(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl Default for HashVerification {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_streaming() {
        let mut verifier = HashVerification::new();
        verifier.update(b"hello");
        verifier.update(b" ");
        verifier.update(b"world");

        let hash = verifier.finalize();
        // Standard SHA-256 for "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_single_chunk() {
        let mut verifier = HashVerification::new();
        verifier.update(b"hello world");
        let hash = verifier.finalize();
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_empty() {
        let verifier = HashVerification::new();
        let hash = verifier.finalize();
        // SHA-256 of empty input
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
