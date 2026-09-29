//! Nexis Core Financial Ledger Platform - Rust Crypto Engine
//! Module: Block Cryptographic Validator & Merkle Verifier
//!
//! Computes block digests and validates Merkle inclusion proofs using
//! SHA-256 and SHA-512 digest algorithms provided by the ring crate.

use ring::digest::{self, SHA256, SHA512};
use std::sync::RwLock;

/// Error enumeration for block validation.
#[derive(Debug)]
pub enum ValidationError {
    InvalidMerkleRoot,
    HashMismatch,
    MalformedProof,
    CorruptedBlockData,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidMerkleRoot => write!(f, "Computed Merkle root does not match block header"),
            ValidationError::HashMismatch => write!(f, "Block header SHA-256 digest mismatch"),
            ValidationError::MalformedProof => write!(f, "Merkle audit path is malformed"),
            ValidationError::CorruptedBlockData => write!(f, "Block serialized payload is corrupted"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Block header representation for cryptographic validation.
pub struct BlockHeader {
    pub index: u64,
    pub previous_hash: Vec<u8>,
    pub merkle_root: Vec<u8>,
    pub timestamp: u64,
    pub nonce: u64,
}

/// Cryptographic validator for ledger blocks and Merkle inclusion proofs.
pub struct BlockValidator {
    sha256_digests_computed: RwLock<u64>,
    sha512_digests_computed: RwLock<u64>,
    blocks_validated: RwLock<u64>,
}

impl BlockValidator {
    /// Creates a new BlockValidator instance.
    pub fn new() -> Self {
        Self {
            sha256_digests_computed: RwLock::new(0),
            sha512_digests_computed: RwLock::new(0),
            blocks_validated: RwLock::new(0),
        }
    }

    /// Computes SHA-256 digest of input data bytes.
    /// Captured by Spectra rule: digest::SHA256 (ALGO-SHA2-256)
    pub fn compute_sha256(&self, data: &[u8]) -> Vec<u8> {
        // Spectra detection target: &digest::SHA256
        let output = digest::digest(&SHA256, data);

        let mut count = self.sha256_digests_computed.write().unwrap();
        *count += 1;

        output.as_ref().to_vec()
    }

    /// Computes SHA-512 digest for high-security block checkpoints.
    /// Captured by Spectra rule: digest::SHA512 (ALGO-SHA2-512)
    pub fn compute_sha512(&self, data: &[u8]) -> Vec<u8> {
        // Spectra detection target: &digest::SHA512
        let output = digest::digest(&SHA512, data);

        let mut count = self.sha512_digests_computed.write().unwrap();
        *count += 1;

        output.as_ref().to_vec()
    }

    /// Computes the block header hash by hashing index, prev_hash, merkle_root, ts, and nonce.
    pub fn compute_header_hash(&self, header: &BlockHeader) -> Vec<u8> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&header.index.to_be_bytes());
        buffer.extend_from_slice(&header.previous_hash);
        buffer.extend_from_slice(&header.merkle_root);
        buffer.extend_from_slice(&header.timestamp.to_be_bytes());
        buffer.extend_from_slice(&header.nonce.to_be_bytes());

        self.compute_sha256(&buffer)
    }

    /// Verifies that a block header's hash satisfies expected digest.
    pub fn verify_block_hash(&self, header: &BlockHeader, expected_hash: &[u8]) -> Result<bool, ValidationError> {
        let computed = self.compute_header_hash(header);
        if computed != expected_hash {
            return Err(ValidationError::HashMismatch);
        }

        let mut count = self.blocks_validated.write().unwrap();
        *count += 1;

        Ok(true)
    }

    /// Verifies Merkle tree inclusion proof for a single leaf transaction.
    pub fn verify_merkle_proof(
        &self,
        leaf_hash: &[u8],
        proof_path: &[Vec<u8>],
        merkle_root: &[u8],
    ) -> Result<bool, ValidationError> {
        let mut current_hash = leaf_hash.to_vec();

        for sibling in proof_path {
            let mut combined = Vec::new();
            if current_hash <= *sibling {
                combined.extend_from_slice(&current_hash);
                combined.extend_from_slice(sibling);
            } else {
                combined.extend_from_slice(sibling);
                combined.extend_from_slice(&current_hash);
            }
            current_hash = self.compute_sha256(&combined);
        }

        if current_hash != merkle_root {
            return Err(ValidationError::InvalidMerkleRoot);
        }

        Ok(true)
    }

    /// Returns operational digest computation statistics.
    pub fn get_telemetry(&self) -> (u64, u64, u64) {
        let s256 = *self.sha256_digests_computed.read().unwrap();
        let s512 = *self.sha512_digests_computed.read().unwrap();
        let blocks = *self.blocks_validated.read().unwrap();
        (s256, s512, blocks)
    }
}
