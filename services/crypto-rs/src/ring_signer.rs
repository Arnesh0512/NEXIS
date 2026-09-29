//! Nexis Core Financial Ledger Platform - Rust Crypto Engine
//! Module: Ring Digital Signatures (Ed25519 and RSA)
//!
//! Provides cryptographic signing and verification primitives using the ring crate,
//! implementing Ed25519 and RSA-PKCS#1 v1.5 verification for transaction envelopes.

use ring::rand::SystemRandom;
use ring::signature::{
    self, Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519,
    RSA_PKCS1_2048_8192_SHA256,
};
use std::collections::HashMap;
use std::sync::RwLock;

/// Error enumeration for signature operations.
#[derive(Debug)]
pub enum SignerError {
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    KeyNotFound(String),
    InvalidKeyFormat,
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignerError::KeyGenerationFailed => write!(f, "Failed to generate digital signature keypair"),
            SignerError::SigningFailed => write!(f, "Digital signature generation failed"),
            SignerError::VerificationFailed => write!(f, "Digital signature verification rejected"),
            SignerError::KeyNotFound(k) => write!(f, "Signature key not found: {}", k),
            SignerError::InvalidKeyFormat => write!(f, "Invalid key format or encoding"),
        }
    }
}

impl std::error::Error for SignerError {}

/// Digital signature manager supporting Ed25519 and RSA verification via ring.
pub struct RingSigner {
    rng: SystemRandom,
    ed_keypairs: RwLock<HashMap<String, Ed25519KeyPair>>,
    ed_public_keys: RwLock<HashMap<String, Vec<u8>>>,
    signatures_created: RwLock<u64>,
    signatures_verified: RwLock<u64>,
}

impl RingSigner {
    /// Creates a new RingSigner instance.
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
            ed_keypairs: RwLock::new(HashMap::new()),
            ed_public_keys: RwLock::new(HashMap::new()),
            signatures_created: RwLock::new(0),
            signatures_verified: RwLock::new(0),
        }
    }

    /// Generates and registers an Ed25519 keypair under a given alias.
    /// Captured by Spectra rule: signature::ED25519 (ALGO-ED25519)
    pub fn generate_ed25519_keypair(&self, alias: &str) -> Result<Vec<u8>, SignerError> {
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&self.rng)
            .map_err(|_| SignerError::KeyGenerationFailed)?;

        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .map_err(|_| SignerError::KeyGenerationFailed)?;

        let public_key_bytes = key_pair.public_key().as_ref().to_vec();

        let mut kp_lock = self.ed_keypairs.write().unwrap();
        kp_lock.insert(alias.to_string(), key_pair);

        let mut pk_lock = self.ed_public_keys.write().unwrap();
        pk_lock.insert(alias.to_string(), public_key_bytes.clone());

        Ok(public_key_bytes)
    }

    /// Signs message bytes using the registered Ed25519 private key.
    pub fn sign_ed25519(&self, alias: &str, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        let kp_lock = self.ed_keypairs.read().unwrap();
        let key_pair = kp_lock
            .get(alias)
            .ok_or_else(|| SignerError::KeyNotFound(alias.to_string()))?;

        let sig = key_pair.sign(message);

        let mut count = self.signatures_created.write().unwrap();
        *count += 1;

        Ok(sig.as_ref().to_vec())
    }

    /// Verifies an Ed25519 signature against message and public key.
    /// Captured by Spectra rule: signature::ED25519 (ALGO-ED25519)
    pub fn verify_ed25519(
        &self,
        public_key_bytes: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, SignerError> {
        // Spectra detection target: &signature::ED25519
        let peer_public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);

        match peer_public_key.verify(message, signature_bytes) {
            Ok(()) => {
                let mut count = self.signatures_verified.write().unwrap();
                *count += 1;
                Ok(true)
            }
            Err(_) => Err(SignerError::VerificationFailed),
        }
    }

    /// Verifies an RSA-PKCS#1 v1.5 SHA-256 signature against an RSA public key.
    /// Captured by Spectra rule: signature::RSA_PKCS1_2048_8192_SHA256 (ALGO-RSA)
    pub fn verify_rsa_pkcs1(
        &self,
        rsa_public_key_bytes: &[u8],
        message: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, SignerError> {
        // Spectra detection target: &signature::RSA_PKCS1_2048_8192_SHA256
        let peer_public_key = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, rsa_public_key_bytes);

        match peer_public_key.verify(message, signature_bytes) {
            Ok(()) => {
                let mut count = self.signatures_verified.write().unwrap();
                *count += 1;
                Ok(true)
            }
            Err(_) => Err(SignerError::VerificationFailed),
        }
    }

    /// Retrieves cached public key bytes for an alias.
    pub fn get_public_key(&self, alias: &str) -> Option<Vec<u8>> {
        let lock = self.ed_public_keys.read().unwrap();
        lock.get(alias).cloned()
    }

    /// Returns operational metrics.
    pub fn get_telemetry(&self) -> (u64, u64, usize) {
        let created = *self.signatures_created.read().unwrap();
        let verified = *self.signatures_verified.read().unwrap();
        let total_keys = self.ed_keypairs.read().unwrap().len();
        (created, verified, total_keys)
    }
}
