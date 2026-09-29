//! Nexis Core Financial Ledger Platform - Rust Crypto Engine
//! Module: Post-Quantum KEM Hardware Acceleration (ML-KEM-768 / Kyber)
//!
//! Implements FIPS 203 ML-KEM post-quantum key encapsulation using pqcrypto-kyber
//! to establish forward-secret symmetric keys resilient against quantum decryption.

use pqcrypto_kyber::kyber768::{
    self, encapsulate, decapsulate, PublicKey, SecretKey,
};
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};
use std::collections::HashMap;
use std::sync::RwLock;

/// Error enumeration for PQC KEM operations.
#[derive(Debug)]
pub enum PqcError {
    KeyGenerationFailed,
    EncapsulationFailed,
    DecapsulationFailed,
    KeyNotFound(String),
    InvalidLength,
}

impl std::fmt::Display for PqcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqcError::KeyGenerationFailed => write!(f, "Post-Quantum keypair generation failed"),
            PqcError::EncapsulationFailed => write!(f, "Kyber768 key encapsulation failed"),
            PqcError::DecapsulationFailed => write!(f, "Kyber768 key decapsulation failed"),
            PqcError::KeyNotFound(k) => write!(f, "PQC key alias not found: {}", k),
            PqcError::InvalidLength => write!(f, "Invalid Kyber768 buffer length"),
        }
    }
}

impl std::error::Error for PqcError {}

/// Encapsulation container carrying ciphertext and derived shared secret.
pub struct KemEnvelope {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Post-Quantum Kyber-768 (ML-KEM-768) encapsulation manager.
pub struct PqcKemManager {
    secret_keys: RwLock<HashMap<String, SecretKey>>,
    public_keys: RwLock<HashMap<String, PublicKey>>,
    keypairs_generated: RwLock<u64>,
    encaps_count: RwLock<u64>,
    decaps_count: RwLock<u64>,
}

impl PqcKemManager {
    /// Instantiates a new Post-Quantum KEM manager.
    pub fn new() -> Self {
        Self {
            secret_keys: RwLock::new(HashMap::new()),
            public_keys: RwLock::new(HashMap::new()),
            keypairs_generated: RwLock::new(0),
            encaps_count: RwLock::new(0),
            decaps_count: RwLock::new(0),
        }
    }

    /// Generates a new Kyber-768 (ML-KEM-768) keypair.
    /// Captured by Spectra rule: kyber768::keypair (ALGO-ML-KEM)
    pub fn generate_keypair(&self, alias: &str) -> Result<Vec<u8>, PqcError> {
        // Spectra detection target: kyber768::keypair
        let (pk, sk) = kyber768::keypair();

        let pk_bytes = pk.as_bytes().to_vec();

        let mut sk_lock = self.secret_keys.write().unwrap();
        sk_lock.insert(alias.to_string(), sk);

        let mut pk_lock = self.public_keys.write().unwrap();
        pk_lock.insert(alias.to_string(), pk);

        let mut count = self.keypairs_generated.write().unwrap();
        *count += 1;

        Ok(pk_bytes)
    }

    /// Encapsulates a shared secret using a peer's Kyber768 public key.
    pub fn encapsulate_secret(&self, peer_pk_bytes: &[u8]) -> Result<KemEnvelope, PqcError> {
        let peer_pk = PublicKey::from_bytes(peer_pk_bytes).map_err(|_| PqcError::InvalidLength)?;

        let (ss, ct) = encapsulate(&peer_pk);

        let mut count = self.encaps_count.write().unwrap();
        *count += 1;

        Ok(KemEnvelope {
            ciphertext: ct.as_bytes().to_vec(),
            shared_secret: ss.as_bytes().to_vec(),
        })
    }

    /// Decapsulates ciphertext using the local node's private key.
    pub fn decapsulate_secret(&self, alias: &str, ct_bytes: &[u8]) -> Result<Vec<u8>, PqcError> {
        let sk_lock = self.secret_keys.read().unwrap();
        let sk = sk_lock
            .get(alias)
            .ok_or_else(|| PqcError::KeyNotFound(alias.to_string()))?;

        let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(ct_bytes)
            .map_err(|_| PqcError::InvalidLength)?;

        let ss = decapsulate(&ct, sk);

        let mut count = self.decaps_count.write().unwrap();
        *count += 1;

        Ok(ss.as_bytes().to_vec())
    }

    /// Exports public key bytes for an alias.
    pub fn export_public_key(&self, alias: &str) -> Option<Vec<u8>> {
        let pk_lock = self.public_keys.read().unwrap();
        pk_lock.get(alias).map(|pk| pk.as_bytes().to_vec())
    }

    /// Returns algorithm metadata.
    pub fn algorithm_name(&self) -> &'static str {
        "ML-KEM-768"
    }

    /// Returns operational telemetry metrics.
    pub fn get_telemetry(&self) -> (u64, u64, u64, usize) {
        let gen = *self.keypairs_generated.read().unwrap();
        let enc = *self.encaps_count.read().unwrap();
        let dec = *self.decaps_count.read().unwrap();
        let keys = self.secret_keys.read().unwrap().len();
        (gen, enc, dec, keys)
    }
}
