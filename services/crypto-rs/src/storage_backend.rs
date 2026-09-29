//! Nexis Core Financial Ledger Platform - Rust Crypto Engine
//! Module: Encrypted Key-Value Storage Backend (AES-256-GCM)
//!
//! Provides authenticated encryption and decryption for sensitive persistent
//! vault state on disk using the aes-gcm crate with 256-bit symmetric keys.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::collections::HashMap;
use std::sync::RwLock;

/// Error enumeration for vault storage operations.
#[derive(Debug)]
pub enum StorageError {
    EncryptionFailed,
    DecryptionFailed,
    KeyNotFound(String),
    CorruptedRecord,
    InvalidKeyLength,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::EncryptionFailed => write!(f, "AES-GCM encryption operation failed"),
            StorageError::DecryptionFailed => write!(f, "AES-GCM decryption / authentication tag verification failed"),
            StorageError::KeyNotFound(k) => write!(f, "Storage key not found: {}", k),
            StorageError::CorruptedRecord => write!(f, "Encrypted record format corrupted"),
            StorageError::InvalidKeyLength => write!(f, "Master key must be exactly 32 bytes for AES-256"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Encrypted container holding ciphertext and 12-byte initialization nonce.
#[derive(Clone, Debug)]
pub struct EncryptedContainer {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub timestamp: u64,
}

/// Thread-safe in-memory key-value store secured with AES-256-GCM.
pub struct StorageBackend {
    cipher: Aes256Gcm,
    records: RwLock<HashMap<String, EncryptedContainer>>,
    encryption_count: RwLock<u64>,
    decryption_count: RwLock<u64>,
}

impl StorageBackend {
    /// Creates a new storage backend instance with a 32-byte master key.
    /// Captured by Spectra rule: Aes256Gcm::new (ALGO-AES)
    pub fn new(master_key_bytes: &[u8]) -> Result<Self, StorageError> {
        if master_key_bytes.len() != 32 {
            return Err(StorageError::InvalidKeyLength);
        }

        // Spectra detection target: Key Init
        let key = Key::<Aes256Gcm>::from_slice(master_key_bytes);

        // Spectra detection target: Aes256Gcm::new
        let cipher = Aes256Gcm::new(key);

        Ok(Self {
            cipher,
            records: RwLock::new(HashMap::new()),
            encryption_count: RwLock::new(0),
            decryption_count: RwLock::new(0),
        })
    }

    /// Encrypts plaintext and persists it under the specified key identifier.
    pub fn put(&self, key: &str, plaintext: &[u8], associated_data: &[u8]) -> Result<(), StorageError> {
        // Generate pseudo-random nonce for simulation
        let mut nonce_bytes = [0u8; 12];
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for (i, b) in ts.to_le_bytes().iter().take(12).enumerate() {
            nonce_bytes[i] = *b;
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        // Spectra detection target: cipher.encrypt (Aead::encrypt)
        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|_| StorageError::EncryptionFailed)?;

        let container = EncryptedContainer {
            nonce: nonce_bytes,
            ciphertext,
            timestamp: (ts / 1_000_000) as u64,
        };

        let mut lock = self.records.write().unwrap();
        lock.insert(key.to_string(), container);

        let mut enc_lock = self.encryption_count.write().unwrap();
        *enc_lock += 1;

        Ok(())
    }

    /// Decrypts and authenticates data stored under key identifier.
    pub fn get(&self, key: &str, associated_data: &[u8]) -> Result<Vec<u8>, StorageError> {
        let lock = self.records.read().unwrap();
        let container = lock
            .get(key)
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))?;

        let nonce = Nonce::from_slice(&container.nonce);
        let payload = Payload {
            msg: &container.ciphertext,
            aad: associated_data,
        };

        // Spectra detection target: cipher.decrypt (Aead::decrypt)
        let plaintext = self
            .cipher
            .decrypt(nonce, payload)
            .map_err(|_| StorageError::DecryptionFailed)?;

        let mut dec_lock = self.decryption_count.write().unwrap();
        *dec_lock += 1;

        Ok(plaintext)
    }

    /// Removes a key from the storage backend.
    pub fn delete(&self, key: &str) -> bool {
        let mut lock = self.records.write().unwrap();
        lock.remove(key).is_some()
    }

    /// Checks if a key exists in storage.
    pub fn contains_key(&self, key: &str) -> bool {
        let lock = self.records.read().unwrap();
        lock.contains_key(key)
    }

    /// Returns the total number of records managed.
    pub fn record_count(&self) -> usize {
        let lock = self.records.read().unwrap();
        lock.len()
    }

    /// Returns operational metrics.
    pub fn get_telemetry(&self) -> (u64, u64, usize) {
        let encs = *self.encryption_count.read().unwrap();
        let decs = *self.decryption_count.read().unwrap();
        let count = self.record_count();
        (encs, decs, count)
    }
}
