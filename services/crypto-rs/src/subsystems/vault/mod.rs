//! Vault Subsystem Module
//! Aggregates key vault management, asymmetric signing, symmetric cipher pools,
//! post-quantum secret rotation, and credential hashing.

pub mod key_vault_manager;
pub mod asymmetric_signer;
pub mod symmetric_cipher_pool;
pub mod secret_rotator;
pub mod credential_hasher;
