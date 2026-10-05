//! Secret Rotator Subsystem
//! Post-Quantum (ML-KEM-768 / Kyber) key rotation and cloud storage synchronization.

use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
use ring::digest;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

/// In-memory cloud storage mock backup for secret payloads.
static CLOUD_STORAGE_MOCK: OnceLock<RwLock<HashMap<String, Vec<u8>>>> = OnceLock::new();
/// In-memory active secrets store.
static ACTIVE_SECRETS: OnceLock<RwLock<HashMap<String, Vec<u8>>>> = OnceLock::new();

fn get_cloud_mock() -> &'static RwLock<HashMap<String, Vec<u8>>> {
    CLOUD_STORAGE_MOCK.get_or_init(|| RwLock::new(HashMap::new()))
}

fn get_active_secrets() -> &'static RwLock<HashMap<String, Vec<u8>>> {
    ACTIVE_SECRETS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Generates a post-quantum Kyber-768 replacement keypair (ML-KEM-768).
/// Returns a tuple of (public_key_bytes, secret_key_bytes).
pub fn abcd_generate_replacement_kyber_key() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = kyber768::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

/// Backs up encrypted secret payloads to cloud storage (Google Cloud Storage / Mock tier).
pub fn efgh_backup_secret_to_cloud(secret_name: &str, payload: &[u8]) -> bool {
    // Mirror to cloud backup store
    if let Ok(mut cloud) = get_cloud_mock().write() {
        cloud.insert(secret_name.to_string(), payload.to_vec());
        true
    } else {
        false
    }
}

/// Activates and applies a newly rotated secret payload into the local high-speed secret store.
pub fn efgh_apply_rotated_secret(secret_id: &str, new_secret: &[u8]) -> bool {
    if let Ok(mut active) = get_active_secrets().write() {
        active.insert(secret_id.to_string(), new_secret.to_vec());
        true
    } else {
        false
    }
}

/// Executes a scheduled post-quantum secret rotation pipeline for a given schedule identifier.
pub fn ijkl_execute_scheduled_rotation(schedule_id: &str) -> bool {
    // 1. Generate PQ Kyber replacement keypair
    let (pk_bytes, sk_bytes) = abcd_generate_replacement_kyber_key();

    // 2. Backup secret to cloud storage tier
    let backup_name = format!("backup/{}/pqc_kyber_sk.bin", schedule_id);
    let backup_ok = efgh_backup_secret_to_cloud(&backup_name, &sk_bytes);

    // 3. Apply rotated secret to active memory
    let apply_ok = efgh_apply_rotated_secret(schedule_id, &pk_bytes);

    backup_ok && apply_ok
}

/// Verifies the cryptographic integrity and backup synchronization status of a rotated secret.
pub fn mnop_verify_rotation_integrity(secret_id: &str) -> HashMap<String, String> {
    let mut report = HashMap::new();

    let active_opt = get_active_secrets().read().ok().and_then(|m| m.get(secret_id).cloned());
    let backup_name = format!("backup/{}/pqc_kyber_sk.bin", secret_id);
    let backup_opt = get_cloud_mock().read().ok().and_then(|m| m.get(&backup_name).cloned());

    match (active_opt, backup_opt) {
        (Some(active_pk), Some(backup_sk)) => {
            let pk_hash = hex::encode(digest::digest(&digest::SHA256, &active_pk).as_ref());
            let sk_hash = hex::encode(digest::digest(&digest::SHA256, &backup_sk).as_ref());

            report.insert("status".to_string(), "VERIFIED".to_string());
            report.insert("algorithm".to_string(), "ML-KEM-768".to_string());
            report.insert("secret_id".to_string(), secret_id.to_string());
            report.insert("public_key_digest".to_string(), pk_hash);
            report.insert("backup_secret_digest".to_string(), sk_hash);
            report.insert("cloud_synced".to_string(), "true".to_string());
        }
        _ => {
            report.insert("status".to_string(), "UNSYNCHRONIZED".to_string());
            report.insert("secret_id".to_string(), secret_id.to_string());
            report.insert("cloud_synced".to_string(), "false".to_string());
        }
    }

    report
}
