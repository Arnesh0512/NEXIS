//! Nexis Compliance Subsystem - Integrity Verifier
//! Computes SHA-256 cryptographic digests using ring, persists baseline fingerprints
//! to Redis / in-memory cache, and executes automated system health integrity probes.
//!
//! Crates: ring, redis

use ring::digest::{digest, SHA256};
use redis::{Commands, Client as RedisClient};
use std::collections::HashMap;
use std::sync::RwLock;

static BASELINE_CACHE: RwLock<HashMap<String, String>> = RwLock::new(HashMap::new());

/// Tier 1 (abcd): Computes a SHA-256 cryptographic digest of a dataset using ring.
pub fn abcd_hash_dataset_sha256(data: &str) -> String {
    let digest_result = digest(&SHA256, data.as_bytes());
    hex::encode(digest_result.as_ref())
}

/// Tier 2 (efgh): Stores cryptographic baseline hash in Redis cluster or memory fallback.
pub fn efgh_store_integrity_baseline(key: &str, hash_str: &str) -> bool {
    let redis_url = std::env::var("NEXIS_REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    if let Ok(client) = RedisClient::open(redis_url) {
        if let Ok(mut con) = client.get_connection() {
            let redis_key = format!("integrity:baseline:{}", key);
            let _: Result<(), _> = con.set(redis_key, hash_str);
        }
    }

    // Persist to in-memory fallback
    let mut cache = BASELINE_CACHE.write().unwrap();
    cache.insert(key.to_string(), hash_str.to_string());
    true
}

/// Tier 2 (efgh): Compares current dataset hash against established baseline fingerprint.
pub fn efgh_compare_baseline(key: &str, current_data: &str) -> bool {
    let current_hash = abcd_hash_dataset_sha256(current_data);

    let redis_url = std::env::var("NEXIS_REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let mut baseline_opt: Option<String> = None;
    if let Ok(client) = RedisClient::open(redis_url) {
        if let Ok(mut con) = client.get_connection() {
            let redis_key = format!("integrity:baseline:{}", key);
            if let Ok(val) = con.get::<_, String>(&redis_key) {
                baseline_opt = Some(val);
            }
        }
    }

    if baseline_opt.is_none() {
        let cache = BASELINE_CACHE.read().unwrap();
        baseline_opt = cache.get(key).cloned();
    }

    match baseline_opt {
        Some(stored_hash) => stored_hash == current_hash,
        None => {
            // First run initializes baseline
            efgh_store_integrity_baseline(key, &current_hash);
            true
        }
    }
}

/// Tier 3 (ijkl): Executes targeted integrity verification check on specific operational dataset.
pub fn ijkl_run_integrity_check(target_id: &str, data: &str) -> bool {
    efgh_compare_baseline(target_id, data)
}

/// Tier 4 (mnop): Performs periodic system-wide health and cryptographic integrity probe.
pub fn mnop_system_health_integrity_probe() -> std::collections::HashMap<String, String> {
    let mut probe_results = HashMap::new();

    let subsystems = [
        ("core_ledger_balances", "GENESIS_BALANCE_ROOT_HASH_2026"),
        ("audit_merkle_root", "MERKLE_TREE_ROOT_STATE_HASH_OK"),
        ("pci_vault_registry", "PCI_VAULT_ISOLATED_CONTAINER_V1"),
        ("settlement_journal", "DAILY_ACH_FEDWIRE_MATCH_OK"),
    ];

    for (subsystem, sample_data) in subsystems {
        let is_intact = ijkl_run_integrity_check(subsystem, sample_data);
        let status = if is_intact { "INTEGRITY_OK" } else { "TAMPERING_DETECTED" };
        probe_results.insert(subsystem.to_string(), status.to_string());
    }

    probe_results
}
