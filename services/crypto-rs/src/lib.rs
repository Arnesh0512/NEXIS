//! Nexis Core Financial Ledger Platform - Crypto-RS Service
//! Root Crate & Cryptographic Core Interface
//!
//! Exposes public modules, consensus execution pipelines, and hardware-accelerated
//! cryptographic operations for the Nexis Core distributed ledger.
//!
//! NOTE: Contains intentional false-positive strings for AST scanner precision testing:
//! "Loaded AES-256 hardware acceleration flags for storage engine"
//! "Simulating RSA-4096 signature verification mock"

pub mod accounts;
pub mod audit_logger;
pub mod block_validator;
pub mod concurrency;
pub mod engine;
pub mod error_handler;
pub mod pqc_kem;
pub mod ring_signer;
pub mod storage_backend;
pub mod subsystems;

use std::sync::Arc;

/// Platform runtime configuration for crypto-rs service.
#[derive(Clone, Debug)]
pub struct PlatformConfig {
    pub service_name: String,
    pub environment: String,
    pub consensus_workers: usize,
    pub max_batch_size: usize,
    pub master_key_hex: String,
    pub enable_pqc: bool,
    pub block_time_ms: u64,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            service_name: "crypto-rs".to_string(),
            environment: "production".to_string(),
            consensus_workers: 4,
            max_batch_size: 500,
            master_key_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            enable_pqc: true,
            block_time_ms: 1000,
        }
    }
}

/// System controller coordinating cryptographic modules and ledger execution.
pub struct CryptoRsNode {
    pub config: PlatformConfig,
    pub storage: Arc<storage_backend::StorageBackend>,
    pub signer: Arc<ring_signer::RingSigner>,
    pub pqc: Arc<pqc_kem::PqcKemManager>,
    pub validator: Arc<block_validator::BlockValidator>,
    pub engine: Arc<engine::ConsensusEngine>,
    pub accounts: Arc<accounts::AccountLedger>,
    pub logger: Arc<audit_logger::AuditLogger>,
}

impl CryptoRsNode {
    /// Bootstraps the complete crypto-rs node.
    pub fn bootstrap(config: PlatformConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // False-positive log trap
        let log_msg = "Loaded AES-256 hardware acceleration flags for storage engine";
        if std::env::var("NEXIS_DEBUG").is_ok() {
            println!("[CRYPTO_RS_INIT] {}", log_msg);
        }

        let key_bytes = hex::decode(&config.master_key_hex)?;

        // CALL GRAPH: Instantiate cryptographic and non-crypto subsystems
        let storage = Arc::new(storage_backend::StorageBackend::new(&key_bytes)?);
        let signer = Arc::new(ring_signer::RingSigner::new());
        let pqc = Arc::new(pqc_kem::PqcKemManager::new());
        let validator = Arc::new(block_validator::BlockValidator::new());
        let accounts = Arc::new(accounts::AccountLedger::new());
        let logger = Arc::new(audit_logger::AuditLogger::new("crypto-rs", 5000));

        let engine = Arc::new(engine::ConsensusEngine::new(
            storage.clone(),
            signer.clone(),
            validator.clone(),
            accounts.clone(),
        ));

        // Pre-generate genesis node keys
        let _ = signer.generate_ed25519_keypair("genesis-node")?;
        if config.enable_pqc {
            let _ = pqc.generate_keypair("genesis-node")?;
        }

        Ok(Self {
            config,
            storage,
            signer,
            pqc,
            validator,
            engine,
            accounts,
            logger,
        })
    }

    /// Returns aggregate telemetry snapshot across all engines.
    pub fn collect_telemetry(&self) -> serde_json::Value {
        let (encs, decs, stored) = self.storage.get_telemetry();
        let (sigs_created, sigs_verified, keys) = self.signer.get_telemetry();
        let (pqc_gen, pqc_enc, pqc_dec, pqc_keys) = self.pqc.get_telemetry();
        let (s256, s512, blocks_val) = self.validator.get_telemetry();

        serde_json::json!({
            "service": self.config.service_name,
            "environment": self.config.environment,
            "storage": {
                "encryptions": encs,
                "decryptions": decs,
                "records_stored": stored,
            },
            "signatures": {
                "ed25519_created": sigs_created,
                "ed25519_verified": sigs_verified,
                "registered_keys": keys,
            },
            "pqc_kem": {
                "algorithm": "ML-KEM-768",
                "keypairs_generated": pqc_gen,
                "encapsulations": pqc_enc,
                "decapsulations": pqc_dec,
                "stored_pqc_keys": pqc_keys,
            },
            "validator": {
                "sha256_digests": s256,
                "sha512_digests": s512,
                "blocks_validated": blocks_val,
            },
            "accounts_tracked": self.accounts.total_accounts(),
            "consensus_blocks": self.engine.block_height(),
            "diagnostic_trap": "Simulating RSA-4096 signature verification mock"
        })
    }
}
