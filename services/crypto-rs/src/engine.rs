//! Nexis Core Financial Ledger Platform - Crypto-RS Service
//! Module: Consensus Engine & Block Assembly State Machine
//!
//! Coordinates state transitions, invokes cryptographic validation on inbound
//! transactions, signs finalized block digests, and persists snapshots to encrypted vault storage.

use crate::accounts::AccountLedger;
use crate::block_validator::{BlockHeader, BlockValidator};
use crate::ring_signer::RingSigner;
use crate::storage_backend::StorageBackend;
use std::sync::{Arc, RwLock};

/// Represents an atomic ledger transaction processed by consensus.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
}

/// Represents a finalized block in the ledger chain.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Block {
    pub height: u64,
    pub previous_hash: String,
    pub merkle_root: String,
    pub transactions: Vec<Transaction>,
    pub signature: String,
    pub timestamp: u64,
}

/// Consensus state machine driving distributed block sequencing.
pub struct ConsensusEngine {
    storage: Arc<StorageBackend>,
    signer: Arc<RingSigner>,
    validator: Arc<BlockValidator>,
    accounts: Arc<AccountLedger>,
    mempool: RwLock<Vec<Transaction>>,
    chain: RwLock<Vec<Block>>,
    blocks_produced: RwLock<u64>,
}

impl ConsensusEngine {
    /// Creates a new ConsensusEngine instance.
    pub fn new(
        storage: Arc<StorageBackend>,
        signer: Arc<RingSigner>,
        validator: Arc<BlockValidator>,
        accounts: Arc<AccountLedger>,
    ) -> Self {
        let genesis = Block {
            height: 0,
            previous_hash: "0".repeat(64),
            merkle_root: "0".repeat(64),
            transactions: Vec::new(),
            signature: "genesis_signature".to_string(),
            timestamp: 1700000000,
        };

        Self {
            storage,
            signer,
            validator,
            accounts,
            mempool: RwLock::new(Vec::new()),
            chain: RwLock::new(vec![genesis]),
            blocks_produced: RwLock::new(0),
        }
    }

    /// Submits a validated transaction to the memory pool.
    pub fn submit_transaction(&self, tx: Transaction) -> Result<String, String> {
        if tx.amount == 0 {
            return Err("Transaction amount must be positive".to_string());
        }

        // Validate account balance
        if !self.accounts.has_sufficient_balance(&tx.source, tx.amount + tx.fee) {
            return Err(format!("Insufficient balance in account: {}", tx.source));
        }

        let mut pool = self.mempool.write().unwrap();
        let tx_id = tx.id.clone();
        pool.push(tx);

        Ok(tx_id)
    }

    /// Assembles, validates, signs, and commits a new block.
    /// CALL GRAPH: calls BlockValidator.compute_sha256,
    ///             RingSigner.sign_ed25519,
    ///             StorageBackend.put
    pub fn produce_block(&self, batch_size: usize) -> Result<Block, String> {
        let mut pool = self.mempool.write().unwrap();
        if pool.is_empty() {
            return Err("Mempool is empty, no transactions to seal".to_string());
        }

        let drain_count = batch_size.min(pool.len());
        let txs: Vec<Transaction> = pool.drain(0..drain_count).collect();
        drop(pool); // Release mempool lock

        let last_block = {
            let ch = self.chain.read().unwrap();
            ch.last().unwrap().clone()
        };

        // CALL GRAPH: Compute Merkle Root using BlockValidator
        let mut leaf_hashes: Vec<Vec<u8>> = Vec::new();
        for tx in &txs {
            let serialized = serde_json::to_vec(tx).map_err(|e| e.to_string())?;
            // CALL GRAPH: compute SHA-256 leaf digest
            let leaf = self.validator.compute_sha256(&serialized);
            leaf_hashes.push(leaf);
        }

        let merkle_root_bytes = if leaf_hashes.is_empty() {
            vec![0u8; 32]
        } else {
            leaf_hashes[0].clone()
        };
        let merkle_root_hex = hex::encode(&merkle_root_bytes);

        let height = last_block.height + 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Construct block header to sign
        let header_str = format!("{}:{}:{}:{}", height, last_block.merkle_root, merkle_root_hex, now);

        // CALL GRAPH: Sign block using RingSigner
        let sig_bytes = self
            .signer
            .sign_ed25519("genesis-node", header_str.as_bytes())
            .map_err(|e| e.to_string())?;
        let signature_hex = hex::encode(sig_bytes);

        // Apply state updates to accounts ledger
        for tx in &txs {
            let _ = self.accounts.debit(&tx.source, tx.amount + tx.fee);
            let _ = self.accounts.credit(&tx.destination, tx.amount);
        }

        let new_block = Block {
            height,
            previous_hash: last_block.merkle_root,
            merkle_root: merkle_root_hex,
            transactions: txs,
            signature: signature_hex,
            timestamp: now,
        };

        // CALL GRAPH: Persist encrypted block checkpoint in StorageBackend
        let serialized_block = serde_json::to_vec(&new_block).map_err(|e| e.to_string())?;
        let block_key = format!("block_{:012}", height);
        self.storage
            .put(&block_key, &serialized_block, b"BLOCK_CHECKPOINT")
            .map_err(|e| e.to_string())?;

        let mut ch = self.chain.write().unwrap();
        ch.push(new_block.clone());

        let mut count = self.blocks_produced.write().unwrap();
        *count += 1;

        Ok(new_block)
    }

    /// Returns current block height of the ledger chain.
    pub fn block_height(&self) -> u64 {
        let ch = self.chain.read().unwrap();
        ch.len() as u64 - 1
    }

    /// Returns number of pending uncommitted transactions in mempool.
    pub fn mempool_depth(&self) -> usize {
        let pool = self.mempool.read().unwrap();
        pool.len()
    }
}
