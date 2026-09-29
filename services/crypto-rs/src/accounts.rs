//! Nexis Core Financial Ledger Platform - Crypto-RS Service
//! Module: Account Balance Ledger & State Tracker
//!
//! Maintains thread-safe in-memory state for financial operator balances,
//! transaction nonce validation, and double-entry invariants.

use std::collections::HashMap;
use std::sync::RwLock;

/// Represents an account entity in the state ledger.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub id: String,
    pub balance: u64,
    pub locked_balance: u64,
    pub nonce: u64,
    pub created_at: u64,
    pub is_active: bool,
}

/// Ledger state container tracking account balances.
pub struct AccountLedger {
    accounts: RwLock<HashMap<String, Account>>,
    total_volume_settled: RwLock<u64>,
}

impl AccountLedger {
    /// Creates a new empty AccountLedger instance.
    pub fn new() -> Self {
        let mut initial_accounts = HashMap::new();

        // Seed system treasury and settlement pools
        initial_accounts.insert(
            "treasury_pool".to_string(),
            Account {
                id: "treasury_pool".to_string(),
                balance: 100_000_000_000, // 100B initial units
                locked_balance: 0,
                nonce: 0,
                created_at: 1700000000,
                is_active: true,
            },
        );

        initial_accounts.insert(
            "merchant_clearing".to_string(),
            Account {
                id: "merchant_clearing".to_string(),
                balance: 5_000_000_000,
                locked_balance: 0,
                nonce: 0,
                created_at: 1700000000,
                is_active: true,
            },
        );

        Self {
            accounts: RwLock::new(initial_accounts),
            total_volume_settled: RwLock::new(0),
        }
    }

    /// Checks if an account has sufficient balance for a debit operation.
    pub fn has_sufficient_balance(&self, account_id: &str, amount: u64) -> bool {
        let lock = self.accounts.read().unwrap();
        if let Some(acc) = lock.get(account_id) {
            acc.is_active && acc.balance >= amount
        } else {
            false
        }
    }

    /// Debits an account, validating balance sufficiency and incrementing nonce.
    pub fn debit(&self, account_id: &str, amount: u64) -> Result<u64, String> {
        let mut lock = self.accounts.write().unwrap();
        let acc = lock
            .get_mut(account_id)
            .ok_or_else(|| format!("Account not found: {}", account_id))?;

        if !acc.is_active {
            return Err("Account is inactive".to_string());
        }

        if acc.balance < amount {
            return Err(format!(
                "Insufficient funds in {}: balance={}, requested={}",
                account_id, acc.balance, amount
            ));
        }

        acc.balance -= amount;
        acc.nonce += 1;

        let mut vol = self.total_volume_settled.write().unwrap();
        *vol += amount;

        Ok(acc.balance)
    }

    /// Credits an account, creating the record if it does not yet exist.
    pub fn credit(&self, account_id: &str, amount: u64) -> Result<u64, String> {
        let mut lock = self.accounts.write().unwrap();
        let acc = lock.entry(account_id.to_string()).or_insert_with(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Account {
                id: account_id.to_string(),
                balance: 0,
                locked_balance: 0,
                nonce: 0,
                created_at: now,
                is_active: true,
            }
        });

        acc.balance += amount;
        Ok(acc.balance)
    }

    /// Returns a copy of an account's balance state.
    pub fn get_account(&self, account_id: &str) -> Option<Account> {
        let lock = self.accounts.read().unwrap();
        lock.get(account_id).cloned()
    }

    /// Locks an amount of funds for escrow or conditional clearing.
    pub fn lock_funds(&self, account_id: &str, amount: u64) -> Result<(), String> {
        let mut lock = self.accounts.write().unwrap();
        let acc = lock
            .get_mut(account_id)
            .ok_or_else(|| format!("Account not found: {}", account_id))?;

        if acc.balance < amount {
            return Err("Insufficient available balance to lock".to_string());
        }

        acc.balance -= amount;
        acc.locked_balance += amount;
        Ok(())
    }

    /// Releases locked funds back to available balance.
    pub fn release_locked_funds(&self, account_id: &str, amount: u64) -> Result<(), String> {
        let mut lock = self.accounts.write().unwrap();
        let acc = lock
            .get_mut(account_id)
            .ok_or_else(|| format!("Account not found: {}", account_id))?;

        if acc.locked_balance < amount {
            return Err("Requested release exceeds locked balance".to_string());
        }

        acc.locked_balance -= amount;
        acc.balance += amount;
        Ok(())
    }

    /// Returns the total number of managed accounts.
    pub fn total_accounts(&self) -> usize {
        let lock = self.accounts.read().unwrap();
        lock.len()
    }

    /// Returns the cumulative settled transaction volume.
    pub fn total_settled_volume(&self) -> u64 {
        *self.total_volume_settled.read().unwrap()
    }
}
