//! Nexis Core Financial Ledger Platform - Rust Crypto Engine
//! Module: Domain Error Hierarchy & Fault Categorization
//!
//! Defines strongly typed domain error enumerations, recovery hints,
//! and standard error code mappings across the cryptographic microservice.

use std::fmt;

/// Top-level error categories across the ledger engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCategory {
    CryptographicFailure,
    ConsensusViolation,
    StorageCorruption,
    AuthenticationDenied,
    ValidationRejection,
    InternalSystemFault,
}

/// Standardized domain error type.
#[derive(Debug, Clone)]
pub struct CryptoRsError {
    pub category: ErrorCategory,
    pub code: String,
    pub message: String,
    pub details: Option<String>,
    pub timestamp: u64,
}

impl CryptoRsError {
    /// Creates a new CryptoRsError.
    pub fn new(category: ErrorCategory, code: &str, message: &str) -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            category,
            code: code.to_string(),
            message: message.to_string(),
            details: None,
            timestamp: ts,
        }
    }

    /// Attaches additional error context details.
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    /// Maps domain error to an HTTP status code equivalent.
    pub fn http_status_code(&self) -> u16 {
        match self.category {
            ErrorCategory::AuthenticationDenied => 401,
            ErrorCategory::ValidationRejection => 422,
            ErrorCategory::ConsensusViolation => 409,
            ErrorCategory::StorageCorruption => 500,
            ErrorCategory::CryptographicFailure => 500,
            ErrorCategory::InternalSystemFault => 500,
        }
    }

    /// Factory for invalid signature error.
    pub fn invalid_signature(reason: &str) -> Self {
        Self::new(
            ErrorCategory::CryptographicFailure,
            "ERR_CRYPTO_SIG_INVALID",
            reason,
        )
    }

    /// Factory for insufficient account balance error.
    pub fn insufficient_balance(account: &str, available: u64, requested: u64) -> Self {
        let msg = format!(
            "Account {} has {} available, but {} was requested",
            account, available, requested
        );
        Self::new(
            ErrorCategory::ValidationRejection,
            "ERR_LEDGER_INSUFFICIENT_FUNDS",
            &msg,
        )
    }

    /// Factory for invalid Merkle root.
    pub fn invalid_merkle_root(expected: &str, actual: &str) -> Self {
        let msg = format!("Expected root {}, calculated {}", expected, actual);
        Self::new(
            ErrorCategory::ConsensusViolation,
            "ERR_CONSENSUS_MERKLE_MISMATCH",
            &msg,
        )
    }
}

impl fmt::Display for CryptoRsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}: {}",
            self.code,
            format!("{:?}", self.category),
            self.message
        )
    }
}

impl std::error::Error for CryptoRsError {}
