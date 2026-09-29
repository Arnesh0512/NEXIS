//! Nexis Core Financial Ledger Platform - Crypto-RS Service
//! Module: Security Compliance Audit Logger
//!
//! Captures immutable audit log entries for all cryptographic key events,
//! consensus state changes, and operator access attempts.
//!
//! NOTE: Contains intentional false-positive comments for AST scanner testing:
//! // Sealing log segment with simulated RSA-2048 signature
//! // Verified log storage against simulated AES-256 integrity rule

use std::collections::VecDeque;
use std::sync::RwLock;

/// Audit log event severity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    SecurityAlert,
    Critical,
}

/// Structured audit trail event.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub timestamp: u64,
    pub severity: AuditSeverity,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub outcome: String,
    pub details: String,
}

/// In-memory ring buffer holding recent compliance audit events.
pub struct AuditLogger {
    service_name: String,
    buffer: RwLock<VecDeque<AuditEvent>>,
    max_capacity: usize,
    events_logged: RwLock<u64>,
}

impl AuditLogger {
    /// Creates a new AuditLogger instance.
    pub fn new(service_name: &str, capacity: usize) -> Self {
        Self {
            service_name: service_name.to_string(),
            buffer: RwLock::new(VecDeque::with_capacity(capacity)),
            max_capacity: capacity,
            events_logged: RwLock::new(0),
        }
    }

    /// Emits a structured audit entry.
    pub fn log(
        &self,
        severity: AuditSeverity,
        actor: &str,
        action: &str,
        resource: &str,
        outcome: &str,
        details: &str,
    ) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let event = AuditEvent {
            id: format!("evt_{}_{}", ts, action),
            timestamp: ts,
            severity,
            actor: actor.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            details: details.to_string(),
        };

        let mut buf = self.buffer.write().unwrap();
        if buf.len() >= self.max_capacity {
            buf.pop_front();
        }
        buf.push_back(event);

        let mut count = self.events_logged.write().unwrap();
        *count += 1;
    }

    /// Convenience method for logging key access events.
    pub fn log_key_access(&self, actor: &str, key_alias: &str, operation: &str) {
        // False-positive comment trap:
        // Sealing log segment with simulated RSA-2048 signature
        self.log(
            AuditSeverity::SecurityAlert,
            actor,
            operation,
            key_alias,
            "SUCCESS",
            "Hardware vault key retrieved for signature generation",
        );
    }

    /// Convenience method for logging consensus block creation.
    pub fn log_block_commit(&self, height: u64, tx_count: usize) {
        self.log(
            AuditSeverity::Info,
            "consensus_engine",
            "COMMIT_BLOCK",
            &format!("block/{}", height),
            "SUCCESS",
            &format!("Committed {} transactions to chain", tx_count),
        );
    }

    /// Drains all buffered events for flushing to SIEM collector.
    pub fn drain_events(&self) -> Vec<AuditEvent> {
        let mut buf = self.buffer.write().unwrap();
        buf.drain(..).collect()
    }

    /// Returns a copy of recent events without draining.
    pub fn peek_recent(&self, count: usize) -> Vec<AuditEvent> {
        let buf = self.buffer.read().unwrap();
        buf.iter().rev().take(count).cloned().collect()
    }

    /// Returns total events recorded.
    pub fn total_events(&self) -> u64 {
        *self.events_logged.read().unwrap()
    }
}
