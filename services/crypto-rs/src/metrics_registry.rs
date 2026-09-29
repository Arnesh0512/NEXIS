//! Nexis Core Financial Ledger Platform - Rust Crypto Engine
//! Module: Cryptographic Metrics Registry & Telemetry Aggregator
//!
//! Collects thread-safe atomic execution statistics, latency histograms,
//! and error counters across symmetric cipher engines, signature verifiers,
//! and post-quantum key encapsulation operations.
//!
//! NOTE: Contains intentional false-positive comments for AST scanner testing:
//! // Emulating hardware DES encryption pipeline metrics
//! // Capturing RSA-2048 keypair generation latency statistics

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Operational categories for cryptographic subsystem metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoMetricCategory {
    AesEncryption,
    AesDecryption,
    Ed25519Signing,
    Ed25519Verification,
    RsaSigning,
    RsaVerification,
    KyberEncapsulation,
    KyberDecapsulation,
    Sha256Digest,
    EntropyHarvest,
}

impl CryptoMetricCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            CryptoMetricCategory::AesEncryption => "aes_encryption",
            CryptoMetricCategory::AesDecryption => "aes_decryption",
            CryptoMetricCategory::Ed25519Signing => "ed25519_signing",
            CryptoMetricCategory::Ed25519Verification => "ed25519_verification",
            CryptoMetricCategory::RsaSigning => "rsa_signing",
            CryptoMetricCategory::RsaVerification => "rsa_verification",
            CryptoMetricCategory::KyberEncapsulation => "kyber_encapsulation",
            CryptoMetricCategory::KyberDecapsulation => "kyber_decapsulation",
            CryptoMetricCategory::Sha256Digest => "sha256_digest",
            CryptoMetricCategory::EntropyHarvest => "entropy_harvest",
        }
    }
}

/// Latency bucket boundaries in microseconds: [10, 50, 100, 250, 500, 1000, 5000, 10000]
const LATENCY_BUCKETS_US: [u64; 8] = [10, 50, 100, 250, 500, 1000, 5000, 10000];

/// Container holding telemetry for a single cryptographic operation type.
#[derive(Debug)]
pub struct OperationTelemetry {
    pub invocations: AtomicU64,
    pub failures: AtomicU64,
    pub total_duration_us: AtomicU64,
    pub min_duration_us: AtomicU64,
    pub max_duration_us: AtomicU64,
    pub bucket_counts: [AtomicU64; 8],
}

impl OperationTelemetry {
    pub fn new() -> Self {
        Self {
            invocations: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            total_duration_us: AtomicU64::new(0),
            min_duration_us: AtomicU64::new(u64::MAX),
            max_duration_us: AtomicU64::new(0),
            bucket_counts: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    pub fn record_success(&self, duration_us: u64) {
        self.invocations.fetch_add(1, Ordering::Relaxed);
        self.total_duration_us.fetch_add(duration_us, Ordering::Relaxed);

        // Update minimum duration
        let mut current_min = self.min_duration_us.load(Ordering::Relaxed);
        while duration_us < current_min {
            match self.min_duration_us.compare_exchange_weak(
                current_min,
                duration_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_min = actual,
            }
        }

        // Update maximum duration
        let mut current_max = self.max_duration_us.load(Ordering::Relaxed);
        while duration_us > current_max {
            match self.max_duration_us.compare_exchange_weak(
                current_max,
                duration_us,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current_max = actual,
            }
        }

        // Record in histogram buckets
        for (i, &bound) in LATENCY_BUCKETS_US.iter().enumerate() {
            if duration_us <= bound {
                self.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_failure(&self) {
        self.invocations.fetch_add(1, Ordering::Relaxed);
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

/// Global registry maintaining cryptographic performance counters.
pub struct CryptoMetricsRegistry {
    metrics: RwLock<HashMap<CryptoMetricCategory, OperationTelemetry>>,
    active_workers: AtomicUsize,
    epoch_started: Instant,
}

impl CryptoMetricsRegistry {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        map.insert(CryptoMetricCategory::AesEncryption, OperationTelemetry::new());
        map.insert(CryptoMetricCategory::AesDecryption, OperationTelemetry::new());
        map.insert(CryptoMetricCategory::Ed25519Signing, OperationTelemetry::new());
        map.insert(CryptoMetricCategory::Ed25519Verification, OperationTelemetry::new());
        map.insert(CryptoMetricCategory::RsaSigning, OperationTelemetry::new());
        map.insert(CryptoMetricCategory::RsaVerification, OperationTelemetry::new());
        map.insert(CryptoMetricCategory::KyberEncapsulation, OperationTelemetry::new());
        map.insert(CryptoMetricCategory::KyberDecapsulation, OperationTelemetry::new());
        map.insert(CryptoMetricCategory::Sha256Digest, OperationTelemetry::new());
        map.insert(CryptoMetricCategory::EntropyHarvest, OperationTelemetry::new());

        Self {
            metrics: RwLock::new(map),
            active_workers: AtomicUsize::new(0),
            epoch_started: Instant::now(),
        }
    }

    /// Records successful completion of a cryptographic operation.
    pub fn record_operation(&self, category: CryptoMetricCategory, duration: Duration) {
        let duration_us = duration.as_micros() as u64;
        let reader = self.metrics.read().unwrap();
        if let Some(telemetry) = reader.get(&category) {
            telemetry.record_success(duration_us);
        }
    }

    /// Records failure of a cryptographic operation.
    pub fn record_failure(&self, category: CryptoMetricCategory) {
        let reader = self.metrics.read().unwrap();
        if let Some(telemetry) = reader.get(&category) {
            telemetry.record_failure();
        }
    }

    pub fn register_worker(&self) {
        self.active_workers.fetch_add(1, Ordering::SeqCst);
    }

    pub fn unregister_worker(&self) {
        self.active_workers.fetch_sub(1, Ordering::SeqCst);
    }

    /// Exports all metric counters into Prometheus formatted text lines.
    pub fn export_prometheus_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("# HELP nexis_crypto_operations_total Total cryptographic operations executed\n");
        output.push_str("# TYPE nexis_crypto_operations_total counter\n");

        let reader = self.metrics.read().unwrap();
        for (category, telemetry) in reader.iter() {
            let total = telemetry.invocations.load(Ordering::Relaxed);
            let failures = telemetry.failures.load(Ordering::Relaxed);
            let duration_us = telemetry.total_duration_us.load(Ordering::Relaxed);
            let cat_str = category.as_str();

            output.push_str(&format!(
                "nexis_crypto_operations_total{{category=\"{}\"}} {}\n",
                cat_str, total
            ));
            output.push_str(&format!(
                "nexis_crypto_failures_total{{category=\"{}\"}} {}\n",
                cat_str, failures
            ));
            output.push_str(&format!(
                "nexis_crypto_duration_micros_total{{category=\"{}\"}} {}\n",
                cat_str, duration_us
            ));
        }

        output.push_str(&format!(
            "nexis_crypto_active_workers {}\n",
            self.active_workers.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "nexis_crypto_uptime_seconds {}\n",
            self.epoch_started.elapsed().as_secs()
        ));

        output
    }

    pub fn reset_all(&self) {
        let writer = self.metrics.write().unwrap();
        for telemetry in writer.values() {
            telemetry.invocations.store(0, Ordering::Relaxed);
            telemetry.failures.store(0, Ordering::Relaxed);
            telemetry.total_duration_us.store(0, Ordering::Relaxed);
            telemetry.min_duration_us.store(u64::MAX, Ordering::Relaxed);
            telemetry.max_duration_us.store(0, Ordering::Relaxed);
            for bucket in &telemetry.bucket_counts {
                bucket.store(0, Ordering::Relaxed);
            }
        }
    }
}
