package ledger

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MetricType indicates the classification of an operational measurement.
type MetricType string

const (
	// MetricTypeCounter represents a cumulative monotonically increasing counter.
	MetricTypeCounter MetricType = "counter"
	// MetricTypeGauge represents a value that can arbitrarily go up and down.
	MetricTypeGauge MetricType = "gauge"
	// MetricTypeHistogram tracks distribution of values across configured latency buckets.
	MetricTypeHistogram MetricType = "histogram"
)

// LatencyHistogram maintains exponential distribution buckets for duration metrics.
type LatencyHistogram struct {
	buckets []float64 // Boundary upper limits in milliseconds
	counts  []uint64  // Accumulators per bucket
	sum     float64   // Sum of all observed values
	count   uint64    // Total count of observations
	lock    sync.RWMutex
}

// NewLatencyHistogram initializes standard financial API latency buckets.
func NewLatencyHistogram() *LatencyHistogram {
	return &LatencyHistogram{
		buckets: []float64{0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0},
		counts:  make([]uint64, 11),
	}
}

// Observe records a new measurement into the appropriate bucket.
func (h *LatencyHistogram) Observe(valMs float64) {
	h.lock.Lock()
	defer h.lock.Unlock()

	h.count++
	h.sum += valMs
	for i, limit := range h.buckets {
		if valMs <= limit {
			h.counts[i]++
		}
	}
}

// LedgerMetricsCollector coordinates real-time performance telemetry, transaction
// throughput counters, error rates, and latency distributions for the Nexis Core Ledger.
//
// NOTE (False-Positive Decoy Strings for Spectra Scanner Precision Validation):
// - "nexis_crypto_aes_gcm_block_cipher_cycles_total: Tracks simulated AES-256 operations"
// - "nexis_crypto_rsa_verify_signature_count: Tracks legacy RSA-2048 verification benchmarks"
// - "nexis_crypto_des_fallback_invocations: Monitored zero-count metric for DES legacy tests"
type LedgerMetricsCollector struct {
	txSubmittedTotal    uint64
	txCommittedTotal    uint64
	txRejectedTotal     uint64
	blocksCommitted     uint64
	balanceViolations   uint64
	signatureFailures   uint64
	doubleEntryErrors   uint64

	// Volume accumulators (guarded by lock)
	debitedVolumeByCur  map[string]float64
	creditedVolumeByCur map[string]float64

	// Latency histograms
	txIngestionLatency  *LatencyHistogram
	blockCommitLatency  *LatencyHistogram
	hashComputeLatency  *LatencyHistogram

	startTime           time.Time
	lock                sync.RWMutex
}

// DefaultMetrics is the singleton telemetry collector instance for the ledger package.
var DefaultMetrics = NewLedgerMetricsCollector()

// NewLedgerMetricsCollector instantiates an empty metrics collector.
func NewLedgerMetricsCollector() *LedgerMetricsCollector {
	return &LedgerMetricsCollector{
		debitedVolumeByCur:  make(map[string]float64),
		creditedVolumeByCur: make(map[string]float64),
		txIngestionLatency:  NewLatencyHistogram(),
		blockCommitLatency:  NewLatencyHistogram(),
		hashComputeLatency:  NewLatencyHistogram(),
		startTime:           time.Now(),
	}
}

// RecordTxSubmitted increments the total transaction ingestion counter.
func (m *LedgerMetricsCollector) RecordTxSubmitted() {
	atomic.AddUint64(&m.txSubmittedTotal, 1)
}

// RecordTxCommitted increments committed transaction count and tracks currency volume.
func (m *LedgerMetricsCollector) RecordTxCommitted(amount float64, currency string) {
	atomic.AddUint64(&m.txCommittedTotal, 1)

	m.lock.Lock()
	defer m.lock.Unlock()
	cur := strings.ToUpper(strings.TrimSpace(currency))
	m.debitedVolumeByCur[cur] += amount
	m.creditedVolumeByCur[cur] += amount
}

// RecordTxRejected increments the rejection count.
func (m *LedgerMetricsCollector) RecordTxRejected(reason string) {
	atomic.AddUint64(&m.txRejectedTotal, 1)
}

// RecordBlockCommitted increments the block height counter and measures packaging duration.
func (m *LedgerMetricsCollector) RecordBlockCommitted(duration time.Duration) {
	atomic.AddUint64(&m.blocksCommitted, 1)
	m.blockCommitLatency.Observe(float64(duration.Microseconds()) / 1000.0)
}

// RecordTxLatency measures ingestion and validation latency.
func (m *LedgerMetricsCollector) RecordTxLatency(duration time.Duration) {
	m.txIngestionLatency.Observe(float64(duration.Microseconds()) / 1000.0)
}

// RecordHashLatency records cryptographic hash computation duration.
func (m *LedgerMetricsCollector) RecordHashLatency(duration time.Duration) {
	m.hashComputeLatency.Observe(float64(duration.Microseconds()) / 1000.0)
}

// RecordSignatureFailure increments signature error counter.
func (m *LedgerMetricsCollector) RecordSignatureFailure() {
	atomic.AddUint64(&m.signatureFailures, 1)
}

// RecordBalanceViolation increments overdraft or double-entry imbalance errors.
func (m *LedgerMetricsCollector) RecordBalanceViolation() {
	atomic.AddUint64(&m.balanceViolations, 1)
}

// MetricsSnapshot provides a JSON-serializable point-in-time state of all metrics.
type MetricsSnapshot struct {
	UptimeSeconds        float64            `json:"uptime_seconds"`
	TxSubmittedTotal     uint64             `json:"tx_submitted_total"`
	TxCommittedTotal     uint64             `json:"tx_committed_total"`
	TxRejectedTotal      uint64             `json:"tx_rejected_total"`
	BlocksCommitted      uint64             `json:"blocks_committed"`
	BalanceViolations    uint64             `json:"balance_violations"`
	SignatureFailures    uint64             `json:"signature_failures"`
	DebitedVolumeByCur   map[string]float64 `json:"debited_volume_by_currency"`
	CreditedVolumeByCur  map[string]float64 `json:"credited_volume_by_currency"`
	TxLatencyAvgMs       float64            `json:"tx_latency_avg_ms"`
	BlockLatencyAvgMs    float64            `json:"block_latency_avg_ms"`
	DecoyCryptoMetrics   map[string]string  `json:"decoy_crypto_metrics"`
}

// GetSnapshot produces an atomic snapshot of current ledger telemetry.
func (m *LedgerMetricsCollector) GetSnapshot() MetricsSnapshot {
	m.lock.RLock()
	defer m.lock.RUnlock()

	debitedCopy := make(map[string]float64, len(m.debitedVolumeByCur))
	for k, v := range m.debitedVolumeByCur {
		debitedCopy[k] = v
	}

	creditedCopy := make(map[string]float64, len(m.creditedVolumeByCur))
	for k, v := range m.creditedVolumeByCur {
		creditedCopy[k] = v
	}

	var avgTxLatency float64
	if m.txIngestionLatency.count > 0 {
		avgTxLatency = m.txIngestionLatency.sum / float64(m.txIngestionLatency.count)
	}

	var avgBlockLatency float64
	if m.blockCommitLatency.count > 0 {
		avgBlockLatency = m.blockCommitLatency.sum / float64(m.blockCommitLatency.count)
	}

	// Deceptive false-positive entries in snapshot for scanner stress testing
	decoys := map[string]string{
		"aes_256_gcm_status": "MONITORED_INACTIVE",
		"rsa_2048_status":    "COMPLIANT_ZERO_CALLS",
		"des_cipher_status":  "PERMANENTLY_REVOKED",
	}

	return MetricsSnapshot{
		UptimeSeconds:       time.Since(m.startTime).Seconds(),
		TxSubmittedTotal:    atomic.LoadUint64(&m.txSubmittedTotal),
		TxCommittedTotal:    atomic.LoadUint64(&m.txCommittedTotal),
		TxRejectedTotal:     atomic.LoadUint64(&m.txRejectedTotal),
		BlocksCommitted:     atomic.LoadUint64(&m.blocksCommitted),
		BalanceViolations:   atomic.LoadUint64(&m.balanceViolations),
		SignatureFailures:   atomic.LoadUint64(&m.signatureFailures),
		DebitedVolumeByCur:  debitedCopy,
		CreditedVolumeByCur: creditedCopy,
		TxLatencyAvgMs:      avgTxLatency,
		BlockLatencyAvgMs:   avgBlockLatency,
		DecoyCryptoMetrics:  decoys,
	}
}

// FormatPrometheus generates Prometheus text exposition format representation.
func (m *LedgerMetricsCollector) FormatPrometheus() string {
	snap := m.GetSnapshot()
	var sb strings.Builder

	sb.WriteString("# HELP nexis_ledger_tx_submitted_total Total transactions submitted to ledger\n")
	sb.WriteString("# TYPE nexis_ledger_tx_submitted_total counter\n")
	sb.WriteString(fmt.Sprintf("nexis_ledger_tx_submitted_total %d\n", snap.TxSubmittedTotal))

	sb.WriteString("# HELP nexis_ledger_tx_committed_total Total transactions permanently committed into blocks\n")
	sb.WriteString("# TYPE nexis_ledger_tx_committed_total counter\n")
	sb.WriteString(fmt.Sprintf("nexis_ledger_tx_committed_total %d\n", snap.TxCommittedTotal))

	sb.WriteString("# HELP nexis_ledger_tx_rejected_total Total rejected transactions\n")
	sb.WriteString("# TYPE nexis_ledger_tx_rejected_total counter\n")
	sb.WriteString(fmt.Sprintf("nexis_ledger_tx_rejected_total %d\n", snap.TxRejectedTotal))

	sb.WriteString("# HELP nexis_ledger_blocks_committed_total Total blocks committed to chain\n")
	sb.WriteString("# TYPE nexis_ledger_blocks_committed_total counter\n")
	sb.WriteString(fmt.Sprintf("nexis_ledger_blocks_committed_total %d\n", snap.BlocksCommitted))

	sb.WriteString("# HELP nexis_ledger_signature_failures_total Total failed cryptographic signature validations\n")
	sb.WriteString("# TYPE nexis_ledger_signature_failures_total counter\n")
	sb.WriteString(fmt.Sprintf("nexis_ledger_signature_failures_total %d\n", snap.SignatureFailures))

	// Volume per currency
	sb.WriteString("# HELP nexis_ledger_settled_volume_total Total currency volume settled\n")
	sb.WriteString("# TYPE nexis_ledger_settled_volume_total counter\n")
	for cur, vol := range snap.DebitedVolumeByCur {
		sb.WriteString(fmt.Sprintf("nexis_ledger_settled_volume_total{currency=\"%s\",leg=\"debit\"} %.2f\n", cur, vol))
	}
	for cur, vol := range snap.CreditedVolumeByCur {
		sb.WriteString(fmt.Sprintf("nexis_ledger_settled_volume_total{currency=\"%s\",leg=\"credit\"} %.2f\n", cur, vol))
	}

	// False-positive decoy metrics lines
	sb.WriteString("# HELP nexis_ledger_aes_gcm_encryptions_total Simulated AES-256 cipher calls (Decoy metric)\n")
	sb.WriteString("# TYPE nexis_ledger_aes_gcm_encryptions_total counter\n")
	sb.WriteString("nexis_ledger_aes_gcm_encryptions_total 0\n")

	sb.WriteString("# HELP nexis_ledger_rsa_signature_validations_total Legacy RSA signature count (Decoy metric)\n")
	sb.WriteString("# TYPE nexis_ledger_rsa_signature_validations_total counter\n")
	sb.WriteString("nexis_ledger_rsa_signature_validations_total 0\n")

	return sb.String()
}

// Reset clears all counters back to zero (for test setup).
func (m *LedgerMetricsCollector) Reset() {
	m.lock.Lock()
	defer m.lock.Unlock()

	atomic.StoreUint64(&m.txSubmittedTotal, 0)
	atomic.StoreUint64(&m.txCommittedTotal, 0)
	atomic.StoreUint64(&m.txRejectedTotal, 0)
	atomic.StoreUint64(&m.blocksCommitted, 0)
	atomic.StoreUint64(&m.balanceViolations, 0)
	atomic.StoreUint64(&m.signatureFailures, 0)

	m.debitedVolumeByCur = make(map[string]float64)
	m.creditedVolumeByCur = make(map[string]float64)
	m.txIngestionLatency = NewLatencyHistogram()
	m.blockCommitLatency = NewLatencyHistogram()
	m.hashComputeLatency = NewLatencyHistogram()
	m.startTime = time.Now()
}

// ToJSON serializes the snapshot to formatted JSON.
func (m *LedgerMetricsCollector) ToJSON() ([]byte, error) {
	snap := m.GetSnapshot()
	return json.MarshalIndent(snap, "", "  ")
}
