package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// WalRecord encapsulates a single append-only ledger transaction record.
type WalRecord struct {
	SequenceNumber int64  `json:"seq"`
	RecordType     string `json:"type"`
	Payload        string `json:"payload"`
	CreatedAt      int64  `json:"created_at"`
}

// PersistenceEngine manages the Write-Ahead Log (WAL) on disk.
type PersistenceEngine struct {
	baseDir         string
	currentFile     *os.File
	currentSeq      int64
	maxSegmentBytes int64
	lock            sync.Mutex
	recordsWritten  int64
}

// NewPersistenceEngine opens or initializes a WAL storage directory.
func NewPersistenceEngine(storageDir string) (*PersistenceEngine, error) {
	if storageDir == "" {
		storageDir = filepath.Join(os.TempDir(), "nexis-ledger-wal")
	}

	if err := os.MkdirAll(storageDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create WAL directory: %w", err)
	}

	pe := &PersistenceEngine{
		baseDir:         storageDir,
		maxSegmentBytes: 10 * 1024 * 1024, // 10MB segments
	}

	if err := pe.rotateSegment(); err != nil {
		return nil, fmt.Errorf("failed to initialize initial WAL segment: %w", err)
	}

	return pe, nil
}

// AppendTransaction writes a transaction record to the active WAL segment.
func (pe *PersistenceEngine) AppendTransaction(txID, payloadJSON string) (int64, error) {
	pe.lock.Lock()
	defer pe.lock.Unlock()

	pe.currentSeq++
	record := WalRecord{
		SequenceNumber: pe.currentSeq,
		RecordType:     "TRANSACTION",
		Payload:        payloadJSON,
		CreatedAt:      time.Now().UnixNano(),
	}

	serialized, err := json.Marshal(record)
	if err != nil {
		return 0, fmt.Errorf("serialization error: %w", err)
	}

	line := append(serialized, '\n')
	if _, err := pe.currentFile.Write(line); err != nil {
		return 0, fmt.Errorf("WAL write failed: %w", err)
	}

	// Flush to disk
	_ = pe.currentFile.Sync()
	pe.recordsWritten++

	// Check if segment rotation is required
	info, err := pe.currentFile.Stat()
	if err == nil && info.Size() >= pe.maxSegmentBytes {
		_ = pe.rotateSegment()
	}

	return pe.currentSeq, nil
}

func (pe *PersistenceEngine) rotateSegment() error {
	if pe.currentFile != nil {
		_ = pe.currentFile.Sync()
		_ = pe.currentFile.Close()
	}

	filename := fmt.Sprintf("wal_%016d_%d.log", pe.currentSeq, time.Now().Unix())
	filePath := filepath.Join(pe.baseDir, filename)

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	pe.currentFile = f
	return nil
}

// Close flushes and releases active WAL file descriptors.
func (pe *PersistenceEngine) Close() error {
	pe.lock.Lock()
	defer pe.lock.Unlock()

	if pe.currentFile != nil {
		_ = pe.currentFile.Sync()
		err := pe.currentFile.Close()
		pe.currentFile = nil
		return err
	}
	return nil
}

// SaveSnapshot writes an in-memory ledger state snapshot to disk.
func (pe *PersistenceEngine) SaveSnapshot(snapshotData []byte) error {
	pe.lock.Lock()
	defer pe.lock.Unlock()

	snapshotPath := filepath.Join(pe.baseDir, fmt.Sprintf("snapshot_%d.dat", time.Now().Unix()))
	return os.WriteFile(snapshotPath, snapshotData, 0644)
}

// GetTelemetry returns statistics on disk persistence.
func (pe *PersistenceEngine) GetTelemetry() map[string]interface{} {
	pe.lock.Lock()
	defer pe.lock.Unlock()

	return map[string]interface{}{
		"base_dir":        pe.baseDir,
		"current_seq":     pe.currentSeq,
		"records_written": pe.recordsWritten,
	}
}
