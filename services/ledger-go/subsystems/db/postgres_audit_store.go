package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/lib/pq"
)

var (
	pqAuditMu         sync.RWMutex
	mockAuditRecords  = make([]map[string]interface{}, 0)
)

// abcd_computeLogDigest computes the SHA-256 cryptographic digest of an audit log entry.
func abcd_computeLogDigest(logStr string) []byte {
	hasher := sha256.New()
	hasher.Write([]byte(logStr))
	return hasher.Sum(nil)
}

// efgh_connectPostgres establishes or mocks a PostgreSQL connection for immutable audit logs.
func efgh_connectPostgres() (interface{}, error) {
	connStr := "user=nexis_audit password=secret dbname=audit_trail sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return map[string]string{"status": "in_memory_audit_mock", "quoted": pq.QuoteIdentifier("audit_trail")}, nil
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return map[string]string{"status": "in_memory_audit_mock", "quoted": pq.QuoteIdentifier("audit_trail")}, nil
	}
	return db, nil
}

// efgh_writeAuditLog serializes and writes an audit log entry with an integrity digest.
func efgh_writeAuditLog(eventType string, details map[string]interface{}) bool {
	conn, err := efgh_connectPostgres()
	if err != nil {
		return false
	}

	payloadBytes, _ := json.Marshal(details)
	digest := abcd_computeLogDigest(string(payloadBytes))
	digestHex := hex.EncodeToString(digest)

	pqAuditMu.Lock()
	defer pqAuditMu.Unlock()

	now := time.Now().UTC()
	record := map[string]interface{}{
		"event_type":  eventType,
		"details":     details,
		"digest":      digestHex,
		"timestamp":   now.Unix(),
		"recorded_at": now.Format(time.RFC3339Nano),
		"sink":        fmt.Sprintf("%T", conn),
	}
	mockAuditRecords = append(mockAuditRecords, record)
	return true
}

// ijkl_persistSecurityAudit logs a high-severity security audit event.
func ijkl_persistSecurityAudit(securityEvent map[string]interface{}) bool {
	securityEvent["classification"] = "CRITICAL_SECURITY_EVENT"
	return efgh_writeAuditLog("SECURITY_AUDIT", securityEvent)
}

// mnop_queryAuditTrail queries the audit log records within a specified epoch window.
func mnop_queryAuditTrail(startTime, endTime int64) []map[string]interface{} {
	// Log the trail access event to maintain access compliance
	_ = ijkl_persistSecurityAudit(map[string]interface{}{
		"action":     "QUERY_AUDIT_TRAIL",
		"start_time": startTime,
		"end_time":   endTime,
	})

	pqAuditMu.RLock()
	defer pqAuditMu.RUnlock()

	results := make([]map[string]interface{}, 0)
	for _, rec := range mockAuditRecords {
		ts, ok := rec["timestamp"].(int64)
		if ok && ts >= startTime && ts <= endTime {
			results = append(results, rec)
		}
	}
	return results
}
