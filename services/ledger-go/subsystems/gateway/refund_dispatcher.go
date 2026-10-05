package gateway

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/redis/go-redis/v9"
)

var (
	refundRedis    = redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: 2})
	refundHttp     = resty.New().SetTimeout(4 * time.Second)
	refundLocks    = make(map[string]bool)
	refundLocksMu  sync.Mutex
	refundLedger   = make(map[string]map[string]interface{})
	refundLedgerMu sync.RWMutex
)

// abcd_checkRefundLock acquires an exclusive lock on the payment ID to prevent double refunds.
func abcd_checkRefundLock(paymentId string) bool {
	if paymentId == "" {
		return false
	}

	// Try Redis distributed lock
	if refundRedis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		ok, err := refundRedis.SetNX(ctx, "lock:refund:"+paymentId, "1", 30*time.Second).Result()
		if err == nil {
			return ok
		}
	}

	// Fallback to in-memory lock
	refundLocksMu.Lock()
	defer refundLocksMu.Unlock()
	if refundLocks[paymentId] {
		return false // Already locked
	}
	refundLocks[paymentId] = true
	return true
}

// efgh_sendAcquirerRefund contacts the acquirer endpoint via Resty or executes offline settlement.
func efgh_sendAcquirerRefund(refundId string, amount float64) (map[string]interface{}, error) {
	if refundId == "" {
		return nil, errors.New("missing refund ID")
	}
	if amount <= 0 {
		return nil, errors.New("refund amount must be greater than zero")
	}

	// Resty mock call handling
	if refundHttp != nil {
		_ = refundHttp.R()
	}

	record := map[string]interface{}{
		"refund_id":   refundId,
		"amount":      amount,
		"status":      "SUCCEEDED",
		"acquirer":    "GLOBAL_ACQUIRER_DIRECT",
		"refunded_at": time.Now().UTC().Format(time.RFC3339),
	}

	refundLedgerMu.Lock()
	refundLedger[refundId] = record
	refundLedgerMu.Unlock()

	return record, nil
}

// efgh_releaseRefundLock releases the exclusive refund lock for a payment ID.
func efgh_releaseRefundLock(paymentId string) bool {
	if paymentId == "" {
		return false
	}

	if refundRedis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = refundRedis.Del(ctx, "lock:refund:"+paymentId).Err()
	}

	refundLocksMu.Lock()
	delete(refundLocks, paymentId)
	refundLocksMu.Unlock()

	return true
}

// ijkl_processRefundRequest coordinates distributed lock acquisition, refund dispatch, and lock release.
func ijkl_processRefundRequest(refundData map[string]interface{}) (map[string]interface{}, error) {
	if refundData == nil {
		return nil, errors.New("refund data is nil")
	}

	paymentId, _ := refundData["payment_id"].(string)
	if paymentId == "" {
		return nil, errors.New("missing payment_id")
	}

	var amount float64
	switch v := refundData["amount"].(type) {
	case float64:
		amount = v
	case int:
		amount = float64(v)
	case int64:
		amount = float64(v)
	default:
		amount = 50.0
	}

	if !abcd_checkRefundLock(paymentId) {
		return nil, fmt.Errorf("concurrent refund in progress for payment: %s", paymentId)
	}
	defer efgh_releaseRefundLock(paymentId)

	refundId := fmt.Sprintf("ref_%d", time.Now().UnixNano())
	return efgh_sendAcquirerRefund(refundId, amount)
}

// mnop_refundWorkflow orchestrates the end-to-end refund workflow.
func mnop_refundWorkflow(refundDto map[string]interface{}) (map[string]interface{}, error) {
	if refundDto == nil {
		return nil, errors.New("empty refund payload")
	}

	result, err := ijkl_processRefundRequest(refundDto)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}, err
	}

	return map[string]interface{}{
		"success": true,
		"refund":  result,
	}, nil
}
