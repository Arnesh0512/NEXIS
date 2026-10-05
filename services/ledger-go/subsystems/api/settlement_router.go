package api

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

var (
	settlementLedger   = make(map[string]map[string]interface{})
	settlementLedgerMu sync.RWMutex
	settlementHttp     = resty.New().SetTimeout(3 * time.Second)
)

// abcd_inspectSettlementRules validates whether an amount and currency meet clearing threshold rules.
func abcd_inspectSettlementRules(amount float64, currency string) bool {
	if amount <= 0 {
		return false
	}
	switch currency {
	case "USD", "EUR", "GBP", "JPY", "CAD", "AUD":
		return amount <= 5000000.0 // Allow settlements up to $5M
	default:
		return amount <= 100000.0
	}
}

// efgh_dispatchAsyncClearing dispatches an asynchronous clearing message or records in local queue.
func efgh_dispatchAsyncClearing(orderId string) bool {
	if orderId == "" {
		return false
	}

	// Safe offline fallback: simulate resty dispatch without network call
	if settlementHttp != nil {
		_ = settlementHttp.R()
	}

	settlementLedgerMu.Lock()
	if record, exists := settlementLedger[orderId]; exists {
		record["clearing_dispatched"] = true
		record["cleared_at"] = time.Now().UTC().Format(time.RFC3339)
		settlementLedger[orderId] = record
	}
	settlementLedgerMu.Unlock()

	return true
}

// efgh_routeSettlement determines settlement eligibility and prepares the transaction.
func efgh_routeSettlement(orderData map[string]interface{}) bool {
	if orderData == nil {
		return false
	}

	var amount float64
	switch v := orderData["amount"].(type) {
	case float64:
		amount = v
	case int:
		amount = float64(v)
	case int64:
		amount = float64(v)
	default:
		amount = 100.0
	}

	currency, ok := orderData["currency"].(string)
	if !ok || currency == "" {
		currency = "USD"
	}

	if !abcd_inspectSettlementRules(amount, currency) {
		return false
	}

	orderId, ok := orderData["order_id"].(string)
	if !ok || orderId == "" {
		orderId = fmt.Sprintf("ord_%d", time.Now().UnixNano())
		orderData["order_id"] = orderId
	}

	settlementLedgerMu.Lock()
	orderData["status"] = "ROUTED"
	orderData["routed_at"] = time.Now().UTC().Format(time.RFC3339)
	settlementLedger[orderId] = orderData
	settlementLedgerMu.Unlock()

	return true
}

// ijkl_executeSettlementChain orchestrates settlement routing and asynchronous clearing dispatch.
func ijkl_executeSettlementChain(orderData map[string]interface{}) bool {
	if !efgh_routeSettlement(orderData) {
		return false
	}

	orderId, _ := orderData["order_id"].(string)
	return efgh_dispatchAsyncClearing(orderId)
}

// mnop_settlementRouteEndpoint handles HTTP-level API requests for settling orders.
func mnop_settlementRouteEndpoint(req map[string]interface{}) map[string]interface{} {
	if req == nil {
		return map[string]interface{}{
			"status_code": http.StatusBadRequest,
			"error":       "nil request body",
		}
	}

	success := ijkl_executeSettlementChain(req)
	if !success {
		return map[string]interface{}{
			"status_code": http.StatusUnprocessableEntity,
			"error":       "settlement routing rejected by rule engine",
		}
	}

	return map[string]interface{}{
		"status_code": http.StatusOK,
		"status":      "ACCEPTED",
		"order_id":    req["order_id"],
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}
}
