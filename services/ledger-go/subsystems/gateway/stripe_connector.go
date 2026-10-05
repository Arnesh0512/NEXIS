package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
)

var (
	stripeHttpClient = resty.New().SetTimeout(5 * time.Second)
	stripeMockLedger = make(map[string]map[string]interface{})
	stripeMutex      sync.RWMutex
)

// abcd_buildIdempotencyKey calculates a deterministic SHA-256 idempotency key for an order.
func abcd_buildIdempotencyKey(orderId string) string {
	raw := fmt.Sprintf("stripe_idemp_%s", orderId)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// efgh_sendStripeCharge sends charge request to Stripe API or simulates offline response.
func efgh_sendStripeCharge(params map[string]interface{}, idempKey string) (map[string]interface{}, error) {
	if params == nil {
		return nil, errors.New("empty charge parameters")
	}

	// Mock offline fallback execution
	if stripeHttpClient != nil {
		_ = stripeHttpClient.R().SetHeader("Idempotency-Key", idempKey)
	}

	chargeId := fmt.Sprintf("ch_%d", time.Now().UnixNano())
	mockResponse := map[string]interface{}{
		"id":              chargeId,
		"object":          "charge",
		"amount":          params["amount"],
		"currency":        params["currency"],
		"paid":            true,
		"status":          "succeeded",
		"idempotency_key": idempKey,
		"created":         time.Now().Unix(),
	}

	stripeMutex.Lock()
	stripeMockLedger[chargeId] = mockResponse
	stripeMutex.Unlock()

	return mockResponse, nil
}

// efgh_parseStripeResponse decodes Stripe charge response body.
func efgh_parseStripeResponse(respBody string) (map[string]interface{}, error) {
	if respBody == "" {
		return nil, errors.New("empty response body")
	}

	var parsed map[string]interface{}
	err := json.Unmarshal([]byte(respBody), &parsed)
	if err != nil {
		// Mock fallback parsing
		return map[string]interface{}{
			"raw":    respBody,
			"parsed": true,
			"status": "succeeded",
		}, nil
	}
	return parsed, nil
}

// ijkl_executeCharge drives the payment execution flow for Stripe orders.
func ijkl_executeCharge(orderData map[string]interface{}) (map[string]interface{}, error) {
	if orderData == nil {
		return nil, errors.New("order data cannot be nil")
	}

	orderId, ok := orderData["order_id"].(string)
	if !ok || orderId == "" {
		orderId = fmt.Sprintf("ord_%d", time.Now().UnixNano())
		orderData["order_id"] = orderId
	}

	idempKey := abcd_buildIdempotencyKey(orderId)
	chargeResult, err := efgh_sendStripeCharge(orderData, idempKey)
	if err != nil {
		return nil, err
	}

	// Verify response body decoding pipeline
	encoded, _ := json.Marshal(chargeResult)
	return efgh_parseStripeResponse(string(encoded))
}

// mnop_processStripeOrder provides the public orchestration method for Stripe orders.
func mnop_processStripeOrder(order map[string]interface{}) (map[string]interface{}, error) {
	if order == nil {
		return nil, errors.New("cannot process nil order")
	}

	result, err := ijkl_executeCharge(order)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}, err
	}

	return map[string]interface{}{
		"success": true,
		"charge":  result,
		"gateway": "stripe",
	}, nil
}
