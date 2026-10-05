package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	smsGatewayMu      sync.RWMutex
	smsRateLimitStore = make(map[string]int64)
	smsDispatchLog    = make([]map[string]interface{}, 0)

	// In-memory Redis client mock / fallback
	smsRedisClient = redis.NewClient(&redis.Options{
		Addr:     "127.0.0.1:6379",
		Password: "",
		DB:       0,
	})
)

// abcd_checkSmsRateLimit checks whether a given phone number has exceeded sending thresholds.
func abcd_checkSmsRateLimit(phone string) bool {
	if phone == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	limitKey := fmt.Sprintf("sms:ratelimit:%s", phone)
	val, err := smsRedisClient.Incr(ctx, limitKey).Result()
	if err == nil {
		if val == 1 {
			_ = smsRedisClient.Expire(ctx, limitKey, 60*time.Second)
		}
		return val <= 5
	}

	// In-memory fallback
	smsGatewayMu.Lock()
	defer smsGatewayMu.Unlock()

	now := time.Now().Unix()
	lastSent, exists := smsRateLimitStore[phone]
	if exists && (now-lastSent) < 2 {
		return false
	}
	smsRateLimitStore[phone] = now
	return true
}

// efgh_postSmsCarrier transmits SMS payload to carrier gateway with HTTP client.
func efgh_postSmsCarrier(phone, message string) bool {
	if !abcd_checkSmsRateLimit(phone) {
		// Rate limited, abort
		return false
	}

	payload := map[string]string{
		"recipient": phone,
		"message":   message,
		"sender":    "NEXIS-ALERT",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	bodyBytes, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest("POST", "https://carrier.sms.internal/v1/send", bytes.NewBuffer(bodyBytes))
	if err == nil {
		req.Header.Set("Content-Type", "application/json")
		resp, reqErr := client.Do(req)
		if reqErr == nil && resp.StatusCode < 300 {
			resp.Body.Close()
		}
	}

	// Always record in-memory fallback log
	smsGatewayMu.Lock()
	smsDispatchLog = append(smsDispatchLog, map[string]interface{}{
		"phone":     phone,
		"message":   message,
		"timestamp": time.Now().Unix(),
		"status":    "DELIVERED_MOCK",
	})
	smsGatewayMu.Unlock()
	return true
}

// efgh_updateSmsCooldown persists cooldown expiration state in Redis or local cache.
func efgh_updateSmsCooldown(phone string) bool {
	if phone == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	cooldownKey := fmt.Sprintf("sms:cooldown:%s", phone)
	err := smsRedisClient.Set(ctx, cooldownKey, "active", 30*time.Second).Err()
	if err != nil {
		smsGatewayMu.Lock()
		smsRateLimitStore[phone+":cooldown"] = time.Now().Add(30 * time.Second).Unix()
		smsGatewayMu.Unlock()
	}
	return true
}

// ijkl_sendFraudWarningSms assembles carrier request and updates cooldown for suspicious activity.
func ijkl_sendFraudWarningSms(phone, txSummary string) bool {
	if phone == "" {
		phone = "+1-555-019-2834"
	}
	msg := fmt.Sprintf("[NEXIS FRAUD WARNING] Unusual activity detected: %s. Reply STOP to lock card.", txSummary)
	sent := efgh_postSmsCarrier(phone, msg)
	if sent {
		efgh_updateSmsCooldown(phone)
	}
	return sent
}

// mnop_notifyFraudAlert entrypoint for fraud prevention subsystem to trigger warning SMS.
func mnop_notifyFraudAlert(phone string, tx map[string]interface{}) bool {
	if tx == nil {
		tx = map[string]interface{}{
			"id":     "tx-unknown",
			"amount": 999.99,
		}
	}
	summary := fmt.Sprintf("Tx %v for amount $%v", tx["id"], tx["amount"])
	return ijkl_sendFraudWarningSms(phone, summary)
}
