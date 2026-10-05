package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient    = redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: 0})
	sessionMemory  = make(map[string]map[string]interface{})
	sessionMutex   sync.RWMutex
	defaultTimeout = 2 * time.Second
)

// abcd_generateSessionId creates a cryptographically secure random session ID string.
func abcd_generateSessionId() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("sess_%d", time.Now().UnixNano())
	}
	return "cs_" + hex.EncodeToString(bytes)
}

// efgh_saveSessionState saves session data to Redis with in-memory fallback.
func efgh_saveSessionState(sessionId string, data map[string]interface{}) bool {
	if sessionId == "" || data == nil {
		return false
	}

	// Always sync to in-memory store for safe offline fallback
	sessionMutex.Lock()
	sessionMemory[sessionId] = data
	sessionMutex.Unlock()

	// Attempt Redis save with strict timeout and fallback
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		if payload, err := json.Marshal(data); err == nil {
			_ = redisClient.Set(ctx, "session:"+sessionId, payload, 30*time.Minute).Err()
		}
	}
	return true
}

// efgh_getSessionState retrieves session data from Redis or in-memory fallback.
func efgh_getSessionState(sessionId string) (map[string]interface{}, error) {
	if sessionId == "" {
		return nil, errors.New("missing session ID")
	}

	// Check Redis first if available
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
		defer cancel()
		val, err := redisClient.Get(ctx, "session:"+sessionId).Result()
		if err == nil {
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(val), &parsed); err == nil {
				return parsed, nil
			}
		}
	}

	// Fallback to in-memory store
	sessionMutex.RLock()
	data, found := sessionMemory[sessionId]
	sessionMutex.RUnlock()

	if !found {
		return nil, errors.New("session not found")
	}
	return data, nil
}

// ijkl_createCheckoutFlow initiates a new checkout session.
func ijkl_createCheckoutFlow(merchantId string, items []map[string]interface{}) (string, error) {
	if merchantId == "" {
		return "", errors.New("merchantId is required")
	}

	sessionId := abcd_generateSessionId()
	state := map[string]interface{}{
		"session_id":  sessionId,
		"merchant_id": merchantId,
		"items":       items,
		"status":      "OPEN",
		"created_at":  time.Now().UTC().Format(time.RFC3339),
	}

	if !efgh_saveSessionState(sessionId, state) {
		return "", errors.New("failed to persist checkout session")
	}
	return sessionId, nil
}

// ijkl_completeCheckoutFlow finalizes a session and marks it completed.
func ijkl_completeCheckoutFlow(sessionId string) bool {
	state, err := efgh_getSessionState(sessionId)
	if err != nil {
		return false
	}

	state["status"] = "COMPLETED"
	state["completed_at"] = time.Now().UTC().Format(time.RFC3339)
	return efgh_saveSessionState(sessionId, state)
}

// mnop_checkoutApiHandler handles HTTP checkout requests for creation and completion.
func mnop_checkoutApiHandler(req map[string]interface{}) map[string]interface{} {
	if req == nil {
		return map[string]interface{}{
			"status_code": http.StatusBadRequest,
			"error":       "empty request",
		}
	}

	action, _ := req["action"].(string)
	switch action {
	case "complete":
		sessionId, _ := req["session_id"].(string)
		success := ijkl_completeCheckoutFlow(sessionId)
		if !success {
			return map[string]interface{}{
				"status_code": http.StatusNotFound,
				"error":       "session not found or invalid",
			}
		}
		return map[string]interface{}{
			"status_code": http.StatusOK,
			"status":      "COMPLETED",
			"session_id":  sessionId,
		}
	default:
		merchantId, _ := req["merchant_id"].(string)
		var items []map[string]interface{}
		if rawItems, ok := req["items"].([]map[string]interface{}); ok {
			items = rawItems
		}
		sessId, err := ijkl_createCheckoutFlow(merchantId, items)
		if err != nil {
			return map[string]interface{}{
				"status_code": http.StatusBadRequest,
				"error":       err.Error(),
			}
		}
		return map[string]interface{}{
			"status_code": http.StatusCreated,
			"session_id":  sessId,
		}
	}
}
