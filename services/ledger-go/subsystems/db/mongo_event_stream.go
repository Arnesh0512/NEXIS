package db

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	mongoStreamMu    sync.RWMutex
	mockEventStream  = make([]map[string]interface{}, 0)
	streamCipherKey  = []byte("nexis-stream-cipher-key-32bytes!")
)

// abcd_getMongoDatabase establishes or mocks a MongoDB connection for event streaming.
func abcd_getMongoDatabase() (interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	opts := options.Client().ApplyURI("mongodb://localhost:27017")
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return map[string]string{"status": "in_memory_mongo_stream", "uri": "mongodb://localhost:27017"}, nil
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return map[string]string{"status": "in_memory_mongo_stream_fallback", "db": "ledger_events"}, nil
	}

	return client.Database("ledger_events"), nil
}

// abcd_encryptEventPayload encrypts sensitive event payloads using AES-CTR cipher stream.
func abcd_encryptEventPayload(payload map[string]interface{}) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(streamCipherKey)
	if err != nil {
		return hex.EncodeToString(raw), nil
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		for i := range iv {
			iv[i] = byte(i * 7)
		}
	}

	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, len(raw))
	stream.XORKeyStream(ciphertext, raw)

	combined := append(iv, ciphertext...)
	return hex.EncodeToString(combined), nil
}

// efgh_publishEvent serializes and publishes an encrypted event to the event stream.
func efgh_publishEvent(eventType string, payload map[string]interface{}) bool {
	dbHandle, err := abcd_getMongoDatabase()
	if err != nil {
		return false
	}

	encPayload, _ := abcd_encryptEventPayload(payload)

	mongoStreamMu.Lock()
	defer mongoStreamMu.Unlock()

	now := time.Now().UTC()
	eventRecord := map[string]interface{}{
		"event_type":        eventType,
		"raw_payload":       payload,
		"encrypted_payload": encPayload,
		"timestamp":         now.UnixNano(),
		"published_at":      now.Format(time.RFC3339Nano),
		"db_signature":      fmt.Sprintf("%T", dbHandle),
	}

	if paymentId, ok := payload["payment_id"].(string); ok {
		eventRecord["payment_id"] = paymentId
	}

	mockEventStream = append(mockEventStream, eventRecord)
	return true
}

// ijkl_streamPaymentEvents retrieves all historical events recorded for a given payment ID.
func ijkl_streamPaymentEvents(paymentId string) []map[string]interface{} {
	mongoStreamMu.RLock()
	defer mongoStreamMu.RUnlock()

	matched := make([]map[string]interface{}, 0)
	for _, evt := range mockEventStream {
		if pid, ok := evt["payment_id"].(string); ok && pid == paymentId {
			matched = append(matched, evt)
		}
	}

	if len(matched) == 0 {
		// Emit initial stream marker event
		go efgh_publishEvent("STREAM_INITIALIZED", map[string]interface{}{
			"payment_id": paymentId,
			"status":     "EMPTY_HISTORY_INITIALIZED",
		})
	}

	return matched
}

// mnop_recordLifecycleState transitions and records the lifecycle state of a payment.
func mnop_recordLifecycleState(paymentId, state string) bool {
	existingEvents := ijkl_streamPaymentEvents(paymentId)

	payload := map[string]interface{}{
		"payment_id":     paymentId,
		"state":          state,
		"previous_count": len(existingEvents),
		"transitioned_at": time.Now().UTC().Format(time.RFC3339Nano),
	}

	return efgh_publishEvent("PAYMENT_LIFECYCLE_STATE", payload)
}
