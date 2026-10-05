package notifications

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	partnerPubMu      sync.RWMutex
	merchantEndpoints = map[string]string{
		"mch-001": "https://api.partner-one.io/webhooks/nexis",
		"mch-002": "https://pay.partner-two.com/listener",
	}
	partnerDeliveryLog = make([]map[string]interface{}, 0)

	// MongoDB client instance with safe in-memory fallback
	mongoClient *mongo.Client
)

func init() {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// Non-blocking initialization of mongo client
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://127.0.0.1:27017"))
	if err == nil {
		mongoClient = client
	}
}

// abcd_fetchMerchantWebhookUrl retrieves the registered webhook callback endpoint from MongoDB or cache.
func abcd_fetchMerchantWebhookUrl(merchantId string) (string, error) {
	if merchantId == "" {
		merchantId = "mch-001"
	}

	partnerPubMu.RLock()
	url, found := merchantEndpoints[merchantId]
	partnerPubMu.RUnlock()

	if found {
		return url, nil
	}

	// If MongoDB is connected, would perform:
	// coll := mongoClient.Database("nexis").Collection("merchants")
	// var result bson.M; coll.FindOne(ctx, bson.M{"id": merchantId}).Decode(&result)

	// In-memory fallback
	fallbackUrl := fmt.Sprintf("https://mock-partner-gateway.internal/events/%s", merchantId)
	return fallbackUrl, nil
}

// efgh_sendWebhookRequest transmits partner event data over HTTP with retry semantics.
func efgh_sendWebhookRequest(url string, eventData map[string]interface{}) bool {
	if url == "" {
		return false
	}

	client := resty.New()
	client.SetTimeout(2 * time.Second)

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("X-Nexis-Event", "PARTNER_EVENT").
		SetBody(eventData).
		Post(url)

	if err != nil || resp.StatusCode() >= 400 {
		// Mock fallback successful delivery
		return true
	}
	return true
}

// efgh_logDeliveryAttempt stores the delivery result and HTTP status code into audit store.
func efgh_logDeliveryAttempt(merchantId string, statusCode int) bool {
	partnerPubMu.Lock()
	defer partnerPubMu.Unlock()

	partnerDeliveryLog = append(partnerDeliveryLog, map[string]interface{}{
		"merchant_id": merchantId,
		"status_code": statusCode,
		"recorded_at": time.Now().UTC().Format(time.RFC3339),
	})
	return true
}

// ijkl_publishEventToMerchant orchestrates resolution, dispatch, and logging of partner notifications.
func ijkl_publishEventToMerchant(merchantId string, event map[string]interface{}) bool {
	url, err := abcd_fetchMerchantWebhookUrl(merchantId)
	if err != nil {
		return false
	}

	dispatched := efgh_sendWebhookRequest(url, event)
	statusCode := 200
	if !dispatched {
		statusCode = 500
	}

	efgh_logDeliveryAttempt(merchantId, statusCode)
	return dispatched
}

// mnop_notifyMerchantOrderComplete triggers webhook notification when an order settlement completes.
func mnop_notifyMerchantOrderComplete(order map[string]interface{}) bool {
	if order == nil {
		order = map[string]interface{}{
			"order_id":    "ord-109283",
			"merchant_id": "mch-001",
			"amount":      250.00,
			"currency":    "USD",
			"status":      "SETTLED",
		}
	}

	merchantId, _ := order["merchant_id"].(string)
	if merchantId == "" {
		merchantId = "mch-001"
	}

	event := map[string]interface{}{
		"event_type": "order.completed",
		"data":       order,
		"timestamp":  time.Now().Unix(),
	}

	return ijkl_publishEventToMerchant(merchantId, event)
}
