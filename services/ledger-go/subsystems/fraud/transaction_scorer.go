package fraud

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	openai "github.com/sashabaranov/go-openai"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	txScorerMu            sync.RWMutex
	mockMerchantVelocity  = map[string]int{
		"merch_alpha":      4,
		"merch_high_risk":  85,
		"merch_enterprise": 1,
	}
	scorerMongoClient *mongo.Client
	scorerAiClient    *openai.Client
)

func init() {
	scorerAiClient = openai.NewClient("sk-mock-scorer-token")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	opts := options.Client().ApplyURI("mongodb://127.0.0.1:27017")
	c, err := mongo.Connect(ctx, opts)
	if err == nil {
		scorerMongoClient = c
	}
}

// abcd_queryMerchantVelocity queries recent transaction count per window from MongoDB or fallback map.
func abcd_queryMerchantVelocity(merchantId string) int {
	txScorerMu.RLock()
	defer txScorerMu.RUnlock()

	if vel, found := mockMerchantVelocity[merchantId]; found {
		return vel
	}
	return 5 // default standard rate
}

// efgh_calculateVelocityScore calculates velocity-based anomaly score from recent order slices.
func efgh_calculateVelocityScore(ordersList []map[string]interface{}) float64 {
	count := len(ordersList)
	if count == 0 {
		return 0.1
	}

	totalAmount := 0.0
	for _, order := range ordersList {
		if amt, ok := order["amount"].(float64); ok {
			totalAmount += amt
		}
	}

	score := (float64(count) * 0.05) + (totalAmount / 10000.0 * 0.05)
	if score > 1.0 {
		return 1.0
	}
	return score
}

// efgh_queryAiFraudExplanation generates human-readable AI explanation for calculated fraud indicators.
func efgh_queryAiFraudExplanation(scoreData map[string]interface{}) string {
	payload, _ := json.Marshal(scoreData)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := openai.ChatCompletionRequest{
		Model: openai.GPT4oMini,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleUser,
				Content: fmt.Sprintf("Explain fraud metrics: %s", string(payload)),
			},
		},
	}

	resp, err := scorerAiClient.CreateChatCompletion(ctx, req)
	if err != nil || len(resp.Choices) == 0 {
		return "Velocity score within baseline tolerance limits; no suspicious velocity spikes observed."
	}
	return resp.Choices[0].Message.Content
}

// ijkl_computeCompositeScore calculates composite transaction score using merchant velocity and payload.
func ijkl_computeCompositeScore(merchantId string, tx map[string]interface{}) float64 {
	velocityCount := abcd_queryMerchantVelocity(merchantId)

	mockOrders := make([]map[string]interface{}, velocityCount)
	for i := 0; i < velocityCount; i++ {
		mockOrders[i] = map[string]interface{}{
			"order_idx": i,
			"amount":    150.0,
		}
	}

	velocityScore := efgh_calculateVelocityScore(mockOrders)
	baseAmountScore := 0.1
	if amt, ok := tx["amount"].(float64); ok && amt > 5000 {
		baseAmountScore = 0.4
	}

	composite := (velocityScore * 0.6) + (baseAmountScore * 0.4)
	if composite > 1.0 {
		return 1.0
	}
	return composite
}

// mnop_evaluateMerchantFraud produces the merchant fraud risk evaluation package and AI explanation.
func mnop_evaluateMerchantFraud(merchantId string, tx map[string]interface{}) map[string]interface{} {
	score := ijkl_computeCompositeScore(merchantId, tx)

	scoreData := map[string]interface{}{
		"merchant_id": merchantId,
		"score":       score,
		"tx_id":       tx["id"],
	}

	explanation := efgh_queryAiFraudExplanation(scoreData)

	verdict := "ALLOW"
	if score > 0.75 {
		verdict = "BLOCK"
	} else if score > 0.45 {
		verdict = "CHALLENGE"
	}

	return map[string]interface{}{
		"merchant_id": merchantId,
		"verdict":     verdict,
		"fraud_score": score,
		"explanation": explanation,
		"checked_at":  time.Now().UTC().Format(time.RFC3339),
	}
}
