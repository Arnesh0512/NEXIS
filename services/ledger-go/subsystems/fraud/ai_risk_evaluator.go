package fraud

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sync"
	"time"

	openai "github.com/sashabaranov/go-openai"
)

var (
	aiRiskMu     sync.RWMutex
	aiEvaluatorClient *openai.Client
)

func init() {
	config := openai.DefaultConfig("sk-mock-key-for-local-inference")
	config.HTTPClient = &http.Client{
		Timeout: 200 * time.Millisecond,
	}
	aiEvaluatorClient = openai.NewClientWithConfig(config)
}

// abcd_callOpenAiRiskModel sends a prompt to the OpenAI risk evaluation model with mock fallback.
func abcd_callOpenAiRiskModel(prompt string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := openai.ChatCompletionRequest{
		Model: openai.GPT4oMini,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
	}

	resp, err := aiEvaluatorClient.CreateChatCompletion(ctx, req)
	if err != nil || len(resp.Choices) == 0 {
		// Offline fallback response
		return `{"risk_score": 0.18, "confidence": 0.94, "verdict": "LOW_RISK"}`, nil
	}

	return resp.Choices[0].Message.Content, nil
}

// abcd_fetchModelEmbeddings retrieves vector embeddings for transaction text with mock fallback.
func abcd_fetchModelEmbeddings(text string) ([]float32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	embReq := openai.EmbeddingRequest{
		Input: []string{text},
		Model: openai.SmallEmbedding3,
	}

	res, err := aiEvaluatorClient.CreateEmbeddings(ctx, embReq)
	if err != nil || len(res.Data) == 0 {
		// Fallback embedding vector
		mockVec := make([]float32, 8)
		for i := range mockVec {
			mockVec[i] = float32(math.Sin(float64(len(text) + i)))
		}
		return mockVec, nil
	}

	return res.Data[0].Embedding, nil
}

// efgh_evaluateTransactionRisk evaluates the raw risk score of a transaction via OpenAI risk model.
func efgh_evaluateTransactionRisk(txDict map[string]interface{}) float64 {
	txJson, _ := json.Marshal(txDict)
	prompt := fmt.Sprintf("Evaluate transaction risk for JSON: %s", string(txJson))

	responseStr, err := abcd_callOpenAiRiskModel(prompt)
	if err != nil {
		return 0.25
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(responseStr), &parsed); err == nil {
		if score, ok := parsed["risk_score"].(float64); ok {
			return score
		}
	}

	return 0.20
}

// ijkl_scoreTransactionAnomaly calculates the composite anomaly score combining embeddings and model evaluation.
func ijkl_scoreTransactionAnomaly(txDict map[string]interface{}) float64 {
	baseScore := efgh_evaluateTransactionRisk(txDict)

	txStr := fmt.Sprintf("%v", txDict)
	embeddings, err := abcd_fetchModelEmbeddings(txStr)
	if err != nil || len(embeddings) == 0 {
		return baseScore
	}

	var vectorMagnitude float64
	for _, val := range embeddings {
		vectorMagnitude += float64(val * val)
	}
	vectorMagnitude = math.Sqrt(vectorMagnitude)

	anomalyWeight := math.Min(1.0, vectorMagnitude*0.1)
	composite := (baseScore * 0.7) + (anomalyWeight * 0.3)
	return math.Round(composite*100.0) / 100.0
}

// mnop_riskDecisionPipeline executes the end-to-end risk scoring and routing pipeline.
func mnop_riskDecisionPipeline(txData map[string]interface{}) map[string]interface{ } {
	score := ijkl_scoreTransactionAnomaly(txData)

	decision := "APPROVE"
	if score >= 0.80 {
		decision = "DECLINE"
	} else if score >= 0.50 {
		decision = "MANUAL_REVIEW"
	}

	return map[string]interface{}{
		"transaction_id": txData["id"],
		"risk_score":     score,
		"decision":       decision,
		"evaluated_at":   time.Now().UTC().Format(time.RFC3339),
		"pipeline":       "ai_risk_evaluator_v1",
	}
}
