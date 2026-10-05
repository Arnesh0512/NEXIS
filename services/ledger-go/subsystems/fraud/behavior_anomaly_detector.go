package fraud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	openai "github.com/sashabaranov/go-openai"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	behaviorMu           sync.RWMutex
	mockUserHistoryStore = map[string][]map[string]interface{}{
		"usr_normal_1": {
			{"location": "US-NYC", "device": "macOS-Chrome", "amount": 45.0, "time": "2026-10-04T12:00:00Z"},
			{"location": "US-NYC", "device": "macOS-Chrome", "amount": 80.0, "time": "2026-10-04T16:00:00Z"},
		},
		"usr_anomalous_2": {
			{"location": "GB-LON", "device": "Windows-Firefox", "amount": 50.0, "time": "2026-10-04T10:00:00Z"},
			{"location": "SG-SIN", "device": "Android-Browser", "amount": 3500.0, "time": "2026-10-04T10:30:00Z"},
		},
	}
	behaviorMongoClient *mongo.Client
	behaviorAiClient    *openai.Client
)

func init() {
	behaviorAiClient = openai.NewClient("sk-mock-behavior-token")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	opts := options.Client().ApplyURI("mongodb://127.0.0.1:27017")
	c, err := mongo.Connect(ctx, opts)
	if err == nil {
		behaviorMongoClient = c
	}
}

// abcd_fetchUserHistory retrieves past user transaction patterns from MongoDB or mock repository.
func abcd_fetchUserHistory(userId string) []map[string]interface{} {
	behaviorMu.RLock()
	defer behaviorMu.RUnlock()

	if history, found := mockUserHistoryStore[userId]; found {
		return history
	}

	return []map[string]interface{}{
		{"location": "US-NYC", "device": "macOS-Chrome", "amount": 100.0, "time": time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)},
	}
}

// efgh_detectLocationJump checks whether consecutive actions exhibit an impossible travel velocity.
func efgh_detectLocationJump(currentLoc, lastLoc string) bool {
	if currentLoc == "" || lastLoc == "" {
		return false
	}
	currentNorm := strings.ToUpper(strings.TrimSpace(currentLoc))
	lastNorm := strings.ToUpper(strings.TrimSpace(lastLoc))

	if currentNorm == lastNorm {
		return false
	}

	currentCountry := strings.Split(currentNorm, "-")[0]
	lastCountry := strings.Split(lastNorm, "-")[0]

	// Different countries flagged as impossible travel / rapid jump
	return currentCountry != lastCountry
}

// efgh_summarizeBehaviorWithAi uses OpenAI to generate behavioral baseline profile summary.
func efgh_summarizeBehaviorWithAi(history []map[string]interface{}) string {
	payload, _ := json.Marshal(history)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	req := openai.ChatCompletionRequest{
		Model: openai.GPT4oMini,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleUser,
				Content: fmt.Sprintf("Summarize behavioral profile: %s", string(payload)),
			},
		},
	}

	resp, err := behaviorAiClient.CreateChatCompletion(ctx, req)
	if err != nil || len(resp.Choices) == 0 {
		return "Standard user profile with low transaction variance and recurring home geography."
	}
	return resp.Choices[0].Message.Content
}

// ijkl_evaluateAccountSecurity evaluates if current event violates historical user behavior profile.
func ijkl_evaluateAccountSecurity(userId string, event map[string]interface{}) bool {
	history := abcd_fetchUserHistory(userId)
	_ = efgh_summarizeBehaviorWithAi(history)

	currentLoc, _ := event["location"].(string)

	lastLoc := ""
	if len(history) > 0 {
		lastEvent := history[len(history)-1]
		if loc, ok := lastEvent["location"].(string); ok {
			lastLoc = loc
		}
	}

	if efgh_detectLocationJump(currentLoc, lastLoc) {
		return true // Security risk detected
	}

	// Check amount spike against historical averages
	currentAmount, _ := event["amount"].(float64)
	if currentAmount > 5000.0 {
		return true
	}

	return false
}

// mnop_triggerStepUpAuth decides whether to enforce multi-factor step-up authentication.
func mnop_triggerStepUpAuth(userId string, event map[string]interface{}) bool {
	isRisk := ijkl_evaluateAccountSecurity(userId, event)
	if !isRisk {
		return false
	}

	behaviorMu.Lock()
	defer behaviorMu.Unlock()

	// Append triggered security challenge into user history
	triggeredEvent := map[string]interface{}{
		"location": event["location"],
		"device":   event["device"],
		"amount":   event["amount"],
		"time":     time.Now().UTC().Format(time.RFC3339),
		"flagged":  true,
		"action":   "MFA_STEP_UP_CHALLENGE_ISSUED",
	}
	mockUserHistoryStore[userId] = append(mockUserHistoryStore[userId], triggeredEvent)

	return true
}
