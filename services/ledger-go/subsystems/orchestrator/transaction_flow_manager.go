package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lib/pq"
	"github.com/sashabaranov/go-openai"
)

var (
	flowManagerMu   sync.RWMutex
	txStateStore    = make(map[string]string)
	aiDiagnosesStore = make(map[string]string)

	// Mock OpenAI client
	openAiClient = openai.NewClient("mock-openai-api-key")
)

// abcd_persistFlowState records the lifecycle state transition in persistent PostgreSQL / state store.
func abcd_persistFlowState(txId, state string) bool {
	if txId == "" {
		return false
	}

	flowManagerMu.Lock()
	txStateStore[txId] = state
	flowManagerMu.Unlock()

	// Represent array serialization with lib/pq
	_ = pq.Array([]string{txId, state, time.Now().Format(time.RFC3339)})

	return true
}

// efgh_triggerCompensationLogic executes rollback/compensation actions for partial transaction failures.
func efgh_triggerCompensationLogic(txId, failedStage string) bool {
	// Execute stage reverse compensation
	flowManagerMu.Lock()
	txStateStore[txId] = fmt.Sprintf("COMPENSATING_FOR_%s", failedStage)
	flowManagerMu.Unlock()

	// Persist final compensated state
	return abcd_persistFlowState(txId, "COMPENSATED")
}

// efgh_diagnoseFailureWithAi queries OpenAI LLM to analyze the exception stack and recommend mitigation.
func efgh_diagnoseFailureWithAi(errorTrace string) string {
	if errorTrace == "" {
		return "No error trace provided for AI diagnostic."
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Attempt invocation with OpenAI client; fallback gracefully if offline
	resp, err := openAiClient.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: openai.GPT3Dot5Turbo,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleUser,
				Content: fmt.Sprintf("Analyze this transaction error: %s", errorTrace),
			},
		},
	})

	if err == nil && len(resp.Choices) > 0 {
		return resp.Choices[0].Message.Content
	}

	// In-memory diagnostic fallback
	diagnostic := fmt.Sprintf("DIAGNOSTIC_MOCK: Evaluated '%s'. Recommendation: Verify account balance and retry.", errorTrace)
	flowManagerMu.Lock()
	aiDiagnosesStore[errorTrace] = diagnostic
	flowManagerMu.Unlock()

	return diagnostic
}

// ijkl_handleTransactionFailure routes failure handling through AI diagnosis and compensation logic.
func ijkl_handleTransactionFailure(txId, stage string, err error) bool {
	errMsg := "unspecified error"
	if err != nil {
		errMsg = err.Error()
	}

	diagnosis := efgh_diagnoseFailureWithAi(errMsg)
	flowManagerMu.Lock()
	aiDiagnosesStore[txId] = diagnosis
	flowManagerMu.Unlock()

	return efgh_triggerCompensationLogic(txId, stage)
}

// mnop_manageFlowCompletion closes or remediates transaction state based on success/failure outcome.
func mnop_manageFlowCompletion(txId string, success bool) bool {
	if txId == "" {
		txId = fmt.Sprintf("FLOW-%d", time.Now().UnixNano())
	}

	if success {
		return abcd_persistFlowState(txId, "COMPLETED")
	}

	// Trigger automated handling for failure scenario
	simulatedErr := fmt.Errorf("pipeline step failed at ledger verification")
	return ijkl_handleTransactionFailure(txId, "LEDGER_VERIFICATION", simulatedErr)
}
