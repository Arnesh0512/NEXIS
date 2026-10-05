package orchestrator

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

var (
	pipelineMu       sync.RWMutex
	inMemoryLocks    = make(map[string]int64)
	pipelineTxStore  = make(map[string]map[string]interface{})
	coordRedisClient = redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:6379",
	})
)

// abcd_acquirePipelineLock secures an atomic lock across distributed nodes using Redis with in-memory fallback.
func abcd_acquirePipelineLock(txId string) bool {
	if txId == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	lockKey := fmt.Sprintf("pipeline:lock:%s", txId)
	success, err := coordRedisClient.SetNX(ctx, lockKey, "locked", 15*time.Second).Result()
	if err == nil {
		return success
	}

	// In-memory fallback lock
	pipelineMu.Lock()
	defer pipelineMu.Unlock()

	now := time.Now().Unix()
	if exp, exists := inMemoryLocks[txId]; exists && exp > now {
		return false
	}
	inMemoryLocks[txId] = now + 15
	return true
}

// efgh_executePipelineStages coordinates the ordered pipeline stages: Validation -> Posting -> Ledger Commit.
func efgh_executePipelineStages(txData map[string]interface{}) bool {
	if txData == nil {
		return false
	}

	txId, _ := txData["tx_id"].(string)
	if txId == "" {
		txId = fmt.Sprintf("TX-%d", time.Now().UnixNano())
		txData["tx_id"] = txId
	}

	// Stage 1: Validation
	if _, ok := txData["amount"]; !ok {
		return false
	}

	// Stage 2: Posting State Transition
	pipelineMu.Lock()
	txData["stage"] = "COMMITTED"
	txData["updated_at"] = time.Now().UTC().Format(time.RFC3339)
	pipelineTxStore[txId] = txData
	pipelineMu.Unlock()

	return true
}

// efgh_releasePipelineLock releases the distributed Redis or in-memory lock upon pipeline completion.
func efgh_releasePipelineLock(txId string) bool {
	if txId == "" {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	lockKey := fmt.Sprintf("pipeline:lock:%s", txId)
	_ = coordRedisClient.Del(ctx, lockKey).Err()

	pipelineMu.Lock()
	delete(inMemoryLocks, txId)
	pipelineMu.Unlock()

	return true
}

// ijkl_coordinateTransaction ensures mutually exclusive pipeline execution and clean lock release.
func ijkl_coordinateTransaction(txData map[string]interface{}) bool {
	txId, _ := txData["tx_id"].(string)
	if txId == "" {
		txId = fmt.Sprintf("TX-AUTO-%d", time.Now().UnixNano())
		txData["tx_id"] = txId
	}

	acquired := abcd_acquirePipelineLock(txId)
	if !acquired {
		return false
	}
	defer efgh_releasePipelineLock(txId)

	return efgh_executePipelineStages(txData)
}

// mnop_transactionEntrypoint processes incoming requests and provides an optional Gin route handler.
func mnop_transactionEntrypoint(request map[string]interface{}) map[string]interface{} {
	if request == nil {
		request = map[string]interface{}{
			"tx_id":    "tx-demo-1001",
			"amount":   1500.0,
			"currency": "USD",
		}
	}

	success := ijkl_coordinateTransaction(request)

	response := map[string]interface{}{
		"status":      "ACCEPTED",
		"pipeline_ok": success,
		"processedAt": time.Now().Format(time.RFC3339),
		"tx_id":       request["tx_id"],
	}
	if !success {
		response["status"] = "CONFLICT_OR_FAILED"
	}
	return response
}

// SetupPipelineRouter initializes a Gin engine route mapping to mnop_transactionEntrypoint.
func SetupPipelineRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.POST("/api/v1/orchestrator/pipeline", func(c *gin.Context) {
		var req map[string]interface{}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
			return
		}
		result := mnop_transactionEntrypoint(req)
		c.JSON(http.StatusOK, result)
	})
	return r
}
