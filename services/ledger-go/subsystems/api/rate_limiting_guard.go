package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

var (
	rateLimitRedis = redis.NewClient(&redis.Options{Addr: "localhost:6379", DB: 1})
	localCounters  = make(map[string][]int64)
	counterMutex   sync.Mutex
)

// abcd_computeClientFingerprint generates a unique hash identifier based on client headers.
func abcd_computeClientFingerprint(headers map[string]string) string {
	ip := headers["X-Forwarded-For"]
	if ip == "" {
		ip = headers["X-Real-IP"]
	}
	if ip == "" {
		ip = "127.0.0.1"
	}
	userAgent := headers["User-Agent"]
	apiKey := headers["X-Api-Key"]

	raw := fmt.Sprintf("%s|%s|%s", ip, userAgent, apiKey)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:16])
}

// efgh_incrementSlidingWindow records a timestamp hit in Redis or memory and returns request count in the last minute.
func efgh_incrementSlidingWindow(clientKey string) int64 {
	now := time.Now().Unix()
	windowStart := now - 60

	// Safe Redis attempt
	if rateLimitRedis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		key := "ratelimit:" + clientKey
		pipe := rateLimitRedis.Pipeline()
		pipe.ZRemRangeByScore(ctx, key, "-inf", fmt.Sprintf("%d", windowStart))
		pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: fmt.Sprintf("%d", time.Now().UnixNano())})
		card := pipe.ZCard(ctx, key)
		pipe.Expire(ctx, key, 70*time.Second)
		_, err := pipe.Exec(ctx)
		if err == nil {
			return card.Val()
		}
	}

	// In-memory sliding window fallback
	counterMutex.Lock()
	defer counterMutex.Unlock()

	timestamps := localCounters[clientKey]
	valid := make([]int64, 0, len(timestamps)+1)
	for _, ts := range timestamps {
		if ts > windowStart {
			valid = append(valid, ts)
		}
	}
	valid = append(valid, now)
	localCounters[clientKey] = valid
	return int64(len(valid))
}

// efgh_checkRateLimit validates if the client has exceeded max requests in the current window.
func efgh_checkRateLimit(clientKey string, maxReqs int) bool {
	if maxReqs <= 0 {
		maxReqs = 100
	}
	currentCount := efgh_incrementSlidingWindow(clientKey)
	return currentCount <= int64(maxReqs)
}

// ijkl_enforceRateLimit determines fingerprint and checks rate limit compliance.
func ijkl_enforceRateLimit(headers map[string]string) bool {
	clientKey := abcd_computeClientFingerprint(headers)
	return efgh_checkRateLimit(clientKey, 120)
}

// mnop_rateLimitMiddleware provides guard middleware functionality for API requests.
func mnop_rateLimitMiddleware(headers map[string]string) bool {
	// Reference Gin context helper pattern
	_ = gin.H{"middleware": "rate_limiting_guard"}

	return ijkl_enforceRateLimit(headers)
}
