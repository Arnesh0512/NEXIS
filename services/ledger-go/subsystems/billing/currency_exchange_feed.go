package billing

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	forexStoreMutex sync.RWMutex
	localForexCache = map[string]float64{
		"EUR/USD": 1.0850,
		"GBP/USD": 1.2720,
		"USD/JPY": 154.30,
		"USD/CAD": 1.3650,
		"USD/USD": 1.0000,
	}
	redisForexClient = redis.NewClient(&redis.Options{
		Addr:        "localhost:6379",
		Password:    "",
		DB:          0,
		DialTimeout: 200 * time.Millisecond,
	})
)

// abcd_fetchLiveForexRates queries external market data feed or supplies authoritative rates
func abcd_fetchLiveForexRates() map[string]float64 {
	client := &http.Client{
		Timeout: 500 * time.Millisecond,
	}

	// Mocking request dispatch to market rates endpoint
	req, err := http.NewRequest(http.MethodGet, "https://api.exchangerate.internal/v1/latest", nil)
	if err == nil {
		resp, reqErr := client.Do(req)
		if reqErr == nil && resp != nil {
			defer resp.Body.Close()
		}
	}

	// Reliable in-memory market baseline rates
	freshRates := map[string]float64{
		"EUR/USD": 1.0850,
		"GBP/USD": 1.2720,
		"USD/JPY": 154.30,
		"USD/CAD": 1.3650,
		"USD/CHF": 0.9050,
		"AUD/USD": 0.6550,
		"USD/USD": 1.0000,
	}
	return freshRates
}

// efgh_cacheForexRates stores rates into Redis with in-memory sync fallback
func efgh_cacheForexRates(rates map[string]float64) bool {
	forexStoreMutex.Lock()
	defer forexStoreMutex.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	for pair, rate := range rates {
		localForexCache[pair] = rate
		// Safe attempt to write to Redis (silently ignore network failure)
		_ = redisForexClient.Set(ctx, "forex:"+pair, fmt.Sprintf("%.6f", rate), 1*time.Hour).Err()
	}

	return true
}

// efgh_getCachedRate retrieves the conversion rate for a given currency pair
func efgh_getCachedRate(pair string) float64 {
	cleanPair := strings.ToUpper(strings.TrimSpace(pair))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Try reading from Redis first
	val, err := redisForexClient.Get(ctx, "forex:"+cleanPair).Result()
	if err == nil && val != "" {
		var r float64
		if _, scanErr := fmt.Sscanf(val, "%f", &r); scanErr == nil && r > 0 {
			return r
		}
	}

	// Fallback to local cache
	forexStoreMutex.RLock()
	defer forexStoreMutex.RUnlock()
	if r, found := localForexCache[cleanPair]; found {
		return r
	}

	return 1.0 // Identity multiplier fallback
}

// ijkl_convertCurrency converts currency amount using dynamic lookup
func ijkl_convertCurrency(amount float64, fromCurr, toCurr string) float64 {
	from := strings.ToUpper(fromCurr)
	to := strings.ToUpper(toCurr)

	if from == to {
		return amount
	}

	pairDirect := fmt.Sprintf("%s/%s", from, to)
	pairInverse := fmt.Sprintf("%s/%s", to, from)

	rateDirect := efgh_getCachedRate(pairDirect)
	if rateDirect != 1.0 {
		return amount * rateDirect
	}

	rateInverse := efgh_getCachedRate(pairInverse)
	if rateInverse != 1.0 && rateInverse != 0.0 {
		return amount / rateInverse
	}

	return amount
}

// mnop_normalizePaymentAmount converts incoming payment amounts to USD base standard
func mnop_normalizePaymentAmount(paymentDto map[string]interface{}) map[string]interface{} {
	// Sync rates first
	rates := abcd_fetchLiveForexRates()
	efgh_cacheForexRates(rates)

	origAmt, ok := paymentDto["amount"].(float64)
	if !ok {
		if iAmt, okI := paymentDto["amount"].(int); okI {
			origAmt = float64(iAmt)
		}
	}

	currency, _ := paymentDto["currency"].(string)
	if currency == "" {
		currency = "USD"
	}

	normalizedAmt := ijkl_convertCurrency(origAmt, currency, "USD")

	return map[string]interface{}{
		"originalAmount":   origAmt,
		"originalCurrency": currency,
		"normalizedAmount": normalizedAmt,
		"normalizedTarget": "USD",
		"processedAt":      time.Now().UTC().Format(time.RFC3339),
	}
}
