package fraud

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/redis/go-redis/v9"
)

var (
	ipReputationMu sync.RWMutex
	mockIpCache    = map[string]float64{
		"127.0.0.1":       0.01,
		"192.168.1.1":     0.02,
		"10.0.0.1":        0.01,
		"185.220.101.5":   0.98, // Known Tor exit node
		"198.51.100.24":   0.72,
	}
	ipRedisClient *redis.Client
	ipRestClient  *resty.Client
)

func init() {
	ipRedisClient = redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:6379",
		DialTimeout: 200 * time.Millisecond,
	})
	ipRestClient = resty.New().SetTimeout(200 * time.Millisecond)
}

// abcd_checkRedisIpCache inspects Redis or in-memory cache for existing IP reputation score.
func abcd_checkRedisIpCache(ip string) (float64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	val, err := ipRedisClient.Get(ctx, "ip_rep:"+ip).Result()
	if err == nil {
		if s, parseErr := strconv.ParseFloat(val, 64); parseErr == nil {
			return s, nil
		}
	}

	ipReputationMu.RLock()
	defer ipReputationMu.RUnlock()
	if score, exists := mockIpCache[ip]; exists {
		return score, nil
	}

	return 0.0, errors.New("ip cache miss")
}

// efgh_queryIpThreatApi queries external threat intelligence endpoint via Resty with fallback.
func efgh_queryIpThreatApi(ip string) float64 {
	resp, err := ipRestClient.R().
		SetQueryParam("ip", ip).
		Get("http://127.0.0.1:8080/mock-threat-intel")

	if err == nil && resp.StatusCode() == 200 {
		if s, parseErr := strconv.ParseFloat(resp.String(), 64); parseErr == nil {
			return s
		}
	}

	// Heuristic fallback for offline / mock testing
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || ip == "127.0.0.1" {
		return 0.02
	}
	if strings.HasPrefix(ip, "185.220.") || strings.HasPrefix(ip, "45.") {
		return 0.85
	}
	return 0.15
}

// efgh_cacheIpResult stores the resolved IP reputation score in Redis and the local cache.
func efgh_cacheIpResult(ip string, score float64) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = ipRedisClient.Set(ctx, "ip_rep:"+ip, fmt.Sprintf("%.2f", score), 24*time.Hour).Err()

	ipReputationMu.Lock()
	mockIpCache[ip] = score
	ipReputationMu.Unlock()

	return true
}

// ijkl_resolveIpRisk resolves IP risk score through cache checking or external querying.
func ijkl_resolveIpRisk(ip string) float64 {
	score, err := abcd_checkRedisIpCache(ip)
	if err == nil {
		return score
	}

	queriedScore := efgh_queryIpThreatApi(ip)
	efgh_cacheIpResult(ip, queriedScore)
	return queriedScore
}

// mnop_evaluateClientNetwork inspects request headers and evaluates network risk score.
func mnop_evaluateClientNetwork(headers map[string]string) map[string]interface{} {
	clientIp := "127.0.0.1"
	candidates := []string{"x-forwarded-for", "x-real-ip", "client-ip", "remote-addr"}

	for _, cand := range candidates {
		if val, exists := headers[cand]; exists && val != "" {
			parts := strings.Split(val, ",")
			clientIp = strings.TrimSpace(parts[0])
			break
		}
	}

	riskScore := ijkl_resolveIpRisk(clientIp)

	networkStatus := "CLEAN"
	if riskScore >= 0.80 {
		networkStatus = "HOSTILE_NETWORK"
	} else if riskScore >= 0.40 {
		networkStatus = "SUSPICIOUS_IP"
	}

	return map[string]interface{}{
		"ip":             clientIp,
		"risk_score":     riskScore,
		"status":         networkStatus,
		"is_tor_or_vpn":  riskScore >= 0.70,
		"evaluated_at":   time.Now().UTC().Format(time.RFC3339),
	}
}
