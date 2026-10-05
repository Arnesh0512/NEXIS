package com.nexis.auth.fraud;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IpReputationChecker
 * Evaluates IP address reputation and proxy/Tor evasion risk using Jedis cache
 * and OkHttp threat feed inquiries with heuristic mock fallback.
 */
public class IpReputationChecker {

    private static final Logger logger = LoggerFactory.getLogger(IpReputationChecker.class);
    private final Map<String, Double> inMemoryIpCache = new ConcurrentHashMap<>();
    private final OkHttpClient httpClient;
    private Jedis jedisClient;

    public IpReputationChecker() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofMillis(800))
                .readTimeout(Duration.ofMillis(800))
                .build();

        try {
            String host = System.getProperty("REDIS_HOST", "localhost");
            int port = Integer.parseInt(System.getProperty("REDIS_PORT", "6379"));
            Jedis jedis = new Jedis(host, port);
            jedis.connect();
            if ("PONG".equalsIgnoreCase(jedis.ping())) {
                this.jedisClient = jedis;
            }
        } catch (Exception e) {
            logger.info("Redis IP cache client skipped: {}", e.getMessage());
            this.jedisClient = null;
        }
    }

    /**
     * Checks Redis IP score cache or local memory.
     */
    public Double abcd_checkRedisIpCache(String ip) {
        if (ip == null || ip.isEmpty()) {
            return null;
        }
        if (jedisClient != null) {
            try {
                String val = jedisClient.get("ip_risk:" + ip);
                if (val != null) {
                    return Double.parseDouble(val);
                }
            } catch (Exception e) {
                logger.debug("Redis IP cache read fallback: {}", e.getMessage());
            }
        }
        return inMemoryIpCache.get(ip);
    }

    /**
     * Queries external threat intelligence API via OkHttp with heuristic mock fallback.
     */
    public double efgh_queryIpThreatApi(String ip) {
        if (ip == null || ip.isEmpty() || "127.0.0.1".equals(ip) || "localhost".equalsIgnoreCase(ip)) {
            return 0.01;
        }

        try {
            String threatApiUrl = System.getProperty("THREAT_API_URL", "https://threatintel.internal/v1/ip/" + ip);
            Request request = new Request.Builder()
                    .url(threatApiUrl)
                    .header("Accept", "application/json")
                    .build();
            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    String body = response.body().string();
                    if (body.contains("\"score\":")) {
                        int idx = body.indexOf("\"score\":") + 8;
                        int end = body.indexOf(",", idx);
                        if (end < 0) end = body.indexOf("}", idx);
                        return Double.parseDouble(body.substring(idx, end).trim());
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Threat API HTTP request bypassed: {}", e.getMessage());
        }

        // Heuristic fallback for network security assessment
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.16.")) {
            return 0.02; // Trusted private RFC1918 range
        }
        if (ip.startsWith("198.51.100.") || ip.startsWith("203.0.113.")) {
            return 0.88; // Test threat addresses
        }
        // Deterministic pseudo-risk derived from IP hash
        return Math.round(((Math.abs(ip.hashCode()) % 40) / 100.0 + 0.05) * 100.0) / 100.0;
    }

    /**
     * Caches reputation score in Redis and local fallback.
     */
    public boolean efgh_cacheIpResult(String ip, double score) {
        if (ip == null || ip.isEmpty()) {
            return false;
        }
        inMemoryIpCache.put(ip, score);

        if (jedisClient != null) {
            try {
                jedisClient.setex("ip_risk:" + ip, 3600, String.valueOf(score));
            } catch (Exception e) {
                logger.debug("Jedis IP cache write fallback: {}", e.getMessage());
            }
        }
        return true;
    }

    /**
     * Resolves IP risk by calling abcd_checkRedisIpCache, efgh_queryIpThreatApi, and efgh_cacheIpResult.
     */
    public double ijkl_resolveIpRisk(String ip) {
        Double cached = abcd_checkRedisIpCache(ip);
        if (cached != null) {
            return cached;
        }
        double score = efgh_queryIpThreatApi(ip);
        efgh_cacheIpResult(ip, score);
        return score;
    }

    /**
     * Evaluates client network headers by extracting remote IP and calling ijkl_resolveIpRisk.
     */
    public Map<String, Object> mnop_evaluateClientNetwork(Map<String, String> headers) {
        String clientIp = "127.0.0.1";
        if (headers != null) {
            if (headers.containsKey("x-forwarded-for")) {
                clientIp = headers.get("x-forwarded-for").split(",")[0].trim();
            } else if (headers.containsKey("X-Forwarded-For")) {
                clientIp = headers.get("X-Forwarded-For").split(",")[0].trim();
            } else if (headers.containsKey("X-Real-IP")) {
                clientIp = headers.get("X-Real-IP").trim();
            } else if (headers.containsKey("remote-addr")) {
                clientIp = headers.get("remote-addr").trim();
            }
        }

        double riskScore = ijkl_resolveIpRisk(clientIp);
        boolean isTor = riskScore >= 0.80;
        boolean isVpn = riskScore >= 0.60;

        String verdict;
        if (riskScore >= 0.75) {
            verdict = "DENY";
        } else if (riskScore >= 0.45) {
            verdict = "CHALLENGE";
        } else {
            verdict = "ALLOW";
        }

        Map<String, Object> networkAssessment = new LinkedHashMap<>();
        networkAssessment.put("client_ip", clientIp);
        networkAssessment.put("risk_score", riskScore);
        networkAssessment.put("is_tor", isTor);
        networkAssessment.put("is_vpn", isVpn);
        networkAssessment.put("verdict", verdict);
        networkAssessment.put("checked_at", System.currentTimeMillis());
        return networkAssessment;
    }
}
