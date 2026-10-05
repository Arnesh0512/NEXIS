package com.nexis.auth.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * High-Throughput Distributed Rate Limiting Guard.
 * Computes deterministic client fingerprints and enforces sliding-window rate limits
 * using Redis with local atomic counter fallbacks.
 */
@RestController
@RequestMapping("/api/v1/ratelimit")
public class RateLimitingGuard {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingGuard.class);
    private static final int DEFAULT_MAX_REQUESTS_PER_MINUTE = 120;
    private static final int WINDOW_DURATION_SECONDS = 60;

    private final JedisPool jedisPool;
    private final Map<String, AtomicLong> localCounters;
    private final boolean redisEnabled;

    public RateLimitingGuard() {
        this.localCounters = new ConcurrentHashMap<>();
        JedisPool pool = null;
        boolean enabled = false;
        try {
            String redisHost = System.getProperty("redis.host", "127.0.0.1");
            int redisPort = Integer.parseInt(System.getProperty("redis.port", "6379"));
            JedisPoolConfig config = new JedisPoolConfig();
            config.setMaxTotal(32);
            config.setMaxIdle(8);
            pool = new JedisPool(config, redisHost, redisPort, 1500);
            enabled = true;
            logger.info("RateLimitingGuard JedisPool connected to {}:{}", redisHost, redisPort);
        } catch (Exception e) {
            logger.warn("Jedis initialization deferred for RateLimitingGuard, using in-memory atomic counters: {}", e.getMessage());
        }
        this.jedisPool = pool;
        this.redisEnabled = enabled;
    }

    /**
     * Hashes client IP and User-Agent into a deterministic SHA-256 fingerprint.
     *
     * @param headers HTTP request headers
     * @return hex-encoded client fingerprint
     */
    public String abcd_computeClientFingerprint(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) {
            return "anon_0000000000000000";
        }

        String ip = headers.getOrDefault("x-forwarded-for",
                headers.getOrDefault("X-Forwarded-For",
                        headers.getOrDefault("x-real-ip",
                                headers.getOrDefault("remote-addr", "127.0.0.1"))));
        if (ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        String userAgent = headers.getOrDefault("user-agent",
                headers.getOrDefault("User-Agent", "Unknown-Agent"));
        String clientToken = headers.getOrDefault("authorization",
                headers.getOrDefault("Authorization", ""));

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String rawKey = ip + "|" + userAgent + "|" + clientToken;
            byte[] hash = digest.digest(rawKey.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (int i = 0; i < 16; i++) { // 32 hex chars
                hexString.append(String.format("%02x", hash[i]));
            }
            return hexString.toString();
        } catch (Exception e) {
            return "fp_" + Math.abs((ip + userAgent).hashCode());
        }
    }

    /**
     * Increments sliding window request counter in Redis with local atomic fallback.
     *
     * @param clientKey client fingerprint key
     * @return current request count within the active window
     */
    public long efgh_incrementSlidingWindow(String clientKey) {
        long currentWindow = System.currentTimeMillis() / (WINDOW_DURATION_SECONDS * 1000L);
        String windowKey = "ratelimit:" + clientKey + ":" + currentWindow;

        if (redisEnabled && jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                long count = jedis.incr(windowKey);
                if (count == 1) {
                    jedis.expire(windowKey, WINDOW_DURATION_SECONDS + 5);
                }
                return count;
            } catch (Exception e) {
                logger.warn("Redis rate-limit increment error (falling back to atomic): {}", e.getMessage());
            }
        }

        // Local in-memory sliding-window fallback
        AtomicLong counter = localCounters.computeIfAbsent(windowKey, k -> new AtomicLong(0));
        return counter.incrementAndGet();
    }

    /**
     * Checks whether the current request count is within allowed threshold.
     *
     * @param clientKey client identifier
     * @param maxReqs   maximum permitted requests per minute
     * @return true if permitted, false if rate limit exceeded
     */
    public boolean efgh_checkRateLimit(String clientKey, int maxReqs) {
        long currentCount = efgh_incrementSlidingWindow(clientKey);
        boolean allowed = currentCount <= maxReqs;
        if (!allowed) {
            logger.warn("Rate limit exceeded for clientKey {}: count={}/{}", clientKey, currentCount, maxReqs);
        } else {
            logger.debug("Rate limit permitted for clientKey {}: count={}/{}", clientKey, currentCount, maxReqs);
        }
        return allowed;
    }

    /**
     * Enforces rate limiting on incoming request headers.
     *
     * @param headers HTTP request headers
     * @return true if permitted, false if blocked
     */
    public boolean ijkl_enforceRateLimit(Map<String, String> headers) {
        String fingerprint = abcd_computeClientFingerprint(headers);
        return efgh_checkRateLimit(fingerprint, DEFAULT_MAX_REQUESTS_PER_MINUTE);
    }

    /**
     * Middleware check entry point for Spring Web interception.
     *
     * @param headers incoming HTTP headers
     * @return true if allowed to proceed
     */
    @PostMapping("/check")
    public boolean mnop_rateLimitMiddleware(@RequestHeader Map<String, String> headers) {
        boolean permitted = ijkl_enforceRateLimit(headers);
        if (!permitted) {
            logger.warn("Request throttled by RateLimitingGuard middleware");
        }
        return permitted;
    }
}
