package com.nexis.auth.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Checkout Session State Manager.
 * Orchestrates multi-step hosted checkout sessions with low-latency Redis session caching
 * and in-memory fallback persistence.
 */
@RestController
@RequestMapping("/api/v1/checkout")
public class CheckoutSessionManager {

    private static final Logger logger = LoggerFactory.getLogger(CheckoutSessionManager.class);
    private static final int DEFAULT_TTL_SECONDS = 1800; // 30 minutes
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final JedisPool jedisPool;
    private final Map<String, Map<String, Object>> inMemorySessionStore;
    private final boolean redisEnabled;

    public CheckoutSessionManager() {
        this.inMemorySessionStore = new ConcurrentHashMap<>();
        JedisPool pool = null;
        boolean enabled = false;
        try {
            String redisHost = System.getProperty("redis.host", "127.0.0.1");
            int redisPort = Integer.parseInt(System.getProperty("redis.port", "6379"));
            JedisPoolConfig poolConfig = new JedisPoolConfig();
            poolConfig.setMaxTotal(16);
            poolConfig.setMaxIdle(8);
            pool = new JedisPool(poolConfig, redisHost, redisPort, 2000);
            enabled = true;
            logger.info("JedisPool initialized for {}:{}", redisHost, redisPort);
        } catch (Exception e) {
            logger.warn("Redis client initialization deferred to in-memory fallback: {}", e.getMessage());
        }
        this.jedisPool = pool;
        this.redisEnabled = enabled;
    }

    /**
     * Generates a cryptographic UUID-based session ID.
     *
     * @return unique secure session identifier prefixed with 'cs_live_'
     */
    public String abcd_generateSessionId() {
        byte[] randomBytes = new byte[8];
        SECURE_RANDOM.nextBytes(randomBytes);
        StringBuilder sb = new StringBuilder("cs_live_");
        sb.append(UUID.randomUUID().toString().replace("-", ""));
        for (byte b : randomBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Saves checkout session state to Redis with TTL, falling back to local concurrent map.
     *
     * @param sessionId unique session ID
     * @param data      session state attributes
     * @return true if successfully saved
     */
    public boolean efgh_saveSessionState(String sessionId, Map<String, Object> data) {
        if (sessionId == null || data == null) {
            return false;
        }

        // Always update local memory store for resilience
        inMemorySessionStore.put(sessionId, new ConcurrentHashMap<>(data));

        if (redisEnabled && jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                String redisKey = "checkout:session:" + sessionId;
                Map<String, String> stringMap = new HashMap<>();
                for (Map.Entry<String, Object> entry : data.entrySet()) {
                    stringMap.put(entry.getKey(), String.valueOf(entry.getValue()));
                }
                jedis.hset(redisKey, stringMap);
                jedis.expire(redisKey, DEFAULT_TTL_SECONDS);
                logger.debug("Checkout session {} saved to Redis with TTL {}s", sessionId, DEFAULT_TTL_SECONDS);
                return true;
            } catch (Exception e) {
                logger.warn("Failed to persist session to Redis (using in-memory store): {}", e.getMessage());
            }
        }

        return true;
    }

    /**
     * Retrieves checkout session state from Redis or local in-memory fallback.
     *
     * @param sessionId unique session ID
     * @return session state map or empty map if not found
     */
    public Map<String, Object> efgh_getSessionState(String sessionId) {
        if (sessionId == null) {
            return Collections.emptyMap();
        }

        if (redisEnabled && jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                String redisKey = "checkout:session:" + sessionId;
                Map<String, String> cached = jedis.hgetAll(redisKey);
                if (cached != null && !cached.isEmpty()) {
                    Map<String, Object> result = new LinkedHashMap<>(cached);
                    return result;
                }
            } catch (Exception e) {
                logger.warn("Redis read exception for session {} (falling back to memory): {}", sessionId, e.getMessage());
            }
        }

        Map<String, Object> localData = inMemorySessionStore.get(sessionId);
        return (localData != null) ? new LinkedHashMap<>(localData) : Collections.emptyMap();
    }

    /**
     * Creates a new hosted checkout flow and persists its initial state.
     *
     * @param merchantId merchant account ID
     * @param items      list of item specifications
     * @return generated session ID
     */
    public String ijkl_createCheckoutFlow(String merchantId, List<Map<String, Object>> items) {
        String sessionId = abcd_generateSessionId();
        Map<String, Object> sessionData = new LinkedHashMap<>();

        double calculatedTotal = 0.0;
        int itemCount = 0;
        if (items != null) {
            itemCount = items.size();
            for (Map<String, Object> item : items) {
                try {
                    double price = Double.parseDouble(item.getOrDefault("price", "0.0").toString());
                    int qty = Integer.parseInt(item.getOrDefault("quantity", "1").toString());
                    calculatedTotal += (price * qty);
                } catch (Exception ignored) {}
            }
        }

        sessionData.put("sessionId", sessionId);
        sessionData.put("merchantId", (merchantId != null) ? merchantId : "acct_default");
        sessionData.put("itemCount", itemCount);
        sessionData.put("totalAmount", calculatedTotal);
        sessionData.put("status", "OPEN");
        sessionData.put("createdAt", Instant.now().toString());

        efgh_saveSessionState(sessionId, sessionData);
        logger.info("Created checkout flow {} for merchant {} with {} items", sessionId, merchantId, itemCount);
        return sessionId;
    }

    /**
     * Completes a checkout flow by validating session existence and transitioning status.
     *
     * @param sessionId session identifier
     * @return true if successfully completed
     */
    public boolean ijkl_completeCheckoutFlow(String sessionId) {
        Map<String, Object> session = efgh_getSessionState(sessionId);
        if (session.isEmpty()) {
            logger.warn("Cannot complete checkout: session {} not found", sessionId);
            return false;
        }

        String currentStatus = String.valueOf(session.get("status"));
        if ("COMPLETED".equalsIgnoreCase(currentStatus)) {
            logger.info("Session {} is already completed", sessionId);
            return true;
        }

        session.put("status", "COMPLETED");
        session.put("completedAt", Instant.now().toString());
        efgh_saveSessionState(sessionId, session);
        logger.info("Successfully completed checkout session {}", sessionId);
        return true;
    }

    /**
     * Spring REST controller handler for session creation and status management.
     *
     * @param req request parameters
     * @return API response map
     */
    @PostMapping("/session")
    public Map<String, Object> mnop_checkoutApiHandler(@RequestBody Map<String, Object> req) {
        Map<String, Object> response = new LinkedHashMap<>();
        if (req == null) {
            req = Collections.emptyMap();
        }

        String action = Optional.ofNullable(req.get("action"))
                .map(Object::toString)
                .orElse("create");

        if ("complete".equalsIgnoreCase(action)) {
            String sessionId = Optional.ofNullable(req.get("sessionId"))
                    .map(Object::toString)
                    .orElseThrow(() -> new IllegalArgumentException("sessionId required to complete checkout"));

            boolean completed = ijkl_completeCheckoutFlow(sessionId);
            response.put("sessionId", sessionId);
            response.put("status", completed ? "COMPLETED" : "FAILED");
            response.put("success", completed);
            return response;
        }

        // Action: create
        String merchantId = Optional.ofNullable(req.get("merchantId")).map(Object::toString).orElse("acct_nexis");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) req.get("items");

        String sessionId = ijkl_createCheckoutFlow(merchantId, items);
        response.put("sessionId", sessionId);
        response.put("status", "OPEN");
        response.put("merchantId", merchantId);
        response.put("checkoutUrl", "https://checkout.nexis.io/pay/" + sessionId);
        response.put("timestamp", Instant.now().toString());

        return response;
    }
}
