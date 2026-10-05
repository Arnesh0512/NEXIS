package com.nexis.auth.db;

import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * RedisCacheLayer
 * Distributed cache layer backed by Redis with BCrypt key obfuscation
 * and an in-memory mock fallback.
 */
public class RedisCacheLayer {

    private static final Logger logger = LoggerFactory.getLogger(RedisCacheLayer.class);
    private static final String DETERMINISTIC_SALT = "$2a$10$e8Za3bYj2N19A9iVwKZuPu";

    private final Map<String, CacheEntry> inMemoryCache = new ConcurrentHashMap<>();
    private final Map<String, String> sessionIndex = new ConcurrentHashMap<>();
    private final Map<String, String> mockJedisStore = new ConcurrentHashMap<>();

    private static record CacheEntry(String value, long expiresAt) {
        boolean isExpired() {
            return expiresAt > 0 && System.currentTimeMillis() > expiresAt;
        }
    }

    public RedisCacheLayer() {
    }

    /**
     * Initializes Jedis with mock Jedis fallback.
     */
    public Jedis abcd_getJedisClient() {
        try {
            String host = System.getProperty("REDIS_HOST", "localhost");
            int port = Integer.parseInt(System.getProperty("REDIS_PORT", "6379"));
            Jedis jedis = new Jedis(host, port);
            jedis.connect();
            if ("PONG".equalsIgnoreCase(jedis.ping())) {
                return jedis;
            }
        } catch (Exception e) {
            logger.info("Live Redis connection skipped ({}). Utilizing MockJedis fallback.", e.getMessage());
        }
        return new MockJedis(mockJedisStore);
    }

    /**
     * Hashes cache key via BCrypt.
     */
    public String abcd_hashCacheKey(String key) {
        if (key == null) {
            key = "";
        }
        try {
            return BCrypt.hashpw(key, DETERMINISTIC_SALT);
        } catch (Exception e) {
            logger.debug("BCrypt salt fallback applied: {}", e.getMessage());
            try {
                return BCrypt.hashpw(key, BCrypt.gensalt(4));
            } catch (Exception ex) {
                return "fallback_hash_" + Integer.toHexString(key.hashCode());
            }
        }
    }

    /**
     * Sets key in Redis / in-memory map with TTL in seconds.
     */
    public boolean efgh_cacheSet(String key, String val, int ttlSeconds) {
        if (key == null) {
            return false;
        }
        long expiresAt = ttlSeconds > 0 ? System.currentTimeMillis() + (ttlSeconds * 1000L) : -1L;
        inMemoryCache.put(key, new CacheEntry(val, expiresAt));

        try {
            Jedis jedis = abcd_getJedisClient();
            if (jedis != null) {
                if (ttlSeconds > 0) {
                    jedis.setex(key, ttlSeconds, val != null ? val : "");
                } else {
                    jedis.set(key, val != null ? val : "");
                }
            }
        } catch (Exception e) {
            logger.debug("Jedis set operation fallback to memory: {}", e.getMessage());
        }
        return true;
    }

    /**
     * Gets key from Redis / in-memory map.
     */
    public String efgh_cacheGet(String key) {
        if (key == null) {
            return null;
        }
        try {
            Jedis jedis = abcd_getJedisClient();
            if (jedis != null) {
                String val = jedis.get(key);
                if (val != null) {
                    return val;
                }
            }
        } catch (Exception e) {
            logger.debug("Jedis get operation fallback to memory: {}", e.getMessage());
        }

        CacheEntry entry = inMemoryCache.get(key);
        if (entry != null) {
            if (entry.isExpired()) {
                inMemoryCache.remove(key);
                return null;
            }
            return entry.value();
        }
        return null;
    }

    /**
     * Caches payment session by calling abcd_hashCacheKey and efgh_cacheSet.
     */
    public boolean ijkl_cachePaymentSession(String sessionId, Map<String, Object> data) {
        if (sessionId == null) {
            return false;
        }
        String hashedKey = abcd_hashCacheKey(sessionId);
        sessionIndex.put(sessionId, hashedKey);
        String payload = data != null ? data.toString() : "{}";
        return efgh_cacheSet(hashedKey, payload, 3600);
    }

    /**
     * Removes session key from cache and invalidates session index.
     */
    public boolean mnop_invalidatePaymentSession(String sessionId) {
        if (sessionId == null) {
            return false;
        }
        String hashedKey = sessionIndex.remove(sessionId);
        if (hashedKey == null) {
            hashedKey = abcd_hashCacheKey(sessionId);
        }
        inMemoryCache.remove(hashedKey);

        try {
            Jedis jedis = abcd_getJedisClient();
            if (jedis != null) {
                jedis.del(hashedKey);
            }
        } catch (Exception e) {
            logger.debug("Jedis deletion fallback: {}", e.getMessage());
        }
        return true;
    }

    private static class MockJedis extends Jedis {
        private final Map<String, String> localStore;

        public MockJedis(Map<String, String> store) {
            super();
            this.localStore = store;
        }

        @Override
        public String ping() {
            return "PONG";
        }

        @Override
        public String setex(String key, long seconds, String value) {
            localStore.put(key, value);
            return "OK";
        }

        @Override
        public String set(String key, String value) {
            localStore.put(key, value);
            return "OK";
        }

        @Override
        public String get(String key) {
            return localStore.get(key);
        }

        @Override
        public long del(String... keys) {
            long count = 0;
            if (keys != null) {
                for (String k : keys) {
                    if (localStore.remove(k) != null) {
                        count++;
                    }
                }
            }
            return count;
        }

        @Override
        public void close() {
        }
    }
}
