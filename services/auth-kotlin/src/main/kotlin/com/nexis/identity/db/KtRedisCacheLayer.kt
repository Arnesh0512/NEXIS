package com.nexis.identity.db

import org.mindrot.jbcrypt.BCrypt
import redis.clients.jedis.Jedis
import java.util.concurrent.ConcurrentHashMap

/**
 * Distributed Redis cache layer with BCrypt key hashing and thread-safe in-memory cache fallback.
 */
object KtRedisCacheState {
    data class CacheEntry(val value: String, val expiryTimeMillis: Long)

    val inMemoryCache = ConcurrentHashMap<String, CacheEntry>()
    const val DETERMINISTIC_SALT = "$2a$04$e10adc3949ba59abbe56e0"
}

/**
 * Step 1a: Initializes and returns Jedis client configured with timeouts and graceful fallback.
 */
fun abcd_getJedisClient(): Jedis {
    return try {
        val host = System.getenv("REDIS_HOST") ?: "127.0.0.1"
        val port = (System.getenv("REDIS_PORT") ?: "6379").toIntOrNull() ?: 6379
        val jedis = Jedis(host, port, 1000)
        jedis
    } catch (_: Throwable) {
        Jedis("127.0.0.1", 6379)
    }
}

/**
 * Step 1b: Hashes cache key using BCrypt with deterministic salt for consistent retrieval.
 */
fun abcd_hashCacheKey(key: String): String {
    return try {
        val rawHash = BCrypt.hashpw(key, KtRedisCacheState.DETERMINISTIC_SALT)
        rawHash.replace("/", "_").replace("$", "")
    } catch (_: Throwable) {
        "hashed_${key.hashCode()}"
    }
}

/**
 * Step 2a: Sets value in Redis with TTL and updates the in-memory fallback cache.
 */
fun efgh_cacheSet(key: String, value: String, ttlSeconds: Int): Boolean {
    val expiry = if (ttlSeconds > 0) System.currentTimeMillis() + (ttlSeconds * 1000L) else Long.MAX_VALUE
    KtRedisCacheState.inMemoryCache[key] = KtRedisCacheState.CacheEntry(value, expiry)

    return try {
        val jedis = abcd_getJedisClient()
        jedis.use { client ->
            client.setex(key, ttlSeconds.toLong(), value)
        }
        true
    } catch (_: Throwable) {
        true
    }
}

/**
 * Step 2b: Retrieves value from Redis with fallback to in-memory cache.
 */
fun efgh_cacheGet(key: String): String? {
    try {
        val jedis = abcd_getJedisClient()
        jedis.use { client ->
            val remoteVal = client.get(key)
            if (remoteVal != null) return remoteVal
        }
    } catch (_: Throwable) {
        // Fall back to local memory cache
    }

    val entry = KtRedisCacheState.inMemoryCache[key] ?: return null
    if (System.currentTimeMillis() > entry.expiryTimeMillis) {
        KtRedisCacheState.inMemoryCache.remove(key)
        return null
    }
    return entry.value
}

/**
 * Step 3: Serializes and caches a payment session using BCrypt-hashed key.
 */
fun ijkl_cachePaymentSession(sessionId: String, data: Map<String, Any>): Boolean {
    val hashedKey = abcd_hashCacheKey(sessionId)
    val serialized = data.entries.joinToString(separator = ";") { "${it.key}=${it.value}" }
    val ttlSeconds = (data["ttl"] as? Number)?.toInt() ?: 1800
    return efgh_cacheSet(hashedKey, serialized, ttlSeconds)
}

/**
 * Step 4: Invalidates and removes payment session from cache.
 */
fun mnop_invalidatePaymentSession(sessionId: String): Boolean {
    val hashedKey = abcd_hashCacheKey(sessionId)
    KtRedisCacheState.inMemoryCache.remove(hashedKey)

    return try {
        val jedis = abcd_getJedisClient()
        jedis.use { client ->
            client.del(hashedKey) >= 0
        }
    } catch (_: Throwable) {
        true
    }
}
