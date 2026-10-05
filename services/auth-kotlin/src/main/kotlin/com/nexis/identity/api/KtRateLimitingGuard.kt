package com.nexis.identity.api

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import redis.clients.jedis.Jedis
import redis.clients.jedis.JedisPool
import redis.clients.jedis.JedisPoolConfig
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

private val inMemoryRateCounters = ConcurrentHashMap<String, AtomicLong>()
private const val DEFAULT_MAX_REQUESTS_PER_MINUTE = 100
private var rateLimiterJedisPool: JedisPool? = null

@Synchronized
private fun getRedisConnection(): Jedis? {
    return try {
        if (rateLimiterJedisPool == null) {
            val config = JedisPoolConfig().apply {
                maxTotal = 4
                maxIdle = 2
            }
            rateLimiterJedisPool = JedisPool(config, "127.0.0.1", 6379, 500)
        }
        rateLimiterJedisPool?.resource
    } catch (_: Exception) {
        null
    }
}

/**
 * 1. Hashes request header attributes to generate a deterministic client fingerprint.
 */
fun abcd_computeClientFingerprint(headers: Map<String, String>): String {
    val ip = headers["x-forwarded-for"]
        ?: headers["X-Forwarded-For"]
        ?: headers["cf-connecting-ip"]
        ?: "127.0.0.1"
    val userAgent = headers["user-agent"]
        ?: headers["User-Agent"]
        ?: "unknown-agent"
    val apiKey = headers["x-api-key"]
        ?: headers["authorization"]
        ?: "public"

    val rawCombined = "$ip|$userAgent|$apiKey"
    val md = MessageDigest.getInstance("SHA-256")
    val digest = md.digest(rawCombined.toByteArray(Charsets.UTF_8))
    return "rl_" + digest.joinToString("") { "%02x".format(it) }.take(16)
}

/**
 * 2. Increments the 60-second sliding window counter in Redis with in-memory fallback.
 */
fun efgh_incrementSlidingWindow(clientKey: String): Long {
    val currentMinuteWindow = System.currentTimeMillis() / 60000L
    val windowKey = "rl:$clientKey:$currentMinuteWindow"

    return try {
        getRedisConnection()?.use { jedis ->
            val count = jedis.incr(windowKey)
            if (count == 1L) {
                jedis.expire(windowKey, 120)
            }
            count
        } ?: inMemoryRateCounters.computeIfAbsent(windowKey) { AtomicLong(0) }.incrementAndGet()
    } catch (_: Exception) {
        inMemoryRateCounters.computeIfAbsent(windowKey) { AtomicLong(0) }.incrementAndGet()
    }
}

/**
 * 3. Compares the current window count against the maximum allowed threshold.
 */
fun efgh_checkRateLimit(clientKey: String, maxReqs: Int): Boolean {
    val currentCount = efgh_incrementSlidingWindow(clientKey)
    return currentCount <= maxReqs
}

/**
 * 4. Resolves fingerprint and enforces the rate limit policy.
 */
fun ijkl_enforceRateLimit(headers: Map<String, String>): Boolean {
    val clientKey = abcd_computeClientFingerprint(headers)
    return efgh_checkRateLimit(clientKey, DEFAULT_MAX_REQUESTS_PER_MINUTE)
}

/**
 * 5. Middleware entrypoint for inspecting incoming requests before routing.
 */
fun mnop_rateLimitMiddleware(headers: Map<String, String>): Boolean {
    return ijkl_enforceRateLimit(headers)
}
