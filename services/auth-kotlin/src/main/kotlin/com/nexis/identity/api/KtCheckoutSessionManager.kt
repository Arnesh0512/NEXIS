package com.nexis.identity.api

import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import redis.clients.jedis.Jedis
import redis.clients.jedis.JedisPool
import redis.clients.jedis.JedisPoolConfig
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

private val inMemorySessionStore = ConcurrentHashMap<String, Map<String, Any>>()
private const val SESSION_TTL_SECONDS = 1800L
private var jedisPoolInstance: JedisPool? = null

@Synchronized
private fun getJedisClient(): Jedis? {
    return try {
        if (jedisPoolInstance == null) {
            val config = JedisPoolConfig().apply {
                maxTotal = 4
                maxIdle = 2
            }
            jedisPoolInstance = JedisPool(config, "127.0.0.1", 6379, 500)
        }
        jedisPoolInstance?.resource
    } catch (_: Exception) {
        null
    }
}

/**
 * 1. Generates a cryptographically random UUID checkout session identifier.
 */
fun abcd_generateSessionId(): String {
    return "cs_" + UUID.randomUUID().toString().replace("-", "")
}

/**
 * 2. Persists checkout session state to Redis with TTL, falling back gracefully to in-memory store.
 */
fun efgh_saveSessionState(sessionId: String, data: Map<String, Any>): Boolean {
    // In-memory update guarantees operational continuity
    inMemorySessionStore[sessionId] = data

    return try {
        getJedisClient()?.use { jedis ->
            val key = "checkout:session:$sessionId"
            val stringMap = data.entries.associate { (k, v) -> k to v.toString() }
            jedis.hset(key, stringMap)
            jedis.expire(key, SESSION_TTL_SECONDS)
            true
        } ?: true
    } catch (_: Exception) {
        true // Graceful fallback
    }
}

/**
 * 3. Retrieves checkout session state from Redis, falling back to in-memory store.
 */
fun efgh_getSessionState(sessionId: String): Map<String, Any>? {
    return try {
        val remoteData = getJedisClient()?.use { jedis ->
            val key = "checkout:session:$sessionId"
            val hash = jedis.hgetAll(key)
            if (hash.isNotEmpty()) hash else null
        }
        remoteData ?: inMemorySessionStore[sessionId]
    } catch (_: Exception) {
        inMemorySessionStore[sessionId]
    }
}

/**
 * 4. Initiates a new checkout flow by generating session ID and persisting state.
 */
fun ijkl_createCheckoutFlow(merchantId: String, items: List<Map<String, Any>>): String {
    val sessionId = abcd_generateSessionId()
    val sessionData: Map<String, Any> = mapOf(
        "sessionId" to sessionId,
        "merchantId" to merchantId,
        "itemCount" to items.size,
        "status" to "ACTIVE",
        "createdAt" to System.currentTimeMillis()
    )

    efgh_saveSessionState(sessionId, sessionData)
    return sessionId
}

/**
 * 5. Marks an existing checkout session as completed.
 */
fun ijkl_completeCheckoutFlow(sessionId: String): Boolean {
    val state = efgh_getSessionState(sessionId) ?: return false
    val updatedState = HashMap(state).apply {
        put("status", "COMPLETED")
        put("completedAt", System.currentTimeMillis().toString())
    }
    return efgh_saveSessionState(sessionId, updatedState)
}

/**
 * 6. Top-level API Handler managing checkout lifecycle actions.
 */
fun mnop_checkoutApiHandler(req: Map<String, Any>): Map<String, Any> {
    val action = (req["action"] as? String)?.lowercase() ?: "create"

    return when (action) {
        "complete" -> {
            val sessionId = req["sessionId"]?.toString() ?: ""
            val success = ijkl_completeCheckoutFlow(sessionId)
            mapOf(
                "action" to "complete",
                "sessionId" to sessionId,
                "success" to success,
                "status" to if (success) "COMPLETED" else "SESSION_NOT_FOUND"
            )
        }
        else -> {
            val merchantId = req["merchantId"]?.toString() ?: "merch_default"
            @Suppress("UNCHECKED_CAST")
            val items = (req["items"] as? List<Map<String, Any>>) ?: emptyList()
            val sessionId = ijkl_createCheckoutFlow(merchantId, items)
            mapOf(
                "action" to "create",
                "sessionId" to sessionId,
                "merchantId" to merchantId,
                "status" to "CREATED"
            )
        }
    }
}
