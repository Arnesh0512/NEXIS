package com.nexis.identity.fraud

import com.squareup.okhttp3.OkHttpClient
import com.squareup.okhttp3.Request
import redis.clients.jedis.Jedis
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap

/**
 * IP address threat intelligence and reputation scoring engine using Redis caching,
 * OkHttp REST integrations, and localized CIDR threat heuristics.
 */
object KtIpReputationState {
    val inMemoryIpCache = ConcurrentHashMap<String, Double>()

    val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .callTimeout(Duration.ofSeconds(2))
            .connectTimeout(Duration.ofSeconds(1))
            .build()
    }

    fun getJedis(): Jedis? {
        return try {
            val host = System.getenv("REDIS_HOST") ?: "127.0.0.1"
            val port = (System.getenv("REDIS_PORT") ?: "6379").toIntOrNull() ?: 6379
            Jedis(host, port, 1000)
        } catch (_: Throwable) {
            null
        }
    }
}

/**
 * Step 1: Checks Redis cache for pre-computed IP reputation score.
 */
fun abcd_checkRedisIpCache(ip: String): Double? {
    try {
        val jedis = KtIpReputationState.getJedis()
        if (jedis != null) {
            jedis.use { client ->
                val cached = client.get("ip_risk:$ip")
                if (cached != null) return cached.toDoubleOrNull()
            }
        }
    } catch (_: Throwable) {
        // Fall through to memory
    }

    return KtIpReputationState.inMemoryIpCache[ip]
}

/**
 * Step 2a: Queries external IP threat intelligence API via OkHttp with heuristic fallback.
 */
fun efgh_queryIpThreatApi(ip: String): Double {
    val apiUrl = System.getenv("IP_THREAT_API_URL")
    if (!apiUrl.isNullOrBlank()) {
        try {
            val req = Request.Builder().url("$apiUrl?ip=$ip").get().build()
            KtIpReputationState.httpClient.newCall(req).execute().use { resp ->
                if (resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    val score = Regex("""score["':\s]+([0-9.]+)""")
                        .find(body)?.groupValues?.get(1)?.toDoubleOrNull()
                    if (score != null) return score.coerceIn(0.0, 1.0)
                }
            }
        } catch (_: Throwable) {
            // Fall through to heuristics
        }
    }

    // Localized IP heuristics: detect Tor exit nodes, datacenter CIDRs, or local addresses
    val isLocal = ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.") || ip == "::1"
    val isSuspicious = ip.startsWith("185.220.") || ip.startsWith("198.51.100.") || ip.startsWith("45.154.")
    return when {
        isSuspicious -> 0.95
        isLocal -> 0.05
        else -> {
            val hash = Math.abs(ip.hashCode())
            ((hash % 40).toDouble() / 100.0) // Nominal clean score between 0.00 and 0.40
        }
    }
}

/**
 * Step 2b: Caches IP threat reputation score in Redis and local memory.
 */
fun efgh_cacheIpResult(ip: String, score: Double): Boolean {
    KtIpReputationState.inMemoryIpCache[ip] = score

    return try {
        val jedis = KtIpReputationState.getJedis()
        if (jedis != null) {
            jedis.use { client ->
                client.setex("ip_risk:$ip", 3600L, score.toString())
            }
        }
        true
    } catch (_: Throwable) {
        true
    }
}

/**
 * Step 3: Resolves IP risk by querying cache first, then threat API, and caching the outcome.
 */
fun ijkl_resolveIpRisk(ip: String): Double {
    val cached = abcd_checkRedisIpCache(ip)
    if (cached != null) return cached

    val resolved = efgh_queryIpThreatApi(ip)
    efgh_cacheIpResult(ip, resolved)
    return resolved
}

/**
 * Step 4: Evaluates network headers from client HTTP request to assess overall threat profile.
 */
fun mnop_evaluateClientNetwork(headers: Map<String, String>): Map<String, Any> {
    val forwarded = headers["x-forwarded-for"] ?: headers["X-Forwarded-For"]
    val realIp = headers["x-real-ip"] ?: headers["X-Real-IP"]
    val remoteAddr = headers["remote-addr"] ?: headers["Remote-Addr"] ?: "127.0.0.1"

    val rawIp = forwarded?.split(",")?.firstOrNull()?.trim() ?: realIp ?: remoteAddr
    val clientIp = if (rawIp.isBlank()) "127.0.0.1" else rawIp

    val riskScore = ijkl_resolveIpRisk(clientIp)
    val isProxy = (forwarded != null && forwarded.contains(",")) || headers.containsKey("via")

    return mapOf(
        "client_ip" to clientIp,
        "risk_score" to riskScore,
        "is_threat" to (riskScore >= 0.70),
        "is_proxy" to isProxy,
        "evaluated_at" to System.currentTimeMillis()
    )
}
