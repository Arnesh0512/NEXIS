package com.nexis.identity

import java.util.concurrent.ConcurrentHashMap

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Module: Identity Ingress Rate Limiting Filter
 *
 * Implements leaky-bucket rate limiting across operator login and token
 * refresh endpoints to defend against automated password spraying attacks.
 */
class KtRateLimitFilter(
    private val maxTokens: Int = 60,
    private val refillRatePerSecond: Double = 1.0
) {

    data class ClientBucket(
        var availableTokens: Double,
        var lastRefillTimestamp: Long,
        var totalViolations: Int = 0
    )

    private val clientBuckets = ConcurrentHashMap<String, ClientBucket>()
    private var totalFilteredRequests: Long = 0
    private var totalThrottledRequests: Long = 0

    /**
     * Attempts to acquire a single token for a client IP or client ID.
     *
     * @param clientIdentifier IP address or username
     * @return true if allowed to proceed, false if rate limited
     */
    fun tryAcquire(clientIdentifier: String): Boolean {
        totalFilteredRequests++
        val now = System.currentTimeMillis()

        val bucket = clientBuckets.computeIfAbsent(clientIdentifier) {
            ClientBucket(
                availableTokens = maxTokens.toDouble(),
                lastRefillTimestamp = now,
                totalViolations = 0
            )
        }

        synchronized(bucket) {
            refill(bucket, now)

            if (bucket.availableTokens >= 1.0) {
                bucket.availableTokens -= 1.0
                return true
            } else {
                bucket.totalViolations++
                totalThrottledRequests++
                return false
            }
        }
    }

    /**
     * Refills bucket proportionally to elapsed time since last request.
     */
    private fun refill(bucket: ClientBucket, now: Long) {
        val elapsedMs = now - bucket.lastRefillTimestamp
        if (elapsedMs <= 0) return

        val tokensToAdd = (elapsedMs / 1000.0) * refillRatePerSecond
        bucket.availableTokens = Math.min(maxTokens.toDouble(), bucket.availableTokens + tokensToAdd)
        bucket.lastRefillTimestamp = now
    }

    /**
     * Resets bucket for a client identifier upon successful MFA verification.
     */
    fun resetClient(clientIdentifier: String) {
        clientBuckets.remove(clientIdentifier)
    }

    /**
     * Returns count of violations for a client.
     */
    fun getViolationCount(clientIdentifier: String): Int {
        return clientBuckets[clientIdentifier]?.totalViolations ?: 0
    }

    /**
     * Removes inactive buckets to free JVM memory.
     */
    fun sweepInactive(inactivityThresholdMs: Long = 3600000L): Int {
        val now = System.currentTimeMillis()
        var purged = 0
        val iterator = clientBuckets.entries.iterator()

        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value.lastRefillTimestamp > inactivityThresholdMs) {
                iterator.remove()
                purged++
            }
        }
        return purged
    }

    fun getTotalFiltered(): Long = totalFilteredRequests
    fun getTotalThrottled(): Long = totalThrottledRequests
    fun getTrackedClientsCount(): Int = clientBuckets.size
}
