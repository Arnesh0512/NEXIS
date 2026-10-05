package com.nexis.identity.billing

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import kotlinx.coroutines.runBlocking
import redis.clients.jedis.Jedis
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
 * KtCurrencyExchangeFeed
 * Subsystem 7: Billing & Reconciliation
 *
 * Implements real-time foreign exchange rate ingestion using Ktor CIO engine,
 * Redis caching with in-memory fallback, dynamic multi-currency conversions,
 * and payment normalization into platform base currency.
 */
class KtCurrencyExchangeFeed(
    private val fxApiUrl: String = System.getenv("FOREX_FEED_URL") ?: "https://api.forex.nexis.internal/v1/rates",
    private val redisHost: String = System.getenv("REDIS_HOST") ?: "localhost",
    private val redisPort: Int = System.getenv("REDIS_PORT")?.toIntOrNull() ?: 6379
) {

    companion object {
        private val localForexCache = ConcurrentHashMap<String, Double>()

        init {
            // Seed base exchange pairs (pegged to USD and EUR)
            localForexCache["USD/EUR"] = 0.9200
            localForexCache["EUR/USD"] = 1.0870
            localForexCache["USD/GBP"] = 0.7900
            localForexCache["GBP/USD"] = 1.2660
            localForexCache["USD/JPY"] = 155.2000
            localForexCache["JPY/USD"] = 0.00644
            localForexCache["USD/CAD"] = 1.3600
            localForexCache["CAD/USD"] = 0.7353
            localForexCache["USD/USD"] = 1.0000
            localForexCache["EUR/EUR"] = 1.0000
            localForexCache["GBP/GBP"] = 1.0000
        }
    }

    /**
     * 1. abcd_fetchLiveForexRates
     * Ingests real-time FX rates via Ktor CIO client with fallback rates.
     */
    fun abcd_fetchLiveForexRates(): Map<String, Double> {
        val fetchedRates = mutableMapOf<String, Double>()
        try {
            val client = HttpClient(CIO) {
                engine {
                    requestTimeout = 1500
                }
            }
            runBlocking {
                try {
                    val response = client.get(fxApiUrl)
                    val body = response.bodyAsText()
                    // If response contains formatted pairs, parse them
                    if (body.contains(":")) {
                        body.lines().forEach { line ->
                            val parts = line.split(":")
                            if (parts.size == 2) {
                                val pair = parts[0].trim().uppercase()
                                val rate = parts[1].trim().toDoubleOrNull()
                                if (rate != null) fetchedRates[pair] = rate
                            }
                        }
                    }
                } finally {
                    client.close()
                }
            }
        } catch (_: Throwable) {
            // Network or engine timeout; use default rates
        }

        if (fetchedRates.isEmpty()) {
            fetchedRates.putAll(localForexCache)
        }
        return fetchedRates
    }

    /**
     * 2. efgh_cacheForexRates
     * Persists forex pairs into Redis cache with in-memory fallback.
     */
    fun efgh_cacheForexRates(rates: Map<String, Double>): Boolean {
        if (rates.isEmpty()) return false

        try {
            Jedis(redisHost, redisPort).use { jedis ->
                for ((pair, rate) in rates) {
                    jedis.setex("fx:$pair", 3600, rate.toString())
                }
            }
        } catch (_: Throwable) {
            // Redis offline; write to memory cache
        }

        localForexCache.putAll(rates)
        return true
    }

    /**
     * 3. efgh_getCachedRate
     * Reads exchange rate for pair from Redis or in-memory fallback.
     */
    fun efgh_getCachedRate(pair: String): Double {
        val normalizedPair = pair.trim().uppercase()
        if (normalizedPair.startsWith("USD/USD") || normalizedPair == "EUR/EUR") return 1.0

        try {
            Jedis(redisHost, redisPort).use { jedis ->
                val cached = jedis.get("fx:$normalizedPair")
                if (cached != null) {
                    return cached.toDoubleOrNull() ?: 1.0
                }
            }
        } catch (_: Throwable) {
            // Fallback to local memory cache
        }

        // Direct lookup
        localForexCache[normalizedPair]?.let { return it }

        // Inverted lookup
        val parts = normalizedPair.split("/")
        if (parts.size == 2) {
            val invertedPair = "${parts[1]}/${parts[0]}"
            val invRate = localForexCache[invertedPair]
            if (invRate != null && invRate > 0.0) {
                return 1.0 / invRate
            }
        }

        return 1.0
    }

    /**
     * 4. ijkl_convertCurrency
     * Converts monetary amount from source currency to target currency using cached rates.
     */
    fun ijkl_convertCurrency(amount: Double, fromCurr: String, toCurr: String): Double {
        val src = fromCurr.trim().uppercase()
        val dst = toCurr.trim().uppercase()
        if (src == dst) return amount

        val pair = "$src/$dst"
        val rate = efgh_getCachedRate(pair)
        val converted = amount * rate
        return String.format("%.4f", converted).toDouble()
    }

    /**
     * 5. mnop_normalizePaymentAmount
     * Orchestrates: normalizes payment DTO amount to platform standard base currency (USD).
     */
    fun mnop_normalizePaymentAmount(paymentDto: Map<String, Any>): Map<String, Any> {
        val rawAmount = when (val a = paymentDto["amount"]) {
            is Number -> a.toDouble()
            is String -> a.toDoubleOrNull() ?: 0.0
            else -> 0.0
        }
        val currency = paymentDto["currency"]?.toString()?.uppercase() ?: "USD"
        val baseCurrency = "USD"

        val convertedAmount = ijkl_convertCurrency(rawAmount, currency, baseCurrency)
        val rateApplied = if (rawAmount > 0.0) convertedAmount / rawAmount else 1.0

        return mutableMapOf<String, Any>().apply {
            putAll(paymentDto)
            put("originalAmount", rawAmount)
            put("originalCurrency", currency)
            put("baseCurrency", baseCurrency)
            put("normalizedAmount", convertedAmount)
            put("exchangeRateApplied", String.format("%.4f", rateApplied).toDouble())
            put("normalizedAt", Instant.now().toString())
        }
    }
}
