package com.nexis.identity.api

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.runBlocking
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

private val allowedCurrencies = setOf("USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "SGD")
private const val MAX_SETTLEMENT_LIMIT = 5_000_000.0
private val localClearingQueue = ConcurrentLinkedQueue<String>()
private val settlementAuditLog = ConcurrentHashMap<String, Map<String, Any>>()

/**
 * 1. Validates settlement limits and currency compliance rules.
 */
fun abcd_inspectSettlementRules(amount: Double, currency: String): Boolean {
    if (amount <= 0.0 || amount > MAX_SETTLEMENT_LIMIT) {
        return false
    }
    return allowedCurrencies.contains(currency.uppercase().trim())
}

/**
 * 2. Posts clearing dispatch asynchronously via Ktor CIO client with fallback to local queue.
 */
fun efgh_dispatchAsyncClearing(orderId: String): Boolean {
    return try {
        val client = HttpClient(CIO) {
            engine {
                requestTimeout = 2000
            }
        }
        val result = runBlocking {
            try {
                val response = client.post("http://127.0.0.1:8090/api/v1/clearing/batch") {
                    contentType(ContentType.Application.Json)
                    setBody("""{"orderId":"$orderId","timestamp":${System.currentTimeMillis()}}""")
                }
                response.status.value in 200..299
            } finally {
                client.close()
            }
        }
        if (!result) {
            localClearingQueue.add(orderId)
        }
        true
    } catch (_: Exception) {
        // Fallback: Queue into local clearing buffer
        localClearingQueue.add(orderId)
        true
    }
}

/**
 * 3. Validates business constraints and routes clearing request.
 */
fun efgh_routeSettlement(orderData: Map<String, Any>): Boolean {
    val amount = when (val a = orderData["amount"]) {
        is Number -> a.toDouble()
        is String -> a.toDoubleOrNull() ?: 0.0
        else -> 0.0
    }
    val currency = orderData["currency"]?.toString() ?: "USD"

    val rulesPassed = abcd_inspectSettlementRules(amount, currency)
    if (!rulesPassed) {
        return false
    }

    val orderId = orderData["orderId"]?.toString() ?: "ord_${UUID.randomUUID()}"
    return efgh_dispatchAsyncClearing(orderId)
}

/**
 * 4. Coordinates the end-to-end settlement pipeline and audit recording.
 */
fun ijkl_executeSettlementChain(orderData: Map<String, Any>): Boolean {
    val orderId = orderData["orderId"]?.toString() ?: "ord_${UUID.randomUUID()}"
    val routed = efgh_routeSettlement(orderData)

    settlementAuditLog[orderId] = mapOf(
        "orderId" to orderId,
        "routed" to routed,
        "timestamp" to System.currentTimeMillis()
    )

    return routed
}

/**
 * 5. Primary settlement route endpoint for API ingestion.
 */
fun mnop_settlementRouteEndpoint(req: Map<String, Any>): Map<String, Any> {
    val orderId = req["orderId"]?.toString() ?: "ord_${UUID.randomUUID()}"
    val enrichedReq = HashMap(req).apply { put("orderId", orderId) }

    val success = ijkl_executeSettlementChain(enrichedReq)

    return mapOf(
        "orderId" to orderId,
        "settled" to success,
        "status" to if (success) "SETTLEMENT_ACCEPTED" else "SETTLEMENT_REJECTED",
        "pendingQueueDepth" to localClearingQueue.size,
        "timestamp" to System.currentTimeMillis()
    )
}
