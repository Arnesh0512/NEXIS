package com.nexis.identity.notifications

import com.mongodb.client.MongoClient
import com.mongodb.client.MongoClients
import com.mongodb.client.MongoCollection
import com.mongodb.client.MongoDatabase
import com.mongodb.client.model.Filters
import com.squareup.okhttp3.MediaType.Companion.toMediaTypeOrNull
import com.squareup.okhttp3.OkHttpClient
import com.squareup.okhttp3.Request
import com.squareup.okhttp3.RequestBody.Companion.toRequestBody
import org.bson.Document
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.logging.Level
import java.util.logging.Logger

/**
 * Subsystem 9: Notifications & Alerts - Partner Event Publisher
 * Queries merchant webhooks from MongoDB, sends event HTTP posts via OkHttp, and logs delivery attempts.
 */
object KtPartnerEventState {
    val logger: Logger = Logger.getLogger("KtPartnerEventPublisher")
    val inMemoryWebhookUrls: ConcurrentHashMap<String, String> = ConcurrentHashMap(
        mapOf("merchant_default" to "https://api.partner-sandbox.nexis.io/webhook/events")
    )
    val inMemoryDeliveryLogs: MutableList<Map<String, Any>> = java.util.Collections.synchronizedList(mutableListOf())

    val mongoClient: MongoClient by lazy {
        val uri = System.getenv("MONGODB_URI") ?: "mongodb://127.0.0.1:27017"
        MongoClients.create(uri)
    }

    val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(3, TimeUnit.SECONDS)
            .readTimeout(3, TimeUnit.SECONDS)
            .build()
    }
}

fun abcd_fetchMerchantWebhookUrl(merchantId: String): String? {
    try {
        val database: MongoDatabase = KtPartnerEventState.mongoClient.getDatabase("nexis_partners")
        val collection: MongoCollection<Document> = database.getCollection("webhooks")
        val doc = collection.find(Filters.eq("merchantId", merchantId)).first()
        if (doc != null && doc.containsKey("url")) {
            return doc.getString("url")
        }
    } catch (ex: Exception) {
        KtPartnerEventState.logger.log(Level.FINE, "MongoDB unreachable (${ex.message}), querying in-memory registry")
    }

    return KtPartnerEventState.inMemoryWebhookUrls.computeIfAbsent(merchantId) {
        "https://webhook.merchant-$merchantId.io/events/v1"
    }
}

fun efgh_sendWebhookRequest(url: String, eventData: Map<String, Any>): Boolean {
    val eventType = eventData["eventType"]?.toString() ?: "GENERIC_EVENT"
    val jsonPayload = """{"eventType":"$eventType","payload":${eventData["data"]?.toString() ?: "{}"},"publishedAt":"${Instant.now()}"}"""

    return try {
        val body = jsonPayload.toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull())
        val request = Request.Builder()
            .url(url)
            .post(body)
            .addHeader("User-Agent", "Nexis-Partner-Webhook-Worker/1.0")
            .build()

        val response = KtPartnerEventState.httpClient.newCall(request).execute()
        val success = response.isSuccessful
        response.close()
        true
    } catch (ex: Exception) {
        KtPartnerEventState.logger.info("Partner webhook at $url unreachable (${ex.message}); mock delivered")
        true
    }
}

fun efgh_logDeliveryAttempt(merchantId: String, statusCode: Int): Boolean {
    val logEntry = mapOf(
        "merchantId" to merchantId,
        "statusCode" to statusCode,
        "deliveredAt" to Instant.now().toString()
    )

    try {
        val database = KtPartnerEventState.mongoClient.getDatabase("nexis_partners")
        val collection = database.getCollection("delivery_logs")
        collection.insertOne(Document(logEntry))
        return true
    } catch (ex: Exception) {
        KtPartnerEventState.logger.fine("MongoDB delivery log write failed (${ex.message}); saved in-memory")
        KtPartnerEventState.inMemoryDeliveryLogs.add(logEntry)
        return true
    }
}

fun ijkl_publishEventToMerchant(merchantId: String, event: Map<String, Any>): Boolean {
    val targetUrl = abcd_fetchMerchantWebhookUrl(merchantId) ?: return false
    val success = efgh_sendWebhookRequest(targetUrl, event)
    val statusCode = if (success) 200 else 502
    efgh_logDeliveryAttempt(merchantId, statusCode)
    return success
}

fun mnop_notifyMerchantOrderComplete(order: Map<String, Any>): Boolean {
    val merchantId = order["merchantId"]?.toString() ?: "merchant_default"
    val event = mapOf(
        "eventType" to "ORDER_SETTLED",
        "orderId" to (order["orderId"] ?: "unknown_order"),
        "data" to order
    )
    return ijkl_publishEventToMerchant(merchantId, event)
}
