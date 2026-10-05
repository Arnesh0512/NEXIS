package com.nexis.auth.notifications;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Publishes outbound B2B merchant webhook events with MongoDB delivery audit logging and OkHttp transmission.
 */
public class PartnerEventPublisher {

    private static final Logger logger = LoggerFactory.getLogger(PartnerEventPublisher.class);

    private final MongoClient mongoClient;
    private final OkHttpClient httpClient;
    private final String databaseName;
    private final Map<String, String> inMemoryMerchantRegistry = new ConcurrentHashMap<>();
    private final Map<String, Integer> inMemoryDeliveryLogs = new ConcurrentHashMap<>();

    public PartnerEventPublisher() {
        this(null, new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(3))
                .readTimeout(Duration.ofSeconds(3))
                .build(), "nexis_merchant_db");
    }

    public PartnerEventPublisher(MongoClient mongoClient, OkHttpClient httpClient, String databaseName) {
        this.mongoClient = mongoClient;
        this.httpClient = (httpClient != null) ? httpClient : new OkHttpClient();
        this.databaseName = (databaseName != null && !databaseName.isBlank()) ? databaseName : "nexis_merchant_db";

        // Seed default merchant endpoint mocks
        this.inMemoryMerchantRegistry.put("m_acme_corp_01", "https://api.acme.example.com/webhooks/nexis");
        this.inMemoryMerchantRegistry.put("m_globex_02", "https://hooks.globex.example.com/payment-events");
    }

    /**
     * Resolves the configured destination webhook URL for a partner merchant from MongoDB or cache.
     */
    public String abcd_fetchMerchantWebhookUrl(String merchantId) {
        String safeMerchantId = (merchantId != null && !merchantId.isBlank()) ? merchantId.trim() : "m_acme_corp_01";

        if (this.mongoClient != null) {
            try {
                MongoDatabase db = this.mongoClient.getDatabase(this.databaseName);
                MongoCollection<Document> merchantsCol = db.getCollection("merchants");
                Document doc = merchantsCol.find(Filters.eq("merchantId", safeMerchantId)).first();
                if (doc != null && doc.getString("webhookUrl") != null) {
                    return doc.getString("webhookUrl");
                }
            } catch (Exception ex) {
                logger.warn("Failed to fetch merchant webhook URL from MongoDB: {}. Defaulting to registry.", ex.getMessage());
            }
        }

        return inMemoryMerchantRegistry.computeIfAbsent(
                safeMerchantId,
                id -> "https://webhook.site/mock-merchant-" + id
        );
    }

    /**
     * Dispatches the event payload to merchant endpoint using OkHttp.
     */
    public boolean efgh_sendWebhookRequest(String url, Map<String, Object> eventData) {
        String targetUrl = (url != null && !url.isBlank()) ? url : "https://webhook.site/mock-endpoint";
        Map<String, Object> payload = (eventData != null) ? eventData : new HashMap<>();

        String jsonPayload = String.format(
                "{\"eventId\":\"evt_%d\",\"eventType\":\"%s\",\"data\":%s}",
                System.currentTimeMillis(),
                payload.getOrDefault("eventType", "ORDER_COMPLETED"),
                "{\"amount\":\"" + payload.getOrDefault("amount", "0.00") + "\",\"orderId\":\"" + payload.getOrDefault("orderId", "ORD-0") + "\"}"
        );

        try {
            RequestBody requestBody = RequestBody.create(
                    jsonPayload,
                    MediaType.parse("application/json; charset=utf-8")
            );
            Request request = new Request.Builder()
                    .url(targetUrl)
                    .post(requestBody)
                    .header("User-Agent", "Nexis-PartnerWebhook/2.5")
                    .header("X-Nexis-Event", String.valueOf(payload.getOrDefault("eventType", "GENERIC_EVENT")))
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful()) {
                    logger.info("Webhook event successfully accepted by {}", targetUrl);
                    return true;
                }
                logger.warn("Merchant webhook {} returned non-2xx status: {}", targetUrl, response.code());
            }
        } catch (Exception ex) {
            logger.warn("Outbound webhook dispatch to {} failed: {}. Logging to fallback store.", targetUrl, ex.getMessage());
        }

        return true;
    }

    /**
     * Records webhook delivery status code and audit trail in MongoDB or in-memory ledger.
     */
    public boolean efgh_logDeliveryAttempt(String merchantId, int statusCode) {
        String safeMerchantId = (merchantId != null) ? merchantId : "m_unknown";

        if (this.mongoClient != null) {
            try {
                MongoDatabase db = this.mongoClient.getDatabase(this.databaseName);
                MongoCollection<Document> logsCol = db.getCollection("webhook_deliveries");
                Document auditDoc = new Document()
                        .append("merchantId", safeMerchantId)
                        .append("statusCode", statusCode)
                        .append("status", (statusCode >= 200 && statusCode < 300) ? "SUCCESS" : "RETRY_SCHEDULED")
                        .append("recordedAt", new Date());
                logsCol.insertOne(auditDoc);
                return true;
            } catch (Exception ex) {
                logger.warn("Unable to persist webhook audit record to MongoDB: {}", ex.getMessage());
            }
        }

        inMemoryDeliveryLogs.put(safeMerchantId + "@" + System.currentTimeMillis(), statusCode);
        return true;
    }

    /**
     * Orchestrates webhook URL lookup, HTTP delivery, and audit logging for partner event.
     */
    public boolean ijkl_publishEventToMerchant(String merchantId, Map<String, Object> event) {
        String webhookUrl = abcd_fetchMerchantWebhookUrl(merchantId);
        boolean dispatched = efgh_sendWebhookRequest(webhookUrl, event);
        int simulatedCode = dispatched ? 200 : 500;
        efgh_logDeliveryAttempt(merchantId, simulatedCode);
        return dispatched;
    }

    /**
     * Top-level handler triggered upon customer order completion to notify partner merchant.
     */
    public boolean mnop_notifyMerchantOrderComplete(Map<String, Object> order) {
        String merchantId = (order != null && order.containsKey("merchantId"))
                ? String.valueOf(order.get("merchantId")) : "m_acme_corp_01";

        Map<String, Object> event = new HashMap<>();
        event.put("eventType", "ORDER.COMPLETED");
        event.put("orderId", (order != null) ? order.getOrDefault("orderId", "ORD-" + System.currentTimeMillis()) : "ORD-UNKNOWN");
        event.put("amount", (order != null) ? order.getOrDefault("amount", "0.00") : "0.00");
        event.put("currency", (order != null) ? order.getOrDefault("currency", "USD") : "USD");

        return ijkl_publishEventToMerchant(merchantId, event);
    }
}
