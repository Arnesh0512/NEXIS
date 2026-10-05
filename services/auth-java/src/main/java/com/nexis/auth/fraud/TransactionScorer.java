package com.nexis.auth.fraud;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.service.OpenAiService;
import org.bson.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * TransactionScorer
 * Multi-dimensional merchant fraud scoring incorporating order velocity checks
 * against MongoDB and generative AI explanations with mock fallbacks.
 */
public class TransactionScorer {

    private static final Logger logger = LoggerFactory.getLogger(TransactionScorer.class);
    private final Map<String, List<Map<String, Object>>> inMemoryMerchantOrders = new ConcurrentHashMap<>();
    private MongoClient mongoClient;
    private OpenAiService openAiService;

    public TransactionScorer() {
        try {
            String uri = System.getProperty("MONGO_URI", "mongodb://localhost:27017");
            this.mongoClient = MongoClients.create(uri);
        } catch (Exception e) {
            logger.info("MongoDB client initialization skipped: {}", e.getMessage());
            this.mongoClient = null;
        }

        String apiKey = System.getenv("OPENAI_API_KEY");
        if (apiKey != null && !apiKey.trim().isEmpty() && !apiKey.startsWith("mock")) {
            try {
                this.openAiService = new OpenAiService(apiKey, Duration.ofSeconds(3));
            } catch (Exception e) {
                logger.info("OpenAiService initialization skipped: {}", e.getMessage());
                this.openAiService = null;
            }
        } else {
            this.openAiService = null;
        }
    }

    /**
     * Queries recent transaction velocity for the given merchant from MongoDB / in-memory store.
     */
    public int abcd_queryMerchantVelocity(String merchantId) {
        if (merchantId == null) {
            return 0;
        }
        if (mongoClient != null) {
            try {
                MongoDatabase db = mongoClient.getDatabase("nexis_fraud");
                MongoCollection<Document> coll = db.getCollection("merchant_orders");
                long count = coll.countDocuments(new Document("merchantId", merchantId));
                return (int) count;
            } catch (Exception e) {
                logger.debug("MongoDB merchant velocity query fallback to memory: {}", e.getMessage());
            }
        }
        List<Map<String, Object>> orders = inMemoryMerchantOrders.get(merchantId);
        return orders != null ? orders.size() : 0;
    }

    /**
     * Computes velocity score based on transaction volume and order clustering.
     */
    public double efgh_calculateVelocityScore(List<Map<String, Object>> ordersList) {
        if (ordersList == null || ordersList.isEmpty()) {
            return 0.05;
        }
        int count = ordersList.size();
        if (count > 50) {
            return 0.90;
        } else if (count > 20) {
            return 0.65;
        } else if (count > 5) {
            return 0.35;
        } else {
            return 0.10;
        }
    }

    /**
     * Generates an AI-backed human-readable explanation of the fraud score factors.
     */
    public String efgh_queryAiFraudExplanation(Map<String, Object> scoreData) {
        if (openAiService != null) {
            try {
                String prompt = "Provide a 1-sentence fraud explanation for metrics: " + scoreData;
                ChatCompletionRequest req = ChatCompletionRequest.builder()
                        .model("gpt-4o-mini")
                        .messages(List.of(new ChatMessage("user", prompt)))
                        .maxTokens(60)
                        .build();
                return openAiService.createChatCompletion(req).getChoices().get(0).getMessage().getContent();
            } catch (Exception e) {
                logger.debug("AI explanation query fallback: {}", e.getMessage());
            }
        }
        double score = 0.0;
        if (scoreData != null && scoreData.get("velocityScore") instanceof Number num) {
            score = num.doubleValue();
        }
        return score > 0.5
                ? "Elevated merchant transaction velocity detected across recent settlement window."
                : "Transaction flow conforms to standard merchant baseline profile.";
    }

    /**
     * Computes composite score by calling abcd_queryMerchantVelocity, efgh_calculateVelocityScore, and efgh_queryAiFraudExplanation.
     */
    public double ijkl_computeCompositeScore(String merchantId, Map<String, Object> tx) {
        if (merchantId == null) {
            merchantId = "UNKNOWN_MERCHANT";
        }
        // Record incoming transaction in memory store
        inMemoryMerchantOrders.computeIfAbsent(merchantId, k -> new CopyOnWriteArrayList<>())
                .add(tx != null ? new HashMap<>(tx) : Collections.emptyMap());

        int velocity = abcd_queryMerchantVelocity(merchantId);
        List<Map<String, Object>> orders = inMemoryMerchantOrders.getOrDefault(merchantId, Collections.emptyList());
        double velocityScore = efgh_calculateVelocityScore(orders);

        Map<String, Object> scoreContext = new HashMap<>();
        scoreContext.put("merchantId", merchantId);
        scoreContext.put("velocity", velocity);
        scoreContext.put("velocityScore", velocityScore);
        scoreContext.put("txAmount", tx != null ? tx.getOrDefault("amount", 0) : 0);

        String explanation = efgh_queryAiFraudExplanation(scoreContext);
        logger.debug("Merchant assessment rationale: {}", explanation);

        double amountFactor = 0.1;
        if (tx != null && tx.get("amount") instanceof Number num) {
            double amt = num.doubleValue();
            if (amt > 5000.0) amountFactor = 0.5;
            else if (amt > 1000.0) amountFactor = 0.25;
        }

        double composite = (velocityScore * 0.7) + (amountFactor * 0.3);
        return Math.min(1.0, Math.max(0.0, Math.round(composite * 1000.0) / 1000.0));
    }

    /**
     * Evaluates merchant fraud posture by calling ijkl_computeCompositeScore.
     */
    public Map<String, Object> mnop_evaluateMerchantFraud(String merchantId, Map<String, Object> tx) {
        double compositeScore = ijkl_computeCompositeScore(merchantId, tx);

        String action;
        String riskStatus;
        if (compositeScore >= 0.70) {
            action = "BLOCK";
            riskStatus = "HIGH";
        } else if (compositeScore >= 0.35) {
            action = "CHALLENGE";
            riskStatus = "MEDIUM";
        } else {
            action = "ALLOW";
            riskStatus = "LOW";
        }

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("merchant_id", merchantId);
        report.put("composite_score", compositeScore);
        report.put("risk_status", riskStatus);
        report.put("action", action);
        report.put("timestamp", System.currentTimeMillis());
        return report;
    }
}
