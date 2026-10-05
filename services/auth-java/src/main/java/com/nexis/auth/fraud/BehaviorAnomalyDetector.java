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
 * BehaviorAnomalyDetector
 * Analyzes continuous user telemetry, geo-velocity impossible travel jumps,
 * and AI-generated behavioral profiles with in-memory fallbacks.
 */
public class BehaviorAnomalyDetector {

    private static final Logger logger = LoggerFactory.getLogger(BehaviorAnomalyDetector.class);
    private final Map<String, List<Map<String, Object>>> inMemoryUserHistory = new ConcurrentHashMap<>();
    private MongoClient mongoClient;
    private OpenAiService openAiService;

    public BehaviorAnomalyDetector() {
        try {
            String uri = System.getProperty("MONGO_URI", "mongodb://localhost:27017");
            this.mongoClient = MongoClients.create(uri);
        } catch (Exception e) {
            logger.info("MongoDB telemetry client skipped: {}", e.getMessage());
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
     * Retrieves chronological activity history for the given user from MongoDB or in-memory store.
     */
    public List<Map<String, Object>> abcd_fetchUserHistory(String userId) {
        if (userId == null) {
            return Collections.emptyList();
        }
        if (mongoClient != null) {
            try {
                MongoDatabase db = mongoClient.getDatabase("nexis_telemetry");
                MongoCollection<Document> coll = db.getCollection("user_activity");
                List<Map<String, Object>> list = new ArrayList<>();
                for (Document doc : coll.find(new Document("userId", userId)).limit(50)) {
                    list.add(new HashMap<>(doc));
                }
                if (!list.isEmpty()) {
                    return list;
                }
            } catch (Exception e) {
                logger.debug("MongoDB telemetry query fallback to memory: {}", e.getMessage());
            }
        }
        List<Map<String, Object>> local = inMemoryUserHistory.get(userId);
        return local != null ? new ArrayList<>(local) : Collections.emptyList();
    }

    /**
     * Detects impossible travel distance between consecutive location coordinates or country codes.
     */
    public boolean efgh_detectLocationJump(String currentLoc, String lastLoc) {
        if (currentLoc == null || lastLoc == null || currentLoc.trim().isEmpty() || lastLoc.trim().isEmpty()) {
            return false;
        }
        if (currentLoc.equalsIgnoreCase(lastLoc)) {
            return false;
        }

        // Support coordinate distance calculation if formatted as "lat,lon"
        if (currentLoc.contains(",") && lastLoc.contains(",")) {
            try {
                String[] p1 = currentLoc.split(",");
                String[] p2 = lastLoc.split(",");
                double lat1 = Double.parseDouble(p1[0].trim());
                double lon1 = Double.parseDouble(p1[1].trim());
                double lat2 = Double.parseDouble(p2[0].trim());
                double lon2 = Double.parseDouble(p2[1].trim());

                // Approximate Euclidean distance in degrees
                double dist = Math.hypot(lat1 - lat2, lon1 - lon2);
                return dist > 5.0; // Significant geographic leap
            } catch (Exception ignored) {}
        }

        // Distinct country or region codes indicate jump
        return !currentLoc.equalsIgnoreCase(lastLoc);
    }

    /**
     * Generates a behavioral pattern summary using OpenAI chat completion or heuristic rule-engine.
     */
    public String efgh_summarizeBehaviorWithAi(List<Map<String, Object>> history) {
        if (history == null || history.isEmpty()) {
            return "No historical baseline established for subject.";
        }

        if (openAiService != null) {
            try {
                String prompt = "Summarize user behavioral anomalies based on activity history: " + history;
                ChatCompletionRequest req = ChatCompletionRequest.builder()
                        .model("gpt-4o-mini")
                        .messages(List.of(new ChatMessage("user", prompt)))
                        .maxTokens(60)
                        .build();
                return openAiService.createChatCompletion(req).getChoices().get(0).getMessage().getContent();
            } catch (Exception e) {
                logger.debug("OpenAI behavioral summary fallback: {}", e.getMessage());
            }
        }

        return String.format("User baseline contains %d recorded events with standard temporal distribution.", history.size());
    }

    /**
     * Evaluates account security risk by calling abcd_fetchUserHistory, efgh_detectLocationJump,
     * and efgh_summarizeBehaviorWithAi.
     */
    public boolean ijkl_evaluateAccountSecurity(String userId, Map<String, Object> event) {
        if (userId == null || event == null) {
            return false;
        }

        List<Map<String, Object>> history = abcd_fetchUserHistory(userId);
        String lastLocation = null;
        if (!history.isEmpty()) {
            Map<String, Object> lastEvent = history.get(history.size() - 1);
            lastLocation = String.valueOf(lastEvent.getOrDefault("location", lastEvent.getOrDefault("country", "")));
        }

        String currentLocation = String.valueOf(event.getOrDefault("location", event.getOrDefault("country", "")));
        boolean locationJump = efgh_detectLocationJump(currentLocation, lastLocation);

        String summary = efgh_summarizeBehaviorWithAi(history);
        logger.debug("Telemetry summary for {}: {}", userId, summary);

        // Record event into in-memory history
        inMemoryUserHistory.computeIfAbsent(userId, k -> new CopyOnWriteArrayList<>())
                .add(new HashMap<>(event));

        boolean isNewDevice = Boolean.TRUE.equals(event.get("is_new_device")) || Boolean.TRUE.equals(event.get("newDevice"));
        boolean suspiciousAction = Boolean.TRUE.equals(event.get("suspicious_action"));

        return locationJump || isNewDevice || suspiciousAction;
    }

    /**
     * Determines whether step-up authentication is mandatory by calling ijkl_evaluateAccountSecurity.
     */
    public boolean mnop_triggerStepUpAuth(String userId, Map<String, Object> event) {
        return ijkl_evaluateAccountSecurity(userId, event);
    }
}
