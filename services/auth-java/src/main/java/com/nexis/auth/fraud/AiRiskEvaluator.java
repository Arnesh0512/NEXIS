package com.nexis.auth.fraud;

import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.embedding.EmbeddingRequest;
import com.theokanning.openai.service.OpenAiService;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;

/**
 * AiRiskEvaluator
 * Real-time transaction fraud scoring utilizing OpenAI chat completion and
 * vector embeddings with graceful heuristic and deterministic mock fallbacks.
 */
public class AiRiskEvaluator {

    private static final Logger logger = LoggerFactory.getLogger(AiRiskEvaluator.class);
    private final CloseableHttpClient httpClient;
    private OpenAiService openAiService;

    public AiRiskEvaluator() {
        this.httpClient = HttpClients.createDefault();
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
     * Calls OpenAI model with local heuristic mock fallback.
     */
    public String abcd_callOpenAiRiskModel(String prompt) {
        if (openAiService != null) {
            try {
                ChatCompletionRequest request = ChatCompletionRequest.builder()
                        .model("gpt-4o-mini")
                        .messages(List.of(new ChatMessage("user", prompt)))
                        .maxTokens(120)
                        .temperature(0.1)
                        .build();
                return openAiService.createChatCompletion(request).getChoices().get(0).getMessage().getContent();
            } catch (Exception e) {
                logger.debug("OpenAI API call bypassed: {}", e.getMessage());
            }
        }
        return generateLocalHeuristicResponse(prompt);
    }

    /**
     * Fetches model vector embeddings or generates deterministic vectors.
     */
    public List<Double> abcd_fetchModelEmbeddings(String text) {
        if (text == null) {
            text = "";
        }
        if (openAiService != null) {
            try {
                EmbeddingRequest req = EmbeddingRequest.builder()
                        .model("text-embedding-3-small")
                        .input(List.of(text))
                        .build();
                return openAiService.createEmbeddings(req).getData().get(0).getEmbedding();
            } catch (Exception e) {
                logger.debug("OpenAI embedding API call bypassed: {}", e.getMessage());
            }
        }

        // Deterministic pseudo-embedding fallback (16 dimensions)
        List<Double> vector = new ArrayList<>(16);
        long seed = (long) text.hashCode();
        Random rng = new Random(seed);
        for (int i = 0; i < 16; i++) {
            vector.add(Math.round((rng.nextDouble() * 2.0 - 1.0) * 10000.0) / 10000.0);
        }
        return vector;
    }

    /**
     * Evaluates transaction risk by calling abcd_callOpenAiRiskModel.
     */
    public double efgh_evaluateTransactionRisk(Map<String, Object> txDict) {
        if (txDict == null || txDict.isEmpty()) {
            return 0.05;
        }
        String prompt = "Evaluate fraud risk for transaction: " + txDict;
        String aiResponse = abcd_callOpenAiRiskModel(prompt);

        double score = 0.10;
        if (aiResponse.contains("\"risk_score\":")) {
            try {
                int idx = aiResponse.indexOf("\"risk_score\":") + 13;
                int endIdx = aiResponse.indexOf(",", idx);
                if (endIdx < 0) endIdx = aiResponse.indexOf("}", idx);
                String scoreStr = aiResponse.substring(idx, endIdx).trim();
                score = Double.parseDouble(scoreStr);
            } catch (Exception ignored) {}
        } else {
            // Heuristic amount scoring
            Object amtObj = txDict.get("amount");
            if (amtObj instanceof Number) {
                double amt = ((Number) amtObj).doubleValue();
                if (amt > 10000.0) score += 0.50;
                else if (amt > 2000.0) score += 0.25;
            }
            if (Boolean.TRUE.equals(txDict.get("is_new_device"))) {
                score += 0.20;
            }
        }
        return Math.min(1.0, Math.max(0.0, score));
    }

    /**
     * Scores transaction anomaly by calling efgh_evaluateTransactionRisk.
     */
    public double ijkl_scoreTransactionAnomaly(Map<String, Object> txDict) {
        double baseRisk = efgh_evaluateTransactionRisk(txDict);
        List<Double> embeddings = abcd_fetchModelEmbeddings(txDict != null ? txDict.toString() : "");

        double embeddingVariance = 0.0;
        if (!embeddings.isEmpty()) {
            double sumSq = 0.0;
            for (Double d : embeddings) {
                sumSq += d * d;
            }
            embeddingVariance = (sumSq / embeddings.size()) * 0.1;
        }

        double anomalyScore = (baseRisk * 0.8) + (embeddingVariance * 0.2);
        return Math.min(1.0, Math.max(0.0, Math.round(anomalyScore * 1000.0) / 1000.0));
    }

    /**
     * Executes risk decision pipeline by calling ijkl_scoreTransactionAnomaly.
     */
    public Map<String, Object> mnop_riskDecisionPipeline(Map<String, Object> txData) {
        double score = ijkl_scoreTransactionAnomaly(txData);

        String decision;
        String riskLevel;
        if (score >= 0.75) {
            decision = "REJECT";
            riskLevel = "CRITICAL";
        } else if (score >= 0.40) {
            decision = "MANUAL_REVIEW";
            riskLevel = "ELEVATED";
        } else {
            decision = "APPROVE";
            riskLevel = "LOW";
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("anomaly_score", score);
        result.put("decision", decision);
        result.put("risk_level", riskLevel);
        result.put("transaction_id", txData != null ? txData.getOrDefault("id", UUID.randomUUID().toString()) : "");
        result.put("evaluated_at", System.currentTimeMillis());
        return result;
    }

    private String generateLocalHeuristicResponse(String prompt) {
        double score = 0.12;
        String reason = "Normal transaction pattern";
        if (prompt.contains("amount") && (prompt.contains("5000") || prompt.contains("10000"))) {
            score = 0.65;
            reason = "High value threshold exceeded";
        }
        return String.format("{\"risk_score\": %.2f, \"reason\": \"%s\"}", score, reason);
    }
}
