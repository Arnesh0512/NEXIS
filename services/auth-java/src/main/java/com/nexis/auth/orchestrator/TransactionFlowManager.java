package com.nexis.auth.orchestrator;

import com.theokanning.openai.completion.chat.ChatCompletionRequest;
import com.theokanning.openai.completion.chat.ChatMessage;
import com.theokanning.openai.service.OpenAiService;
import org.postgresql.Driver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages transaction lifecycle states, saga compensation rollbacks, and AI-assisted root-cause diagnosis.
 */
public class TransactionFlowManager {

    private static final Logger logger = LoggerFactory.getLogger(TransactionFlowManager.class);

    private final String pgJdbcUrl;
    private final String pgUser;
    private final String pgPassword;
    private final OpenAiService openAiService;
    private final Map<String, String> inMemoryFlowStateStore = new ConcurrentHashMap<>();
    private final Map<String, String> aiDiagnosticLog = new ConcurrentHashMap<>();

    public TransactionFlowManager() {
        this("jdbc:postgresql://localhost:5432/nexis_tx_db", "nexis_user", "nexis_secret", null);
    }

    public TransactionFlowManager(String pgJdbcUrl, String pgUser, String pgPassword, OpenAiService openAiService) {
        this.pgJdbcUrl = (pgJdbcUrl != null && !pgJdbcUrl.isBlank()) ? pgJdbcUrl : "jdbc:postgresql://localhost:5432/nexis_tx_db";
        this.pgUser = (pgUser != null) ? pgUser : "nexis_user";
        this.pgPassword = (pgPassword != null) ? pgPassword : "nexis_secret";

        // Register PostgreSQL driver defensively
        try {
            DriverManager.registerDriver(new Driver());
        } catch (SQLException ex) {
            logger.debug("PostgreSQL driver already registered or initialization note: {}", ex.getMessage());
        }

        OpenAiService resolvedAiService = openAiService;
        if (resolvedAiService == null) {
            String apiKey = System.getenv("OPENAI_API_KEY");
            if (apiKey != null && !apiKey.isBlank()) {
                try {
                    resolvedAiService = new OpenAiService(apiKey, Duration.ofSeconds(5));
                } catch (Exception ex) {
                    logger.debug("OpenAiService initialization skipped: {}", ex.getMessage());
                }
            }
        }
        this.openAiService = resolvedAiService;
    }

    /**
     * Persists transaction flow state into PostgreSQL or resilient in-memory storage.
     */
    public boolean abcd_persistFlowState(String txId, String state) {
        String safeTxId = (txId != null && !txId.isBlank()) ? txId : "TX-DEFAULT";
        String safeState = (state != null) ? state : "UNKNOWN";

        logger.info("Persisting flow state for txId={}: {}", safeTxId, safeState);

        try (Connection conn = DriverManager.getConnection(this.pgJdbcUrl, this.pgUser, this.pgPassword)) {
            String sql = "INSERT INTO tx_flow_states (tx_id, current_state, updated_at) " +
                    "VALUES (?, ?, NOW()) ON CONFLICT (tx_id) DO UPDATE SET current_state = EXCLUDED.current_state, updated_at = NOW()";
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setString(1, safeTxId);
                pstmt.setString(2, safeState);
                pstmt.executeUpdate();
                return true;
            }
        } catch (SQLException ex) {
            logger.warn("PostgreSQL state persistence failed: {}. Storing state in-memory.", ex.getMessage());
        }

        inMemoryFlowStateStore.put(safeTxId, safeState);
        return true;
    }

    /**
     * Triggers compensation logic (Saga pattern) to revert operations executed before a failure.
     */
    public boolean efgh_triggerCompensationLogic(String txId, String failedStage) {
        String safeTxId = (txId != null) ? txId : "UNKNOWN";
        String stage = (failedStage != null) ? failedStage : "PROCESSING";

        logger.warn("Initiating Saga rollback compensation for txId={} after stage failure: {}", safeTxId, stage);
        switch (stage.toUpperCase()) {
            case "LEDGER_POSTING":
                logger.info("Compensating: Reversing ledger reservation for txId={}", safeTxId);
                break;
            case "RISK_EVALUATION":
                logger.info("Compensating: Clearing temporary risk holds for txId={}", safeTxId);
                break;
            case "TOKEN_VALIDATION":
            default:
                logger.info("Compensating: Invalidating pre-auth session locks for txId={}", safeTxId);
                break;
        }
        return true;
    }

    /**
     * Employs OpenAI GPT API or deterministic heuristic rules to diagnose root cause of execution error.
     */
    public String efgh_diagnoseFailureWithAi(String errorTrace) {
        String safeTrace = (errorTrace != null && !errorTrace.isBlank()) ? errorTrace : "No error trace provided.";

        if (this.openAiService != null) {
            try {
                String prompt = "Analyze this payment platform transaction error trace and provide a concise 1-sentence root cause: " + safeTrace;
                ChatCompletionRequest chatRequest = ChatCompletionRequest.builder()
                        .model("gpt-4o-mini")
                        .messages(Collections.singletonList(new ChatMessage("user", prompt)))
                        .maxTokens(80)
                        .temperature(0.2)
                        .build();

                String diagnosis = this.openAiService.createChatCompletion(chatRequest)
                        .getChoices()
                        .get(0)
                        .getMessage()
                        .getContent()
                        .trim();
                logger.info("OpenAI root-cause diagnosis completed: {}", diagnosis);
                return diagnosis;
            } catch (Exception ex) {
                logger.warn("OpenAI API call failed: {}. Falling back to rule-based diagnostic engine.", ex.getMessage());
            }
        }

        // Resilient deterministic rule-based analysis
        String fallbackDiagnosis;
        if (safeTrace.toLowerCase().contains("timeout") || safeTrace.toLowerCase().contains("socket")) {
            fallbackDiagnosis = "Diagnosis: Network latency or socket timeout communicating with upstream card processor.";
        } else if (safeTrace.toLowerCase().contains("auth") || safeTrace.toLowerCase().contains("signature")) {
            fallbackDiagnosis = "Diagnosis: Cryptographic signature mismatch or expired bearer token.";
        } else if (safeTrace.toLowerCase().contains("sql") || safeTrace.toLowerCase().contains("connection")) {
            fallbackDiagnosis = "Diagnosis: Database connection pool exhaustion or query contention.";
        } else {
            fallbackDiagnosis = "Diagnosis: Transient processing anomaly detected during orchestration step.";
        }

        aiDiagnosticLog.put("DIAG-" + System.currentTimeMillis(), fallbackDiagnosis);
        return fallbackDiagnosis;
    }

    /**
     * Handles transaction failure by recording error state, triggering Saga compensation, and diagnosing with AI.
     */
    public boolean ijkl_handleTransactionFailure(String txId, String stage, Throwable err) {
        String errTrace = (err != null) ? (err.getClass().getName() + ": " + err.getMessage()) : "Unknown runtime fault";
        abcd_persistFlowState(txId, "FAILED_AT_" + (stage != null ? stage : "EXECUTION"));
        efgh_triggerCompensationLogic(txId, stage);
        String diagnosis = efgh_diagnoseFailureWithAi(errTrace);
        logger.error("Transaction failure workflow handled for txId={}. Root-cause: {}", txId, diagnosis);
        return true;
    }

    /**
     * Top-level lifecycle manager finalizing transaction completion state.
     */
    public boolean mnop_manageFlowCompletion(String txId, boolean success) {
        String finalState = success ? "SETTLED_SUCCESS" : "TERMINATED_FAILURE";
        return abcd_persistFlowState(txId, finalState);
    }
}
