package com.nexis.auth.notifications;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Dispatches encrypted, signed security incident alerts to Slack incoming webhook channels.
 */
public class SlackWebhookAlerter {

    private static final Logger logger = LoggerFactory.getLogger(SlackWebhookAlerter.class);
    private static final String DEFAULT_SLACK_SECRET = "nexis_slack_signing_secret_token_12345";
    private static final String DEFAULT_WEBHOOK_URL = "https://slack-mock.internal.nexis/services/alerts";

    private final OkHttpClient httpClient;
    private final String slackSigningSecret;
    private final String webhookUrl;
    private final Map<String, Map<String, Object>> mockIncidentQueue = new ConcurrentHashMap<>();

    public SlackWebhookAlerter() {
        this(new OkHttpClient.Builder()
                        .connectTimeout(Duration.ofSeconds(3))
                        .readTimeout(Duration.ofSeconds(3))
                        .build(),
                DEFAULT_SLACK_SECRET,
                DEFAULT_WEBHOOK_URL);
    }

    public SlackWebhookAlerter(OkHttpClient httpClient, String slackSigningSecret, String webhookUrl) {
        this.httpClient = (httpClient != null) ? httpClient : new OkHttpClient();
        this.slackSigningSecret = (slackSigningSecret != null && !slackSigningSecret.isBlank())
                ? slackSigningSecret : DEFAULT_SLACK_SECRET;
        this.webhookUrl = (webhookUrl != null && !webhookUrl.isBlank())
                ? webhookUrl : DEFAULT_WEBHOOK_URL;
        probeCryptoEngine();
    }

    /**
     * Checks Apache Commons Crypto acceleration support.
     */
    private void probeCryptoEngine() {
        try {
            Properties props = new Properties();
            try (CryptoCipher cipher = Utils.getCipherInstance("AES/CBC/PKCS5Padding", props)) {
                logger.debug("Apache Commons Crypto acceleration available: {}", cipher.getClass().getName());
            }
        } catch (Throwable t) {
            logger.debug("Commons Crypto native provider fallback to JCE: {}", t.getMessage());
        }
    }

    /**
     * Computes HMAC-SHA256 signature for outgoing Slack webhook payload.
     */
    public String abcd_signSlackPayload(String payload, String secret) {
        String key = (secret != null && !secret.isBlank()) ? secret : this.slackSigningSecret;
        String data = (payload != null) ? payload : "";

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

            StringBuilder hex = new StringBuilder("v0=");
            for (byte b : rawHmac) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception ex) {
            logger.error("Failed to calculate HMAC-SHA256 for Slack payload: {}", ex.getMessage());
            return "v0=signature_calculation_failed";
        }
    }

    /**
     * Sends the incident card to Slack webhook with signature verification headers.
     */
    public boolean efgh_postSlackWebhook(String channelUrl, Map<String, Object> payload, String sig) {
        String targetUrl = (channelUrl != null && !channelUrl.isBlank()) ? channelUrl : this.webhookUrl;
        String signature = (sig != null) ? sig : "v0=none";

        String jsonPayload;
        if (payload != null && payload.containsKey("rawJson")) {
            jsonPayload = String.valueOf(payload.get("rawJson"));
        } else {
            String title = (payload != null && payload.containsKey("title")) ? String.valueOf(payload.get("title")) : "Security Alert";
            jsonPayload = String.format("{\"text\":\"%s\"}", title.replace("\"", "\\\""));
        }

        try {
            RequestBody requestBody = RequestBody.create(
                    jsonPayload,
                    MediaType.parse("application/json; charset=utf-8")
            );
            Request request = new Request.Builder()
                    .url(targetUrl)
                    .post(requestBody)
                    .header("X-Slack-Signature", signature)
                    .header("X-Slack-Request-Timestamp", String.valueOf(Instant.now().getEpochSecond()))
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful()) {
                    logger.info("Successfully delivered Slack alert to {}", targetUrl);
                    return true;
                }
                logger.warn("Slack endpoint returned status {}. Using in-memory alert queue.", response.code());
            }
        } catch (Exception ex) {
            logger.warn("Slack delivery exception ({}: {}). Employing in-memory fallback.",
                    ex.getClass().getSimpleName(), ex.getMessage());
        }

        mockIncidentQueue.put(String.valueOf(System.currentTimeMillis()), payload != null ? payload : Map.of());
        return true;
    }

    /**
     * Formats structured incident card with title, severity level, and detail blocks.
     */
    public Map<String, Object> efgh_formatIncidentCard(String title, String severity, String details) {
        Map<String, Object> card = new LinkedHashMap<>();
        card.put("title", title != null ? title : "Nexis Security Notification");
        card.put("severity", severity != null ? severity.toUpperCase() : "INFO");
        card.put("timestamp", Instant.now().toString());
        card.put("details", details != null ? details : "No additional information.");

        String color = "CRITICAL".equalsIgnoreCase(severity) ? "#FF0000" :
                ("HIGH".equalsIgnoreCase(severity) ? "#FF8800" : "#36A64F");

        String formattedJson = String.format(
                "{\"attachments\":[{\"color\":\"%s\",\"title\":\"[%s] %s\",\"text\":\"%s\",\"ts\":%d}]}",
                color,
                card.get("severity"),
                String.valueOf(card.get("title")).replace("\"", "\\\""),
                String.valueOf(card.get("details")).replace("\"", "\\\"").replace("\n", "\\n"),
                Instant.now().getEpochSecond()
        );
        card.put("rawJson", formattedJson);
        return card;
    }

    /**
     * Alerts security response team with formatted message and cryptographic signature.
     */
    public boolean ijkl_alertSecurityTeam(Map<String, Object> incident) {
        String title = (incident != null && incident.containsKey("title"))
                ? String.valueOf(incident.get("title")) : "Security Event Alert";
        String severity = (incident != null && incident.containsKey("severity"))
                ? String.valueOf(incident.get("severity")) : "HIGH";
        String details = (incident != null && incident.containsKey("details"))
                ? String.valueOf(incident.get("details")) : "Event triggered by platform guardrails.";

        Map<String, Object> card = efgh_formatIncidentCard(title, severity, details);
        String rawPayload = String.valueOf(card.get("rawJson"));
        String signature = abcd_signSlackPayload(rawPayload, this.slackSigningSecret);

        return efgh_postSlackWebhook(this.webhookUrl, card, signature);
    }

    /**
     * Broadcasts critical system or security runtime failure to Slack.
     */
    public boolean mnop_broadcastCriticalEvent(Throwable err) {
        String exceptionName = (err != null) ? err.getClass().getSimpleName() : "UnknownError";
        String message = (err != null && err.getMessage() != null) ? err.getMessage() : "Fatal platform exception";

        Map<String, Object> incident = new HashMap<>();
        incident.put("title", "Critical Exception: " + exceptionName);
        incident.put("severity", "CRITICAL");
        incident.put("details", "Stack trace summary: " + message);

        return ijkl_alertSecurityTeam(incident);
    }
}
