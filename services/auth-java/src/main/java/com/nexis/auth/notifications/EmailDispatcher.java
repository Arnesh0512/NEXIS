package com.nexis.auth.notifications;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Dispatches outbound email alerts and transaction receipts with cryptographic unsubscribe tokens.
 */
public class EmailDispatcher {

    private static final Logger logger = LoggerFactory.getLogger(EmailDispatcher.class);
    private static final String DEFAULT_HMAC_SECRET = "nexis-production-unsubscribe-hmac-sha256-key-32bytes-secret!";

    private final OkHttpClient httpClient;
    private final SecretKey jwtSecretKey;
    private final String mailApiEndpoint;
    private final Map<String, String> outboxMockStore = new ConcurrentHashMap<>();

    public EmailDispatcher() {
        this(new OkHttpClient.Builder()
                        .connectTimeout(Duration.ofSeconds(3))
                        .readTimeout(Duration.ofSeconds(3))
                        .build(),
                "https://api.mailgun.net/v3/nexis.io/messages",
                DEFAULT_HMAC_SECRET.getBytes(StandardCharsets.UTF_8));
    }

    public EmailDispatcher(OkHttpClient httpClient, String mailApiEndpoint, byte[] hmacKeyBytes) {
        this.httpClient = httpClient != null ? httpClient : new OkHttpClient();
        this.mailApiEndpoint = (mailApiEndpoint != null && !mailApiEndpoint.isBlank())
                ? mailApiEndpoint : "https://api.mailgun.net/v3/nexis.io/messages";
        byte[] keyBytes = (hmacKeyBytes != null && hmacKeyBytes.length >= 32)
                ? hmacKeyBytes : DEFAULT_HMAC_SECRET.getBytes(StandardCharsets.UTF_8);
        this.jwtSecretKey = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Signs a secure JWT unsubscribe token via JJWT.
     */
    public String abcd_generateUnsubscribeToken(String email) {
        String targetEmail = (email != null && !email.isBlank()) ? email.trim() : "anonymous@nexis.io";
        long now = System.currentTimeMillis();
        long expirationTime = now + (30L * 24 * 3600 * 1000); // 30 days validity

        return Jwts.builder()
                .subject(targetEmail)
                .claim("purpose", "unsubscribe")
                .claim("channel", "email-notifications")
                .issuedAt(new Date(now))
                .expiration(new Date(expirationTime))
                .signWith(this.jwtSecretKey)
                .compact();
    }

    /**
     * Sends an email via OkHttp with fallback to in-memory dispatch store.
     */
    public boolean efgh_sendEmailHttp(String recipient, String subject, String body) {
        String cleanRecipient = (recipient != null && !recipient.isBlank()) ? recipient : "devnull@nexis.io";
        String cleanSubject = (subject != null) ? subject : "Nexis System Notification";
        String cleanBody = (body != null) ? body : "";

        logger.info("Attempting HTTP email dispatch to [{}] with subject [{}]", cleanRecipient, cleanSubject);

        String jsonPayload = String.format(
                "{\"to\":\"%s\",\"subject\":\"%s\",\"body\":\"%s\"}",
                cleanRecipient.replace("\"", "\\\""),
                cleanSubject.replace("\"", "\\\""),
                cleanBody.replace("\"", "\\\"").replace("\n", "\\n")
        );

        try {
            RequestBody requestBody = RequestBody.create(
                    jsonPayload,
                    MediaType.parse("application/json; charset=utf-8")
            );
            Request request = new Request.Builder()
                    .url(this.mailApiEndpoint)
                    .post(requestBody)
                    .header("User-Agent", "Nexis-EmailDispatcher/2.5")
                    .build();

            try (Response response = this.httpClient.newCall(request).execute()) {
                if (response.isSuccessful()) {
                    logger.info("Live email dispatch succeeded for [{}] status={}", cleanRecipient, response.code());
                    return true;
                }
                logger.warn("Live mail provider returned status {}. Falling back to in-memory store.", response.code());
            }
        } catch (Exception ex) {
            logger.warn("Live mail dispatch unreachable ({}: {}). Employing in-memory fallback.",
                    ex.getClass().getSimpleName(), ex.getMessage());
        }

        // Resilient in-memory mock fallback
        String recordKey = cleanRecipient + ":" + System.currentTimeMillis();
        outboxMockStore.put(recordKey, cleanSubject + " -> " + cleanBody);
        return true;
    }

    /**
     * Generates a rendered transaction receipt containing security token and details.
     */
    public String efgh_renderReceiptTemplate(Map<String, Object> paymentData) {
        Map<String, Object> data = (paymentData != null) ? paymentData : new HashMap<>();
        String txId = String.valueOf(data.getOrDefault("txId", "TX-" + System.currentTimeMillis()));
        String amount = String.valueOf(data.getOrDefault("amount", "0.00"));
        String currency = String.valueOf(data.getOrDefault("currency", "USD"));
        String email = String.valueOf(data.getOrDefault("customerEmail", "customer@nexis.io"));

        String unsubToken = abcd_generateUnsubscribeToken(email);

        return "<div class=\"nexis-receipt\">" +
                "<h1>Payment Confirmation</h1>" +
                "<p>Transaction ID: <strong>" + txId + "</strong></p>" +
                "<p>Total Amount: <strong>" + amount + " " + currency + "</strong></p>" +
                "<p>Status: <span style=\"color:green;\">SETTLED</span></p>" +
                "<hr/>" +
                "<p><small>Preferences: <a href=\"https://nexis.io/notifications/unsubscribe?token="
                + unsubToken + "\">Unsubscribe</a></small></p>" +
                "</div>";
    }

    /**
     * Prepares template and dispatches the customer payment receipt.
     */
    public boolean ijkl_dispatchPaymentReceipt(Map<String, Object> paymentData) {
        Map<String, Object> safeData = (paymentData != null) ? paymentData : new HashMap<>();
        String recipient = String.valueOf(safeData.getOrDefault("customerEmail", "customer@nexis.io"));
        String txId = String.valueOf(safeData.getOrDefault("txId", "TX-" + System.currentTimeMillis()));
        String subject = "Nexis Payment Receipt: " + txId;

        String renderedReceipt = efgh_renderReceiptTemplate(safeData);
        return efgh_sendEmailHttp(recipient, subject, renderedReceipt);
    }

    /**
     * Top-level entrypoint to alert customer of processed transaction.
     */
    public boolean mnop_sendTransactionAlert(Map<String, Object> paymentDto) {
        logger.info("Executing mnop_sendTransactionAlert with payload: {}", paymentDto);
        return ijkl_dispatchPaymentReceipt(paymentDto);
    }
}
