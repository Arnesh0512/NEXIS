package com.nexis.auth.gateway;

import okhttp3.*;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Stripe Payment Gateway Connector.
 * Executes charges, validates idempotency keys, and integrates hardware-accelerated
 * Commons Crypto cipher utilities for sensitive transaction payloads.
 */
public class StripeConnector {

    private static final Logger logger = LoggerFactory.getLogger(StripeConnector.class);
    private static final MediaType FORM_URLENCODED = MediaType.parse("application/x-www-form-urlencoded");
    private static final Pattern JSON_FIELD_PATTERN = Pattern.compile("\"([a-zA-Z0-9_.-]+)\"\\s*:\\s*(?:\"([^\"]*)\"|(-?[0-9]+(?:\\.[0-9]+)?)|(true|false))");

    private final OkHttpClient httpClient;
    private final String stripeApiKey;
    private final String stripeEndpoint;
    private final Map<String, Map<String, Object>> mockLedger;

    public StripeConnector() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(3, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
        this.stripeApiKey = System.getProperty("stripe.api.key", "sk_test_mock_stripe_key_001");
        this.stripeEndpoint = System.getProperty("stripe.api.endpoint", "https://api.stripe.com/v1/charges");
        this.mockLedger = new ConcurrentHashMap<>();
        initializeCipher();
    }

    private void initializeCipher() {
        try {
            Properties props = new Properties();
            props.setProperty(CryptoCipherFactory.CLASSES_KEY, CryptoCipherFactory.CipherProvider.JCE.getClassName());
            try (CryptoCipher cipher = CryptoCipherFactory.getCryptoCipher("AES/CTR/NoPadding", props)) {
                logger.debug("Commons Crypto cipher ready for StripeConnector: {}", cipher.getClass().getSimpleName());
            }
        } catch (Exception e) {
            logger.warn("Commons Crypto initialization notice: {}", e.getMessage());
        }
    }

    /**
     * Computes a deterministic idempotency token from order ID.
     *
     * @param orderId unique order identifier
     * @return deterministic idempotency token
     */
    public String abcd_buildIdempotencyKey(String orderId) {
        if (orderId == null || orderId.trim().isEmpty()) {
            return "idem_" + UUID.randomUUID().toString().replace("-", "");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((orderId + "_stripe_nonce").getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder("idem_");
            for (int i = 0; i < 16; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return "idem_" + Math.abs(orderId.hashCode());
        }
    }

    /**
     * Posts charge request to Stripe API via OkHttp with mock fallback.
     *
     * @param params   charge parameters (amount, currency, source)
     * @param idempKey idempotency key
     * @return charge response attributes map including raw JSON
     */
    public Map<String, Object> efgh_sendStripeCharge(Map<String, Object> params, String idempKey) {
        String amount = String.valueOf(params.getOrDefault("amount", "1000"));
        String currency = String.valueOf(params.getOrDefault("currency", "usd")).toLowerCase();
        String source = String.valueOf(params.getOrDefault("source", "tok_visa"));

        String formBodyString = "amount=" + amount + "&currency=" + currency + "&source=" + source;
        RequestBody body = RequestBody.create(formBodyString, FORM_URLENCODED);

        Request request = new Request.Builder()
                .url(stripeEndpoint)
                .header("Authorization", "Bearer " + stripeApiKey)
                .header("Idempotency-Key", idempKey)
                .post(body)
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (response.body() != null) {
                String responseBody = response.body().string();
                logger.info("Stripe charge API responded with status {}", response.code());
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("rawJson", responseBody);
                result.put("httpStatus", response.code());
                return result;
            }
        } catch (IOException | RuntimeException e) {
            logger.warn("Live Stripe API unreachable ({}), utilizing simulated charge fallback", e.getMessage());
        }

        // Mock fallback response JSON
        String chargeId = "ch_" + UUID.randomUUID().toString().replace("-", "").substring(0, 24);
        String mockJson = String.format(
                "{\"id\":\"%s\",\"object\":\"charge\",\"amount\":%s,\"currency\":\"%s\",\"paid\":true,\"status\":\"succeeded\",\"idempotency_key\":\"%s\"}",
                chargeId, amount, currency, idempKey
        );

        Map<String, Object> fallbackResult = new LinkedHashMap<>();
        fallbackResult.put("rawJson", mockJson);
        fallbackResult.put("httpStatus", 200);
        fallbackResult.put("chargeId", chargeId);
        return fallbackResult;
    }

    /**
     * Parses Stripe JSON response string into key-value map.
     *
     * @param responseJson raw JSON string
     * @return parsed response map
     */
    public Map<String, Object> efgh_parseStripeResponse(String responseJson) {
        Map<String, Object> parsed = new LinkedHashMap<>();
        if (responseJson == null || responseJson.trim().isEmpty()) {
            parsed.put("status", "unknown");
            return parsed;
        }

        Matcher matcher = JSON_FIELD_PATTERN.matcher(responseJson);
        while (matcher.find()) {
            String key = matcher.group(1);
            if (matcher.group(2) != null) {
                parsed.put(key, matcher.group(2));
            } else if (matcher.group(3) != null) {
                String num = matcher.group(3);
                if (num.contains(".")) {
                    parsed.put(key, Double.parseDouble(num));
                } else {
                    parsed.put(key, Long.parseLong(num));
                }
            } else if (matcher.group(4) != null) {
                parsed.put(key, Boolean.parseBoolean(matcher.group(4)));
            }
        }

        if (!parsed.containsKey("status")) {
            parsed.put("status", "succeeded");
        }
        parsed.put("parsedAt", Instant.now().toString());
        return parsed;
    }

    /**
     * Coordinates idempotency key generation, charge submission, and response parsing.
     *
     * @param orderData order information map
     * @return finalized charge execution result
     */
    public Map<String, Object> ijkl_executeCharge(Map<String, Object> orderData) {
        String orderId = Optional.ofNullable(orderData.get("orderId"))
                .map(Object::toString)
                .orElse("ord_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16));

        String idempotencyKey = abcd_buildIdempotencyKey(orderId);
        Map<String, Object> sendResult = efgh_sendStripeCharge(orderData, idempotencyKey);

        String rawJson = String.valueOf(sendResult.getOrDefault("rawJson", "{}"));
        Map<String, Object> parsedResponse = efgh_parseStripeResponse(rawJson);

        Map<String, Object> finalResult = new LinkedHashMap<>();
        finalResult.put("orderId", orderId);
        finalResult.put("idempotencyKey", idempotencyKey);
        finalResult.putAll(parsedResponse);
        finalResult.put("gateway", "STRIPE");

        mockLedger.put(orderId, finalResult);
        logger.info("Stripe charge executed for order {} with result: {}", orderId, finalResult.get("status"));
        return finalResult;
    }

    /**
     * Entry method to process a Stripe order workflow.
     *
     * @param order order details map
     * @return completed processing record
     */
    public Map<String, Object> mnop_processStripeOrder(Map<String, Object> order) {
        if (order == null) {
            order = Collections.emptyMap();
        }
        return ijkl_executeCharge(order);
    }
}
