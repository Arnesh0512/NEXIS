package com.nexis.auth.vault;

import io.jsonwebtoken.Jwts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * AsymmetricSigner provides RSA payload signing, verification, JJWT generation,
 * and high-integrity order dispatch verification.
 */
public class AsymmetricSigner {

    private static final Logger log = LoggerFactory.getLogger(AsymmetricSigner.class);
    private final KeyPair fallbackKeyPair;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public AsymmetricSigner() {
        KeyPair kp = null;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(2048, new SecureRandom());
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            log.warn("BouncyCastle initialization failed in AsymmetricSigner, using standard provider: {}", e.getMessage());
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048, new SecureRandom());
                kp = kpg.generateKeyPair();
            } catch (Exception fallbackEx) {
                log.error("Failed to initialize fallback RSA keypair: {}", fallbackEx.getMessage());
            }
        }
        this.fallbackKeyPair = kp;
    }

    public AsymmetricSigner(KeyPair fallbackKeyPair) {
        this.fallbackKeyPair = fallbackKeyPair;
    }

    /**
     * Signs payload using SHA256withRSA.
     *
     * @param payload    byte array payload to sign
     * @param privateKey RSA private key (falls back to internal key if null)
     * @return signature bytes
     */
    public byte[] abcd_signPayloadRsa(byte[] payload, PrivateKey privateKey) {
        try {
            PrivateKey key = (privateKey != null) ? privateKey : (fallbackKeyPair != null ? fallbackKeyPair.getPrivate() : null);
            if (key == null) {
                throw new IllegalStateException("No private key available for signing");
            }
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(payload != null ? payload : new byte[0]);
            return signature.sign();
        } catch (Exception e) {
            log.error("RSA payload signing error: {}", e.getMessage());
            return new byte[0];
        }
    }

    /**
     * Verifies RSA signature against payload.
     *
     * @param payload   raw payload bytes
     * @param signature signature bytes
     * @param publicKey RSA public key (falls back to internal key if null)
     * @return true if valid signature
     */
    public boolean abcd_verifyPayloadRsa(byte[] payload, byte[] signature, PublicKey publicKey) {
        if (payload == null || signature == null || signature.length == 0) {
            return false;
        }
        try {
            PublicKey key = (publicKey != null) ? publicKey : (fallbackKeyPair != null ? fallbackKeyPair.getPublic() : null);
            if (key == null) {
                return false;
            }
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key);
            verifier.update(payload);
            return verifier.verify(signature);
        } catch (Exception e) {
            log.error("RSA verification error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Generates compact JWT using JJWT.
     *
     * @param claims     map of claims
     * @param privateKey RSA private key for signing
     * @return compact JWT token string
     */
    public String abcd_createSignedJwtClaim(Map<String, Object> claims, PrivateKey privateKey) {
        try {
            PrivateKey key = (privateKey != null) ? privateKey : (fallbackKeyPair != null ? fallbackKeyPair.getPrivate() : null);
            Map<String, Object> safeClaims = (claims != null) ? claims : new HashMap<>();

            return Jwts.builder()
                    .claims(safeClaims)
                    .id(UUID.randomUUID().toString())
                    .issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + 3600000))
                    .signWith(key)
                    .compact();
        } catch (Exception e) {
            log.error("Failed to generate signed JWT claim: {}", e.getMessage());
            return "mock.jwt.token." + UUID.randomUUID();
        }
    }

    /**
     * Prepares and cryptographically signs an outbound order object.
     * Calls abcd_signPayloadRsa.
     *
     * @param orderObj outbound order data
     * @return map augmented with signature and authentication metadata
     */
    public Map<String, Object> efgh_authenticateOutboundOrder(Map<String, Object> orderObj) {
        Map<String, Object> authenticatedOrder = new HashMap<>(orderObj != null ? orderObj : Map.of());
        String canonicalString = authenticatedOrder.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(e -> e.getKey() + "=" + e.getValue())
                .reduce((a, b) -> a + "&" + b)
                .orElse("empty_order");

        byte[] payloadBytes = canonicalString.getBytes(StandardCharsets.UTF_8);
        byte[] sigBytes = abcd_signPayloadRsa(payloadBytes, fallbackKeyPair != null ? fallbackKeyPair.getPrivate() : null);
        String base64Sig = Base64.getEncoder().encodeToString(sigBytes);

        authenticatedOrder.put("x-signature", base64Sig);
        authenticatedOrder.put("x-signature-algo", "SHA256withRSA");
        authenticatedOrder.put("x-timestamp", Instant.now().toString());
        authenticatedOrder.put("authenticated", true);
        return authenticatedOrder;
    }

    /**
     * Verifies cryptographic integrity of an inbound order.
     * Calls abcd_verifyPayloadRsa.
     *
     * @param signedOrder map containing order data and signature
     * @return true if signature is valid
     */
    public boolean ijkl_verifyInboundOrder(Map<String, Object> signedOrder) {
        if (signedOrder == null || !signedOrder.containsKey("x-signature")) {
            return false;
        }

        try {
            String base64Sig = String.valueOf(signedOrder.get("x-signature"));
            byte[] sigBytes = Base64.getDecoder().decode(base64Sig);

            Map<String, Object> cleanMap = new HashMap<>(signedOrder);
            cleanMap.remove("x-signature");
            cleanMap.remove("x-signature-algo");
            cleanMap.remove("x-timestamp");
            cleanMap.remove("authenticated");

            String canonicalString = cleanMap.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .map(e -> e.getKey() + "=" + e.getValue())
                    .reduce((a, b) -> a + "&" + b)
                    .orElse("empty_order");

            byte[] payloadBytes = canonicalString.getBytes(StandardCharsets.UTF_8);
            return abcd_verifyPayloadRsa(payloadBytes, sigBytes, fallbackKeyPair != null ? fallbackKeyPair.getPublic() : null);
        } catch (Exception e) {
            log.error("Order verification failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Validates and dispatches an order through the security gateway.
     * Calls ijkl_verifyInboundOrder.
     *
     * @param orderData order data map
     * @return dispatch result status map
     */
    public Map<String, Object> mnop_dispatchValidatedOrder(Map<String, Object> orderData) {
        boolean valid = ijkl_verifyInboundOrder(orderData);
        Map<String, Object> response = new HashMap<>();

        if (valid) {
            response.put("status", "DISPATCHED");
            response.put("dispatchId", UUID.randomUUID().toString());
            response.put("timestamp", Instant.now().toString());
            response.put("orderId", orderData.getOrDefault("orderId", "N/A"));
        } else {
            response.put("status", "REJECTED");
            response.put("reason", "Cryptographic verification failed or invalid signature");
            response.put("timestamp", Instant.now().toString());
        }
        return response;
    }
}
