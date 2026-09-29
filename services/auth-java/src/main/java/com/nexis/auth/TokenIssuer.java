package com.nexis.auth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: Token Issuer & Cryptographic Signature Gateway
 *
 * Implements digital signature generation and HMAC authentication using standard
 * Java Cryptography Architecture (JCA) APIs.
 */
public class TokenIssuer {

    private final byte[] hmacSecret;
    private final String issuerIdentifier;
    private final Map<String, Long> revokedTokensCache;
    private long totalIssuedCount;
    private long totalVerifiedCount;

    public TokenIssuer(String hmacSecretKey, String issuerIdentifier) {
        Objects.requireNonNull(hmacSecretKey, "HMAC secret cannot be null");
        if (hmacSecretKey.length() < 32) {
            throw new IllegalArgumentException("HMAC key must contain at least 32 characters.");
        }
        this.hmacSecret = hmacSecretKey.getBytes(StandardCharsets.UTF_8);
        this.issuerIdentifier = issuerIdentifier != null ? issuerIdentifier : "https://auth.nexis.io";
        this.revokedTokensCache = new ConcurrentHashMap<>();
        this.totalIssuedCount = 0;
        this.totalVerifiedCount = 0;
    }

    /**
     * Computes an HMAC-SHA256 message authentication code for a token payload.
     * Captured by Spectra rule: Mac.getInstance("HmacSHA256") (ALGO-HMAC)
     *
     * @param payloadData The plaintext content to authenticate
     * @return Base64-encoded HMAC string
     * @throws NoSuchAlgorithmException If algorithm is not supported
     * @throws InvalidKeyException If key specification fails
     */
    public String computeHmacSignature(String payloadData) throws NoSuchAlgorithmException, InvalidKeyException {
        Objects.requireNonNull(payloadData, "Payload data must not be null");

        // Spectra detection target: SecretKeySpec instantiation
        SecretKeySpec signingKey = new SecretKeySpec(this.hmacSecret, "HmacSHA256");

        // Spectra detection target: Mac.getInstance
        Mac macInstance = Mac.getInstance("HmacSHA256");
        macInstance.init(signingKey);

        // Spectra detection target: Mac.doFinal
        byte[] rawHmac = macInstance.doFinal(payloadData.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(rawHmac);
    }

    /**
     * Verifies the authenticity of an incoming HMAC-SHA256 tag.
     *
     * @param payloadData Plaintext payload
     * @param expectedSignature Received HMAC tag
     * @return true if signature is valid
     */
    public boolean verifyHmacSignature(String payloadData, String expectedSignature) {
        if (payloadData == null || expectedSignature == null) {
            return false;
        }

        try {
            String computed = computeHmacSignature(payloadData);
            this.totalVerifiedCount++;
            return constantTimeEquals(computed, expectedSignature);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            return false;
        }
    }

    /**
     * Signs an arbitrary financial assertion with an RSA private key.
     * Captured by Spectra rule: Signature.getInstance("SHA256withRSA") (ALGO-RSA)
     *
     * @param dataBytes Content to be signed
     * @param privateKey The RSA private key
     * @return Base64 encoded signature
     * @throws NoSuchAlgorithmException If signature algorithm missing
     * @throws InvalidKeyException If key is invalid
     * @throws SignatureException If signing fails
     */
    public String signWithRsa(byte[] dataBytes, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Objects.requireNonNull(dataBytes, "Data bytes cannot be null");
        Objects.requireNonNull(privateKey, "Private key must not be null");

        // Spectra detection target: Signature.getInstance
        Signature rsaSigner = Signature.getInstance("SHA256withRSA");
        rsaSigner.initSign(privateKey);
        rsaSigner.update(dataBytes);

        // Spectra detection target: Signature.sign
        byte[] digitalSignature = rsaSigner.sign();
        this.totalIssuedCount++;

        return Base64.getEncoder().encodeToString(digitalSignature);
    }

    /**
     * Verifies an RSA digital signature using public key.
     * Captured by Spectra rule: Signature.verify (ALGO-RSA)
     *
     * @param dataBytes The original signed data
     * @param signatureBase64 The base64 signature
     * @param publicKey The corresponding RSA public key
     * @return true if valid
     */
    public boolean verifyRsaSignature(byte[] dataBytes, String signatureBase64, PublicKey publicKey) {
        if (dataBytes == null || signatureBase64 == null || publicKey == null) {
            return false;
        }

        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

            // Spectra detection target: Signature.getInstance
            Signature rsaVerifier = Signature.getInstance("SHA256withRSA");
            rsaVerifier.initVerify(publicKey);
            rsaVerifier.update(dataBytes);

            // Spectra detection target: Signature.verify
            boolean verified = rsaVerifier.verify(signatureBytes);
            this.totalVerifiedCount++;
            return verified;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Issues a synthetic compact authorization token.
     */
    public String issueAuthorizationToken(String subject, String tenantId, String role, long validitySeconds) {
        long now = System.currentTimeMillis() / 1000L;
        long exp = now + validitySeconds;
        String tokenId = "tok_" + Long.toHexString(System.nanoTime());

        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String body = String.format("{\"sub\":\"%s\",\"iss\":\"%s\",\"tid\":\"%s\",\"rol\":\"%s\",\"iat\":%d,\"exp\":%d,\"jti\":\"%s\"}",
                subject, this.issuerIdentifier, tenantId, role, now, exp, tokenId);
        String bodyEncoded = Base64.getUrlEncoder().withoutPadding().encodeToString(body.getBytes(StandardCharsets.UTF_8));

        String contentToSign = header + "." + bodyEncoded;
        try {
            String signature = computeHmacSignature(contentToSign);
            this.totalIssuedCount++;
            return contentToSign + "." + signature;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to sign token", e);
        }
    }

    /**
     * Revokes a token by identifier.
     */
    public void revokeToken(String jti, long expiryTimestamp) {
        if (jti != null) {
            this.revokedTokensCache.put(jti, expiryTimestamp);
        }
    }

    /**
     * Checks if a token ID has been revoked.
     */
    public boolean isRevoked(String jti) {
        if (jti == null) return false;
        Long exp = this.revokedTokensCache.get(jti);
        if (exp == null) return false;
        if (System.currentTimeMillis() / 1000L > exp) {
            this.revokedTokensCache.remove(jti);
            return false;
        }
        return true;
    }

    /**
     * Constant-time string equality comparison.
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    public long getTotalIssuedCount() {
        return this.totalIssuedCount;
    }

    public long getTotalVerifiedCount() {
        return this.totalVerifiedCount;
    }

    public String getIssuerIdentifier() {
        return this.issuerIdentifier;
    }
}
