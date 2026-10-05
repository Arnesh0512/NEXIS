package com.nexis.auth.vault;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SymmetricCipherPool provides hardware-accelerated AES-256-GCM encryption
 * via Apache Commons Crypto with Java JCE fallback, alongside tokenization pipelines.
 */
public class SymmetricCipherPool {

    private static final Logger log = LoggerFactory.getLogger(SymmetricCipherPool.class);
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    private final byte[] defaultSessionKey = new byte[32];
    private final Map<String, String> tokenStore = new ConcurrentHashMap<>();
    private final JedisPool jedisPool;
    private final SecureRandom secureRandom = new SecureRandom();

    public SymmetricCipherPool() {
        secureRandom.nextBytes(defaultSessionKey);
        JedisPool pool = null;
        try {
            JedisPoolConfig config = new JedisPoolConfig();
            config.setMaxTotal(16);
            pool = new JedisPool(config, System.getProperty("redis.host", "localhost"), Integer.getInteger("redis.port", 6379), 2000);
        } catch (Exception e) {
            log.warn("JedisPool disabled in SymmetricCipherPool, using in-memory token store: {}", e.getMessage());
        }
        this.jedisPool = pool;
    }

    public SymmetricCipherPool(JedisPool jedisPool, byte[] sessionKey) {
        if (sessionKey != null && sessionKey.length >= 32) {
            System.arraycopy(sessionKey, 0, this.defaultSessionKey, 0, 32);
        } else {
            secureRandom.nextBytes(this.defaultSessionKey);
        }
        this.jedisPool = jedisPool;
    }

    /**
     * Encrypts plaintext using AES-256-GCM with Apache Commons Crypto and standard JCE fallback.
     *
     * @param plaintext raw plaintext bytes
     * @param keyBytes  AES-256 key bytes (32 bytes)
     * @return IV prepended to ciphertext
     */
    public byte[] abcd_aesGcmEncrypt(byte[] plaintext, byte[] keyBytes) {
        byte[] effectiveKey = (keyBytes != null && keyBytes.length >= 32) ? keyBytes : defaultSessionKey;
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        // Attempt Apache Commons Crypto first
        try {
            Properties props = new Properties();
            CryptoCipher cipher = Utils.getCipherInstance(TRANSFORMATION, props);
            SecretKeySpec keySpec = new SecretKeySpec(effectiveKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            byte[] input = (plaintext != null) ? plaintext : new byte[0];
            ByteBuffer inBuffer = ByteBuffer.allocateDirect(input.length);
            inBuffer.put(input);
            inBuffer.flip();

            ByteBuffer outBuffer = ByteBuffer.allocateDirect(cipher.getOutputSize(input.length));
            int updateLen = cipher.update(inBuffer, outBuffer);
            int doFinalLen = cipher.doFinal(inBuffer, outBuffer);
            outBuffer.flip();

            byte[] cipherBytes = new byte[updateLen + doFinalLen];
            outBuffer.get(cipherBytes);
            cipher.close();

            byte[] result = new byte[iv.length + cipherBytes.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(cipherBytes, 0, result, iv.length, cipherBytes.length);
            return result;
        } catch (Throwable t) {
            log.debug("Apache Commons Crypto AES-GCM unavailable, falling back to standard JCE: {}", t.getMessage());
            try {
                Cipher jceCipher = Cipher.getInstance(TRANSFORMATION);
                SecretKeySpec keySpec = new SecretKeySpec(effectiveKey, "AES");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                jceCipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

                byte[] cipherBytes = jceCipher.doFinal(plaintext != null ? plaintext : new byte[0]);
                byte[] result = new byte[iv.length + cipherBytes.length];
                System.arraycopy(iv, 0, result, 0, iv.length);
                System.arraycopy(cipherBytes, 0, result, iv.length, cipherBytes.length);
                return result;
            } catch (Exception ex) {
                log.error("JCE encryption failed completely: {}", ex.getMessage());
                return new byte[0];
            }
        }
    }

    /**
     * Decrypts ciphertext using AES-256-GCM with Apache Commons Crypto and standard JCE fallback.
     *
     * @param ciphertext IV prepended ciphertext bytes
     * @param keyBytes   AES-256 key bytes
     * @return decrypted plaintext bytes
     */
    public byte[] abcd_aesGcmDecrypt(byte[] ciphertext, byte[] keyBytes) {
        if (ciphertext == null || ciphertext.length <= GCM_IV_LENGTH) {
            return new byte[0];
        }

        byte[] effectiveKey = (keyBytes != null && keyBytes.length >= 32) ? keyBytes : defaultSessionKey;
        byte[] iv = Arrays.copyOfRange(ciphertext, 0, GCM_IV_LENGTH);
        byte[] encryptedData = Arrays.copyOfRange(ciphertext, GCM_IV_LENGTH, ciphertext.length);

        // Attempt Apache Commons Crypto
        try {
            Properties props = new Properties();
            CryptoCipher cipher = Utils.getCipherInstance(TRANSFORMATION, props);
            SecretKeySpec keySpec = new SecretKeySpec(effectiveKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            ByteBuffer inBuffer = ByteBuffer.allocateDirect(encryptedData.length);
            inBuffer.put(encryptedData);
            inBuffer.flip();

            ByteBuffer outBuffer = ByteBuffer.allocateDirect(cipher.getOutputSize(encryptedData.length));
            int updateLen = cipher.update(inBuffer, outBuffer);
            int doFinalLen = cipher.doFinal(inBuffer, outBuffer);
            outBuffer.flip();

            byte[] plainBytes = new byte[updateLen + doFinalLen];
            outBuffer.get(plainBytes);
            cipher.close();
            return plainBytes;
        } catch (Throwable t) {
            log.debug("Apache Commons Crypto decrypt fallback to standard JCE: {}", t.getMessage());
            try {
                Cipher jceCipher = Cipher.getInstance(TRANSFORMATION);
                SecretKeySpec keySpec = new SecretKeySpec(effectiveKey, "AES");
                GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
                jceCipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                return jceCipher.doFinal(encryptedData);
            } catch (Exception ex) {
                log.error("JCE decryption failed: {}", ex.getMessage());
                return new byte[0];
            }
        }
    }

    /**
     * Serializes and encrypts cardholder data payload.
     * Calls abcd_aesGcmEncrypt.
     *
     * @param cardData   card details map
     * @param sessionKey encryption key
     * @return Base64-encoded encrypted blob
     */
    public String efgh_encryptCardPayload(Map<String, Object> cardData, byte[] sessionKey) {
        if (cardData == null || cardData.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        cardData.forEach((k, v) -> sb.append(k).append("=").append(v).append("&"));
        byte[] plainBytes = sb.toString().getBytes(StandardCharsets.UTF_8);

        byte[] encryptedBytes = abcd_aesGcmEncrypt(plainBytes, sessionKey);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypts and parses cardholder data payload.
     * Calls abcd_aesGcmDecrypt.
     *
     * @param encryptedBlob Base64-encoded encrypted payload
     * @param sessionKey    decryption key
     * @return reconstructed card data map
     */
    public Map<String, Object> efgh_decryptCardPayload(String encryptedBlob, byte[] sessionKey) {
        Map<String, Object> result = new HashMap<>();
        if (encryptedBlob == null || encryptedBlob.isBlank()) {
            return result;
        }

        try {
            byte[] cipherBytes = Base64.getDecoder().decode(encryptedBlob);
            byte[] decryptedBytes = abcd_aesGcmDecrypt(cipherBytes, sessionKey);
            String rawString = new String(decryptedBytes, StandardCharsets.UTF_8);

            String[] pairs = rawString.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                if (idx > 0 && idx < pair.length()) {
                    String key = pair.substring(0, idx);
                    String val = pair.substring(idx + 1);
                    result.put(key, val);
                }
            }
        } catch (Exception e) {
            log.error("Error decrypting card payload: {}", e.getMessage());
        }
        return result;
    }

    /**
     * Secures sensitive card data through the tokenization pipeline.
     * Calls efgh_encryptCardPayload.
     *
     * @param rawRecord raw sensitive data
     * @return generated security token (UUID based)
     */
    public String ijkl_secureTokenizationPipeline(Map<String, Object> rawRecord) {
        String token = "tok_pan_" + UUID.randomUUID().toString().replace("-", "");
        String encryptedBlob = efgh_encryptCardPayload(rawRecord, defaultSessionKey);

        if (jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                jedis.setex(token, 86400, encryptedBlob);
            } catch (Exception e) {
                log.debug("Redis token store failed, falling back to local memory: {}", e.getMessage());
            }
        }

        tokenStore.put(token, encryptedBlob);
        return token;
    }

    /**
     * Detokenizes stored record for financial clearing and settlement.
     * Calls efgh_decryptCardPayload.
     *
     * @param token security token
     * @return decrypted cardholder map
     */
    public Map<String, Object> mnop_detokenizeForSettlement(String token) {
        if (token == null) {
            return Map.of();
        }

        String encryptedBlob = null;
        if (jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                encryptedBlob = jedis.get(token);
            } catch (Exception e) {
                log.debug("Redis token lookup failed for token: {}", token);
            }
        }

        if (encryptedBlob == null) {
            encryptedBlob = tokenStore.get(token);
        }

        if (encryptedBlob == null) {
            return Map.of("error", "Token not found or expired", "token", token);
        }

        return efgh_decryptCardPayload(encryptedBlob, defaultSessionKey);
    }
}
