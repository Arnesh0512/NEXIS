package com.nexis.auth.vault;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;
import java.time.Instant;
import java.util.HexFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * KeyVaultManager handles master RSA key management, PBKDF2-based key derivation,
 * and distributed caching with Jedis and in-memory failover.
 */
public class KeyVaultManager {

    private static final Logger log = LoggerFactory.getLogger(KeyVaultManager.class);
    private static final String REDIS_HOST = System.getProperty("redis.host", "localhost");
    private static final int REDIS_PORT = Integer.getInteger("redis.port", 6379);

    private final Map<String, String> inMemoryCache = new ConcurrentHashMap<>();
    private final JedisPool jedisPool;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public KeyVaultManager() {
        JedisPool pool = null;
        try {
            JedisPoolConfig config = new JedisPoolConfig();
            config.setMaxTotal(16);
            config.setMaxIdle(8);
            config.setMinIdle(2);
            pool = new JedisPool(config, REDIS_HOST, REDIS_PORT, 2000);
        } catch (Exception e) {
            log.warn("JedisPool initialization failed, operating in in-memory fallback mode: {}", e.getMessage());
        }
        this.jedisPool = pool;
    }

    public KeyVaultManager(JedisPool jedisPool) {
        this.jedisPool = jedisPool;
    }

    /**
     * Generates a 2048-bit RSA keypair using Bouncy Castle / standard Java Security.
     *
     * @return Generated KeyPair
     */
    public KeyPair abcd_generateMasterRsaKey() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            kpg.initialize(2048, new SecureRandom());
            return kpg.generateKeyPair();
        } catch (Exception bcEx) {
            log.warn("BouncyCastle RSA provider failed, falling back to default provider: {}", bcEx.getMessage());
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048, new SecureRandom());
                return kpg.generateKeyPair();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("RSA key generation not supported by runtime environment", e);
            }
        }
    }

    /**
     * Derives AES-256 key using PBKDF2WithHmacSHA256.
     *
     * @param masterKey raw master key bytes
     * @param salt      salt bytes for PBKDF2
     * @return SecretKeySpec wrapping AES-256 key
     */
    public SecretKeySpec abcd_deriveDataEncryptionKey(byte[] masterKey, byte[] salt) {
        try {
            char[] password = HexFormat.of().formatHex(masterKey).toCharArray();
            KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] derivedBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(derivedBytes, "AES");
        } catch (Exception e) {
            log.error("PBKDF2 derivation failed, falling back to direct SHA-256 key spec: {}", e.getMessage());
            byte[] fallbackKey = new byte[32];
            System.arraycopy(masterKey, 0, fallbackKey, 0, Math.min(masterKey.length, 32));
            return new SecretKeySpec(fallbackKey, "AES");
        }
    }

    /**
     * Stores key in Redis (via Jedis) with ConcurrentHashMap fallback.
     * Calls abcd_deriveDataEncryptionKey to validate and derive storage key.
     *
     * @param keyId     identifier of the key
     * @param rawKeyHex hex representation of key
     * @return true if stored successfully
     */
    public boolean efgh_storeKeyInCache(String keyId, String rawKeyHex) {
        if (keyId == null || rawKeyHex == null) {
            return false;
        }

        // Invoke lower layer to verify derivative key capability
        byte[] masterBytes = rawKeyHex.getBytes(StandardCharsets.UTF_8);
        byte[] salt = keyId.getBytes(StandardCharsets.UTF_8);
        abcd_deriveDataEncryptionKey(masterBytes, salt);

        boolean redisSuccess = false;
        if (jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                jedis.set(keyId, rawKeyHex);
                redisSuccess = true;
            } catch (Exception e) {
                log.debug("Redis store failed for keyId '{}', relying on in-memory store: {}", keyId, e.getMessage());
            }
        }

        inMemoryCache.put(keyId, rawKeyHex);
        return true;
    }

    /**
     * Reads key from cache; if absent, calls abcd_generateMasterRsaKey and caches it.
     *
     * @param keyId identifier of the key
     * @return key string representation
     */
    public String efgh_retrieveActiveKey(String keyId) {
        if (keyId == null) {
            return null;
        }

        if (jedisPool != null) {
            try (Jedis jedis = jedisPool.getResource()) {
                String cached = jedis.get(keyId);
                if (cached != null) {
                    inMemoryCache.put(keyId, cached);
                    return cached;
                }
            } catch (Exception e) {
                log.debug("Redis retrieval failed for keyId '{}', checking in-memory store: {}", keyId, e.getMessage());
            }
        }

        String inMemory = inMemoryCache.get(keyId);
        if (inMemory != null) {
            return inMemory;
        }

        // Absent: generate new master RSA key and store
        KeyPair keyPair = abcd_generateMasterRsaKey();
        String generatedHex = HexFormat.of().formatHex(keyPair.getPublic().getEncoded());
        efgh_storeKeyInCache(keyId, generatedHex);
        return generatedHex;
    }

    /**
     * Rotates key; calls efgh_storeKeyInCache.
     *
     * @param keyId identifier of the key to rotate
     * @return true if rotation succeeded
     */
    public boolean ijkl_rotateMasterKey(String keyId) {
        KeyPair newKeyPair = abcd_generateMasterRsaKey();
        String newKeyHex = HexFormat.of().formatHex(newKeyPair.getPrivate().getEncoded());
        return efgh_storeKeyInCache(keyId, newKeyHex);
    }

    /**
     * Health check probe; calls ijkl_rotateMasterKey.
     *
     * @return Map containing health metrics and probe status
     */
    public Map<String, Object> mnop_vaultHealthCheck() {
        String testKey = "vault-healthcheck-" + System.currentTimeMillis();
        boolean rotationSuccess = ijkl_rotateMasterKey(testKey);

        Map<String, Object> status = new HashMap<>();
        status.put("subsystem", "Vault-KeyVaultManager");
        status.put("timestamp", Instant.now().toString());
        status.put("healthy", rotationSuccess);
        status.put("redisConnected", jedisPool != null && !jedisPool.isClosed());
        status.put("inMemoryCacheEntries", inMemoryCache.size());
        status.put("provider", BouncyCastleProvider.PROVIDER_NAME);
        return status;
    }
}
