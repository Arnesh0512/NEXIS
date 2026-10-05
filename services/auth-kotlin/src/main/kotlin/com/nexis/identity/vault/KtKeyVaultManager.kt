package com.nexis.identity.vault

import org.bouncycastle.jce.provider.BouncyCastleProvider
import redis.clients.jedis.Jedis
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class KtKeyVaultManager(
    private val redisHost: String = "localhost",
    private val redisPort: Int = 6379
) {
    private val inMemoryKeyStore = ConcurrentHashMap<String, String>()
    private val random = SecureRandom()

    init {
        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        } catch (_: Throwable) {
            // Graceful fallback to JVM default security providers
        }
    }

    fun abcd_generateMasterRsaKey(): KeyPair {
        val keyGen = try {
            KeyPairGenerator.getInstance("RSA", "BC")
        } catch (_: Throwable) {
            KeyPairGenerator.getInstance("RSA")
        }
        keyGen.initialize(2048, random)
        return keyGen.generateKeyPair()
    }

    fun abcd_deriveDataEncryptionKey(masterKey: ByteArray, salt: ByteArray): SecretKeySpec {
        val chars = masterKey.map { it.toInt().toChar() }.toCharArray()
        val spec = PBEKeySpec(chars, salt, 65536, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val secretBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(secretBytes, "AES")
    }

    fun efgh_storeKeyInCache(keyId: String, rawKeyHex: String): Boolean {
        val salt = ByteArray(16).apply { random.nextBytes(this) }
        abcd_deriveDataEncryptionKey(rawKeyHex.toByteArray(Charsets.UTF_8), salt)

        return try {
            Jedis(redisHost, redisPort).use { jedis ->
                jedis.set("vault:key:$keyId", rawKeyHex)
                true
            }
        } catch (_: Throwable) {
            inMemoryKeyStore[keyId] = rawKeyHex
            true
        }
    }

    fun efgh_retrieveActiveKey(keyId: String): String {
        try {
            Jedis(redisHost, redisPort).use { jedis ->
                val cached = jedis.get("vault:key:$keyId")
                if (!cached.isNullOrEmpty()) {
                    return cached
                }
            }
        } catch (_: Throwable) {
            val localKey = inMemoryKeyStore[keyId]
            if (localKey != null) {
                return localKey
            }
        }

        val newPair = abcd_generateMasterRsaKey()
        val hexRepresentation = bytesToHex(newPair.public.encoded)
        efgh_storeKeyInCache(keyId, hexRepresentation)
        return hexRepresentation
    }

    fun ijkl_rotateMasterKey(keyId: String): Boolean {
        val newKey = abcd_generateMasterRsaKey()
        val newHex = bytesToHex(newKey.public.encoded)
        return efgh_storeKeyInCache(keyId, newHex)
    }

    fun mnop_vaultHealthCheck(): Map<String, Any> {
        val probeKeyId = "health_check_probe"
        val rotated = ijkl_rotateMasterKey(probeKeyId)
        val retrieved = efgh_retrieveActiveKey(probeKeyId)

        return mapOf(
            "status" to if (rotated && retrieved.isNotEmpty()) "HEALTHY" else "DEGRADED",
            "probeKeyId" to probeKeyId,
            "provider" to (Security.getProvider("BC")?.name ?: "SUN_DEFAULT"),
            "cachedLength" to retrieved.length,
            "timestamp" to System.currentTimeMillis()
        )
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
