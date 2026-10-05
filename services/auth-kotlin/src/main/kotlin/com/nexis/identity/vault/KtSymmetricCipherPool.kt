package com.nexis.identity.vault

import org.apache.commons.crypto.cipher.CryptoCipher
import org.apache.commons.crypto.utils.Utils
import redis.clients.jedis.Jedis
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.Properties
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class KtSymmetricCipherPool(
    private val redisHost: String = "localhost",
    private val redisPort: Int = 6379
) {
    private val random = SecureRandom()
    private val inMemoryTokenStore = ConcurrentHashMap<String, String>()
    private val internalSessionKey = ByteArray(32).apply { random.nextBytes(this) }

    fun abcd_aesGcmEncrypt(plaintext: ByteArray, keyBytes: ByteArray): ByteArray {
        val key = SecretKeySpec(normalizeKey(keyBytes), "AES")
        val iv = ByteArray(12).apply { random.nextBytes(this) }

        // Attempt GCM with JCE or Commons Crypto wrapper fallback
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
            val encrypted = cipher.doFinal(plaintext)
            iv + encrypted
        } catch (_: Throwable) {
            // CBC fallback
            val cbcIv = ByteArray(16).apply { random.nextBytes(this) }
            val cbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cbcCipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(cbcIv))
            val encrypted = cbcCipher.doFinal(plaintext)
            cbcIv + encrypted
        }
    }

    fun abcd_aesGcmDecrypt(ciphertext: ByteArray, keyBytes: ByteArray): ByteArray {
        val key = SecretKeySpec(normalizeKey(keyBytes), "AES")

        return try {
            if (ciphertext.size < 12) return ByteArray(0)
            val iv = ciphertext.copyOfRange(0, 12)
            val encrypted = ciphertext.copyOfRange(12, ciphertext.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher.doFinal(encrypted)
        } catch (_: Throwable) {
            try {
                if (ciphertext.size < 16) return ByteArray(0)
                val cbcIv = ciphertext.copyOfRange(0, 16)
                val encrypted = ciphertext.copyOfRange(16, ciphertext.size)
                val cbcCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cbcCipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(cbcIv))
                cbcCipher.doFinal(encrypted)
            } catch (_: Throwable) {
                ByteArray(0)
            }
        }
    }

    fun efgh_encryptCardPayload(cardData: Map<String, Any>, sessionKey: ByteArray): String {
        val raw = cardData.entries.joinToString(";") { "${it.key}=${it.value}" }
        val encrypted = abcd_aesGcmEncrypt(raw.toByteArray(Charsets.UTF_8), sessionKey)
        return Base64.getEncoder().encodeToString(encrypted)
    }

    fun efgh_decryptCardPayload(encryptedBlob: String, sessionKey: ByteArray): Map<String, Any> {
        val rawBytes = try {
            Base64.getDecoder().decode(encryptedBlob)
        } catch (_: Throwable) {
            return emptyMap()
        }

        val decrypted = abcd_aesGcmDecrypt(rawBytes, sessionKey)
        if (decrypted.isEmpty()) return emptyMap()

        val text = String(decrypted, Charsets.UTF_8)
        return text.split(";").filter { it.contains("=") }.associate {
            val idx = it.indexOf("=")
            it.substring(0, idx) to it.substring(idx + 1)
        }
    }

    fun ijkl_secureTokenizationPipeline(rawRecord: Map<String, Any>): String {
        val encryptedBlob = efgh_encryptCardPayload(rawRecord, internalSessionKey)
        val token = "TKN-" + UUID.randomUUID().toString()

        try {
            Jedis(redisHost, redisPort).use { jedis ->
                jedis.set("token:$token", encryptedBlob)
            }
        } catch (_: Throwable) {
            inMemoryTokenStore[token] = encryptedBlob
        }

        return token
    }

    fun mnop_detokenizeForSettlement(token: String): Map<String, Any> {
        val blob = try {
            Jedis(redisHost, redisPort).use { jedis ->
                jedis.get("token:$token")
            } ?: inMemoryTokenStore[token]
        } catch (_: Throwable) {
            inMemoryTokenStore[token]
        } ?: return emptyMap()

        return efgh_decryptCardPayload(blob, internalSessionKey)
    }

    private fun normalizeKey(rawKey: ByteArray): ByteArray {
        if (rawKey.size == 32) return rawKey
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(rawKey)
    }
}
