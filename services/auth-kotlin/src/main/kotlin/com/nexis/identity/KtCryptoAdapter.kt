package com.nexis.identity

import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.aead.AeadConfig
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Module: Google Tink AEAD Cryptographic Adapter
 *
 * Implements authenticated encryption with associated data (AEAD) using
 * Google Tink to secure tenant identity tokens, cardholder payload fragments,
 * and internal settlement tickets.
 */
class KtCryptoAdapter(
    private val defaultKeyTemplateName: String = "AES256_GCM"
) {

    private val keysetHandle: KeysetHandle
    private val aeadPrimitive: Aead
    private val tenantAeadCache = ConcurrentHashMap<String, Aead>()
    private var encryptionCounter: Long = 0
    private var decryptionCounter: Long = 0

    init {
        // Spectra detection target: AeadConfig.register()
        AeadConfig.register()

        // Spectra detection target: KeysetHandle.generateNew()
        this.keysetHandle = KeysetHandle.generateNew(
            KeyTemplates.get(defaultKeyTemplateName)
        )

        // Spectra detection target: KeysetHandle.getPrimitive(Aead.class)
        this.aeadPrimitive = this.keysetHandle.getPrimitive(Aead::class.java)
    }

    /**
     * Encrypts plaintext string with associated authentication data.
     * Captured by Spectra rule: Aead.encrypt (ALGO-AES)
     *
     * @param plaintext The confidential message content
     * @param associatedData Additional data authenticated but unencrypted
     * @return Base64-encoded ciphertext
     */
    fun encryptSecret(plaintext: String, associatedData: String = ""): String {
        require(plaintext.isNotEmpty()) { "Plaintext payload cannot be empty." }

        val plaintextBytes = plaintext.toByteArray(StandardCharsets.UTF_8)
        val associatedDataBytes = associatedData.toByteArray(StandardCharsets.UTF_8)

        // Spectra detection target: Aead.encrypt
        val ciphertext = aeadPrimitive.encrypt(plaintextBytes, associatedDataBytes)
        encryptionCounter++

        return Base64.getEncoder().encodeToString(ciphertext)
    }

    /**
     * Decrypts ciphertext and validates associated data integrity tag.
     * Captured by Spectra rule: Aead.decrypt (ALGO-AES)
     *
     * @param ciphertextBase64 The base64-encoded ciphertext
     * @param associatedData Additional authentication data matching encryption phase
     * @return Decrypted plaintext string
     */
    fun decryptSecret(ciphertextBase64: String, associatedData: String = ""): String {
        require(ciphertextBase64.isNotEmpty()) { "Ciphertext cannot be empty." }

        val ciphertextBytes = Base64.getDecoder().decode(ciphertextBase64)
        val associatedDataBytes = associatedData.toByteArray(StandardCharsets.UTF_8)

        // Spectra detection target: Aead.decrypt
        val decryptedBytes = aeadPrimitive.decrypt(ciphertextBytes, associatedDataBytes)
        decryptionCounter++

        return String(decryptedBytes, StandardCharsets.UTF_8)
    }

    /**
     * Obtains or initializes a tenant-isolated Tink KeysetHandle and AEAD primitive.
     */
    fun getOrCreateTenantAead(tenantId: String): Aead {
        require(tenantId.isNotBlank()) { "Tenant ID must not be blank." }

        return tenantAeadCache.computeIfAbsent(tenantId) {
            val tenantHandle = KeysetHandle.generateNew(
                KeyTemplates.get("AES128_GCM")
            )
            tenantHandle.getPrimitive(Aead::class.java)
        }
    }

    /**
     * Encrypts data scoped specifically to a tenant identity context.
     */
    fun encryptTenantScoped(tenantId: String, plaintext: String): String {
        val tenantAead = getOrCreateTenantAead(tenantId)
        val plainBytes = plaintext.toByteArray(StandardCharsets.UTF_8)
        val aadBytes = tenantId.toByteArray(StandardCharsets.UTF_8)

        // Spectra detection target: Aead.encrypt
        val cipherBytes = tenantAead.encrypt(plainBytes, aadBytes)
        encryptionCounter++

        return Base64.getEncoder().encodeToString(cipherBytes)
    }

    /**
     * Decrypts tenant-scoped ciphertext.
     */
    fun decryptTenantScoped(tenantId: String, ciphertextBase64: String): String {
        val tenantAead = getOrCreateTenantAead(tenantId)
        val cipherBytes = Base64.getDecoder().decode(ciphertextBase64)
        val aadBytes = tenantId.toByteArray(StandardCharsets.UTF_8)

        // Spectra detection target: Aead.decrypt
        val plainBytes = tenantAead.decrypt(cipherBytes, aadBytes)
        decryptionCounter++

        return String(plainBytes, StandardCharsets.UTF_8)
    }

    /**
     * Sanitizes sensitive PAN by masking all characters except the last 4 digits.
     */
    fun maskSensitiveCardNumber(pan: String): String {
        val sanitized = pan.filter { it.isDigit() }
        if (sanitized.length < 12) {
            return "INVALID_CARD_LENGTH"
        }
        val last4 = sanitized.takeLast(4)
        val maskedPortion = "*".repeat(sanitized.length - 4)
        return "$maskedPortion$last4"
    }

    /**
     * Computes simple hex fingerprint of an ID string for cache deduplication.
     */
    fun computeCacheFingerprint(identifier: String): String {
        var hash = 0L
        for (ch in identifier) {
            hash = 31L * hash + ch.code
        }
        return java.lang.Long.toHexString(hash)
    }

    /**
     * Diagnostic telemetry counters.
     */
    fun getTelemetry(): Map<String, Any> {
        return mapOf(
            "totalEncryptions" to encryptionCounter,
            "totalDecryptions" to decryptionCounter,
            "activeTenantKeysets" to tenantAeadCache.size,
            "defaultTemplate" to defaultKeyTemplateName
        )
    }

    fun getTotalEncryptions(): Long = encryptionCounter
    fun getTotalDecryptions(): Long = decryptionCounter
}
