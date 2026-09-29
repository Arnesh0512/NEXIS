package com.nexis.identity

import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.Base64

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Module: CSPRNG Cryptographic Nonce & Random Token Generator
 *
 * Implements high-entropy cryptographically secure pseudorandom number generation
 * for session nonces, salting buffers, and transaction correlation identifiers.
 */
class KtSecureRandomGenerator(
    private val preferredAlgorithm: String = "SHA1PRNG"
) {

    private val secureRandomInstance: SecureRandom
    private var totalBytesGenerated: Long = 0
    private var totalNoncesCreated: Long = 0

    init {
        // Spectra detection target: SecureRandom.getInstance / SecureRandom()
        this.secureRandomInstance = try {
            SecureRandom.getInstance(preferredAlgorithm)
        } catch (e: NoSuchAlgorithmException) {
            SecureRandom()
        }
    }

    /**
     * Fills a byte array with secure random entropy.
     * Captured by Spectra rule: SecureRandom (ALGO-CSPRNG)
     *
     * @param length Number of entropy bytes
     * @return Freshly filled ByteArray
     */
    fun nextEntropyBytes(length: Int): ByteArray {
        require(length > 0) { "Length must be strictly positive." }

        val buffer = ByteArray(length)
        // Spectra detection target: SecureRandom.nextBytes
        secureRandomInstance.nextBytes(buffer)

        totalBytesGenerated += length
        totalNoncesCreated++

        return buffer
    }

    /**
     * Generates a URL-safe Base64 random nonce.
     */
    fun nextUrlSafeNonce(length: Int = 32): String {
        val bytes = nextEntropyBytes(length)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * Generates a hexadecimal random token string.
     */
    fun nextHexToken(byteCount: Int = 16): String {
        val bytes = nextEntropyBytes(byteCount)
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }

    /**
     * Generates an alphanumeric verification code (e.g. for MFA challenge).
     */
    fun nextAlphanumericCode(length: Int = 6): String {
        require(length > 0) { "Code length must be positive." }
        val chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        val sb = StringBuilder(length)
        val bytes = nextEntropyBytes(length)

        for (i in 0 until length) {
            val unsignedIndex = (bytes[i].toInt() and 0xFF) % chars.length
            sb.append(chars[unsignedIndex])
        }
        return sb.toString()
    }

    /**
     * Generates a numerical OTP code.
     */
    fun nextNumericOtp(digits: Int = 6): String {
        require(digits in 4..10) { "OTP digits must be between 4 and 10." }
        val sb = StringBuilder(digits)
        val bytes = nextEntropyBytes(digits)

        for (i in 0 until digits) {
            val digit = (bytes[i].toInt() and 0xFF) % 10
            sb.append(digit)
        }
        return sb.toString()
    }

    /**
     * Reseeds the CSPRNG entropy pool with additional external seed material.
     */
    fun reseed(additionalSeed: ByteArray) {
        if (additionalSeed.isNotEmpty()) {
            secureRandomInstance.setSeed(additionalSeed)
        }
    }

    /**
     * Returns telemetry on randomness generation.
     */
    fun getTelemetry(): Map<String, Any> {
        return mapOf(
            "algorithm" to secureRandomInstance.algorithm,
            "provider" to secureRandomInstance.provider.name,
            "totalBytesGenerated" to totalBytesGenerated,
            "totalNoncesCreated" to totalNoncesCreated
        )
    }

    fun getTotalBytesGenerated(): Long = totalBytesGenerated
    fun getTotalNoncesCreated(): Long = totalNoncesCreated
}
