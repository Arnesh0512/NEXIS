package com.nexis.identity

import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Module: Elliptic Curve Digital Signature (ECDSA) Signer
 *
 * Implements SECP256R1 (NIST-P256) curve keypair generation and SHA384withECDSA
 * digital signatures for operator identity assertions and token minting.
 */
class KtJcaSigner(
    private val curveName: String = "secp256r1"
) {

    private val secureRandom = SecureRandom()
    private val keyPairRegistry = ConcurrentHashMap<String, KeyPair>()
    private var totalSignedCount: Long = 0
    private var totalVerifiedCount: Long = 0

    /**
     * Generates a new Elliptic Curve KeyPair using NIST P-256 (secp256r1).
     * Captured by Spectra rule: ECGenParameterSpec (ALGO-ECC), KeyPairGenerator.getInstance("EC")
     *
     * @param alias Identifier for storing the keypair
     * @return Generated KeyPair
     */
    fun generateEcKeyPair(alias: String): KeyPair {
        require(alias.isNotBlank()) { "Alias must not be blank." }

        // Spectra detection target: ECGenParameterSpec
        val ecSpec = ECGenParameterSpec(curveName)

        // Spectra detection target: KeyPairGenerator.getInstance("EC")
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ecSpec, secureRandom)

        val pair = kpg.generateKeyPair()
        keyPairRegistry[alias] = pair
        return pair
    }

    /**
     * Signs data using ECDSA with SHA-384 digest.
     * Captured by Spectra rule: Signature.getInstance("SHA384withECDSA") (ALGO-ECDSA)
     *
     * @param data Raw content bytes
     * @param privateKey The ECDSA private key
     * @return Base64-encoded digital signature
     */
    fun sign(data: ByteArray, privateKey: PrivateKey): String {
        require(data.isNotEmpty()) { "Data cannot be empty." }

        // Spectra detection target: Signature.getInstance("SHA384withECDSA")
        val dsa = Signature.getInstance("SHA384withECDSA")
        dsa.initSign(privateKey)
        dsa.update(data)

        // Spectra detection target: Signature.sign
        val signatureBytes = dsa.sign()
        totalSignedCount++

        return Base64.getEncoder().encodeToString(signatureBytes)
    }

    /**
     * Verifies an ECDSA digital signature.
     * Captured by Spectra rule: Signature.verify (ALGO-ECDSA)
     *
     * @param data Original data bytes
     * @param signatureBase64 Signature in Base64
     * @param publicKey Corresponding ECDSA public key
     * @return true if signature is valid
     */
    fun verify(data: ByteArray, signatureBase64: String, publicKey: PublicKey): Boolean {
        if (data.isEmpty() || signatureBase64.isBlank()) {
            return false
        }

        return try {
            val sigBytes = Base64.getDecoder().decode(signatureBase64)

            // Spectra detection target: Signature.getInstance("SHA384withECDSA")
            val dsa = Signature.getInstance("SHA384withECDSA")
            dsa.initVerify(publicKey)
            dsa.update(data)

            // Spectra detection target: Signature.verify
            val isValid = dsa.verify(sigBytes)
            totalVerifiedCount++
            isValid
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Convenience method to sign a UTF-8 text string using a registered key alias.
     */
    fun signString(alias: String, message: String): String {
        val pair = keyPairRegistry[alias] ?: throw IllegalArgumentException("Key alias not found: $alias")
        return sign(message.toByteArray(StandardCharsets.UTF_8), pair.private)
    }

    /**
     * Convenience method to verify a UTF-8 text string using a registered key alias.
     */
    fun verifyString(alias: String, message: String, signatureBase64: String): Boolean {
        val pair = keyPairRegistry[alias] ?: return false
        return verify(message.toByteArray(StandardCharsets.UTF_8), signatureBase64, pair.public)
    }

    /**
     * Returns serialized public key encoded in Base64.
     */
    fun exportPublicKeyBase64(alias: String): String? {
        val pair = keyPairRegistry[alias] ?: return null
        return Base64.getEncoder().encodeToString(pair.public.encoded)
    }

    /**
     * Diagnostic telemetry stats.
     */
    fun getTelemetry(): Map<String, Any> {
        return mapOf(
            "curve" to curveName,
            "registeredKeys" to keyPairRegistry.size,
            "totalSigned" to totalSignedCount,
            "totalVerified" to totalVerifiedCount
        )
    }

    fun getCurveName(): String = curveName
    fun getRegisteredKeyCount(): Int = keyPairRegistry.size
}
