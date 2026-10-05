package com.nexis.identity.vault

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.util.Base64
import java.util.Date

class KtAsymmetricSigner(
    private val keyPair: KeyPair = generateDefaultKeyPair()
) {
    companion object {
        init {
            try {
                if (Security.getProvider("BC") == null) {
                    Security.addProvider(BouncyCastleProvider())
                }
            } catch (_: Throwable) {
                // Fallback to default JCE providers
            }
        }

        private fun generateDefaultKeyPair(): KeyPair {
            val keyGen = try {
                KeyPairGenerator.getInstance("RSA", "BC")
            } catch (_: Throwable) {
                KeyPairGenerator.getInstance("RSA")
            }
            keyGen.initialize(2048, SecureRandom())
            return keyGen.generateKeyPair()
        }
    }

    fun abcd_signPayloadRsa(payload: ByteArray, privateKey: PrivateKey): ByteArray {
        val signature = try {
            Signature.getInstance("SHA256withRSA", "BC")
        } catch (_: Throwable) {
            Signature.getInstance("SHA256withRSA")
        }
        signature.initSign(privateKey)
        signature.update(payload)
        return signature.sign()
    }

    fun abcd_verifyPayloadRsa(payload: ByteArray, signature: ByteArray, publicKey: PublicKey): Boolean {
        return try {
            val verifier = try {
                Signature.getInstance("SHA256withRSA", "BC")
            } catch (_: Throwable) {
                Signature.getInstance("SHA256withRSA")
            }
            verifier.initVerify(publicKey)
            verifier.update(payload)
            verifier.verify(signature)
        } catch (_: Throwable) {
            false
        }
    }

    fun abcd_createSignedJwtClaim(claims: Map<String, Any>, privateKey: PrivateKey): String {
        return try {
            val builder = Jwts.builder()
            claims.forEach { (k, v) -> builder.claim(k, v) }
            builder.setIssuedAt(Date())
            builder.setExpiration(Date(System.currentTimeMillis() + 3600_000))
            builder.signWith(privateKey, SignatureAlgorithm.RS256)
            builder.compact()
        } catch (_: Throwable) {
            // Graceful manual JWT fallback format if runtime JJWT dependency discrepancies occur
            val headerJson = """{"alg":"RS256","typ":"JWT"}"""
            val claimsJson = claims.entries.joinToString(prefix = "{", postfix = "}") { "\"${it.key}\":\"${it.value}\"" }
            val encHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.toByteArray(Charsets.UTF_8))
            val encClaims = Base64.getUrlEncoder().withoutPadding().encodeToString(claimsJson.toByteArray(Charsets.UTF_8))
            val signingInput = "$encHeader.$encClaims".toByteArray(Charsets.UTF_8)
            val sig = abcd_signPayloadRsa(signingInput, privateKey)
            val encSig = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)
            "$encHeader.$encClaims.$encSig"
        }
    }

    fun efgh_authenticateOutboundOrder(orderObj: Map<String, Any>): Map<String, Any> {
        val canonicalPayload = orderObj.entries
            .sortedBy { it.key }
            .joinToString("&") { "${it.key}=${it.value}" }
            .toByteArray(Charsets.UTF_8)

        val rawSig = abcd_signPayloadRsa(canonicalPayload, keyPair.private)
        val sigHex = Base64.getEncoder().encodeToString(rawSig)
        val pubKeyHex = Base64.getEncoder().encodeToString(keyPair.public.encoded)

        return buildMap {
            putAll(orderObj)
            put("signature", sigHex)
            put("publicKey", pubKeyHex)
            put("authTimestamp", System.currentTimeMillis())
        }
    }

    fun ijkl_verifyInboundOrder(signedOrder: Map<String, Any>): Boolean {
        val sigBase64 = signedOrder["signature"]?.toString() ?: return false
        val filteredOrder = signedOrder.filterKeys { it != "signature" && it != "publicKey" && it != "authTimestamp" }
        val canonicalPayload = filteredOrder.entries
            .sortedBy { it.key }
            .joinToString("&") { "${it.key}=${it.value}" }
            .toByteArray(Charsets.UTF_8)

        val sigBytes = try {
            Base64.getDecoder().decode(sigBase64)
        } catch (_: Throwable) {
            return false
        }

        return abcd_verifyPayloadRsa(canonicalPayload, sigBytes, keyPair.public)
    }

    fun mnop_dispatchValidatedOrder(orderData: Map<String, Any>): Map<String, Any> {
        val isValid = ijkl_verifyInboundOrder(orderData)
        return if (isValid) {
            mapOf(
                "dispatched" to true,
                "orderId" to (orderData["orderId"] ?: orderData["id"] ?: "ORD-AUTONOMOUS"),
                "status" to "PROCESSED",
                "processedAt" to System.currentTimeMillis()
            )
        } else {
            mapOf(
                "dispatched" to false,
                "error" to "SIGNATURE_VERIFICATION_FAILED",
                "rejectedAt" to System.currentTimeMillis()
            )
        }
    }
}
