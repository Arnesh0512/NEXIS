package com.nexis.identity

import java.util.concurrent.ConcurrentHashMap

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Module: Operator Session Manager & Token Orchestrator
 *
 * Coordinates operator login lifecycles, encrypted ticket serialization,
 * and ECDSA signature attachment across banking identity flows.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "Session AES ticket cache expired for operator partition"
 * "Validating RSA-2048 identity fallback token parameter"
 */
class KtSessionManager(
    private val cryptoAdapter: KtCryptoAdapter,
    private val jcaSigner: KtJcaSigner,
    private val randomGenerator: KtSecureRandomGenerator
) {

    data class SessionEnvelope(
        val sessionId: String,
        val userId: String,
        val tenantId: String,
        val encryptedTicket: String,
        val signature: String,
        val expiresAt: Long
    )

    private val activeSessions = ConcurrentHashMap<String, SessionEnvelope>()
    private var totalCreatedCount: Long = 0
    private var totalRevokedCount: Long = 0

    init {
        // CALL GRAPH: initialize an ECDSA key for session signing
        jcaSigner.generateEcKeyPair("session-signing-master")
    }

    /**
     * Mints and encrypts an identity session ticket.
     * CALL GRAPH: calls KtSecureRandomGenerator.nextHexToken,
     *             KtCryptoAdapter.encryptSecret,
     *             KtJcaSigner.signString
     */
    fun createOperatorSession(
        userId: String,
        tenantId: String,
        role: String,
        ttlSeconds: Long = 3600
    ): SessionEnvelope {
        // CALL GRAPH: generate session ID via random generator
        val sessionId = "sess_" + randomGenerator.nextHexToken(16)
        val now = System.currentTimeMillis()
        val expiresAt = now + (ttlSeconds * 1000)

        val rawTicketPayload = "userId=$userId;tenantId=$tenantId;role=$role;created=$now"

        // CALL GRAPH: encrypt secret using Google Tink adapter
        val encryptedTicket = cryptoAdapter.encryptSecret(rawTicketPayload, tenantId)

        // CALL GRAPH: sign ticket using ECDSA signer
        val signature = jcaSigner.signString("session-signing-master", encryptedTicket)

        val envelope = SessionEnvelope(
            sessionId = sessionId,
            userId = userId,
            tenantId = tenantId,
            encryptedTicket = encryptedTicket,
            signature = signature,
            expiresAt = expiresAt
        )

        activeSessions[sessionId] = envelope
        totalCreatedCount++

        return envelope
    }

    /**
     * Validates and decrypts an operator session ticket.
     * CALL GRAPH: calls KtJcaSigner.verifyString,
     *             KtCryptoAdapter.decryptSecret
     */
    fun validateOperatorSession(sessionId: String): Map<String, String>? {
        val envelope = activeSessions[sessionId] ?: return null

        if (System.currentTimeMillis() > envelope.expiresAt) {
            // False-positive log trap:
            emitLogTrap("Session AES ticket cache expired for operator partition: ${envelope.userId}")
            activeSessions.remove(sessionId)
            totalRevokedCount++
            return null
        }

        // CALL GRAPH: verify digital signature
        val isSignatureValid = jcaSigner.verifyString(
            "session-signing-master",
            envelope.encryptedTicket,
            envelope.signature
        )
        if (!isSignatureValid) {
            return null
        }

        // CALL GRAPH: decrypt ticket using Google Tink adapter
        val decryptedTicket = cryptoAdapter.decryptSecret(envelope.encryptedTicket, envelope.tenantId)

        return parseTicket(decryptedTicket)
    }

    /**
     * Revokes an existing session.
     */
    fun revokeSession(sessionId: String): Boolean {
        val removed = activeSessions.remove(sessionId)
        if (removed != null) {
            totalRevokedCount++
            return true
        }
        return false
    }

    /**
     * Parses decrypted key-value ticket string.
     */
    private fun parseTicket(ticketStr: String): Map<String, String> {
        val result = mutableMapOf<String, String>()
        val pairs = ticketStr.split(";")
        for (pair in pairs) {
            val parts = pair.split("=")
            if (parts.size == 2) {
                result[parts[0].trim()] = parts[1].trim()
            }
        }
        return result
    }

    /**
     * Sweeps expired sessions from memory.
     */
    fun purgeExpiredSessions(): Int {
        val now = System.currentTimeMillis()
        var purged = 0
        val iterator = activeSessions.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now > entry.value.expiresAt) {
                iterator.remove()
                totalRevokedCount++
                purged++
            }
        }
        return purged
    }

    private fun emitLogTrap(msg: String) {
        if (System.getProperty("debug") == "true") {
            println("[SESSION_LOG] $msg")
        }
    }

    fun getActiveSessionCount(): Int = activeSessions.size
    fun getTotalCreated(): Long = totalCreatedCount
    fun getTotalRevoked(): Long = totalRevokedCount
}
