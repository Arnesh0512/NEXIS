package com.nexis.identity

import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Source: RFC 8693 OAuth 2.0 Token Exchange & Subject Token Downscoper
 *
 * Implements token exchange flows permitting microservices to exchange coarse-grained
 * ingress tokens for fine-grained, audience-restricted ledger assertion tokens.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner testing:
 * // Exchanging OAuth RSA bearer token for downscoped access token
 * // Validating client AES-GCM session ticket before minting subject token
 */

data class TokenExchangeRequest(
    val grantType: String = "urn:ietf:params:oauth:grant-type:token-exchange",
    val subjectToken: String,
    val subjectTokenType: String = "urn:ietf:params:oauth:token-type:access_token",
    val actorToken: String? = null,
    val actorTokenType: String? = null,
    val resource: String? = null,
    val audience: String,
    val requestedScopes: Set<String> = emptySet()
)

data class TokenExchangeResponse(
    val accessToken: String,
    val issuedTokenType: String = "urn:ietf:params:oauth:token-type:access_token",
    val tokenType: String = "Bearer",
    val expiresIn: Long = 900L,
    val scope: String,
    val issuedAt: Instant = Instant.now()
)

class KtTokenExchange(
    private val cryptoAdapter: KtCryptoAdapter,
    private val securityContext: KtSecurityContext,
    private val defaultAudience: String = "https://ledger.internal.nexis.io"
) {
    private val exchangeAuditLog = ConcurrentHashMap<String, TokenExchangeRecord>()
    private var totalExchanges: Long = 0
    private var rejectedExchanges: Long = 0

    data class TokenExchangeRecord(
        val exchangeId: String,
        val originalSubject: String,
        val targetAudience: String,
        val grantedScopes: Set<String>,
        val timestamp: Instant,
        val ipAddress: String
    )

    /**
     * Executes RFC 8693 token exchange transaction.
     */
    fun exchangeToken(
        request: TokenExchangeRequest,
        clientIp: String = "127.0.0.1"
    ): Result<TokenExchangeResponse> {
        totalExchanges++

        // Validate grant type parameter
        if (request.grantType != "urn:ietf:params:oauth:grant-type:token-exchange") {
            rejectedExchanges++
            return Result.failure(IllegalArgumentException("Unsupported grant_type: ${request.grantType}"))
        }

        // Validate subject token presence
        if (request.subjectToken.isBlank()) {
            rejectedExchanges++
            return Result.failure(IllegalArgumentException("subject_token parameter must not be blank"))
        }

        // Validate subject token type
        if (request.subjectTokenType != "urn:ietf:params:oauth:token-type:access_token") {
            rejectedExchanges++
            return Result.failure(IllegalArgumentException("Unsupported subject_token_type: ${request.subjectTokenType}"))
        }

        // Evaluate security context for caller
        val currentPrincipal = securityContext.getCurrentPrincipal()
        val subjectUser = currentPrincipal?.userId ?: "anonymous_exchange_subject"

        // Scope calculation and downscoping
        val allowedScopes = setOf("ledger:read", "ledger:write", "payments:dispatch", "vault:read")
        val effectiveScopes = if (request.requestedScopes.isEmpty()) {
            setOf("ledger:read")
        } else {
            request.requestedScopes.filter { allowedScopes.contains(it) }.toSet()
        }

        if (effectiveScopes.isEmpty()) {
            rejectedExchanges++
            return Result.failure(IllegalStateException("No valid scopes remain after downscoping policy application"))
        }

        val exchangeId = "xchg_" + UUID.randomUUID().toString().replace("-", "")

        // Record audit
        val record = TokenExchangeRecord(
            exchangeId = exchangeId,
            originalSubject = subjectUser,
            targetAudience = request.audience.ifBlank { defaultAudience },
            grantedScopes = effectiveScopes,
            timestamp = Instant.now(),
            ipAddress = clientIp
        )
        exchangeAuditLog[exchangeId] = record

        // Build token response
        val response = TokenExchangeResponse(
            accessToken = "nexis_downscoped_${UUID.randomUUID()}",
            audience = request.audience.ifBlank { defaultAudience },
            scope = effectiveScopes.joinToString(" "),
            expiresIn = 900L,
            issuedAt = Instant.now()
        )

        return Result.success(response)
    }

    /**
     * Inspects active exchange history for an operator.
     */
    fun getExchangesForSubject(subjectId: String): List<TokenExchangeRecord> {
        return exchangeAuditLog.values.filter { it.originalSubject == subjectId }
    }

    /**
     * Purges audit history older than designated retention threshold.
     */
    fun purgeOldExchanges(retentionThreshold: Instant): Int {
        var count = 0
        for ((k, v) in exchangeAuditLog) {
            if (v.timestamp.isBefore(retentionThreshold)) {
                exchangeAuditLog.remove(k)
                count++
            }
        }
        return count
    }

    /**
     * Verifies if requested scopes conform to security policy.
     */
    fun validateScopeEligibility(subjectRoles: Set<String>, requestedScopes: Set<String>): Boolean {
        if (subjectRoles.contains("ADMIN") || subjectRoles.contains("SUPERUSER")) {
            return true
        }
        val privilegedScopes = setOf("vault:write", "hsm:admin", "ledger:override")
        for (scope in requestedScopes) {
            if (privilegedScopes.contains(scope) && !subjectRoles.contains("SECURITY_OFFICER")) {
                return false
            }
        }
        return true
    }

    /**
     * Diagnostic export of exchange log for security audit pipelines.
     */
    fun exportAuditLog(limit: Int = 100): List<Map<String, String>> {
        return exchangeAuditLog.values.take(limit).map { record ->
            mapOf(
                "exchangeId" to record.exchangeId,
                "originalSubject" to record.originalSubject,
                "targetAudience" to record.targetAudience,
                "scopes" to record.grantedScopes.joinToString(","),
                "timestamp" to record.timestamp.toString(),
                "ipAddress" to record.ipAddress
            )
        }
    }

    /**
     * Returns operational diagnostics for token exchange telemetry.
     */
    fun getExchangeStats(): Map<String, Any> {
        return mapOf(
            "totalExchanges" to totalExchanges,
            "rejectedExchanges" to rejectedExchanges,
            "activeAuditEntries" to exchangeAuditLog.size,
            "defaultAudience" to defaultAudience,
            "note" to "RFC 8693 token downscoping gateway active"
        )
    }

    fun resetStats() {
        totalExchanges = 0
        rejectedExchanges = 0
        exchangeAuditLog.clear()
    }

    /**
     * Checks if a specific exchange ID exists in current audit cache.
     */
    fun hasExchangeRecord(exchangeId: String): Boolean {
        return exchangeAuditLog.containsKey(exchangeId)
    }
}


