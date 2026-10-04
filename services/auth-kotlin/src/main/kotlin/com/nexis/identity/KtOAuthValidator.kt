package com.nexis.identity

import java.net.URI
import java.util.concurrent.ConcurrentHashMap

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Module: OAuth 2.0 / OpenID Connect Protocol Validator
 *
 * Implements RFC 6749 OAuth 2.0 authorization framework validation:
 * validates response types, client credentials, PKCE code challenges,
 * redirect URI whitelist matching, and authorization code exchanges.
 */
class KtOAuthValidator(
    private val allowedClients: Map<String, ClientRegistration> = defaultClients()
) {

    data class ClientRegistration(
        val clientId: String,
        val clientSecret: String,
        val allowedRedirectUris: Set<String>,
        val allowedScopes: Set<String>,
        val isConfidential: Boolean
    )

    data class AuthorizationRequest(
        val responseType: String,
        val clientId: String,
        val redirectUri: String,
        val scope: String,
        val state: String,
        val codeChallenge: String?,
        val codeChallengeMethod: String?
    )

    data class ValidationResult(
        val isValid: Boolean,
        val error: String? = null,
        val errorDescription: String? = null
    )

    private val authCodeStore = ConcurrentHashMap<String, AuthorizationRequest>()
    private var totalValidatedRequests: Long = 0
    private var totalValidationFailures: Long = 0

    companion object {
        fun defaultClients(): Map<String, ClientRegistration> = mapOf(
            "nexis-web-client" to ClientRegistration(
                clientId = "nexis-web-client",
                clientSecret = "secret-web-client-2026",
                allowedRedirectUris = setOf("https://app.nexis.io/callback", "http://localhost:3030/callback"),
                allowedScopes = setOf("openid", "profile", "ledger:read", "ledger:write"),
                isConfidential = true
            ),
            "nexis-mobile-app" to ClientRegistration(
                clientId = "nexis-mobile-app",
                clientSecret = "",
                allowedRedirectUris = setOf("io.nexis.app://oauth/callback"),
                allowedScopes = setOf("openid", "profile", "ledger:read"),
                isConfidential = false
            )
        )
    }

    /**
     * Validates incoming OAuth 2.0 authorization request parameters.
     */
    fun validateAuthorizeRequest(request: AuthorizationRequest): ValidationResult {
        totalValidatedRequests++

        // 1. Verify Client Registration
        val client = allowedClients[request.clientId]
        if (client == null) {
            totalValidationFailures++
            return ValidationResult(false, "unauthorized_client", "Unknown client_id: ${request.clientId}")
        }

        // 2. Verify Response Type (currently only 'code' supported)
        if (request.responseType != "code") {
            totalValidationFailures++
            return ValidationResult(false, "unsupported_response_type", "Only response_type=code is supported")
        }

        // 3. Verify Redirect URI exact match
        if (!client.allowedRedirectUris.contains(request.redirectUri)) {
            totalValidationFailures++
            return ValidationResult(false, "invalid_request", "Redirect URI not registered for this client")
        }

        // 4. Verify Scope parameters
        val requestedScopes = request.scope.split(" ").filter { it.isNotBlank() }
        for (sc in requestedScopes) {
            if (!client.allowedScopes.contains(sc)) {
                totalValidationFailures++
                return ValidationResult(false, "invalid_scope", "Requested scope is unauthorized: $sc")
            }
        }

        // 5. PKCE enforcement for public clients
        if (!client.isConfidential && request.codeChallenge.isNullOrBlank()) {
            totalValidationFailures++
            return ValidationResult(false, "invalid_request", "PKCE code_challenge required for public clients")
        }

        return ValidationResult(true)
    }

    /**
     * Stores issued authorization code with original request parameters for token phase exchange.
     */
    fun storeAuthorizationCode(code: String, request: AuthorizationRequest) {
        authCodeStore[code] = request
    }

    /**
     * Consumes and verifies authorization code during token exchange.
     */
    fun consumeAuthorizationCode(code: String, clientId: String, redirectUri: String): AuthorizationRequest? {
        val original = authCodeStore.remove(code) ?: return null

        if (original.clientId != clientId || original.redirectUri != redirectUri) {
            return null
        }

        return original
    }

    /**
     * Validates a redirect URI against strict syntax rules.
     */
    fun isValidUriSyntax(uriStr: String): Boolean {
        return try {
            val uri = URI(uriStr)
            uri.isAbsolute && (uri.scheme == "https" || uri.scheme == "http" || uri.scheme.contains("."))
        } catch (e: Exception) {
            false
        }
    }

    fun getTotalValidated(): Long = totalValidatedRequests
    fun getTotalFailures(): Long = totalValidationFailures
    fun getPendingCodeCount(): Int = authCodeStore.size
}
