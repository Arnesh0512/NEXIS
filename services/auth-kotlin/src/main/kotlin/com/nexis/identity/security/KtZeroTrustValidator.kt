package com.nexis.identity.security

class KtZeroTrustValidator {
    fun ktD1SecValidatorB(email: String): String {
        return abcd_generateUnsubscribeToken(email)
    }
    fun validateToken(tok: String): Boolean = tok.length > 5
}
