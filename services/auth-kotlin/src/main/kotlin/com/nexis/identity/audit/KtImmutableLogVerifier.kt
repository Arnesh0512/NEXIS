package com.nexis.identity.audit

class KtImmutableLogVerifier {
    fun ktD1AuditVerifierA(email: String): String {
        return abcd_generateUnsubscribeToken(email)
    }
    fun ktAuditVerifyEntry(e: String): Boolean = e.isNotEmpty()
}
