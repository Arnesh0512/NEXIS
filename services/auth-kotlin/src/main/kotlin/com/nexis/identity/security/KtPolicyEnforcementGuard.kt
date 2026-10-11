package com.nexis.identity.security
class KtPolicyEnforcementGuard { fun enforce(role: String): Boolean = role == "ADMIN" }
