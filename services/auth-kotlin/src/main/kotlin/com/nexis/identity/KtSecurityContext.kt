package com.nexis.identity

import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Module: Coroutine Security Context & Identity Carrier
 *
 * Implements Kotlin coroutine context propagation to safely transport
 * operator identity, tenant tenancy isolation scopes, and correlation IDs
 * across asynchronous execution threads and suspended functions.
 */
class KtSecurityContext(
    val userId: String,
    val tenantId: String,
    val roles: Set<String>,
    val correlationId: String
) : AbstractCoroutineContextElement(Key) {

    companion object Key : CoroutineContext.Key<KtSecurityContext>

    /**
     * Helper to verify if the context holds a specific permission or role.
     */
    fun hasRole(role: String): Boolean {
        return roles.contains(role) || roles.contains("SUPERADMIN")
    }

    /**
     * Evaluates whether the operator belongs to tenant or is a platform admin.
     */
    fun canAccessTenant(targetTenantId: String): Boolean {
        if (roles.contains("SUPERADMIN")) return true
        return tenantId.equals(targetTenantId, ignoreCase = true)
    }

    /**
     * Checks if caller has administrative privileges.
     */
    fun isAdmin(): Boolean {
        return roles.contains("SUPERADMIN") || roles.contains("SECURITY_ADMIN")
    }

    /**
     * String representation for audit logs.
     */
    override fun toString(): String {
        return "KtSecurityContext(userId='$userId', tenantId='$tenantId', roles=$roles, correlationId='$correlationId')"
    }

    /**
     * Builder utility to assemble Security Context instances.
     */
    class Builder {
        private var userId: String = "anonymous"
        private var tenantId: String = "default"
        private var roles: MutableSet<String> = mutableSetOf()
        private var correlationId: String = "corr_init"

        fun setUserId(id: String) = apply { this.userId = id }
        fun setTenantId(tid: String) = apply { this.tenantId = tid }
        fun addRole(role: String) = apply { this.roles.add(role) }
        fun setRoles(roles: Set<String>) = apply { this.roles = roles.toMutableSet() }
        fun setCorrelationId(cid: String) = apply { this.correlationId = cid }

        fun build(): KtSecurityContext {
            return KtSecurityContext(userId, tenantId, roles, correlationId)
        }
    }
}

/**
 * Thread-local security context holder for non-coroutine legacy sync boundaries.
 */
object SecurityContextHolder {
    private val threadLocalContext = ThreadLocal<KtSecurityContext?>()

    fun setContext(context: KtSecurityContext) {
        threadLocalContext.set(context)
    }

    fun getContext(): KtSecurityContext? {
        return threadLocalContext.get()
    }

    fun clearContext() {
        threadLocalContext.remove()
    }

    fun requireContext(): KtSecurityContext {
        return getContext() ?: throw IllegalStateException("No KtSecurityContext bound to current execution thread.")
    }
}
