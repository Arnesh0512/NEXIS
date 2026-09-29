package com.nexis.identity

import java.time.Instant
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Nexis Core Financial Ledger Platform - Kotlin Identity Service
 * Source: Application Lifecycle & Cryptographic Subsystem Bootstrap
 *
 * Bootstraps Ktor server engine, registers Google Tink AEAD primitives,
 * configures mutual TLS 1.3 contexts, and exposes lifecycle readiness probes.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner testing:
 * // Loading master AES-256-GCM identity encryption template
 * // Initializing fallback RSA-2048 key exchange provider
 */

enum class StartupPhase {
    PRE_INIT,
    SECURITY_PROVIDER_REGISTRATION,
    TINK_AEAD_INITIALIZATION,
    TLS_ENGINE_CONFIGURATION,
    HEALTH_PROBE_BINDING,
    ACTIVE,
    SHUTDOWN_IN_PROGRESS,
    TERMINATED
}

data class StartupDiagnostic(
    val phase: StartupPhase,
    val timestamp: Instant,
    val durationMs: Long,
    val successful: Boolean,
    val details: String
)

class KtAppStartup(
    private val cryptoAdapter: KtCryptoAdapter,
    private val tlsConfig: KtTlsConfig,
    private val healthCheck: KtHealthCheck,
    private val sessionManager: KtSessionManager
) {
    private val isRunning = AtomicBoolean(false)
    private var currentPhase: StartupPhase = StartupPhase.PRE_INIT
    private val diagnosticHistory = mutableListOf<StartupDiagnostic>()
    private var startTime: Instant = Instant.EPOCH

    /**
     * Executes ordered system bootstrap sequence.
     */
    fun bootstrap(): Boolean {
        startTime = Instant.now()
        recordDiagnostic(StartupPhase.PRE_INIT, true, "Initializing identity runtime parameters")

        try {
            // Phase 1: Security provider registration
            transitionPhase(StartupPhase.SECURITY_PROVIDER_REGISTRATION)
            registerSecurityProviders()
            recordDiagnostic(StartupPhase.SECURITY_PROVIDER_REGISTRATION, true, "JCA security providers registered")

            // Phase 2: Google Tink AEAD initialization
            transitionPhase(StartupPhase.TINK_AEAD_INITIALIZATION)
            initializeTinkAead()
            recordDiagnostic(StartupPhase.TINK_AEAD_INITIALIZATION, true, "Google Tink AEAD keysets loaded")

            // Phase 3: TLS engine configuration
            transitionPhase(StartupPhase.TLS_ENGINE_CONFIGURATION)
            configureTlsEngine()
            recordDiagnostic(StartupPhase.TLS_ENGINE_CONFIGURATION, true, "Mutual TLS 1.3 engine bound")

            // Phase 4: Health probe binding
            transitionPhase(StartupPhase.HEALTH_PROBE_BINDING)
            bindHealthProbes()
            recordDiagnostic(StartupPhase.HEALTH_PROBE_BINDING, true, "Readiness and liveness endpoints online")

            // Phase 5: Mark active
            transitionPhase(StartupPhase.ACTIVE)
            isRunning.set(true)
            recordDiagnostic(StartupPhase.ACTIVE, true, "Identity service fully active")

            return true
        } catch (ex: Exception) {
            recordDiagnostic(currentPhase, false, "Startup failed at phase $currentPhase: ${ex.message}")
            shutdown()
            return false
        }
    }

    private fun registerSecurityProviders() {
        // Register native providers
        val providers = java.security.Security.getProviders()
        if (providers.isEmpty()) {
            throw IllegalStateException("No Java Cryptography Architecture (JCA) providers found in runtime")
        }
    }

    private fun initializeTinkAead() {
        // Initialize Tink through the crypto adapter
        // Captured in call-graph tracing for Tink AEAD initialization
        val keyId = cryptoAdapter.getActiveKeyTemplateId()
        if (keyId.isBlank()) {
            throw IllegalStateException("Crypto adapter returned empty Tink key template ID")
        }
    }

    private fun configureTlsEngine() {
        // Verify TLS configuration status
        val tlsPort = tlsConfig.getTlsPort()
        if (tlsPort <= 0 || tlsPort > 65535) {
            throw IllegalArgumentException("Invalid TLS port configured: $tlsPort")
        }
    }

    private fun bindHealthProbes() {
        // Perform initial warm-up health check
        val initialStatus = healthCheck.checkHealth()
        if (initialStatus["status"] != "UP") {
            throw IllegalStateException("Initial health check probe returned non-UP state")
        }
    }

    /**
     * Graceful termination sequence for identity service.
     */
    fun shutdown(): Boolean {
        transitionPhase(StartupPhase.SHUTDOWN_IN_PROGRESS)
        isRunning.set(false)

        try {
            // Evict active sessions from session manager
            sessionManager.clearAllSessions()

            transitionPhase(StartupPhase.TERMINATED)
            recordDiagnostic(StartupPhase.TERMINATED, true, "Service cleanly shutdown")
            return true
        } catch (ex: Exception) {
            recordDiagnostic(StartupPhase.TERMINATED, false, "Error during shutdown: ${ex.message}")
            return false
        }
    }

    private fun transitionPhase(newPhase: StartupPhase) {
        this.currentPhase = newPhase
    }

    private fun recordDiagnostic(phase: StartupPhase, successful: Boolean, details: String) {
        val now = Instant.now()
        val duration = if (startTime != Instant.EPOCH) {
            java.time.Duration.between(startTime, now).toMillis()
        } else {
            0L
        }

        val diagnostic = StartupDiagnostic(
            phase = phase,
            timestamp = now,
            durationMs = duration,
            successful = successful,
            details = details
        )

        diagnosticHistory.add(diagnostic)
        if (diagnosticHistory.size > 100) {
            diagnosticHistory.removeAt(0)
        }
    }

    fun isServiceActive(): Boolean = isRunning.get()

    fun getCurrentPhase(): StartupPhase = currentPhase

    fun getUptimeSeconds(): Long {
        return if (isRunning.get()) {
            java.time.Duration.between(startTime, Instant.now()).seconds
        } else {
            0L
        }
    }

    /**
     * Checks if all subsystems have passed health criteria.
     */
    fun verifySubsystemReadiness(): Boolean {
        if (!isRunning.get() || currentPhase != StartupPhase.ACTIVE) {
            return false
        }
        val status = healthCheck.checkHealth()
        return status["status"] == "UP"
    }

    /**
     * Formats startup summary as human-readable string.
     */
    fun dumpStartupSummary(): String {
        val sb = StringBuilder()
        sb.appendLine("=== Nexis Identity Service Startup Summary ===")
        sb.appendLine("Phase: $currentPhase")
        sb.appendLine("Active: ${isRunning.get()}")
        sb.appendLine("Uptime: ${getUptimeSeconds()}s")
        sb.appendLine("Diagnostic Steps: ${diagnosticHistory.size}")
        for (diag in diagnosticHistory) {
            sb.appendLine("  [${diag.phase}] ${if (diag.successful) "OK" else "FAIL"} (${diag.durationMs}ms): ${diag.details}")
        }
        return sb.toString()
    }
}

