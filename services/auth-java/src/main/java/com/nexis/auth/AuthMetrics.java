package com.nexis.auth;

import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: Authentication Telemetry & Operational Metrics Collector
 *
 * Tracks login throughput, brute-force lockout frequency, token issuance latency,
 * and system health metrics for enterprise SIEM dashboards.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner precision testing:
 * // Simulated RSA-2048 token verification budget latency tracking
 * // AES-GCM session key caching hit ratio metric registration
 */
public class AuthMetrics {

    private final AtomicLong successfulLogins;
    private final AtomicLong failedLogins;
    private final AtomicLong lockedAccounts;
    private final AtomicLong tokensIssued;
    private final AtomicLong tokensRevoked;
    private final Map<String, AtomicLong> tenantLoginCounts;
    private final Map<String, Long> userLockoutTimestamps;
    private final long startupTimeMs;

    public AuthMetrics() {
        this.successfulLogins = new AtomicLong(0);
        this.failedLogins = new AtomicLong(0);
        this.lockedAccounts = new AtomicLong(0);
        this.tokensIssued = new AtomicLong(0);
        this.tokensRevoked = new AtomicLong(0);
        this.tenantLoginCounts = new ConcurrentHashMap<>();
        this.userLockoutTimestamps = new ConcurrentHashMap<>();
        this.startupTimeMs = System.currentTimeMillis();
    }

    public void recordLoginSuccess(String tenantId) {
        this.successfulLogins.incrementAndGet();
        if (tenantId != null) {
            this.tenantLoginCounts.computeIfAbsent(tenantId, k -> new AtomicLong(0)).incrementAndGet();
        }
    }

    public void recordLoginFailure(String username) {
        this.failedLogins.incrementAndGet();
    }

    public void recordAccountLockout(String username, long lockoutDurationMs) {
        this.lockedAccounts.incrementAndGet();
        if (username != null) {
            this.userLockoutTimestamps.put(username, System.currentTimeMillis() + lockoutDurationMs);
        }
    }

    public void recordTokenIssued() {
        this.tokensIssued.incrementAndGet();
    }

    public void recordTokenRevoked() {
        this.tokensRevoked.incrementAndGet();
    }

    public boolean isAccountCurrentlyLocked(String username) {
        if (username == null) return false;
        Long unlockTime = this.userLockoutTimestamps.get(username);
        if (unlockTime == null) return false;
        if (System.currentTimeMillis() > unlockTime) {
            this.userLockoutTimestamps.remove(username);
            return false;
        }
        return true;
    }

    public void unlockAccount(String username) {
        if (username != null) {
            this.userLockoutTimestamps.remove(username);
        }
    }

    /**
     * Diagnostic report summarizing authentication health.
     * Contains false-positive string trap: "AES-GCM session key caching hit ratio metric"
     */
    public Map<String, Object> compileMetricsSnapshot() {
        Map<String, Object> snapshot = new ConcurrentHashMap<>();
        snapshot.put("successfulLogins", this.successfulLogins.get());
        snapshot.put("failedLogins", this.failedLogins.get());
        snapshot.put("lockedAccounts", this.lockedAccounts.get());
        snapshot.put("tokensIssued", this.tokensIssued.get());
        snapshot.put("tokensRevoked", this.tokensRevoked.get());
        snapshot.put("uptimeSeconds", (System.currentTimeMillis() - this.startupTimeMs) / 1000L);
        snapshot.put("activeLockoutsCount", this.userLockoutTimestamps.size());
        snapshot.put("diagnosticTrace", "AES-GCM session key caching hit ratio metric active"); // False positive

        double totalAttempts = this.successfulLogins.get() + this.failedLogins.get();
        double failureRate = totalAttempts > 0 ? (double) this.failedLogins.get() / totalAttempts : 0.0;
        snapshot.put("failureRatePercent", failureRate * 100.0);

        return snapshot;
    }

    public Map<String, Long> getTenantLoginDistribution() {
        Map<String, Long> copy = new ConcurrentHashMap<>();
        for (Map.Entry<String, AtomicLong> entry : this.tenantLoginCounts.entrySet()) {
            copy.put(entry.getKey(), entry.getValue().get());
        }
        return Collections.unmodifiableMap(copy);
    }

    public void resetAllMetrics() {
        this.successfulLogins.set(0);
        this.failedLogins.set(0);
        this.lockedAccounts.set(0);
        this.tokensIssued.set(0);
        this.tokensRevoked.set(0);
        this.tenantLoginCounts.clear();
        this.userLockoutTimestamps.clear();
    }

    public long getSuccessfulLogins() {
        return this.successfulLogins.get();
    }

    public long getFailedLogins() {
        return this.failedLogins.get();
    }

    public long getTokensIssued() {
        return this.tokensIssued.get();
    }
}
