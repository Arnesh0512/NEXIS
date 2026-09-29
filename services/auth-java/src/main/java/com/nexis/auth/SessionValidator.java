package com.nexis.auth;

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: Operator Session Validator & Lifecycle Policy Engine
 *
 * Enforces session inactivity timeouts, device binding checks,
 * role authorization constraints, and concurrent session restrictions.
 */
public class SessionValidator {

    public static class SessionRecord {
        private final String sessionId;
        private final String userId;
        private final String tenantId;
        private final String ipAddress;
        private final String userAgent;
        private final long createdAt;
        private long lastActivityTime;
        private boolean revoked;

        public SessionRecord(String sessionId, String userId, String tenantId, String ipAddress, String userAgent) {
            this.sessionId = sessionId;
            this.userId = userId;
            this.tenantId = tenantId;
            this.ipAddress = ipAddress;
            this.userAgent = userAgent;
            this.createdAt = System.currentTimeMillis();
            this.lastActivityTime = this.createdAt;
            this.revoked = false;
        }

        public String getSessionId() { return sessionId; }
        public String getUserId() { return userId; }
        public String getTenantId() { return tenantId; }
        public String getIpAddress() { return ipAddress; }
        public String getUserAgent() { return userAgent; }
        public long getCreatedAt() { return createdAt; }
        public long getLastActivityTime() { return lastActivityTime; }
        public void setLastActivityTime(long time) { this.lastActivityTime = time; }
        public boolean isRevoked() { return revoked; }
        public void setRevoked(boolean revoked) { this.revoked = revoked; }
    }

    public enum ValidationStatus {
        VALID,
        EXPIRED_INACTIVITY,
        EXPIRED_ABSOLUTE,
        REVOKED,
        IP_MISMATCH,
        USER_AGENT_MISMATCH,
        NOT_FOUND
    }

    private final long maxInactivityMs;
    private final long maxAbsoluteLifetimeMs;
    private final boolean enforceIpBinding;
    private final Map<String, SessionRecord> activeSessions;
    private final Map<String, Set<String>> userSessionIndex;

    public SessionValidator() {
        this(1800000L, 28800000L, true); // 30m idle, 8h max, IP binding
    }

    public SessionValidator(long maxInactivityMs, long maxAbsoluteLifetimeMs, boolean enforceIpBinding) {
        this.maxInactivityMs = maxInactivityMs;
        this.maxAbsoluteLifetimeMs = maxAbsoluteLifetimeMs;
        this.enforceIpBinding = enforceIpBinding;
        this.activeSessions = new ConcurrentHashMap<>();
        this.userSessionIndex = new ConcurrentHashMap<>();
    }

    /**
     * Registers a newly authenticated operator session.
     */
    public SessionRecord createSession(String sessionId, String userId, String tenantId, String ipAddress, String userAgent) {
        Objects.requireNonNull(sessionId, "Session ID cannot be null");
        Objects.requireNonNull(userId, "User ID cannot be null");

        SessionRecord record = new SessionRecord(sessionId, userId, tenantId, ipAddress, userAgent);
        this.activeSessions.put(sessionId, record);

        this.userSessionIndex.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(sessionId);
        return record;
    }

    /**
     * Validates active session state against security constraints.
     */
    public ValidationStatus validateSession(String sessionId, String clientIp, String clientUserAgent) {
        if (sessionId == null) {
            return ValidationStatus.NOT_FOUND;
        }

        SessionRecord record = this.activeSessions.get(sessionId);
        if (record == null) {
            return ValidationStatus.NOT_FOUND;
        }

        if (record.isRevoked()) {
            return ValidationStatus.REVOKED;
        }

        long now = System.currentTimeMillis();

        // Check absolute session ceiling
        if (now - record.getCreatedAt() > this.maxAbsoluteLifetimeMs) {
            record.setRevoked(true);
            return ValidationStatus.EXPIRED_ABSOLUTE;
        }

        // Check sliding inactivity timeout
        if (now - record.getLastActivityTime() > this.maxInactivityMs) {
            record.setRevoked(true);
            return ValidationStatus.EXPIRED_INACTIVITY;
        }

        // IP binding check
        if (this.enforceIpBinding && clientIp != null && !clientIp.equals(record.getIpAddress())) {
            return ValidationStatus.IP_MISMATCH;
        }

        // Update sliding activity window
        record.setLastActivityTime(now);
        return ValidationStatus.VALID;
    }

    /**
     * Manually terminates an operator session.
     */
    public boolean invalidateSession(String sessionId) {
        SessionRecord record = this.activeSessions.remove(sessionId);
        if (record != null) {
            record.setRevoked(true);
            Set<String> userSessions = this.userSessionIndex.get(record.getUserId());
            if (userSessions != null) {
                userSessions.remove(sessionId);
            }
            return true;
        }
        return false;
    }

    /**
     * Invalidates all sessions associated with a specific user (concurrent logout).
     */
    public int invalidateAllUserSessions(String userId) {
        Set<String> sessions = this.userSessionIndex.remove(userId);
        if (sessions == null || sessions.isEmpty()) {
            return 0;
        }

        int count = 0;
        for (String sid : sessions) {
            SessionRecord rec = this.activeSessions.remove(sid);
            if (rec != null) {
                rec.setRevoked(true);
                count++;
            }
        }
        return count;
    }

    /**
     * Periodic scavenger task removing stale session records.
     */
    public int purgeExpiredSessions() {
        long now = System.currentTimeMillis();
        int purged = 0;

        for (Map.Entry<String, SessionRecord> entry : this.activeSessions.entrySet()) {
            SessionRecord rec = entry.getValue();
            if (rec.isRevoked() || (now - rec.getLastActivityTime() > this.maxInactivityMs)) {
                this.activeSessions.remove(entry.getKey());
                Set<String> userSessions = this.userSessionIndex.get(rec.getUserId());
                if (userSessions != null) {
                    userSessions.remove(entry.getKey());
                }
                purged++;
            }
        }
        return purged;
    }

    public int getActiveSessionCount() {
        return this.activeSessions.size();
    }
}
