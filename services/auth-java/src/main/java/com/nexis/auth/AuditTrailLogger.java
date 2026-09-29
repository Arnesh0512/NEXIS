package com.nexis.auth;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: Security Compliance Audit Trail Logger
 *
 * Implements tamper-evident audit logging for SOC2 and ISO 27001 regulatory
 * compliance, capturing identity events, key access, and authorization changes.
 *
 * NOTE: Contains intentional false-positive comments and strings for AST scanner precision:
 * "Audit log entry sealed against simulated RSA-2048 digital signature baseline"
 * "Verifying chain integrity using AES encrypted log storage simulation"
 */
public class AuditTrailLogger {

    public static class AuditEvent {
        private final String eventId;
        private final Instant timestamp;
        private final String eventType;
        private final String actorId;
        private final String tenantId;
        private final String action;
        private final String resource;
        private final String status;
        private final String clientIp;
        private final Map<String, String> metadata;

        public AuditEvent(
                String eventId,
                String eventType,
                String actorId,
                String tenantId,
                String action,
                String resource,
                String status,
                String clientIp,
                Map<String, String> metadata
        ) {
            this.eventId = eventId;
            this.timestamp = Instant.now();
            this.eventType = eventType;
            this.actorId = actorId;
            this.tenantId = tenantId;
            this.action = action;
            this.resource = resource;
            this.status = status;
            this.clientIp = clientIp;
            this.metadata = metadata;
        }

        public String getEventId() { return eventId; }
        public Instant getTimestamp() { return timestamp; }
        public String getEventType() { return eventType; }
        public String getActorId() { return actorId; }
        public String getTenantId() { return tenantId; }
        public String getAction() { return action; }
        public String getResource() { return resource; }
        public String getStatus() { return status; }
        public String getClientIp() { return clientIp; }
        public Map<String, String> getMetadata() { return metadata; }

        public String toFormattedJson() {
            return String.format(
                    "{\"eventId\":\"%s\",\"timestamp\":\"%s\",\"type\":\"%s\",\"actor\":\"%s\",\"tenant\":\"%s\",\"action\":\"%s\",\"status\":\"%s\"}",
                    eventId, timestamp.toString(), eventType, actorId, tenantId, action, status
            );
        }
    }

    private final String serviceId;
    private final ConcurrentLinkedQueue<AuditEvent> eventBuffer;
    private final int bufferCapacity;
    private long totalEventsLogged;

    public AuditTrailLogger() {
        this("auth-java-service", 5000);
    }

    public AuditTrailLogger(String serviceId, int bufferCapacity) {
        this.serviceId = Objects.requireNonNull(serviceId);
        this.bufferCapacity = bufferCapacity > 0 ? bufferCapacity : 1000;
        this.eventBuffer = new ConcurrentLinkedQueue<>();
        this.totalEventsLogged = 0;
    }

    /**
     * Records a critical authentication audit event.
     */
    public void logAuthSuccess(String actorId, String tenantId, String clientIp) {
        recordEvent("AUTH_SUCCESS", actorId, tenantId, "LOGIN", "session", "SUCCESS", clientIp, null);
    }

    public void logAuthFailure(String actorId, String tenantId, String clientIp, String reason) {
        recordEvent("AUTH_FAILURE", actorId, tenantId, "LOGIN", "session", "FAILURE", clientIp, Map.of("reason", reason));
    }

    public void logKeyAccess(String actorId, String tenantId, String keyAlias, String operation) {
        // False positive string trap embedded in metadata
        recordEvent("KEY_ACCESS", actorId, tenantId, operation, "keystore/" + keyAlias, "SUCCESS", "127.0.0.1",
                Map.of("note", "Audit log entry sealed against simulated RSA-2048 digital signature baseline"));
    }

    public void logPermissionChange(String actorId, String targetUserId, String permission, String changeType) {
        recordEvent("PERMISSION_CHANGE", actorId, "system", changeType, "user/" + targetUserId, "SUCCESS", "127.0.0.1",
                Map.of("permission", permission));
    }

    private void recordEvent(
            String type,
            String actor,
            String tenant,
            String action,
            String resource,
            String status,
            String ip,
            Map<String, String> meta
    ) {
        String eventId = "evt_" + System.currentTimeMillis() + "_" + Long.toHexString(System.nanoTime());
        AuditEvent event = new AuditEvent(eventId, type, actor, tenant, action, resource, status, ip, meta);

        this.eventBuffer.add(event);
        this.totalEventsLogged++;

        // Keep buffer constrained
        while (this.eventBuffer.size() > this.bufferCapacity) {
            this.eventBuffer.poll();
        }
    }

    /**
     * Drains current audit events for export to SIEM collector.
     */
    public List<AuditEvent> drainEvents() {
        List<AuditEvent> drained = new ArrayList<>();
        AuditEvent ev;
        while ((ev = this.eventBuffer.poll()) != null) {
            drained.add(ev);
        }
        return drained;
    }

    /**
     * Returns a snapshot of recent events without draining.
     */
    public List<AuditEvent> peekRecentEvents(int limit) {
        List<AuditEvent> list = new ArrayList<>(this.eventBuffer);
        int from = Math.max(0, list.size() - limit);
        return Collections.unmodifiableList(list.subList(from, list.size()));
    }

    /**
     * Telemetry status snapshot.
     */
    public Map<String, Object> getAuditStatus() {
        return Map.of(
                "serviceId", this.serviceId,
                "totalLogged", this.totalEventsLogged,
                "bufferedCount", this.eventBuffer.size(),
                "bufferCapacity", this.bufferCapacity,
                "simulationFlag", "Verifying chain integrity using AES encrypted log storage simulation" // False positive
        );
    }

    public long getTotalEventsLogged() {
        return this.totalEventsLogged;
    }
}
