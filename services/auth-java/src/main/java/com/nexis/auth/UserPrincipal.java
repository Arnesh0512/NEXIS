package com.nexis.auth;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: Security Principal & Identity Representation
 *
 * Implements the standard Java Security Principal contract to represent
 * authenticated operators, role authorizations, and multi-tenant security scopes.
 */
public class UserPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 1L;

    public enum Role {
        SUPERADMIN,
        SECURITY_ADMIN,
        SETTLEMENT_OFFICER,
        OPERATOR,
        AUDITOR,
        READ_ONLY
    }

    private final String userId;
    private final String username;
    private final String tenantId;
    private final String role;
    private final Set<String> permissions;
    private final boolean active;
    private final long createdAtEpochMs;
    private String department;
    private String email;

    public UserPrincipal(String userId, String username, String tenantId, String role, boolean active) {
        this.userId = Objects.requireNonNull(userId, "User ID cannot be null");
        this.username = Objects.requireNonNull(username, "Username cannot be null");
        this.tenantId = Objects.requireNonNull(tenantId, "Tenant ID cannot be null");
        this.role = Objects.requireNonNull(role, "Role cannot be null");
        this.active = active;
        this.createdAtEpochMs = System.currentTimeMillis();
        this.permissions = new HashSet<>();

        assignDefaultRolePermissions(role);
    }

    private void assignDefaultRolePermissions(String roleName) {
        switch (roleName.toUpperCase()) {
            case "SUPERADMIN":
                this.permissions.add("ledger:read");
                this.permissions.add("ledger:write");
                this.permissions.add("ledger:admin");
                this.permissions.add("hsm:manage");
                this.permissions.add("settlement:execute");
                this.permissions.add("users:manage");
                break;
            case "SETTLEMENT_OFFICER":
                this.permissions.add("ledger:read");
                this.permissions.add("ledger:write");
                this.permissions.add("settlement:execute");
                break;
            case "OPERATOR":
                this.permissions.add("ledger:read");
                this.permissions.add("ledger:write");
                break;
            case "AUDITOR":
                this.permissions.add("ledger:read");
                this.permissions.add("audit:read");
                break;
            default:
                this.permissions.add("ledger:read");
                break;
        }
    }

    @Override
    public String getName() {
        return this.username;
    }

    public String getUserId() {
        return this.userId;
    }

    public String getUsername() {
        return this.username;
    }

    public String getTenantId() {
        return this.tenantId;
    }

    public String getRole() {
        return this.role;
    }

    public boolean isActive() {
        return this.active;
    }

    public long getCreatedAtEpochMs() {
        return this.createdAtEpochMs;
    }

    public Set<String> getPermissions() {
        return Collections.unmodifiableSet(this.permissions);
    }

    public boolean hasPermission(String requiredPermission) {
        if (requiredPermission == null) return false;
        return this.permissions.contains(requiredPermission) || this.permissions.contains("ledger:admin");
    }

    public void grantPermission(String permission) {
        if (permission != null) {
            this.permissions.add(permission);
        }
    }

    public void revokePermission(String permission) {
        if (permission != null) {
            this.permissions.remove(permission);
        }
    }

    public String getDepartment() {
        return this.department;
    }

    public void setDepartment(String department) {
        this.department = department;
    }

    public String getEmail() {
        return this.email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserPrincipal that = (UserPrincipal) o;
        return Objects.equals(userId, that.userId) &&
               Objects.equals(tenantId, that.tenantId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, tenantId);
    }

    @Override
    public String toString() {
        return "UserPrincipal{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", tenantId='" + tenantId + '\'' +
                ", role='" + role + '\'' +
                ", active=" + active +
                '}';
    }
}
