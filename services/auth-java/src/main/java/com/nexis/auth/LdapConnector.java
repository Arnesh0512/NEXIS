package com.nexis.auth;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: LDAP / Active Directory Enterprise Directory Connector
 *
 * Simulates directory search operations, user DN binding, group membership
 * resolution, and connection pooling for banking enterprise SSO.
 */
public class LdapConnector {

    public static class LdapEntry {
        private final String distinguishedName;
        private final Map<String, String> attributes;

        public LdapEntry(String distinguishedName) {
            this.distinguishedName = distinguishedName;
            this.attributes = new HashMap<>();
        }

        public void addAttribute(String name, String value) {
            this.attributes.put(name.toLowerCase(), value);
        }

        public String getAttribute(String name) {
            return this.attributes.get(name.toLowerCase());
        }

        public String getDistinguishedName() {
            return this.distinguishedName;
        }
    }

    private final String ldapUrl;
    private final String baseDn;
    private final String bindDn;
    private final int connectionTimeoutMs;
    private final Map<String, LdapEntry> simulatedDirectory;
    private boolean connected;
    private long totalQueries;
    private long totalBinds;

    public LdapConnector(String ldapUrl, String baseDn, String bindDn, int timeoutMs) {
        this.ldapUrl = Objects.requireNonNull(ldapUrl, "LDAP URL cannot be null");
        this.baseDn = Objects.requireNonNull(baseDn, "Base DN cannot be null");
        this.bindDn = bindDn;
        this.connectionTimeoutMs = timeoutMs > 0 ? timeoutMs : 5000;
        this.simulatedDirectory = new ConcurrentHashMap<>();
        this.connected = false;
        this.totalQueries = 0;
        this.totalBinds = 0;

        populateDirectoryMock();
    }

    private void populateDirectoryMock() {
        LdapEntry admin = new LdapEntry("uid=admin,ou=system," + this.baseDn);
        admin.addAttribute("mail", "admin@nexis.io");
        admin.addAttribute("cn", "System Administrator");
        admin.addAttribute("memberOf", "cn=FinanceAdmins,ou=groups," + this.baseDn);
        admin.addAttribute("userPassword", "{SSHA}SimulatedHashOnly");

        LdapEntry operator = new LdapEntry("uid=operator,ou=users," + this.baseDn);
        operator.addAttribute("mail", "operator@nexis.io");
        operator.addAttribute("cn", "Settlement Operator");
        operator.addAttribute("memberOf", "cn=Operators,ou=groups," + this.baseDn);
        operator.addAttribute("userPassword", "{SSHA}SimulatedHashOnly");

        this.simulatedDirectory.put("admin@nexis.io", admin);
        this.simulatedDirectory.put("operator@nexis.io", operator);
    }

    /**
     * Establishes simulated connection pool to directory server.
     */
    public boolean connect() {
        this.connected = true;
        return true;
    }

    /**
     * Closes directory connection.
     */
    public void disconnect() {
        this.connected = false;
    }

    /**
     * Queries directory entry for a given username or email filter.
     */
    public LdapEntry findUserByEmail(String email) {
        this.totalQueries++;
        if (!this.connected) {
            connect();
        }
        if (email == null) return null;
        return this.simulatedDirectory.get(email.toLowerCase());
    }

    /**
     * Simulates simple bind authentication against directory.
     */
    public boolean authenticateBind(String userDn, String password) {
        this.totalBinds++;
        if (!this.connected) {
            connect();
        }
        if (userDn == null || password == null || password.isEmpty()) {
            return false;
        }

        // Mock verification: password length > 8
        return password.length() >= 8;
    }

    /**
     * Parses standard distinguished name (DN) components.
     */
    public Map<String, String> parseDn(String dn) {
        Map<String, String> components = new HashMap<>();
        if (dn == null) return components;

        String[] rDNs = dn.split(",");
        for (String rdn : rDNs) {
            String[] kv = rdn.trim().split("=");
            if (kv.length == 2) {
                components.put(kv[0].trim().toUpperCase(), kv[1].trim());
            }
        }
        return components;
    }

    /**
     * Formats user search filter string.
     */
    public String buildSearchFilter(String attribute, String value) {
        String sanitized = sanitizeLdapInput(value);
        return String.format("(&(%s=%s)(objectClass=inetOrgPerson))", attribute, sanitized);
    }

    /**
     * Sanitizes inputs to prevent LDAP injection attacks.
     */
    private String sanitizeLdapInput(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\5c"); break;
                case '*':  sb.append("\\2a"); break;
                case '(':  sb.append("\\28"); break;
                case ')':  sb.append("\\29"); break;
                case '\0': sb.append("\\00"); break;
                default:   sb.append(c); break;
            }
        }
        return sb.toString();
    }

    public boolean isConnected() {
        return this.connected;
    }

    public long getTotalQueries() {
        return this.totalQueries;
    }

    public long getTotalBinds() {
        return this.totalBinds;
    }

    public String getLdapUrl() {
        return this.ldapUrl;
    }

    public String getBaseDn() {
        return this.baseDn;
    }
}
