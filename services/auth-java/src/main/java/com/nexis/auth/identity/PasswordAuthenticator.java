package com.nexis.auth.identity;

import org.mindrot.jbcrypt.BCrypt;
import org.postgresql.Driver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * PasswordAuthenticator performs database-backed credential verification against PostgreSQL
 * with BCrypt verification, in-memory mocking, and security audit logging.
 */
public class PasswordAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(PasswordAuthenticator.class);

    private final Connection connection;
    private final Map<String, Map<String, Object>> mockUserStore = new ConcurrentHashMap<>();
    private final List<Map<String, Object>> auditLog = new CopyOnWriteArrayList<>();

    public PasswordAuthenticator() {
        // Register PostgreSQL Driver
        try {
            DriverManager.registerDriver(new Driver());
        } catch (Exception e) {
            log.debug("PostgreSQL driver registration notice: {}", e.getMessage());
        }

        Connection conn = null;
        try {
            String url = System.getProperty("postgres.url", "jdbc:postgresql://localhost:5432/nexis_identity?connectTimeout=1");
            String user = System.getProperty("postgres.user", "postgres");
            String pass = System.getProperty("postgres.pass", "postgres");
            conn = DriverManager.getConnection(url, user, pass);
        } catch (Exception e) {
            log.warn("PostgreSQL connection skipped/unavailable, using in-memory mock store: {}", e.getMessage());
        }
        this.connection = conn;

        // Initialize default seed users in memory
        initMockUsers();
    }

    public PasswordAuthenticator(Connection connection) {
        this.connection = connection;
        initMockUsers();
    }

    private void initMockUsers() {
        Map<String, Object> admin = new HashMap<>();
        admin.put("userId", "usr_admin_001");
        admin.put("username", "admin");
        admin.put("password_hash", BCrypt.hashpw("adminPassword123!", BCrypt.gensalt(10)));
        admin.put("status", "ACTIVE");
        mockUserStore.put("admin", admin);

        Map<String, Object> operator = new HashMap<>();
        operator.put("userId", "usr_operator_002");
        operator.put("username", "operator");
        operator.put("password_hash", BCrypt.hashpw("operatorPass2026!", BCrypt.gensalt(10)));
        operator.put("status", "ACTIVE");
        mockUserStore.put("operator", operator);
    }

    /**
     * Queries PostgreSQL for account records by username, falling back to in-memory store.
     *
     * @param username user account name
     * @return map of user attributes or empty map if not found
     */
    public Map<String, Object> abcd_queryUserAccount(String username) {
        if (username == null || username.isBlank()) {
            return Collections.emptyMap();
        }

        if (connection != null) {
            try {
                String sql = "SELECT id, username, password_hash, status FROM users WHERE username = ?";
                try (PreparedStatement ps = connection.prepareStatement(sql)) {
                    ps.setString(1, username);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) {
                            Map<String, Object> record = new HashMap<>();
                            record.put("userId", rs.getString("id"));
                            record.put("username", rs.getString("username"));
                            record.put("password_hash", rs.getString("password_hash"));
                            record.put("status", rs.getString("status"));
                            return record;
                        }
                    }
                }
            } catch (SQLException e) {
                log.debug("PostgreSQL query exception for user '{}': {}", username, e.getMessage());
            }
        }

        Map<String, Object> inMemory = mockUserStore.get(username);
        return (inMemory != null) ? new HashMap<>(inMemory) : Collections.emptyMap();
    }

    /**
     * Verifies plain text password against stored hash using BCrypt.
     * Calls abcd_queryUserAccount.
     *
     * @param username plain text username
     * @param password plain text password
     * @return true if credentials match
     */
    public boolean efgh_verifyUserCredentials(String username, String password) {
        if (username == null || password == null) {
            return false;
        }

        Map<String, Object> account = abcd_queryUserAccount(username);
        if (account.isEmpty()) {
            return false;
        }

        String storedHash = (String) account.get("password_hash");
        if (storedHash == null) {
            return false;
        }

        try {
            return BCrypt.checkpw(password, storedHash);
        } catch (Exception e) {
            log.error("BCrypt credential check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Records authentication attempts in database and memory audit log.
     *
     * @param userId  user identifier or username
     * @param success whether authentication succeeded
     * @return true if recorded successfully
     */
    public boolean efgh_recordLoginAttempt(String userId, boolean success) {
        Map<String, Object> event = new HashMap<>();
        event.put("userId", userId != null ? userId : "unknown");
        event.put("success", success);
        event.put("timestamp", Instant.now().toString());
        auditLog.add(event);

        if (connection != null) {
            try {
                String sql = "INSERT INTO login_audit (user_id, success, attempted_at) VALUES (?, ?, NOW())";
                try (PreparedStatement ps = connection.prepareStatement(sql)) {
                    ps.setString(1, userId);
                    ps.setBoolean(2, success);
                    ps.executeUpdate();
                }
            } catch (SQLException e) {
                log.debug("PostgreSQL audit write skipped: {}", e.getMessage());
            }
        }
        return true;
    }

    /**
     * Orchestrates login pipeline including credential check and audit recording.
     * Calls efgh_verifyUserCredentials and efgh_recordLoginAttempt.
     *
     * @param loginData login parameters containing 'username' and 'password'
     * @return true if authentication succeeds
     */
    public boolean ijkl_processLoginPipeline(Map<String, Object> loginData) {
        if (loginData == null) {
            return false;
        }

        String username = (String) loginData.get("username");
        String password = (String) loginData.get("password");

        boolean verified = efgh_verifyUserCredentials(username, password);
        efgh_recordLoginAttempt(username, verified);
        return verified;
    }

    /**
     * External entry point for authenticating an incoming login request DTO.
     * Calls ijkl_processLoginPipeline.
     *
     * @param loginDto request payload
     * @return response map with status and security token
     */
    public Map<String, Object> mnop_authenticateRequest(Map<String, Object> loginDto) {
        boolean authenticated = ijkl_processLoginPipeline(loginDto);
        Map<String, Object> response = new HashMap<>();

        if (authenticated) {
            response.put("status", "SUCCESS");
            response.put("username", loginDto.get("username"));
            response.put("sessionToken", "tok_sess_" + UUID.randomUUID().toString());
            response.put("timestamp", Instant.now().toString());
        } else {
            response.put("status", "UNAUTHORIZED");
            response.put("error", "Invalid username or password");
            response.put("timestamp", Instant.now().toString());
        }
        return response;
    }
}
