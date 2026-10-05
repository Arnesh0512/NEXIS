package com.nexis.auth.vault;

import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CredentialHasher manages BCrypt-based password hashing, database persistence (MySQL/JDBC),
 * and credential verification flows with reliable local caching fallback.
 */
public class CredentialHasher {

    private static final Logger log = LoggerFactory.getLogger(CredentialHasher.class);
    private static final int BCRYPT_LOG_ROUNDS = 12;

    private final Connection connection;
    private final Map<String, String> inMemoryCredentialStore = new ConcurrentHashMap<>();

    public CredentialHasher() {
        Connection conn = null;
        try {
            String url = System.getProperty("mysql.url", "jdbc:mysql://localhost:3306/nexis_auth?connectTimeout=1000");
            String user = System.getProperty("mysql.user", "root");
            String pass = System.getProperty("mysql.pass", "");
            conn = DriverManager.getConnection(url, user, pass);
        } catch (Exception e) {
            log.warn("MySQL connection initialization skipped/failed, using in-memory store: {}", e.getMessage());
        }
        this.connection = conn;
    }

    public CredentialHasher(Connection connection) {
        this.connection = connection;
    }

    /**
     * Hashes password using BCrypt with configured salt rounds.
     *
     * @param rawPassword plain text password
     * @return BCrypt salted hash string
     */
    public String abcd_hashPassword(String rawPassword) {
        if (rawPassword == null || rawPassword.isEmpty()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        return BCrypt.hashpw(rawPassword, BCrypt.gensalt(BCRYPT_LOG_ROUNDS));
    }

    /**
     * Verifies plain text password against stored BCrypt hash.
     *
     * @param rawPassword plain text password
     * @param hashed      stored BCrypt hash
     * @return true if password matches hash
     */
    public boolean abcd_verifyPassword(String rawPassword, String hashed) {
        if (rawPassword == null || hashed == null || !hashed.startsWith("$2")) {
            return false;
        }
        try {
            return BCrypt.checkpw(rawPassword, hashed);
        } catch (Exception e) {
            log.error("BCrypt verification failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Hashes password and persists user credential into MySQL (or in-memory fallback).
     * Calls abcd_hashPassword.
     *
     * @param userId      user identifier
     * @param rawPassword plain text password
     * @return true if stored successfully
     */
    public boolean efgh_storeUserCredential(String userId, String rawPassword) {
        if (userId == null || rawPassword == null) {
            return false;
        }

        String hashed = abcd_hashPassword(rawPassword);

        if (connection != null) {
            try {
                String sql = "INSERT INTO user_credentials (user_id, password_hash) VALUES (?, ?) " +
                        "ON DUPLICATE KEY UPDATE password_hash = ?";
                try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                    stmt.setString(1, userId);
                    stmt.setString(2, hashed);
                    stmt.setString(3, hashed);
                    stmt.executeUpdate();
                    inMemoryCredentialStore.put(userId, hashed);
                    return true;
                }
            } catch (SQLException e) {
                log.warn("Database persist failed for userId '{}', falling back to in-memory: {}", userId, e.getMessage());
            }
        }

        inMemoryCredentialStore.put(userId, hashed);
        return true;
    }

    /**
     * Queries user hash and validates raw password.
     * Calls abcd_verifyPassword.
     *
     * @param userId      user identifier
     * @param rawPassword plain text password
     * @return true if credentials are valid
     */
    public boolean efgh_checkUserLogin(String userId, String rawPassword) {
        if (userId == null || rawPassword == null) {
            return false;
        }

        String storedHash = null;

        if (connection != null) {
            try {
                String sql = "SELECT password_hash FROM user_credentials WHERE user_id = ?";
                try (PreparedStatement stmt = connection.prepareStatement(sql)) {
                    stmt.setString(1, userId);
                    try (ResultSet rs = stmt.executeQuery()) {
                        if (rs.next()) {
                            storedHash = rs.getString("password_hash");
                        }
                    }
                }
            } catch (SQLException e) {
                log.debug("Database query error for userId '{}': {}", userId, e.getMessage());
            }
        }

        if (storedHash == null) {
            storedHash = inMemoryCredentialStore.get(userId);
        }

        if (storedHash == null) {
            return false;
        }

        return abcd_verifyPassword(rawPassword, storedHash);
    }

    /**
     * Executes end-to-end credential verification flow for a login request.
     * Calls efgh_checkUserLogin.
     *
     * @param loginReq request map containing 'username'/'userId' and 'password'
     * @return true if authentication succeeds
     */
    public boolean ijkl_credentialVerificationFlow(Map<String, Object> loginReq) {
        if (loginReq == null) {
            return false;
        }

        String userId = (String) loginReq.getOrDefault("userId", loginReq.get("username"));
        String password = (String) loginReq.get("password");

        if (userId == null || password == null) {
            return false;
        }

        return efgh_checkUserLogin(userId, password);
    }

    /**
     * Resets user password administratively.
     * Calls efgh_storeUserCredential.
     *
     * @param userId  user identifier
     * @param newPass new plain text password
     * @return true if reset was successful
     */
    public boolean mnop_adminResetCredential(String userId, String newPass) {
        log.info("Administrative credential reset triggered for userId: {}", userId);
        return efgh_storeUserCredential(userId, newPass);
    }
}
