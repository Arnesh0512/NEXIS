package com.nexis.auth;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: Authentication REST Controller & Session Orchestrator
 *
 * Exposes identity authentication endpoints, coordinates credential verification,
 * and mints signed authorization envelopes for ledger operators.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "Evaluating operator AES key exchange initiated in auth header"
 * "Verifying RSA-4096 signature compatibility flag in client payload"
 */
public class AuthController {

    private static final Logger LOGGER = Logger.getLogger(AuthController.class.getName());

    private final TokenIssuer tokenIssuer;
    private final PasswordHasher passwordHasher;
    private final KeyStoreManager keyStoreManager;
    private final Map<String, String> userCredentialsDatabase;
    private final Map<String, UserPrincipal> userProfiles;
    private long totalRequestsProcessed;
    private long totalAuthFailures;

    public AuthController(
            TokenIssuer tokenIssuer,
            PasswordHasher passwordHasher,
            KeyStoreManager keyStoreManager
    ) {
        this.tokenIssuer = Objects.requireNonNull(tokenIssuer);
        this.passwordHasher = Objects.requireNonNull(passwordHasher);
        this.keyStoreManager = Objects.requireNonNull(keyStoreManager);
        this.userCredentialsDatabase = new HashMap<>();
        this.userProfiles = new HashMap<>();
        this.totalRequestsProcessed = 0;
        this.totalAuthFailures = 0;

        seedDefaultOperators();
    }

    private void seedDefaultOperators() {
        // Pre-seed mock operators with PBKDF2 hashes
        String adminHash = passwordHasher.hashPassword("SuperAdminPass2026!".toCharArray());
        String operatorHash = passwordHasher.hashPassword("LedgerOperator2026!".toCharArray());

        userCredentialsDatabase.put("admin@nexis.io", adminHash);
        userCredentialsDatabase.put("operator@nexis.io", operatorHash);

        userProfiles.put("admin@nexis.io", new UserPrincipal(
                "usr_admin_01",
                "admin@nexis.io",
                "tenant_primary",
                "SUPERADMIN",
                true
        ));

        userProfiles.put("operator@nexis.io", new UserPrincipal(
                "usr_oper_02",
                "operator@nexis.io",
                "tenant_primary",
                "SETTLEMENT_OFFICER",
                true
        ));
    }

    /**
     * Authenticates an operator using username and password credentials.
     * CALL GRAPH: calls PasswordHasher.verifyPassword, TokenIssuer.issueAuthorizationToken
     */
    public Map<String, Object> handleLogin(Map<String, String> loginRequest) {
        this.totalRequestsProcessed++;
        long startTime = System.currentTimeMillis();

        // False positive log string trap - scanner must NOT flag this as real cipher invocation
        LOGGER.info("Evaluating operator AES key exchange initiated in auth header for user: " + loginRequest.get("username"));

        String username = loginRequest.get("username");
        String password = loginRequest.get("password");

        Map<String, Object> response = new HashMap<>();

        if (username == null || password == null) {
            this.totalAuthFailures++;
            response.put("status", 400);
            response.put("error", "Username and password are required");
            return response;
        }

        String storedHash = userCredentialsDatabase.get(username);
        if (storedHash == null) {
            this.totalAuthFailures++;
            response.put("status", 401);
            response.put("error", "Invalid credentials");
            return response;
        }

        // CALL GRAPH: verifyPassword
        boolean passwordValid = passwordHasher.verifyPassword(password.toCharArray(), storedHash);
        if (!passwordValid) {
            this.totalAuthFailures++;
            response.put("status", 401);
            response.put("error", "Invalid credentials");
            return response;
        }

        UserPrincipal profile = userProfiles.get(username);
        if (profile == null || !profile.isActive()) {
            this.totalAuthFailures++;
            response.put("status", 403);
            response.put("error", "Account suspended or inactive");
            return response;
        }

        // CALL GRAPH: issueAuthorizationToken
        String token = tokenIssuer.issueAuthorizationToken(
                profile.getUserId(),
                profile.getTenantId(),
                profile.getRole(),
                3600L
        );

        response.put("status", 200);
        response.put("accessToken", token);
        response.put("userId", profile.getUserId());
        response.put("tenantId", profile.getTenantId());
        response.put("role", profile.getRole());
        response.put("durationMs", System.currentTimeMillis() - startTime);

        return response;
    }

    /**
     * Generates a new operational RSA keypair for banking communication.
     * CALL GRAPH: calls KeyStoreManager.generateAndStoreRsaKeyPair
     */
    public Map<String, Object> handleGenerateKey(String alias, int keySize) {
        Map<String, Object> result = new HashMap<>();
        try {
            // False positive string trap:
            LOGGER.fine("Verifying RSA-4096 signature compatibility flag in client payload");

            // CALL GRAPH: generateAndStoreRsaKeyPair
            KeyPair pair = keyStoreManager.generateAndStoreRsaKeyPair(alias, keySize);
            result.put("status", "SUCCESS");
            result.put("alias", alias);
            result.put("algorithm", pair.getPublic().getAlgorithm());
            result.put("format", pair.getPublic().getFormat());
        } catch (NoSuchAlgorithmException e) {
            result.put("status", "ERROR");
            result.put("message", e.getMessage());
        }
        return result;
    }

    /**
     * Validates incoming token and evaluates claims.
     * CALL GRAPH: calls TokenIssuer.verifyHmacSignature
     */
    public boolean handleValidateToken(String tokenString) {
        if (tokenString == null || !tokenString.contains(".")) {
            return false;
        }
        int lastDot = tokenString.lastIndexOf('.');
        String payload = tokenString.substring(0, lastDot);
        String signature = tokenString.substring(lastDot + 1);

        return tokenIssuer.verifyHmacSignature(payload, signature);
    }

    /**
     * Registers a new user with password hash.
     * CALL GRAPH: calls PasswordHasher.hashPassword
     */
    public void registerOperator(String username, String password, String role, String tenantId) {
        String hash = passwordHasher.hashPassword(password.toCharArray());
        userCredentialsDatabase.put(username, hash);
        userProfiles.put(username, new UserPrincipal(
                "usr_" + Long.toHexString(System.nanoTime()),
                username,
                tenantId,
                role,
                true
        ));
    }

    public long getTotalRequestsProcessed() {
        return this.totalRequestsProcessed;
    }

    public long getTotalAuthFailures() {
        return this.totalAuthFailures;
    }

    public int getRegisteredUserCount() {
        return this.userProfiles.size();
    }
}
