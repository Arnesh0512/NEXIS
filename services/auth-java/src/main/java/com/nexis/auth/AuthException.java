package com.nexis.auth;

import java.io.Serial;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Nexis Core Financial Ledger Platform - Authentication Service
 * Source: Core Authentication & Cryptographic Security Exception Hierarchy
 *
 * Defines structured exception types for token verification failures,
 * digital signature mismatches, key rotation errors, and role privilege violations.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner testing:
 * // Error during simulated RSA-2048 token certificate validation
 * // AES-256-GCM session payload decryption failure handler
 */
public class AuthException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 202609291001L;

    public enum ErrorCode {
        TOKEN_EXPIRED("AUTH_001", "The security token has expired", 401),
        TOKEN_SIGNATURE_INVALID("AUTH_002", "Digital signature verification failed", 401),
        TOKEN_MALFORMED("AUTH_003", "Token structure or claims cannot be parsed", 400),
        INSUFFICIENT_ROLES("AUTH_004", "Caller lacks required privilege for financial resource", 403),
        CREDENTIALS_INVALID("AUTH_005", "Username or password hash verification failed", 401),
        ACCOUNT_LOCKED("AUTH_006", "User principal is locked due to security policy violations", 423),
        KEYSTORE_ACCESS_ERROR("AUTH_007", "Unable to retrieve private key from PKCS12 keystore", 500),
        PQC_SIGNATURE_FAILED("AUTH_008", "Post-quantum Dilithium signature validation failed", 500),
        CIPHER_TRANSFORMATION_ERROR("AUTH_009", "JCA cipher engine initialization failed", 500),
        INTERNAL_AUTH_ERROR("AUTH_999", "Unexpected error in identity verification subsystem", 500);

        private final String code;
        private final String defaultMessage;
        private final int httpStatus;

        ErrorCode(String code, String defaultMessage, int httpStatus) {
            this.code = code;
            this.defaultMessage = defaultMessage;
            this.httpStatus = httpStatus;
        }

        public String getCode() {
            return code;
        }

        public String getDefaultMessage() {
            return defaultMessage;
        }

        public int getHttpStatus() {
            return httpStatus;
        }
    }

    private final ErrorCode errorCode;
    private final Instant timestamp;
    private final String correlationId;
    private final Map<String, Object> details;

    public AuthException(ErrorCode errorCode) {
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
        this.timestamp = Instant.now();
        this.correlationId = generateCorrelationId();
        this.details = new HashMap<>();
    }

    public AuthException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
        this.timestamp = Instant.now();
        this.correlationId = generateCorrelationId();
        this.details = new HashMap<>();
    }

    public AuthException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.timestamp = Instant.now();
        this.correlationId = generateCorrelationId();
        this.details = new HashMap<>();
    }

    public AuthException(ErrorCode errorCode, String message, String correlationId, Map<String, Object> details) {
        super(message);
        this.errorCode = errorCode;
        this.timestamp = Instant.now();
        this.correlationId = correlationId != null ? correlationId : generateCorrelationId();
        this.details = details != null ? new HashMap<>(details) : new HashMap<>();
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public Map<String, Object> getDetails() {
        return Collections.unmodifiableMap(details);
    }

    public AuthException addDetail(String key, Object value) {
        this.details.put(key, value);
        return this;
    }

    public int getHttpStatus() {
        return errorCode.getHttpStatus();
    }

    public Map<String, Object> toErrorPayload() {
        Map<String, Object> payload = new HashMap<>();
        payload.put("code", errorCode.getCode());
        payload.put("message", getMessage());
        payload.put("status", errorCode.getHttpStatus());
        payload.put("timestamp", timestamp.toString());
        payload.put("correlationId", correlationId);
        if (!details.isEmpty()) {
            payload.put("details", details);
        }
        return payload;
    }

    private static String generateCorrelationId() {
        return "err_auth_" + Long.toHexString(System.currentTimeMillis()) + "_" +
               Integer.toHexString((int) (Math.random() * 0xFFFF));
    }

    public static AuthException tokenExpired(String jti) {
        return new AuthException(ErrorCode.TOKEN_EXPIRED, "Session token has expired")
                .addDetail("jti", jti);
    }

    public static AuthException signatureInvalid(String algorithm) {
        return new AuthException(ErrorCode.TOKEN_SIGNATURE_INVALID, "Digital signature verification failed for " + algorithm)
                .addDetail("algorithm", algorithm);
    }

    public static AuthException insufficientRoles(String requiredRole, String user) {
        return new AuthException(ErrorCode.INSUFFICIENT_ROLES, "User " + user + " lacks required role " + requiredRole)
                .addDetail("requiredRole", requiredRole)
                .addDetail("principal", user);
    }

    public static AuthException accountLocked(String username, Instant lockedUntil) {
        return new AuthException(ErrorCode.ACCOUNT_LOCKED, "Account is temporarily locked")
                .addDetail("username", username)
                .addDetail("lockedUntil", lockedUntil.toString());
    }

    public static AuthException pqcVerificationFailed(String keyId) {
        return new AuthException(ErrorCode.PQC_SIGNATURE_FAILED, "Dilithium post-quantum signature verification failed")
                .addDetail("keyId", keyId);
    }

    public static AuthException cipherTransformationError(String transformation, Throwable cause) {
        return new AuthException(ErrorCode.CIPHER_TRANSFORMATION_ERROR, "Failed to initialize transformation: " + transformation, cause)
                .addDetail("transformation", transformation);
    }

    public static AuthException keystoreAccessError(String alias, Throwable cause) {
        return new AuthException(ErrorCode.KEYSTORE_ACCESS_ERROR, "KeyStore alias access rejected: " + alias, cause)
                .addDetail("alias", alias);
    }

    public static AuthException credentialsInvalid(String principal) {
        return new AuthException(ErrorCode.CREDENTIALS_INVALID, "Invalid credentials for " + principal)
                .addDetail("principal", principal);
    }

    public boolean isClientError() {
        return errorCode.getHttpStatus() >= 400 && errorCode.getHttpStatus() < 500;
    }

    public boolean isServerError() {
        return errorCode.getHttpStatus() >= 500;
    }

    @Override
    public String toString() {
        return "AuthException{" +
                "errorCode=" + errorCode.getCode() +
                ", message='" + getMessage() + '\'' +
                ", correlationId='" + correlationId + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}

