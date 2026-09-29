package com.nexis.auth;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Objects;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: Password & Credential Hasher
 *
 * Implements PBKDF2-HMAC-SHA256 key derivation and SHA-256 integrity digests
 * for secure operator credential verification.
 */
public class PasswordHasher {

    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int DEFAULT_ITERATIONS = 120000;
    private static final int KEY_LENGTH_BITS = 256;
    private static final int SALT_LENGTH_BYTES = 16;

    private final SecureRandom secureRandom;
    private final int iterationCount;
    private long totalHashComputations;
    private long totalVerifications;

    public PasswordHasher() {
        this(DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int iterations) {
        if (iterations < 10000) {
            throw new IllegalArgumentException("Iteration count must be at least 10,000 for brute-force resistance.");
        }
        this.iterationCount = iterations;

        // Spectra detection target: SecureRandom instantiation
        this.secureRandom = new SecureRandom();
        this.totalHashComputations = 0;
        this.totalVerifications = 0;
    }

    /**
     * Generates a PBKDF2-HMAC-SHA256 hash formatted as: iterations:saltBase64:hashBase64
     * Captured by Spectra rule: SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256") (ALGO-PBKDF2)
     *
     * @param rawPassword Plaintext operator password
     * @return Formatted serialized hash string
     */
    public String hashPassword(char[] rawPassword) {
        Objects.requireNonNull(rawPassword, "Password cannot be null");

        byte[] salt = new byte[SALT_LENGTH_BYTES];
        // Spectra detection target: SecureRandom.nextBytes
        this.secureRandom.nextBytes(salt);

        byte[] hash = pbkdf2(rawPassword, salt, this.iterationCount, KEY_LENGTH_BITS);
        this.totalHashComputations++;

        String saltEncoded = Base64.getEncoder().encodeToString(salt);
        String hashEncoded = Base64.getEncoder().encodeToString(hash);

        return this.iterationCount + ":" + saltEncoded + ":" + hashEncoded;
    }

    /**
     * Verifies a candidate password against an existing serialized hash.
     *
     * @param candidatePassword The plaintext password to verify
     * @param storedHash The serialized record: iterations:salt:hash
     * @return true if password matches
     */
    public boolean verifyPassword(char[] candidatePassword, String storedHash) {
        if (candidatePassword == null || storedHash == null) {
            return false;
        }

        String[] parts = storedHash.split(":");
        if (parts.length != 3) {
            return false;
        }

        try {
            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] expectedHash = Base64.getDecoder().decode(parts[2]);

            byte[] computedHash = pbkdf2(candidatePassword, salt, iterations, expectedHash.length * 8);
            this.totalVerifications++;

            return slowEquals(expectedHash, computedHash);
        } catch (NumberFormatException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Computes raw PBKDF2 bytes.
     * Captured by Spectra rule: SecretKeyFactory.getInstance (ALGO-PBKDF2)
     */
    private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyLength) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        try {
            // Spectra detection target: SecretKeyFactory.getInstance
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("PBKDF2 computation failure", e);
        } finally {
            spec.clearPassword();
        }
    }

    /**
     * Computes a SHA-256 cryptographic digest for token verification.
     * Captured by Spectra rule: MessageDigest.getInstance("SHA-256") (ALGO-SHA2-256)
     *
     * @param input Data string to hash
     * @return Hex-encoded digest
     */
    public String computeSha256Digest(String input) {
        Objects.requireNonNull(input, "Input must not be null");

        try {
            // Spectra detection target: MessageDigest.getInstance
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            // Spectra detection target: MessageDigest.digest
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm missing from JCA provider", e);
        }
    }

    /**
     * Computes a SHA-512 cryptographic digest for high-security ledger hashing.
     * Captured by Spectra rule: MessageDigest.getInstance("SHA-512") (ALGO-SHA2-512)
     *
     * @param input Raw bytes to hash
     * @return Hex-encoded digest
     */
    public String computeSha512Digest(byte[] input) {
        Objects.requireNonNull(input, "Input bytes must not be null");

        try {
            // Spectra detection target: MessageDigest.getInstance
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = digest.digest(input);

            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-512 algorithm missing from JCA provider", e);
        }
    }

    /**
     * Constant-time byte array comparison to prevent timing attacks.
     */
    private boolean slowEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    /**
     * Generates a random alphanumeric salt string.
     */
    public String generateRandomSaltHex(int byteLength) {
        byte[] salt = new byte[byteLength];
        this.secureRandom.nextBytes(salt);
        StringBuilder sb = new StringBuilder();
        for (byte b : salt) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public long getTotalHashComputations() {
        return this.totalHashComputations;
    }

    public long getTotalVerifications() {
        return this.totalVerifications;
    }

    public int getIterationCount() {
        return this.iterationCount;
    }
}
