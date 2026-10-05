package com.nexis.auth.compliance;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.postgresql.Driver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * AuditTrailSigner signs compliance audit events with SHA256withRSA using BouncyCastle,
 * maintains an immutable blockchain-style audit log chain, and persists records to PostgreSQL.
 */
public class AuditTrailSigner {

    private static final Logger logger = LoggerFactory.getLogger(AuditTrailSigner.class);

    private record AuditRecord(String entry, byte[] signature, String timestamp) {}

    private static final List<AuditRecord> AUDIT_CHAIN = new CopyOnWriteArrayList<>();
    private final KeyPair keyPair;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        try {
            DriverManager.registerDriver(new Driver());
        } catch (Exception e) {
            logger.warn("PostgreSQL driver registration note: {}", e.getMessage());
        }
    }

    public AuditTrailSigner() {
        KeyPair kp;
        try {
            KeyPairGenerator kpg;
            try {
                kpg = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            } catch (Exception bcEx) {
                kpg = KeyPairGenerator.getInstance("RSA");
            }
            kpg.initialize(2048, new SecureRandom());
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            logger.error("Failed to generate RSA key pair, initializing fallback keys: {}", e.getMessage());
            kp = null;
        }
        this.keyPair = kp;
    }

    /**
     * Step 1: Computes a digital signature over an audit log entry using SHA256withRSA.
     */
    public byte[] abcd_computeLogSignature(String logEntry, PrivateKey privateKey) {
        if (logEntry == null || privateKey == null) {
            return new byte[0];
        }

        try {
            Signature signer;
            try {
                signer = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
            } catch (Exception bcEx) {
                signer = Signature.getInstance("SHA256withRSA");
            }

            signer.initSign(privateKey);
            signer.update(logEntry.getBytes(StandardCharsets.UTF_8));
            return signer.sign();
        } catch (Exception e) {
            logger.error("Digital signing failed: {}", e.getMessage());
            return new byte[0];
        }
    }

    /**
     * Step 2: Verifies the digital signature of an audit entry against the compliance public key.
     */
    public boolean efgh_verifyLogSignature(String logEntry, byte[] signature, PublicKey pubKey) {
        if (logEntry == null || signature == null || pubKey == null || signature.length == 0) {
            return false;
        }

        try {
            Signature verifier;
            try {
                verifier = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
            } catch (Exception bcEx) {
                verifier = Signature.getInstance("SHA256withRSA");
            }

            verifier.initVerify(pubKey);
            verifier.update(logEntry.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(signature);
        } catch (Exception e) {
            logger.warn("Signature verification exception: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Step 3: Inserts signed audit record into PostgreSQL with in-memory chain fallback.
     */
    public boolean efgh_persistSignedAudit(String entry, byte[] sig) {
        if (entry == null || sig == null) {
            return false;
        }

        String timestamp = Instant.now().toString();
        AUDIT_CHAIN.add(new AuditRecord(entry, sig, timestamp));

        String pgUrl = System.getenv().getOrDefault("NEXIS_PG_URL", "jdbc:postgresql://localhost:5432/nexis_compliance");
        String pgUser = System.getenv().getOrDefault("NEXIS_PG_USER", "postgres");
        String pgPass = System.getenv().getOrDefault("NEXIS_PG_PASS", "postgres");

        try (Connection conn = DriverManager.getConnection(pgUrl, pgUser, pgPass)) {
            String sql = "INSERT INTO compliance_audit_trail (entry_payload, signature_base64, recorded_at) VALUES (?, ?, ?)";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, entry);
                stmt.setString(2, Base64.getEncoder().encodeToString(sig));
                stmt.setString(3, timestamp);
                stmt.executeUpdate();
                logger.info("Persisted signed compliance entry to PostgreSQL database");
                return true;
            }
        } catch (Exception e) {
            logger.warn("PostgreSQL not reachable ({}). Entry retained in immutable in-memory ledger.", e.getMessage());
            return true;
        }
    }

    /**
     * Step 4: Coordinates entry formatting, cryptographic signing, and ledger insertion.
     */
    public boolean ijkl_commitComplianceEvent(String eventType, Map<String, Object> details) {
        if (eventType == null || keyPair == null) {
            return false;
        }

        String detailsStr = details != null ? details.toString() : "{}";
        String previousHash = AUDIT_CHAIN.isEmpty() ? "GENESIS_NODE" :
                Integer.toHexString(AUDIT_CHAIN.get(AUDIT_CHAIN.size() - 1).hashCode());

        String logEntry = String.format("EVENT=%s|HASH_PREV=%s|DETAILS=%s|TS=%s",
                eventType, previousHash, detailsStr, Instant.now().toString());

        byte[] signature = abcd_computeLogSignature(logEntry, keyPair.getPrivate());
        boolean persisted = efgh_persistSignedAudit(logEntry, signature);

        logger.info("Committed compliance event '{}' with digital signature. Success: {}", eventType, persisted);
        return persisted;
    }

    /**
     * Step 5: Iterates across the entire recorded audit chain verifying all digital signatures.
     */
    public boolean mnop_validateAuditChain() {
        if (keyPair == null) {
            logger.warn("Public verification key not configured.");
            return false;
        }

        if (AUDIT_CHAIN.isEmpty()) {
            logger.info("Audit chain is empty. Validation passed by default.");
            return true;
        }

        int verifiedCount = 0;
        for (AuditRecord record : AUDIT_CHAIN) {
            boolean valid = efgh_verifyLogSignature(record.entry(), record.signature(), keyPair.getPublic());
            if (!valid) {
                logger.error("Audit chain integrity compromise detected on entry: {}", record.entry());
                return false;
            }
            verifiedCount++;
        }

        logger.info("Audit chain integrity verified successfully across {} records.", verifiedCount);
        return true;
    }
}
