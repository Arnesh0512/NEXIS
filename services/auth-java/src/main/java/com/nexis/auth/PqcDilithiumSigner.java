package com.nexis.auth;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: Post-Quantum Cryptographic Signer (ML-DSA / Crystals-Dilithium)
 *
 * Implements FIPS 204 / ML-DSA post-quantum digital signatures for long-term
 * financial settlements resistant to quantum cryptanalysis (Shor's algorithm).
 */
public class PqcDilithiumSigner {

    private final SecureRandom secureRandom;
    private final DilithiumParameters dilithiumParameters;
    private final Map<String, AsymmetricCipherKeyPair> keyPairStore;
    private long totalPqcSignatures;
    private long totalPqcVerifications;

    static {
        // Spectra detection target: BouncyCastleProvider registration
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public PqcDilithiumSigner() {
        this(DilithiumParameters.dilithium3);
    }

    public PqcDilithiumSigner(DilithiumParameters parameters) {
        this.dilithiumParameters = Objects.requireNonNull(parameters, "Parameters must not be null");
        this.secureRandom = new SecureRandom();
        this.keyPairStore = new ConcurrentHashMap<>();
        this.totalPqcSignatures = 0;
        this.totalPqcVerifications = 0;
    }

    /**
     * Generates a post-quantum Dilithium / ML-DSA keypair.
     * Captured by Spectra rule: DilithiumKeyPairGenerator (ALGO-ML-DSA)
     *
     * @param keyIdentifier Alias to associate with the keypair
     * @return AsymmetricCipherKeyPair containing PQC public and private components
     */
    public AsymmetricCipherKeyPair generatePqcKeyPair(String keyIdentifier) {
        Objects.requireNonNull(keyIdentifier, "Key identifier must not be null");

        // Spectra detection target: DilithiumKeyPairGenerator
        DilithiumKeyPairGenerator keyPairGenerator = new DilithiumKeyPairGenerator();
        DilithiumKeyGenerationParameters genParams = new DilithiumKeyGenerationParameters(
                this.secureRandom,
                this.dilithiumParameters
        );

        keyPairGenerator.init(genParams);
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();

        this.keyPairStore.put(keyIdentifier, keyPair);
        return keyPair;
    }

    /**
     * Signs data bytes using ML-DSA / Crystals-Dilithium private key.
     *
     * @param message Content bytes to sign
     * @param privateKey The Dilithium private key parameter
     * @return Base64 encoded signature
     */
    public String signMessage(byte[] message, DilithiumPrivateKeyParameters privateKey) {
        Objects.requireNonNull(message, "Message bytes must not be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");

        DilithiumSigner signer = new DilithiumSigner();
        signer.init(true, privateKey);

        byte[] signature = signer.generateSignature(message);
        this.totalPqcSignatures++;

        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     * Verifies an ML-DSA / Crystals-Dilithium signature against a public key.
     *
     * @param message Original signed bytes
     * @param signatureBase64 Base64 signature
     * @param publicKey The Dilithium public key parameter
     * @return true if valid
     */
    public boolean verifySignature(byte[] message, String signatureBase64, DilithiumPublicKeyParameters publicKey) {
        if (message == null || signatureBase64 == null || publicKey == null) {
            return false;
        }

        try {
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            DilithiumSigner verifier = new DilithiumSigner();
            verifier.init(false, publicKey);

            boolean isValid = verifier.verifySignature(message, signatureBytes);
            this.totalPqcVerifications++;
            return isValid;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Convenience method to sign payload using stored key alias.
     */
    public String signWithAlias(String alias, byte[] message) {
        AsymmetricCipherKeyPair pair = this.keyPairStore.get(alias);
        if (pair == null) {
            throw new IllegalArgumentException("No PQC key found for alias: " + alias);
        }
        return signMessage(message, (DilithiumPrivateKeyParameters) pair.getPrivate());
    }

    /**
     * Convenience method to verify payload using stored key alias.
     */
    public boolean verifyWithAlias(String alias, byte[] message, String signatureBase64) {
        AsymmetricCipherKeyPair pair = this.keyPairStore.get(alias);
        if (pair == null) {
            return false;
        }
        return verifySignature(message, signatureBase64, (DilithiumPublicKeyParameters) pair.getPublic());
    }

    /**
     * Returns serialized public key bytes for distribution.
     */
    public byte[] exportPublicKeyBytes(String alias) {
        AsymmetricCipherKeyPair pair = this.keyPairStore.get(alias);
        if (pair == null) {
            return null;
        }
        DilithiumPublicKeyParameters pub = (DilithiumPublicKeyParameters) pair.getPublic();
        return pub.getEncoded();
    }

    /**
     * Returns public key encoded in Base64.
     */
    public String exportPublicKeyBase64(String alias) {
        byte[] bytes = exportPublicKeyBytes(alias);
        return bytes != null ? Base64.getEncoder().encodeToString(bytes) : null;
    }

    /**
     * Returns algorithm name.
     */
    public String getAlgorithmName() {
        return "ML-DSA-65";
    }

    public long getTotalPqcSignatures() {
        return this.totalPqcSignatures;
    }

    public long getTotalPqcVerifications() {
        return this.totalPqcVerifications;
    }

    public int getStoredKeyCount() {
        return this.keyPairStore.size();
    }
}
