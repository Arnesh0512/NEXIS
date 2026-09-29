package com.nexis.auth;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Nexis Core Financial Ledger Platform - Auth Service
 * Module: Enterprise KeyStore & Cryptographic Keypair Manager
 *
 * Manages PKCS12 keystore storage, asymmetric RSA keypair generation,
 * and certificate alias resolution using standard Java Security APIs.
 */
public class KeyStoreManager {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String ASYMMETRIC_ALGORITHM = "RSA";
    private static final int DEFAULT_RSA_KEY_SIZE = 2048;

    private final KeyStore keyStore;
    private final char[] keyStorePassword;
    private final SecureRandom secureRandom;
    private final Map<String, KeyPair> cachedKeyPairs;
    private int keysLoadedCount;

    public KeyStoreManager(char[] password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        Objects.requireNonNull(password, "KeyStore password cannot be null");
        this.keyStorePassword = password.clone();
        this.secureRandom = new SecureRandom();
        this.cachedKeyPairs = new HashMap<>();
        this.keysLoadedCount = 0;

        // Spectra detection target: KeyStore.getInstance("PKCS12")
        this.keyStore = KeyStore.getInstance(KEYSTORE_TYPE);

        // Spectra detection target: KeyStore.load (initializing empty keystore)
        this.keyStore.load(null, this.keyStorePassword);
    }

    /**
     * Generates a new RSA 2048-bit keypair and stores it under an alias.
     * Captured by Spectra rule: KeyPairGenerator.getInstance("RSA") (ALGO-RSA)
     *
     * @param alias The identifier under which to store the key
     * @param keySizeBits The key length (minimum 2048)
     * @return Generated KeyPair
     * @throws NoSuchAlgorithmException If algorithm missing
     */
    public KeyPair generateAndStoreRsaKeyPair(String alias, int keySizeBits) throws NoSuchAlgorithmException {
        Objects.requireNonNull(alias, "Alias must not be null");
        if (keySizeBits < 2048) {
            throw new IllegalArgumentException("Key size must be at least 2048 bits for cryptographic security.");
        }

        // Spectra detection target: KeyPairGenerator.getInstance
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);

        // Spectra detection target: KeyPairGenerator.initialize
        keyPairGen.initialize(keySizeBits, this.secureRandom);

        KeyPair keyPair = keyPairGen.generateKeyPair();
        this.cachedKeyPairs.put(alias, keyPair);
        this.keysLoadedCount++;

        return keyPair;
    }

    /**
     * Loads a PKCS12 keystore from serialized byte array input.
     * Captured by Spectra rule: KeyStore.load
     *
     * @param keyStoreBytes Serialized keystore file bytes
     * @throws IOException If parsing fails
     * @throws NoSuchAlgorithmException If algorithm unsupported
     * @throws CertificateException If certificate verification fails
     */
    public void loadFromBytes(byte[] keyStoreBytes) throws IOException, NoSuchAlgorithmException, CertificateException {
        Objects.requireNonNull(keyStoreBytes, "KeyStore bytes cannot be null");

        ByteArrayInputStream bais = new ByteArrayInputStream(keyStoreBytes);
        // Spectra detection target: KeyStore.load
        this.keyStore.load(bais, this.keyStorePassword);
    }

    /**
     * Serializes the current keystore to a byte array.
     */
    public byte[] exportToBytes() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        this.keyStore.store(baos, this.keyStorePassword);
        return baos.toByteArray();
    }

    /**
     * Retrieves an RSA PrivateKey by alias.
     */
    public PrivateKey getPrivateKey(String alias, char[] keyPassword) throws Exception {
        Objects.requireNonNull(alias, "Alias must not be null");

        if (this.cachedKeyPairs.containsKey(alias)) {
            return this.cachedKeyPairs.get(alias).getPrivate();
        }

        Key key = this.keyStore.getKey(alias, keyPassword != null ? keyPassword : this.keyStorePassword);
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }
        return null;
    }

    /**
     * Retrieves an RSA PublicKey by alias.
     */
    public PublicKey getPublicKey(String alias) throws KeyStoreException {
        Objects.requireNonNull(alias, "Alias must not be null");

        if (this.cachedKeyPairs.containsKey(alias)) {
            return this.cachedKeyPairs.get(alias).getPublic();
        }

        Certificate cert = this.keyStore.getCertificate(alias);
        if (cert != null) {
            return cert.getPublicKey();
        }
        return null;
    }

    /**
     * Stores a private key and certificate chain into the PKCS12 store.
     */
    public void storeKey(String alias, Key key, char[] keyPassword, Certificate[] chain) throws KeyStoreException {
        Objects.requireNonNull(alias, "Alias must not be null");
        Objects.requireNonNull(key, "Key must not be null");

        this.keyStore.setKeyEntry(alias, key, keyPassword != null ? keyPassword : this.keyStorePassword, chain);
        this.keysLoadedCount++;
    }

    /**
     * Checks if an alias exists in the keystore.
     */
    public boolean containsAlias(String alias) throws KeyStoreException {
        return this.cachedKeyPairs.containsKey(alias) || this.keyStore.containsAlias(alias);
    }

    /**
     * Lists all stored key aliases.
     */
    public Enumeration<String> listAliases() throws KeyStoreException {
        return this.keyStore.aliases();
    }

    /**
     * Deletes an entry from the keystore.
     */
    public void deleteEntry(String alias) throws KeyStoreException {
        this.cachedKeyPairs.remove(alias);
        if (this.keyStore.containsAlias(alias)) {
            this.keyStore.deleteEntry(alias);
        }
    }

    /**
     * Returns total count of keys managed.
     */
    public int getKeyCount() throws KeyStoreException {
        return this.keyStore.size() + this.cachedKeyPairs.size();
    }

    public String getKeyStoreType() {
        return KEYSTORE_TYPE;
    }

    public int getKeysLoadedCount() {
        return this.keysLoadedCount;
    }
}
