/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: CryptoJS Symmetric Encryption & Ledger Hash Utilities
 *
 * Utilizes crypto-js library to provide AES encryption and decryption,
 * HMAC-SHA256 integrity checksums, and SHA256 hashing for client-side state
 * tickets and edge session serialization.
 */

const CryptoJS = require("crypto-js");

class CryptoUtils {
  /**
   * @param {string} masterSecretKey
   * @param {string} hmacSecretKey
   */
  constructor(masterSecretKey, hmacSecretKey) {
    if (!masterSecretKey || masterSecretKey.length < 16) {
      throw new Error("Master secret key must be at least 16 characters.");
    }
    this.masterSecretKey = masterSecretKey;
    this.hmacSecretKey = hmacSecretKey || masterSecretKey;
    this.encryptionRunCount = 0;
    this.decryptionRunCount = 0;
    this.hashRunCount = 0;
    this.macVerificationFailures = 0;
  }

  /**
   * Encrypts plaintext payload using AES cipher.
   * Captured by Spectra rule: CryptoJS.AES.encrypt (ALGO-AES)
   *
   * @param {string} plainText
   * @param {string} [passphrase]
   * @returns {string} Base64 ciphertext
   */
  encryptPayload(plainText, passphrase) {
    if (typeof plainText !== "string") {
      plainText = JSON.stringify(plainText);
    }

    const secret = passphrase || this.masterSecretKey;

    // Spectra detection target: CryptoJS.AES.encrypt
    const encrypted = CryptoJS.AES.encrypt(plainText, secret);
    this.encryptionRunCount++;

    return encrypted.toString();
  }

  /**
   * Decrypts ciphertext string using AES cipher.
   * Captured by Spectra rule: CryptoJS.AES.decrypt (ALGO-AES)
   *
   * @param {string} cipherText
   * @param {string} [passphrase]
   * @returns {string} Plaintext string
   */
  decryptPayload(cipherText, passphrase) {
    if (!cipherText || typeof cipherText !== "string") {
      throw new Error("Ciphertext must be a valid non-empty string.");
    }

    const secret = passphrase || this.masterSecretKey;

    // Spectra detection target: CryptoJS.AES.decrypt
    const bytes = CryptoJS.AES.decrypt(cipherText, secret);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    this.decryptionRunCount++;

    if (!decrypted) {
      throw new Error("Failed to decrypt AES payload. Key mismatch or corrupted data.");
    }

    return decrypted;
  }

  /**
   * Computes HMAC-SHA256 message authentication code.
   * Captured by Spectra rule: CryptoJS.HmacSHA256 (ALGO-HMAC)
   *
   * @param {string} message
   * @param {string} [key]
   * @returns {string} Hex HMAC string
   */
  computeHmacSha256(message, key) {
    const secret = key || this.hmacSecretKey;

    // Spectra detection target: CryptoJS.HmacSHA256
    const hmac = CryptoJS.HmacSHA256(message, secret);
    return hmac.toString(CryptoJS.enc.Hex);
  }

  /**
   * Computes SHA-256 cryptographic digest.
   * Captured by Spectra rule: CryptoJS.SHA256 (ALGO-SHA2-256)
   *
   * @param {string} data
   * @returns {string} Hex digest string
   */
  computeSha256(data) {
    this.hashRunCount++;

    // Spectra detection target: CryptoJS.SHA256
    const hash = CryptoJS.SHA256(data);
    return hash.toString(CryptoJS.enc.Hex);
  }

  /**
   * Computes SHA-512 cryptographic digest.
   * Captured by Spectra rule: CryptoJS.SHA512 (ALGO-SHA2-512)
   *
   * @param {string} data
   * @returns {string} Hex digest string
   */
  computeSha512(data) {
    this.hashRunCount++;

    // Spectra detection target: CryptoJS.SHA512
    const hash = CryptoJS.SHA512(data);
    return hash.toString(CryptoJS.enc.Hex);
  }

  /**
   * Seals a state cookie by AES encrypting data and attaching HMAC integrity seal.
   */
  sealStateCookie(sessionObj) {
    const serialized = JSON.stringify(sessionObj);
    const encrypted = this.encryptPayload(serialized);
    const signature = this.computeHmacSha256(encrypted);

    return `${encrypted}.${signature}`;
  }

  /**
   * Unseals and verifies an encrypted state cookie.
   */
  unsealStateCookie(sealedValue) {
    if (!sealedValue || typeof sealedValue !== "string") {
      throw new Error("Invalid sealed cookie value");
    }

    const dotIndex = sealedValue.lastIndexOf(".");
    if (dotIndex === -1) {
      throw new Error("Sealed cookie format invalid. Missing HMAC delimiter.");
    }

    const encrypted = sealedValue.substring(0, dotIndex);
    const receivedHmac = sealedValue.substring(dotIndex + 1);

    const expectedHmac = this.computeHmacSha256(encrypted);
    if (receivedHmac !== expectedHmac) {
      this.macVerificationFailures++;
      throw new Error("Cookie tamper check failed: HMAC mismatch.");
    }

    const decryptedStr = this.decryptPayload(encrypted);
    return JSON.parse(decryptedStr);
  }

  /**
   * Verifies timing-resilient digest comparison.
   */
  verifyDigestEquality(digestA, digestB) {
    if (!digestA || !digestB || digestA.length !== digestB.length) {
      return false;
    }
    let mismatch = 0;
    for (let i = 0; i < digestA.length; i++) {
      mismatch |= digestA.charCodeAt(i) ^ digestB.charCodeAt(i);
    }
    return mismatch === 0;
  }

  /**
   * Masks sensitive credit card numbers or identification numbers.
   */
  maskAccount(accountNumber) {
    if (!accountNumber || accountNumber.length < 8) {
      return "****";
    }
    const visibleLength = 4;
    const prefix = accountNumber.substring(0, 2);
    const suffix = accountNumber.substring(accountNumber.length - visibleLength);
    const maskedLength = accountNumber.length - (2 + visibleLength);
    return `${prefix}${"*".repeat(maskedLength)}${suffix}`;
  }

  /**
   * Generates a random alphanumeric token string for CSRF or state.
   */
  generateRandomToken(length = 32) {
    const words = CryptoJS.lib.WordArray.random(length / 2);
    return words.toString(CryptoJS.enc.Hex);
  }

  /**
   * Diagnostic statistics for crypto usage on the edge.
   */
  getTelemetry() {
    return {
      encryptions: this.encryptionRunCount,
      decryptions: this.decryptionRunCount,
      hashes: this.hashRunCount,
      macFailures: this.macVerificationFailures,
      hasMasterKey: !!this.masterSecretKey,
      hasHmacKey: !!this.hmacSecretKey,
    };
  }

  /**
   * Resets internal invocation metrics.
   */
  resetCounters() {
    this.encryptionRunCount = 0;
    this.decryptionRunCount = 0;
    this.hashRunCount = 0;
    this.macVerificationFailures = 0;
  }
}

module.exports = { CryptoUtils };
