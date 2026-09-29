/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Secure Vault Client & Symmetric Envelope Encryption
 *
 * Provides AES-256-GCM authenticated encryption and decryption for sensitive
 * payload attributes (PAN data, bank account numbers, tax IDs) traversing the
 * API gateway boundary before persistence or downstream transmission.
 */

import * as crypto from "node:crypto";

export interface EncryptedVaultRecord {
  ciphertext: string;
  iv: string;
  authTag: string;
  keyVersion: number;
  algorithm: string;
  metadata: {
    createdAt: number;
    tenantId: string;
    dataType: string;
  };
}

export interface DecryptionResult {
  plaintext: string;
  verified: boolean;
  decryptedAt: number;
  keyVersionUsed: number;
}

export class SecureVaultClient {
  private readonly keyRing: Map<number, Buffer>;
  private activeKeyVersion: number;
  private readonly defaultAlgorithm = "aes-256-gcm";
  private encryptionCounter: number = 0;
  private decryptionCounter: number = 0;

  constructor(masterKeyHexMap: Record<number, string>, initialActiveVersion: number = 1) {
    this.keyRing = new Map<number, Buffer>();
    for (const [ver, keyHex] of Object.entries(masterKeyHexMap)) {
      const versionNum = parseInt(ver, 10);
      const keyBuffer = Buffer.from(keyHex, "hex");
      if (keyBuffer.length !== 32) {
        throw new Error(`Master key for version ${ver} must be exactly 32 bytes (256 bits).`);
      }
      this.keyRing.set(versionNum, keyBuffer);
    }

    if (!this.keyRing.has(initialActiveVersion)) {
      throw new Error(`Initial active key version ${initialActiveVersion} not found in keyring.`);
    }
    this.activeKeyVersion = initialActiveVersion;
  }

  /**
   * Encrypts plaintext data using AES-256-GCM authenticated cipher.
   * Captured by Spectra rule: crypto.createCipheriv (ALGO-AES)
   */
  public encryptField(
    plaintext: string,
    tenantId: string,
    dataType: string = "GENERIC_SECRET"
  ): EncryptedVaultRecord {
    const key = this.keyRing.get(this.activeKeyVersion);
    if (!key) {
      throw new Error(`Active encryption key version ${this.activeKeyVersion} missing.`);
    }

    // 12-byte IV standard for GCM mode
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(this.defaultAlgorithm, key, iv);

    const additionalData = Buffer.from(`${tenantId}:${dataType}`, "utf-8");
    cipher.setAAD(additionalData);

    let ciphertext = cipher.update(plaintext, "utf-8", "hex");
    ciphertext += cipher.final("hex");

    const authTag = cipher.getAuthTag();
    this.encryptionCounter++;

    return {
      ciphertext,
      iv: iv.toString("hex"),
      authTag: authTag.toString("hex"),
      keyVersion: this.activeKeyVersion,
      algorithm: "AES-256-GCM",
      metadata: {
        createdAt: Date.now(),
        tenantId,
        dataType,
      },
    };
  }

  /**
   * Decrypts vault record using AES-256-GCM and verifies authenticity tag.
   * Captured by Spectra rule: crypto.createDecipheriv (ALGO-AES)
   */
  public decryptField(record: EncryptedVaultRecord): DecryptionResult {
    const key = this.keyRing.get(record.keyVersion);
    if (!key) {
      throw new Error(`Decryption failed: Key version ${record.keyVersion} not found in keyring.`);
    }

    const iv = Buffer.from(record.iv, "hex");
    const authTag = Buffer.from(record.authTag, "hex");
    const decipher = crypto.createDecipheriv(this.defaultAlgorithm, key, iv);

    const additionalData = Buffer.from(`${record.metadata.tenantId}:${record.metadata.dataType}`, "utf-8");
    decipher.setAAD(additionalData);
    decipher.setAuthTag(authTag);

    let plaintext = decipher.update(record.ciphertext, "hex", "utf-8");
    plaintext += decipher.final("utf-8");

    this.decryptionCounter++;

    return {
      plaintext,
      verified: true,
      decryptedAt: Date.now(),
      keyVersionUsed: record.keyVersion,
    };
  }

  /**
   * Rotates active key to a newly generated or provided version.
   */
  public registerNewKeyVersion(version: number, keyHex: string): void {
    const keyBuffer = Buffer.from(keyHex, "hex");
    if (keyBuffer.length !== 32) {
      throw new Error("Key must be 32 bytes.");
    }
    this.keyRing.set(version, keyBuffer);
    this.activeKeyVersion = version;
  }

  /**
   * Re-encrypts an existing record under the newest active key version (key rotation).
   */
  public reencryptRecord(oldRecord: EncryptedVaultRecord): EncryptedVaultRecord {
    const decrypted = this.decryptField(oldRecord);
    return this.encryptField(
      decrypted.plaintext,
      oldRecord.metadata.tenantId,
      oldRecord.metadata.dataType
    );
  }

  /**
   * Sanitizes credit card PAN by masking all but last 4 digits.
   */
  public maskPan(pan: string): string {
    const cleaned = pan.replace(/[\s-]/g, "");
    if (cleaned.length < 13) {
      return "INVALID_PAN";
    }
    const last4 = cleaned.slice(-4);
    const masked = "*".repeat(cleaned.length - 4);
    return `${masked}${last4}`;
  }

  /**
   * Validates Luhn checksum for financial card numbers.
   */
  public validateLuhn(pan: string): boolean {
    const cleaned = pan.replace(/[\s-]/g, "");
    if (!/^\d+$/.test(cleaned)) return false;

    let sum = 0;
    let shouldDouble = false;
    for (let i = cleaned.length - 1; i >= 0; i--) {
      let digit = parseInt(cleaned.charAt(i), 10);
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }

  public getActiveKeyVersion(): number {
    return this.activeKeyVersion;
  }

  public getTotalOperations(): { encryptions: number; decryptions: number } {
    return {
      encryptions: this.encryptionCounter,
      decryptions: this.decryptionCounter,
    };
  }

  public listAvailableKeyVersions(): number[] {
    return Array.from(this.keyRing.keys()).sort((a, b) => a - b);
  }
}
