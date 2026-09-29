/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Node.js Core Cryptographic Signer & HMAC Authenticator
 *
 * Implements digital signature generation, verification, and HMAC-SHA256
 * request signing for inter-service communication between edge gateway and
 * payment dispatchers using Node.js native crypto APIs.
 */

import * as crypto from "node:crypto";

export interface SignatureEnvelope {
  payloadHash: string;
  signature: string;
  algorithm: string;
  timestamp: number;
  keyId: string;
}

export interface HmacVerificationResult {
  valid: boolean;
  computedHash: string;
  receivedHash: string;
  driftMs: number;
}

export class NodeCryptoSigner {
  private readonly privateKeyPem: string;
  private readonly publicKeyPem: string;
  private readonly hmacSharedSecret: Buffer;
  private readonly defaultHashAlgo: string = "sha256";
  private signatureCache: Map<string, number>;
  private maxClockSkewMs: number = 300000; // 5 minutes

  constructor(
    privateKeyPem: string,
    publicKeyPem: string,
    hmacSecretHex: string
  ) {
    this.privateKeyPem = privateKeyPem;
    this.publicKeyPem = publicKeyPem;
    this.hmacSharedSecret = Buffer.from(hmacSecretHex, "hex");
    this.signatureCache = new Map<string, number>();
  }

  /**
   * Generates a digital signature for an arbitrary financial payload using RSA or ECDSA.
   * Captured by Spectra rule: crypto.createSign (ALGO-SHA2-256)
   */
  public signPayload(payload: string, keyId: string = "default-primary"): SignatureEnvelope {
    const timestamp = Date.now();
    const dataToSign = `${timestamp}.${payload}`;

    // Compute digest
    const hash = crypto.createHash(this.defaultHashAlgo);
    hash.update(payload, "utf-8");
    const payloadHash = hash.digest("hex");

    // Create signature
    const signer = crypto.createSign("SHA256");
    signer.update(dataToSign);
    signer.end();

    const signature = signer.sign(this.privateKeyPem, "base64");

    return {
      payloadHash,
      signature,
      algorithm: "SHA256withRSA",
      timestamp,
      keyId,
    };
  }

  /**
   * Verifies an asymmetric digital signature from upstream services.
   * Captured by Spectra rule: crypto.createVerify (ALGO-SHA2-256)
   */
  public verifyPayloadSignature(
    payload: string,
    envelope: SignatureEnvelope
  ): boolean {
    const now = Date.now();
    const drift = Math.abs(now - envelope.timestamp);
    if (drift > this.maxClockSkewMs) {
      return false;
    }

    const dataToVerify = `${envelope.timestamp}.${payload}`;

    try {
      const verifier = crypto.createVerify("SHA256");
      verifier.update(dataToVerify);
      verifier.end();

      const isValid = verifier.verify(this.publicKeyPem, envelope.signature, "base64");
      return isValid;
    } catch {
      return false;
    }
  }

  /**
   * Computes an HMAC message authentication code for fast symmetric verification.
   * Captured by Spectra rule: crypto.createHmac (ALGO-HMAC)
   */
  public computeHmac(message: string): string {
    const hmacInstance = crypto.createHmac("sha256", this.hmacSharedSecret);
    hmacInstance.update(message, "utf-8");
    return hmacInstance.digest("hex");
  }

  /**
   * Performs constant-time comparison of incoming HMAC to prevent timing attacks.
   */
  public verifyHmac(
    message: string,
    expectedHexSignature: string,
    requestTimestampMs?: number
  ): HmacVerificationResult {
    const now = Date.now();
    const driftMs = requestTimestampMs ? Math.abs(now - requestTimestampMs) : 0;

    const computed = this.computeHmac(message);
    const computedBuffer = Buffer.from(computed, "hex");
    const expectedBuffer = Buffer.from(expectedHexSignature, "hex");

    if (computedBuffer.length !== expectedBuffer.length) {
      return {
        valid: false,
        computedHash: computed,
        receivedHash: expectedHexSignature,
        driftMs,
      };
    }

    const valid = crypto.timingSafeEqual(computedBuffer, expectedBuffer);

    return {
      valid,
      computedHash: computed,
      receivedHash: expectedHexSignature,
      driftMs,
    };
  }

  /**
   * Generates secure CSPRNG random bytes for correlation IDs and salting.
   * Captured by Spectra rule: crypto.randomBytes (ALGO-CSPRNG)
   */
  public generateSecureNonce(byteCount: number = 32): Buffer {
    if (byteCount < 16) {
      throw new Error("Nonce byte count must be at least 16 for cryptographic safety.");
    }
    return crypto.randomBytes(byteCount);
  }

  /**
   * Generates a UUID v4 via CSPRNG.
   * Captured by Spectra rule: crypto.randomUUID (ALGO-CSPRNG)
   */
  public generateTrackingUuid(): string {
    return crypto.randomUUID();
  }

  /**
   * Computes SHA-256 hash of a buffer.
   * Captured by Spectra rule: crypto.createHash (ALGO-SHA2-256)
   */
  public computeSha256Digest(data: Buffer | string): string {
    const hasher = crypto.createHash("sha256");
    if (typeof data === "string") {
      hasher.update(data, "utf-8");
    } else {
      hasher.update(data);
    }
    return hasher.digest("hex");
  }

  /**
   * Anti-replay cache check to guarantee single-use signed requests.
   */
  public checkAndRecordReplayNonce(nonce: string, ttlMs: number = 300000): boolean {
    const now = Date.now();
    this.evictExpiredNonces(now);

    if (this.signatureCache.has(nonce)) {
      return false; // Replay detected!
    }

    this.signatureCache.set(nonce, now + ttlMs);
    return true;
  }

  /**
   * Purges expired entries from the anti-replay memory structure.
   */
  private evictExpiredNonces(currentTimeMs: number): void {
    for (const [nonce, expireAt] of this.signatureCache.entries()) {
      if (expireAt <= currentTimeMs) {
        this.signatureCache.delete(nonce);
      }
    }
  }

  public getCacheSize(): number {
    return this.signatureCache.size;
  }

  public setClockSkewTolerance(skewMs: number): void {
    if (skewMs <= 0) {
      throw new Error("Clock skew tolerance must be strictly positive.");
    }
    this.maxClockSkewMs = skewMs;
  }

  public exportPublicKeyFingerprint(): string {
    return this.computeSha256Digest(this.publicKeyPem);
  }
}
