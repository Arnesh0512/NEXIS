/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Webhook & Request Signature Verifier
 *
 * Validates HMAC signatures on incoming bank settlement webhooks and API
 * requests from partner payment switches using Node.js crypto.
 */

const crypto = require("crypto");

class SignatureVerifier {
  /**
   * @param {string} webhookSecret
   * @param {number} [toleranceMs=300000] 5 minutes clock drift allowance
   */
  constructor(webhookSecret, toleranceMs = 300000) {
    if (!webhookSecret || webhookSecret.length < 16) {
      throw new Error("Webhook signing secret must be at least 16 characters.");
    }
    this.webhookSecret = Buffer.from(webhookSecret, "utf-8");
    this.toleranceMs = toleranceMs;
    this.verifiedCount = 0;
    this.failedCount = 0;
    this.seenNonces = new Map();
    this.rejectionLog = [];
  }

  /**
   * Computes HMAC-SHA256 signature for given payload.
   * Captured by Spectra rule: crypto.createHmac (ALGO-HMAC)
   *
   * @param {string} payload
   * @param {number} timestamp
   * @returns {string} Hex signature
   */
  signPayload(payload, timestamp) {
    const dataToSign = `${timestamp}.${payload}`;

    // Spectra detection target: crypto.createHmac
    const hmac = crypto.createHmac("sha256", this.webhookSecret);
    hmac.update(dataToSign, "utf-8");
    return hmac.digest("hex");
  }

  /**
   * Verifies incoming webhook signature header format: "t=1600000000,v1=hexsignature"
   *
   * @param {string} rawPayload
   * @param {string} signatureHeader
   * @returns {Object} Verification outcome
   */
  verifyWebhookHeader(rawPayload, signatureHeader) {
    if (!signatureHeader || typeof signatureHeader !== "string") {
      this.recordRejection("MISSING_HEADER", "Missing or malformed signature header");
      return { valid: false, reason: "Missing or malformed signature header" };
    }

    const parsed = this.parseSignatureHeader(signatureHeader);
    if (!parsed.timestamp || !parsed.signature) {
      this.recordRejection("MALFORMED_COMPONENTS", "Malformed signature header components");
      return { valid: false, reason: "Malformed signature header components" };
    }

    const now = Date.now();
    const drift = Math.abs(now - parsed.timestamp);
    if (drift > this.toleranceMs) {
      this.recordRejection("DRIFT_EXCEEDED", `Timestamp drift of ${drift}ms exceeds tolerance`);
      return { valid: false, reason: `Timestamp drift of ${drift}ms exceeds tolerance` };
    }

    if (parsed.nonce && !this.checkAndRecordNonce(parsed.nonce)) {
      this.recordRejection("REPLAY_DETECTED", "Replay attack detected for nonce");
      return { valid: false, reason: "Replay attack detected: Nonce reuse" };
    }

    const expectedSignature = this.signPayload(rawPayload, parsed.timestamp);

    const expectedBuffer = Buffer.from(expectedSignature, "hex");
    const receivedBuffer = Buffer.from(parsed.signature, "hex");

    if (expectedBuffer.length !== receivedBuffer.length) {
      this.recordRejection("LENGTH_MISMATCH", "Signature byte length mismatch");
      return { valid: false, reason: "Signature length mismatch" };
    }

    const matches = crypto.timingSafeEqual(expectedBuffer, receivedBuffer);
    if (!matches) {
      this.recordRejection("SIGNATURE_MISMATCH", "HMAC verification failed");
      return { valid: false, reason: "HMAC signature mismatch" };
    }

    this.verifiedCount++;
    return { valid: true, timestamp: parsed.timestamp };
  }

  /**
   * Parses standard signature header: t=12345678,v1=abcdef...
   */
  parseSignatureHeader(header) {
    const parts = header.split(",");
    let timestamp = 0;
    let signature = "";
    let nonce = "";

    for (const part of parts) {
      const [key, value] = part.trim().split("=");
      if (key === "t") {
        timestamp = parseInt(value, 10);
      } else if (key === "v1") {
        signature = value;
      } else if (key === "nonce") {
        nonce = value;
      }
    }

    return { timestamp, signature, nonce };
  }

  /**
   * Replay attack prevention check using transient nonce tracking.
   */
  checkAndRecordNonce(nonce, ttlMs = 300000) {
    if (!nonce) return false;
    const now = Date.now();
    this.purgeExpiredNonces(now);

    if (this.seenNonces.has(nonce)) {
      return false; // Replay attack detected
    }

    this.seenNonces.set(nonce, now + ttlMs);
    return true;
  }

  /**
   * Cleans up expired nonces from memory table.
   */
  purgeExpiredNonces(now) {
    for (const [nonce, expireAt] of this.seenNonces.entries()) {
      if (expireAt <= now) {
        this.seenNonces.delete(nonce);
      }
    }
  }

  /**
   * Computes simple SHA-256 hash for payload deduplication.
   */
  computePayloadHash(payload) {
    const hash = crypto.createHash("sha256");
    hash.update(payload, "utf-8");
    return hash.digest("hex");
  }

  /**
   * Generates a random cryptographic nonce.
   */
  generateNonce() {
    return crypto.randomBytes(16).toString("hex");
  }

  /**
   * Formats a complete outbound signature header for webhook dispatch.
   */
  buildSignatureHeader(payload, timestamp) {
    const ts = timestamp || Date.now();
    const sig = this.signPayload(payload, ts);
    const nonce = this.generateNonce();
    return `t=${ts},v1=${sig},nonce=${nonce}`;
  }

  /**
   * Records a security rejection event in audit history.
   */
  recordRejection(code, reason) {
    this.failedCount++;
    this.rejectionLog.push({
      timestamp: Date.now(),
      code,
      reason,
    });
    if (this.rejectionLog.length > 1000) {
      this.rejectionLog.shift();
    }
  }

  /**
   * Returns verification telemetry counters.
   */
  getTelemetry() {
    return {
      verifiedCount: this.verifiedCount,
      failedCount: this.failedCount,
      activeNonces: this.seenNonces.size,
      toleranceMs: this.toleranceMs,
      rejectionLogLength: this.rejectionLog.length,
    };
  }

  /**
   * Clears internal state buffers.
   */
  reset() {
    this.verifiedCount = 0;
    this.failedCount = 0;
    this.seenNonces.clear();
    this.rejectionLog = [];
  }
}

module.exports = { SignatureVerifier };
