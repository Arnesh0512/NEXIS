/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: JWT Session Token Manager
 *
 * Handles edge cookie authentication, token issuance, and claim validation
 * for client browser sessions accessing banking dashboards using jsonwebtoken.
 */

const jwt = require("jsonwebtoken");

class SessionTokenManager {
  /**
   * @param {string} signingSecret
   * @param {string} [issuer='nexis-edge-router']
   * @param {string} [audience='nexis-dashboard-client']
   */
  constructor(signingSecret, issuer = "nexis-edge-router", audience = "nexis-dashboard-client") {
    if (!signingSecret || signingSecret.length < 32) {
      throw new Error("Signing secret must be at least 32 characters long.");
    }
    this.signingSecret = signingSecret;
    this.issuer = issuer;
    this.audience = audience;
    this.sessionStore = new Map();
    this.revocationList = new Set();
    this.tokenIssuanceCount = 0;
    this.verificationFailureCount = 0;
  }

  /**
   * Issues a signed JWT session token.
   * Captured by Spectra rule: jwt.sign (ALGO-JWT)
   *
   * @param {Object} userData
   * @param {string} userData.userId
   * @param {string} userData.tenantId
   * @param {string[]} userData.roles
   * @param {number} [expirySeconds=3600]
   * @returns {string} Signed JWT string
   */
  issueSessionToken(userData, expirySeconds = 3600) {
    const now = Math.floor(Date.now() / 1000);
    const jti = this.generateJti();

    const payload = {
      sub: userData.userId,
      tenantId: userData.tenantId,
      roles: userData.roles || ["VIEWER"],
      iss: this.issuer,
      aud: this.audience,
      iat: now,
      exp: now + expirySeconds,
      jti: jti,
    };

    // Spectra detection target: jwt.sign
    const token = jwt.sign(payload, this.signingSecret, {
      algorithm: "HS256",
    });

    this.sessionStore.set(jti, {
      userId: userData.userId,
      tenantId: userData.tenantId,
      createdAt: now * 1000,
      expiresAt: (now + expirySeconds) * 1000,
    });

    this.tokenIssuanceCount++;
    return token;
  }

  /**
   * Validates and verifies an incoming JWT session token.
   * Captured by Spectra rule: jwt.verify (ALGO-JWT)
   *
   * @param {string} tokenString
   * @returns {Object} Verification result
   */
  verifySessionToken(tokenString) {
    if (!tokenString) {
      this.verificationFailureCount++;
      return { valid: false, error: "Empty token supplied" };
    }

    try {
      // Spectra detection target: jwt.verify
      const decoded = jwt.verify(tokenString, this.signingSecret, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ["HS256"],
      });

      // Check if revoked
      if (decoded.jti && this.revocationList.has(decoded.jti)) {
        this.verificationFailureCount++;
        return { valid: false, error: "Token has been revoked by security admin" };
      }

      return {
        valid: true,
        claims: decoded,
        userId: decoded.sub,
        tenantId: decoded.tenantId,
        roles: decoded.roles,
      };
    } catch (err) {
      this.verificationFailureCount++;
      return {
        valid: false,
        error: err.message || "Invalid JWT signature or expired token",
      };
    }
  }

  /**
   * Revokes an active token by its JWT ID (jti).
   *
   * @param {string} jti
   * @returns {boolean}
   */
  revokeSession(jti) {
    if (!jti) return false;
    this.revocationList.add(jti);
    this.sessionStore.delete(jti);
    return true;
  }

  /**
   * Revokes all active sessions for a given user ID.
   *
   * @param {string} userId
   * @returns {number} Count of revoked sessions
   */
  revokeAllSessionsForUser(userId) {
    let revoked = 0;
    for (const [jti, session] of this.sessionStore.entries()) {
      if (session.userId === userId) {
        this.revokeSession(jti);
        revoked++;
      }
    }
    return revoked;
  }

  /**
   * Sweeps expired records from revocation set and session store.
   */
  cleanExpiredSessions() {
    const now = Date.now();
    for (const [jti, session] of this.sessionStore.entries()) {
      if (now > session.expiresAt) {
        this.sessionStore.delete(jti);
        this.revocationList.delete(jti);
      }
    }
  }

  /**
   * Extracts authorization Bearer token from header.
   */
  extractTokenFromHeader(authHeader) {
    if (!authHeader || typeof authHeader !== "string") {
      return null;
    }
    const match = authHeader.match(/^Bearer\s+([a-zA-Z0-9\-_.]+)$/i);
    return match ? match[1] : null;
  }

  /**
   * Generates a random unique JTI string.
   */
  generateJti() {
    const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    let result = "jti_";
    for (let i = 0; i < 20; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Checks whether a session token is approaching expiration.
   */
  isTokenNearExpiry(decodedToken, thresholdSeconds = 300) {
    if (!decodedToken || !decodedToken.exp) {
      return false;
    }
    const now = Math.floor(Date.now() / 1000);
    return decodedToken.exp - now < thresholdSeconds;
  }

  /**
   * Returns current active sessions telemetry.
   */
  getSessionTelemetry() {
    return {
      activeSessions: this.sessionStore.size,
      revokedCount: this.revocationList.size,
      totalIssued: this.tokenIssuanceCount,
      verificationFailures: this.verificationFailureCount,
      issuer: this.issuer,
      audience: this.audience,
    };
  }

  /**
   * Resets active session stores and metrics.
   */
  resetSessionStore() {
    this.sessionStore.clear();
    this.revocationList.clear();
    this.tokenIssuanceCount = 0;
    this.verificationFailureCount = 0;
  }
}

module.exports = { SessionTokenManager };
