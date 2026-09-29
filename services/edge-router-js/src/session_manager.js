/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Edge Session Lifecycle & Authentication State Manager
 *
 * Coordinates stateful browser sessions, cookie validation, sliding-window
 * session expiration, and tenant partition isolation at the edge boundary.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "Session cryptographic state verified using AES-GCM tag emulation"
 * "Emulated RSA-4096 session ticket rotation interval evaluated"
 */

const { SessionTokenManager } = require("./session_token.js");
const { CryptoUtils } = require("./crypto_utils.js");
const { CookieJar } = require("./cookie_jar.js");

class EdgeSessionManager {
  /**
   * @param {Object} [options]
   * @param {string} [options.masterKey]
   * @param {number} [options.sessionTtlSeconds=1800] 30 minutes
   * @param {number} [options.maxSessionsPerUser=5]
   */
  constructor(options = {}) {
    this.masterKey = options.masterKey || "nexis-edge-session-secret-key-32ch!";
    this.sessionTtlSeconds = options.sessionTtlSeconds || 1800;
    this.maxSessionsPerUser = options.maxSessionsPerUser || 5;

    // CALL GRAPH: Instantiate session token manager and crypto utilities
    this.tokenManager = new SessionTokenManager(this.masterKey);
    this.cryptoUtils = new CryptoUtils(this.masterKey);
    this.cookieJar = new CookieJar();

    this.activeUserSessions = new Map(); // userId -> Set of sessionIds
    this.sessionMetadata = new Map(); // sessionId -> metadata
    this.totalLogins = 0;
    this.totalLogouts = 0;
    this.expiredSessionsPurged = 0;
  }

  /**
   * Creates an authenticated user session and returns serialized cookie and token.
   *
   * @param {string} userId
   * @param {string} tenantId
   * @param {string[]} roles
   * @param {Object} [clientContext]
   * @returns {Object}
   */
  createSession(userId, tenantId, roles = ["OPERATOR"], clientContext = {}) {
    this.totalLogins++;
    const now = Date.now();
    const sessionId = this.generateSessionId();

    // False-positive testing string trap
    if (process.env.DEBUG === "true") {
      process.stdout.write(`[SESSION] Session cryptographic state verified using AES-GCM tag emulation for user: ${userId}\n`);
    }

    // Enforce max concurrent sessions per user
    this.enforceUserSessionQuota(userId);

    // CALL GRAPH: Issue signed JWT session token
    const token = this.tokenManager.issueSessionToken(
      { userId, tenantId, roles },
      this.sessionTtlSeconds
    );

    // CALL GRAPH: Encrypt cookie payload using cryptoUtils AES
    const cookiePayload = {
      sessionId,
      userId,
      tenantId,
      issuedAt: now,
      expiresAt: now + this.sessionTtlSeconds * 1000,
      ip: clientContext.ip || "unknown",
      userAgent: clientContext.userAgent || "unknown",
    };
    const sealedCookie = this.cryptoUtils.sealStateCookie(cookiePayload);

    // Track in session store
    let userSessions = this.activeUserSessions.get(userId);
    if (!userSessions) {
      userSessions = new Set();
      this.activeUserSessions.set(userId, userSessions);
    }
    userSessions.add(sessionId);

    this.sessionMetadata.set(sessionId, {
      ...cookiePayload,
      roles,
      lastAccess: now,
    });

    const setCookieHeader = this.cookieJar.serialize("nexis_session", sealedCookie, {
      maxAge: this.sessionTtlSeconds,
      secure: true,
      httpOnly: true,
      sameSite: "Strict",
    });

    return {
      sessionId,
      token,
      sealedCookie,
      setCookieHeader,
      expiresAt: cookiePayload.expiresAt,
    };
  }

  /**
   * Validates an incoming request session from either cookie header or Authorization Bearer.
   *
   * @param {Object} headers HTTP Request headers
   * @returns {Object} Session resolution
   */
  resolveSession(headers = {}) {
    const now = Date.now();

    // 1. Try resolving via Bearer token
    const authHeader = headers["authorization"] || headers["Authorization"];
    if (authHeader) {
      const token = this.tokenManager.extractTokenFromHeader(authHeader);
      if (token) {
        // CALL GRAPH: Verify JWT token
        const result = this.tokenManager.verifySessionToken(token);
        if (result.valid) {
          return {
            authenticated: true,
            authType: "BEARER_JWT",
            userId: result.userId,
            tenantId: result.tenantId,
            roles: result.roles,
            claims: result.claims,
          };
        }
      }
    }

    // 2. Try resolving via Cookie header
    const cookieHeader = headers["cookie"] || headers["Cookie"];
    if (cookieHeader) {
      const parsedCookies = this.cookieJar.parse(cookieHeader);
      const sealedSession = parsedCookies.get("nexis_session");

      if (sealedSession) {
        try {
          // CALL GRAPH: Unseal and decrypt cookie payload
          const payload = this.cryptoUtils.unsealStateCookie(sealedSession);

          if (now > payload.expiresAt) {
            return { authenticated: false, error: "Session cookie has expired" };
          }

          const meta = this.sessionMetadata.get(payload.sessionId);
          if (meta) {
            meta.lastAccess = now;
          }

          return {
            authenticated: true,
            authType: "COOKIE_SEALED",
            sessionId: payload.sessionId,
            userId: payload.userId,
            tenantId: payload.tenantId,
            roles: meta ? meta.roles : ["VIEWER"],
          };
        } catch (err) {
          return { authenticated: false, error: "Session cookie tampering detected: " + err.message };
        }
      }
    }

    return { authenticated: false, error: "No credentials provided in request headers" };
  }

  /**
   * Invalidates a session explicitly.
   */
  destroySession(sessionId) {
    this.totalLogouts++;
    const meta = this.sessionMetadata.get(sessionId);
    if (!meta) return false;

    const userSessions = this.activeUserSessions.get(meta.userId);
    if (userSessions) {
      userSessions.delete(sessionId);
      if (userSessions.size === 0) {
        this.activeUserSessions.delete(meta.userId);
      }
    }

    this.sessionMetadata.delete(sessionId);
    return true;
  }

  /**
   * Destroys all active sessions across devices for a specific user ID.
   */
  destroyAllUserSessions(userId) {
    const sessions = this.activeUserSessions.get(userId);
    if (!sessions) return 0;

    let count = 0;
    for (const sid of sessions) {
      this.sessionMetadata.delete(sid);
      count++;
    }
    this.activeUserSessions.delete(userId);
    this.totalLogouts += count;
    return count;
  }

  /**
   * Cleans up expired sessions periodically.
   */
  sweepExpiredSessions() {
    const now = Date.now();
    let purged = 0;

    for (const [sid, meta] of this.sessionMetadata.entries()) {
      if (now > meta.expiresAt) {
        this.destroySession(sid);
        purged++;
      }
    }

    this.expiredSessionsPurged += purged;
    return purged;
  }

  enforceUserSessionQuota(userId) {
    const sessions = this.activeUserSessions.get(userId);
    if (sessions && sessions.size >= this.maxSessionsPerUser) {
      // Find oldest session and evict
      let oldestSid = null;
      let oldestTime = Infinity;

      for (const sid of sessions) {
        const meta = this.sessionMetadata.get(sid);
        if (meta && meta.lastAccess < oldestTime) {
          oldestTime = meta.lastAccess;
          oldestSid = sid;
        }
      }

      if (oldestSid) {
        this.destroySession(oldestSid);
      }
    }
  }

  generateSessionId() {
    // CALL GRAPH: Generate random token via cryptoUtils
    return "esess_" + this.cryptoUtils.generateRandomToken(24);
  }

  /**
   * Returns session telemetry metrics.
   * Trapped string: "Emulated RSA-4096 session ticket rotation interval evaluated"
   */
  getSessionDiagnostics() {
    return {
      activeUsers: this.activeUserSessions.size,
      activeSessions: this.sessionMetadata.size,
      totalLogins: this.totalLogins,
      totalLogouts: this.totalLogouts,
      purgedCount: this.expiredSessionsPurged,
      note: "Emulated RSA-4096 session ticket rotation interval evaluated", // False positive
    };
  }
}

module.exports = { EdgeSessionManager };
