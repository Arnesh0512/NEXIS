/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Token Lifecycle & Session Token Service
 *
 * Provides token minting, claim evaluation, refresh token rotation,
 * and session state tracking for financial operators using jsonwebtoken.
 */

import * as jwt from "jsonwebtoken";

export interface UserSession {
  sessionId: string;
  userId: string;
  orgId: string;
  role: string;
  permissions: string[];
  issuedAt: number;
  expiresAt: number;
  ipAddress: string;
  userAgent: string;
}

export interface MintedTokens {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  expiresIn: number;
  sessionId: string;
}

export class TokenService {
  private readonly jwtSecret: string;
  private readonly refreshSecret: string;
  private readonly issuer: string;
  private activeSessions: Map<string, UserSession>;
  private refreshStore: Map<string, string>; // refreshToken -> sessionId

  constructor(
    jwtSecret: string,
    refreshSecret: string,
    issuer = "nexis-gateway-authority"
  ) {
    if (!jwtSecret || jwtSecret.length < 32) {
      throw new Error("JWT secret must be sufficiently strong (>= 32 chars).");
    }
    this.jwtSecret = jwtSecret;
    this.refreshSecret = refreshSecret;
    this.issuer = issuer;
    this.activeSessions = new Map<string, UserSession>();
    this.refreshStore = new Map<string, string>();
  }

  /**
   * Mints paired access and refresh tokens for an authenticated operator.
   * Captured by Spectra rule: jwt.sign (ALGO-JWT)
   */
  public mintTokenPair(
    userId: string,
    orgId: string,
    role: string,
    permissions: string[],
    clientIp: string,
    userAgent: string
  ): MintedTokens {
    const sessionId = this.generateId("sess_");
    const now = Math.floor(Date.now() / 1000);
    const accessTtl = 900; // 15 minutes
    const refreshTtl = 86400 * 7; // 7 days

    const accessPayload = {
      sub: userId,
      org: orgId,
      rol: role,
      prm: permissions,
      sid: sessionId,
      iss: this.issuer,
      iat: now,
      exp: now + accessTtl,
    };

    // Sign access token
    const accessToken = jwt.sign(accessPayload, this.jwtSecret, {
      algorithm: "HS256",
    });

    const refreshPayload = {
      sub: userId,
      sid: sessionId,
      iss: this.issuer,
      iat: now,
      exp: now + refreshTtl,
      tokenType: "refresh",
    };

    // Sign refresh token
    const refreshToken = jwt.sign(refreshPayload, this.refreshSecret, {
      algorithm: "HS256",
    });

    // Store active session metadata
    const session: UserSession = {
      sessionId,
      userId,
      orgId,
      role,
      permissions,
      issuedAt: now * 1000,
      expiresAt: (now + refreshTtl) * 1000,
      ipAddress: clientIp,
      userAgent,
    };

    this.activeSessions.set(sessionId, session);
    this.refreshStore.set(refreshToken, sessionId);

    return {
      accessToken,
      refreshToken,
      tokenType: "Bearer",
      expiresIn: accessTtl,
      sessionId,
    };
  }

  /**
   * Validates access token and resolves associated live session.
   * Captured by Spectra rule: jwt.verify (ALGO-JWT)
   */
  public authenticateRequestToken(rawToken: string): {
    authenticated: boolean;
    session?: UserSession;
    reason?: string;
  } {
    try {
      const decoded = jwt.verify(rawToken, this.jwtSecret, {
        issuer: this.issuer,
        algorithms: ["HS256"],
      }) as jwt.JwtPayload;

      const sid = decoded.sid as string;
      if (!sid || !this.activeSessions.has(sid)) {
        return { authenticated: false, reason: "Session revoked or expired" };
      }

      const session = this.activeSessions.get(sid)!;
      if (Date.now() > session.expiresAt) {
        this.terminateSession(sid);
        return { authenticated: false, reason: "Session lifecycle elapsed" };
      }

      return { authenticated: true, session };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Verification error";
      return { authenticated: false, reason: message };
    }
  }

  /**
   * Refreshes an expired access token using a valid refresh token.
   * Captured by Spectra rule: jwt.verify (ALGO-JWT)
   */
  public rotateRefreshToken(rawRefreshToken: string, clientIp: string): MintedTokens {
    let decoded: jwt.JwtPayload;
    try {
      decoded = jwt.verify(rawRefreshToken, this.refreshSecret, {
        issuer: this.issuer,
        algorithms: ["HS256"],
      }) as jwt.JwtPayload;
    } catch {
      throw new Error("Invalid or expired refresh token");
    }

    const sid = decoded.sid as string;
    const existingSid = this.refreshStore.get(rawRefreshToken);
    if (!existingSid || existingSid !== sid) {
      throw new Error("Refresh token reuse detected or invalid");
    }

    const session = this.activeSessions.get(sid);
    if (!session) {
      throw new Error("Associated session does not exist");
    }

    // Invalidate old refresh token
    this.refreshStore.delete(rawRefreshToken);

    // Mint new pair
    return this.mintTokenPair(
      session.userId,
      session.orgId,
      session.role,
      session.permissions,
      clientIp,
      session.userAgent
    );
  }

  /**
   * Terminates a session and cleans up active memory records.
   */
  public terminateSession(sessionId: string): boolean {
    if (!this.activeSessions.has(sessionId)) {
      return false;
    }
    this.activeSessions.delete(sessionId);

    for (const [token, sid] of this.refreshStore.entries()) {
      if (sid === sessionId) {
        this.refreshStore.delete(token);
      }
    }
    return true;
  }

  /**
   * Terminates all sessions belonging to a specific user (global logout).
   */
  public terminateAllUserSessions(userId: string): number {
    let terminated = 0;
    for (const [sid, session] of this.activeSessions.entries()) {
      if (session.userId === userId) {
        this.terminateSession(sid);
        terminated++;
      }
    }
    return terminated;
  }

  public getActiveSessionCount(): number {
    return this.activeSessions.size;
  }

  private generateId(prefix: string): string {
    const randomHex = Math.random().toString(36).substring(2, 12);
    const ts = Date.now().toString(36);
    return `${prefix}${ts}_${randomHex}`;
  }
}
