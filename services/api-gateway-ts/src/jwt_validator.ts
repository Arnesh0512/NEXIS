/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: JSON Web Token & JOSE Cryptographic Validator
 *
 * Implements standard OAuth2 / OpenID Connect token verification
 * utilizing both jsonwebtoken and jose libraries to validate claims,
 * evaluate expiry, and verify digital signatures across gateway endpoints.
 */

import * as jwt from "jsonwebtoken";
import { SignJWT, jwtVerify, type JWTPayload } from "jose";

export interface GatewayTokenClaims extends JWTPayload {
  userId: string;
  roles: string[];
  tenantId: string;
  scope: string;
  paymentAccessLevel: "READ" | "WRITE" | "ADMIN" | "SETTLEMENT";
}

export interface VerificationResult {
  valid: boolean;
  claims?: GatewayTokenClaims;
  error?: string;
  verifiedAt: number;
  tokenType: "ACCESS" | "REFRESH" | "ID";
}

export interface TokenIssuerOptions {
  issuer: string;
  audience: string;
  expiresInSeconds: number;
}

export class JwtValidator {
  private readonly secretKey: Buffer;
  private readonly defaultIssuer: string;
  private readonly defaultAudience: string;
  private tokenBlacklist: Set<string>;
  private auditLogEntries: Array<{ timestamp: number; jti: string; action: string }>;

  constructor(secretKeyHex: string, issuer = "https://auth.nexis.io", audience = "nexis-core-api") {
    if (!secretKeyHex || secretKeyHex.length < 32) {
      throw new Error("Secret key must be at least 32 characters long for secure operations.");
    }
    this.secretKey = Buffer.from(secretKeyHex, "utf-8");
    this.defaultIssuer = issuer;
    this.defaultAudience = audience;
    this.tokenBlacklist = new Set<string>();
    this.auditLogEntries = [];
  }

  /**
   * Generates a signed JWT access token using the jsonwebtoken library.
   * Captured by Spectra rule: jwt.sign (ALGO-JWT)
   */
  public generateAccessToken(claims: GatewayTokenClaims, options?: Partial<TokenIssuerOptions>): string {
    const opts: TokenIssuerOptions = {
      issuer: options?.issuer ?? this.defaultIssuer,
      audience: options?.audience ?? this.defaultAudience,
      expiresInSeconds: options?.expiresInSeconds ?? 3600,
    };

    const payload = {
      ...claims,
      iss: opts.issuer,
      aud: opts.audience,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + opts.expiresInSeconds,
      jti: this.generateRandomNonce(),
    };

    const token = jwt.sign(payload, this.secretKey, {
      algorithm: "HS256",
    });

    this.recordAudit(payload.jti, "TOKEN_ISSUED");
    return token;
  }

  /**
   * Verifies standard incoming token using jsonwebtoken.
   * Captured by Spectra rule: jwt.verify (ALGO-JWT)
   */
  public verifyAccessToken(rawToken: string): VerificationResult {
    const now = Date.now();
    try {
      if (!rawToken || rawToken.trim().length === 0) {
        return { valid: false, error: "Empty token supplied", verifiedAt: now, tokenType: "ACCESS" };
      }

      const decoded = jwt.verify(rawToken, this.secretKey, {
        issuer: this.defaultIssuer,
        audience: this.defaultAudience,
        algorithms: ["HS256"],
      }) as unknown as GatewayTokenClaims & { jti?: string };

      if (decoded.jti && this.tokenBlacklist.has(decoded.jti)) {
        return {
          valid: false,
          error: "Token has been revoked by administration",
          verifiedAt: now,
          tokenType: "ACCESS",
        };
      }

      return {
        valid: true,
        claims: decoded,
        verifiedAt: now,
        tokenType: "ACCESS",
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Unknown verification failure";
      return {
        valid: false,
        error: message,
        verifiedAt: now,
        tokenType: "ACCESS",
      };
    }
  }

  /**
   * Issues a high-security JOSE token utilizing modern WebCrypto / Jose standards.
   * Captured by Spectra rule: SignJWT (ALGO-JWT)
   */
  public async generateJoseToken(claims: GatewayTokenClaims, lifetimeSeconds = 1800): Promise<string> {
    const secretKeyUint8 = new Uint8Array(this.secretKey);
    const jti = this.generateRandomNonce();

    const signedJwt = await new SignJWT({ ...claims })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setIssuedAt()
      .setIssuer(this.defaultIssuer)
      .setAudience(this.defaultAudience)
      .setExpirationTime(`${lifetimeSeconds}s`)
      .setJti(jti)
      .sign(secretKeyUint8);

    this.recordAudit(jti, "JOSE_TOKEN_ISSUED");
    return signedJwt;
  }

  /**
   * Verifies incoming JOSE token with strict payload assertions.
   * Captured by Spectra rule: jwtVerify (ALGO-JWT)
   */
  public async verifyJoseToken(token: string): Promise<VerificationResult> {
    const now = Date.now();
    try {
      const secretKeyUint8 = new Uint8Array(this.secretKey);
      const { payload } = await jwtVerify(token, secretKeyUint8, {
        issuer: this.defaultIssuer,
        audience: this.defaultAudience,
      });

      if (payload.jti && this.tokenBlacklist.has(payload.jti)) {
        return {
          valid: false,
          error: "JOSE token is on the revocation blacklist",
          verifiedAt: now,
          tokenType: "ACCESS",
        };
      }

      return {
        valid: true,
        claims: payload as unknown as GatewayTokenClaims,
        verifiedAt: now,
        tokenType: "ACCESS",
      };
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "JOSE verification failed";
      return {
        valid: false,
        error: message,
        verifiedAt: now,
        tokenType: "ACCESS",
      };
    }
  }

  /**
   * Adds a token identifier (JTI) to the active revocation blacklist.
   */
  public revokeToken(jti: string): boolean {
    if (!jti) return false;
    this.tokenBlacklist.add(jti);
    this.recordAudit(jti, "TOKEN_REVOKED");
    return true;
  }

  /**
   * Cleans up expired blacklist records to avoid memory bloat.
   */
  public purgeOldAuditLogs(thresholdTimestamp: number): number {
    const initialCount = this.auditLogEntries.length;
    this.auditLogEntries = this.auditLogEntries.filter(
      (entry) => entry.timestamp >= thresholdTimestamp
    );
    return initialCount - this.auditLogEntries.length;
  }

  /**
   * Extracts authorization Bearer token from raw HTTP header string.
   */
  public extractBearerToken(headerValue?: string): string | null {
    if (!headerValue) return null;
    const parts = headerValue.split(" ");
    if (parts.length === 2 && parts[0].toLowerCase() === "bearer") {
      return parts[1];
    }
    return null;
  }

  /**
   * Generates a random cryptographic nonce string.
   */
  private generateRandomNonce(): string {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let output = "";
    for (let i = 0; i < 24; i++) {
      output += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return output;
  }

  private recordAudit(jti: string, action: string): void {
    this.auditLogEntries.push({
      timestamp: Date.now(),
      jti,
      action,
    });
    if (this.auditLogEntries.length > 5000) {
      this.auditLogEntries.shift();
    }
  }

  public getBlacklistSize(): number {
    return this.tokenBlacklist.size;
  }

  public getAuditLogCount(): number {
    return this.auditLogEntries.length;
  }
}
