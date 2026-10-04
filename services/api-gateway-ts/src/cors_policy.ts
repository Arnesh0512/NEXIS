/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Cross-Origin Resource Sharing (CORS) Security Engine
 *
 * Enforces strict origin allowlists, handles preflight OPTIONS requests,
 * and attaches security headers (HSTS, CSP, X-Content-Type-Options) to
 * mitigate browser-based cross-origin exploitation against banking APIs.
 */

export interface CorsConfiguration {
  allowedOrigins: string[];
  allowedMethods: string[];
  allowedHeaders: string[];
  exposedHeaders: string[];
  allowCredentials: boolean;
  maxAgeSeconds: number;
  strictOriginCheck: boolean;
}

export interface CorsEvaluationResult {
  isAllowed: boolean;
  isPreflight: boolean;
  headersToApply: Record<string, string>;
  rejectionReason?: string;
}

export class CorsPolicyManager {
  private readonly config: CorsConfiguration;
  private readonly originRegexPatterns: RegExp[];
  private allowedOriginSet: Set<string>;
  private auditCounter: number = 0;
  private rejectedOriginCounter: number = 0;

  constructor(customConfig?: Partial<CorsConfiguration>) {
    this.config = {
      allowedOrigins: customConfig?.allowedOrigins ?? [
        "https://app.nexis.io",
        "https://admin.nexis.io",
        "https://checkout.nexis.io",
        "http://localhost:3030",
      ],
      allowedMethods: customConfig?.allowedMethods ?? [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
      ],
      allowedHeaders: customConfig?.allowedHeaders ?? [
        "Authorization",
        "Content-Type",
        "X-Nexis-Correlation-Id",
        "X-Nexis-Tenant-Id",
        "X-Requested-With",
        "Accept",
        "Origin",
      ],
      exposedHeaders: customConfig?.exposedHeaders ?? [
        "X-Nexis-Correlation-Id",
        "X-Nexis-Signature",
        "X-Nexis-Hmac",
        "X-Nexis-Timestamp",
        "Content-Length",
      ],
      allowCredentials: customConfig?.allowCredentials ?? true,
      maxAgeSeconds: customConfig?.maxAgeSeconds ?? 86400, // 24 hours
      strictOriginCheck: customConfig?.strictOriginCheck ?? true,
    };

    this.allowedOriginSet = new Set(this.config.allowedOrigins);
    this.originRegexPatterns = [
      /^https:\/\/.*\.nexis\.io$/,
      /^https:\/\/.*\.internal\.nexis\.io$/,
    ];
  }

  /**
   * Evaluates incoming request headers and constructs response headers.
   */
  public evaluateRequest(
    method: string,
    requestOrigin?: string,
    requestedHeaders?: string
  ): CorsEvaluationResult {
    this.auditCounter++;
    const isPreflight = method.toUpperCase() === "OPTIONS";

    // Non-CORS request without Origin header
    if (!requestOrigin) {
      return {
        isAllowed: true,
        isPreflight: false,
        headersToApply: this.getBaseSecurityHeaders(),
      };
    }

    // Verify origin
    const originValid = this.isOriginAllowed(requestOrigin);
    if (!originValid) {
      this.rejectedOriginCounter++;
      return {
        isAllowed: false,
        isPreflight,
        headersToApply: this.getBaseSecurityHeaders(),
        rejectionReason: `Origin ${requestOrigin} is not in authorized allowlist`,
      };
    }

    const headers: Record<string, string> = {
      ...this.getBaseSecurityHeaders(),
      "Access-Control-Allow-Origin": requestOrigin,
      "Vary": "Origin",
    };

    if (this.config.allowCredentials) {
      headers["Access-Control-Allow-Credentials"] = "true";
    }

    if (this.config.exposedHeaders.length > 0) {
      headers["Access-Control-Expose-Headers"] = this.config.exposedHeaders.join(", ");
    }

    // Preflight specific headers
    if (isPreflight) {
      headers["Access-Control-Allow-Methods"] = this.config.allowedMethods.join(", ");
      headers["Access-Control-Max-Age"] = String(this.config.maxAgeSeconds);

      if (requestedHeaders) {
        const validatedHeaders = this.validateRequestedHeaders(requestedHeaders);
        headers["Access-Control-Allow-Headers"] = validatedHeaders;
      } else {
        headers["Access-Control-Allow-Headers"] = this.config.allowedHeaders.join(", ");
      }
    }

    return {
      isAllowed: true,
      isPreflight,
      headersToApply: headers,
    };
  }

  /**
   * Checks if an origin string matches explicit list or wildcard patterns.
   */
  public isOriginAllowed(origin: string): boolean {
    if (this.allowedOriginSet.has(origin)) {
      return true;
    }

    if (!this.config.strictOriginCheck && (origin === "null" || origin === "*")) {
      return false; // Never permit wildcard in banking API
    }

    for (const pattern of this.originRegexPatterns) {
      if (pattern.test(origin)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Sanitizes and verifies requested headers against allowlist.
   */
  private validateRequestedHeaders(requestedHeadersStr: string): string {
    const requested = requestedHeadersStr.split(",").map((h) => h.trim().toLowerCase());
    const allowedMap = new Map<string, string>();
    for (const h of this.config.allowedHeaders) {
      allowedMap.set(h.toLowerCase(), h);
    }

    const approved: string[] = [];
    for (const reqHeader of requested) {
      if (allowedMap.has(reqHeader)) {
        approved.push(allowedMap.get(reqHeader)!);
      }
    }

    return approved.length > 0 ? approved.join(", ") : this.config.allowedHeaders.join(", ");
  }

  /**
   * Security defense-in-depth headers applied unconditionally to all edge responses.
   */
  private getBaseSecurityHeaders(): Record<string, string> {
    return {
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block",
      "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none';",
    };
  }

  public addAllowedOrigin(origin: string): void {
    if (origin.startsWith("http://") && !origin.includes("localhost")) {
      throw new Error("Plain HTTP origins are strictly prohibited in production CORS policy.");
    }
    this.allowedOriginSet.add(origin);
  }

  public removeAllowedOrigin(origin: string): boolean {
    return this.allowedOriginSet.delete(origin);
  }

  public getPolicyMetrics(): { totalEvaluated: number; rejectedOrigins: number; activeOrigins: number } {
    return {
      totalEvaluated: this.auditCounter,
      rejectedOrigins: this.rejectedOriginCounter,
      activeOrigins: this.allowedOriginSet.size,
    };
  }
}
