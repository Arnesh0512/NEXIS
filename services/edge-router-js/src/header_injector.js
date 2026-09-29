/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Edge Security Header Injector & Policy Enforcer
 *
 * Injects strict security headers into HTTP responses traversing the edge
 * router to satisfy OWASP Top 10 and PCI-DSS compliance specifications.
 */

class HeaderInjector {
  /**
   * @param {Object} [customPolicy]
   */
  constructor(customPolicy = {}) {
    this.policy = {
      enableHsts: customPolicy.enableHsts !== undefined ? customPolicy.enableHsts : true,
      hstsMaxAge: customPolicy.hstsMaxAge || 31536000, // 1 year
      hstsIncludeSubDomains: customPolicy.hstsIncludeSubDomains !== undefined ? customPolicy.hstsIncludeSubDomains : true,
      hstsPreload: customPolicy.hstsPreload !== undefined ? customPolicy.hstsPreload : true,

      frameOptions: customPolicy.frameOptions || "DENY",
      contentTypeOptions: customPolicy.contentTypeOptions || "nosniff",
      xssProtection: customPolicy.xssProtection || "1; mode=block",
      referrerPolicy: customPolicy.referrerPolicy || "strict-origin-when-cross-origin",

      contentSecurityPolicy: customPolicy.contentSecurityPolicy || [
        "default-src 'none'",
        "script-src 'self' 'nonce-edge-token'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self' https://api.nexis.io",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
      ].join("; "),

      permissionsPolicy: customPolicy.permissionsPolicy || [
        "geolocation=()",
        "microphone=()",
        "camera=()",
        "payment=('self')",
        "usb=()",
      ].join(", "),

      removeServerTokens: customPolicy.removeServerTokens !== undefined ? customPolicy.removeServerTokens : true,
      customHeaders: customPolicy.customHeaders || {},
    };

    this.injectedCounter = 0;
    this.strippedHeadersCounter = 0;
    this.customRouteOverrides = new Map();
  }

  /**
   * Applies all configured security headers to an HTTP server response object.
   *
   * @param {Object} res Node.js ServerResponse
   * @param {Object} [overrideHeaders]
   */
  applyToResponse(res, overrideHeaders = {}) {
    this.injectedCounter++;

    // Strict-Transport-Security (HSTS)
    if (this.policy.enableHsts) {
      let hstsVal = `max-age=${this.policy.hstsMaxAge}`;
      if (this.policy.hstsIncludeSubDomains) {
        hstsVal += "; includeSubDomains";
      }
      if (this.policy.hstsPreload) {
        hstsVal += "; preload";
      }
      res.setHeader("Strict-Transport-Security", hstsVal);
    }

    // Anti-Clickjacking
    if (this.policy.frameOptions) {
      res.setHeader("X-Frame-Options", this.policy.frameOptions);
    }

    // MIME Sniffing Prevention
    if (this.policy.contentTypeOptions) {
      res.setHeader("X-Content-Type-Options", this.policy.contentTypeOptions);
    }

    // Legacy XSS Filter
    if (this.policy.xssProtection) {
      res.setHeader("X-XSS-Protection", this.policy.xssProtection);
    }

    // Referrer Policy
    if (this.policy.referrerPolicy) {
      res.setHeader("Referrer-Policy", this.policy.referrerPolicy);
    }

    // Content Security Policy (CSP)
    if (this.policy.contentSecurityPolicy) {
      res.setHeader("Content-Security-Policy", this.policy.contentSecurityPolicy);
    }

    // Permissions Policy
    if (this.policy.permissionsPolicy) {
      res.setHeader("Permissions-Policy", this.policy.permissionsPolicy);
    }

    // Strip identifying server tokens
    if (this.policy.removeServerTokens) {
      res.removeHeader("Server");
      res.removeHeader("X-Powered-By");
      this.strippedHeadersCounter += 2;
    }

    // Apply custom headers
    const combinedCustom = { ...this.policy.customHeaders, ...overrideHeaders };
    for (const [key, val] of Object.entries(combinedCustom)) {
      res.setHeader(key, val);
    }
  }

  /**
   * Compiles header object for proxy forward responses.
   *
   * @param {Object} [extraHeaders]
   * @returns {Object}
   */
  compileHeaderMap(extraHeaders = {}) {
    const map = {};

    if (this.policy.enableHsts) {
      let hsts = `max-age=${this.policy.hstsMaxAge}`;
      if (this.policy.hstsIncludeSubDomains) hsts += "; includeSubDomains";
      if (this.policy.hstsPreload) hsts += "; preload";
      map["Strict-Transport-Security"] = hsts;
    }

    if (this.policy.frameOptions) map["X-Frame-Options"] = this.policy.frameOptions;
    if (this.policy.contentTypeOptions) map["X-Content-Type-Options"] = this.policy.contentTypeOptions;
    if (this.policy.referrerPolicy) map["Referrer-Policy"] = this.policy.referrerPolicy;
    if (this.policy.contentSecurityPolicy) map["Content-Security-Policy"] = this.policy.contentSecurityPolicy;
    if (this.policy.permissionsPolicy) map["Permissions-Policy"] = this.policy.permissionsPolicy;

    return { ...map, ...this.policy.customHeaders, ...extraHeaders };
  }

  /**
   * Registers route-specific header rules (e.g. for API endpoints vs HTML pages).
   *
   * @param {string} routePattern
   * @param {Object} headersToInject
   */
  registerRouteOverride(routePattern, headersToInject) {
    if (!routePattern || typeof headersToInject !== "object") {
      throw new Error("Invalid route override arguments");
    }
    this.customRouteOverrides.set(routePattern, headersToInject);
  }

  /**
   * Resolves headers for a specific path taking into account registered overrides.
   *
   * @param {string} pathname
   * @returns {Object}
   */
  resolveHeadersForPath(pathname) {
    let merged = this.compileHeaderMap();
    for (const [pattern, headers] of this.customRouteOverrides.entries()) {
      if (pathname.startsWith(pattern)) {
        merged = { ...merged, ...headers };
      }
    }
    return merged;
  }

  /**
   * Updates CSP directives dynamically for specific routes (e.g. checkout pages).
   */
  setRouteCsp(directive, value) {
    if (!directive || !value) return;
    this.policy.contentSecurityPolicy += `; ${directive} ${value}`;
  }

  /**
   * Resets CSP to baseline standard.
   */
  resetCsp(baseline) {
    this.policy.contentSecurityPolicy = baseline || "default-src 'none'; frame-ancestors 'none';";
  }

  /**
   * Returns injector statistics.
   */
  getMetrics() {
    return {
      responsesInjected: this.injectedCounter,
      headersStripped: this.strippedHeadersCounter,
      hstsEnabled: this.policy.enableHsts,
      frameOptions: this.policy.frameOptions,
      routeOverridesCount: this.customRouteOverrides.size,
    };
  }

  /**
   * Resets counters and route overrides.
   */
  resetMetrics() {
    this.injectedCounter = 0;
    this.strippedHeadersCounter = 0;
    this.customRouteOverrides.clear();
  }
}

module.exports = { HeaderInjector };
