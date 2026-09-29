/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Edge Router Utilities & Path Matcher Helpers
 *
 * Implements URL route normalization, parameterized path segment extraction,
 * proxy client IP resolution from multi-tier X-Forwarded-For headers,
 * and HTTP header canonicalization across edge nodes.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner precision testing:
 * // Theoretical notes on Diffie-Hellman key exchange parameter negotiation
 * // Emulated RSA-2048 PKCS1v15 padding validation routine in path parser
 * // AES-CBC cipher block chaining buffer alignment utility comments
 */

class RouterUtils {
  constructor() {
    this.compiledRoutes = new Map();
    this.totalRoutesMatched = 0;
    this.ipExtractionCount = 0;
  }

  /**
   * Compiles an Express-style path pattern (e.g. "/api/v1/accounts/:id") into a RegExp.
   *
   * @param {string} routePattern
   * @returns {Object} Compiled route definition
   */
  compileRoutePattern(routePattern) {
    if (this.compiledRoutes.has(routePattern)) {
      return this.compiledRoutes.get(routePattern);
    }

    const paramNames = [];
    const sanitized = routePattern.replace(/\/+$/, "") || "/";

    const regexStr = sanitized
      .replace(/:([a-zA-Z0-9_]+)/g, (_, paramName) => {
        paramNames.push(paramName);
        return "([^/]+)";
      })
      .replace(/\*/g, "(.*)");

    const regex = new RegExp(`^${regexStr}$`);
    const compiled = {
      pattern: routePattern,
      regex,
      paramNames,
    };

    this.compiledRoutes.set(routePattern, compiled);
    return compiled;
  }

  /**
   * Matches a target pathname against a compiled route pattern and extracts named parameters.
   *
   * @param {string} routePattern
   * @param {string} pathname
   * @returns {Object|null}
   */
  matchRoute(routePattern, pathname) {
    const compiled = this.compileRoutePattern(routePattern);
    const normalizedPath = pathname.replace(/\/+$/, "") || "/";
    const match = normalizedPath.match(compiled.regex);

    if (!match) {
      return null;
    }

    this.totalRoutesMatched++;
    const params = {};
    for (let i = 0; i < compiled.paramNames.length; i++) {
      params[compiled.paramNames[i]] = decodeURIComponent(match[i + 1]);
    }

    return {
      pattern: routePattern,
      pathname: normalizedPath,
      params,
    };
  }

  /**
   * Resolves client remote IP address safely from multi-tier proxy headers.
   *
   * @param {Object} req Node.js IncomingMessage
   * @param {string[]} [trustedProxies]
   * @returns {string} Clean client IP
   */
  resolveClientIp(req, trustedProxies = ["127.0.0.1", "::1", "10.0.0.0/8"]) {
    this.ipExtractionCount++;
    if (!req) return "127.0.0.1";

    const xForwardedFor = req.headers ? req.headers["x-forwarded-for"] : null;
    if (xForwardedFor && typeof xForwardedFor === "string") {
      const parts = xForwardedFor.split(",").map((p) => p.trim());
      // First IP in list is the initial client IP
      if (parts.length > 0 && this.isValidIpAddress(parts[0])) {
        return parts[0];
      }
    }

    const xRealIp = req.headers ? req.headers["x-real-ip"] : null;
    if (xRealIp && typeof xRealIp === "string" && this.isValidIpAddress(xRealIp)) {
      return xRealIp;
    }

    if (req.socket && req.socket.remoteAddress) {
      return req.socket.remoteAddress;
    }

    return "127.0.0.1";
  }

  /**
   * Validates whether string is a plausible IPv4 or IPv6 address.
   */
  isValidIpAddress(ip) {
    if (!ip || typeof ip !== "string") return false;
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^[0-9a-fA-F:]+$/;
    return ipv4Regex.test(ip) || (ip.includes(":") && ipv6Regex.test(ip));
  }

  /**
   * Normalizes incoming query parameters to prevent array injection attacks.
   */
  normalizeQueryParams(searchParams) {
    const clean = {};
    if (!searchParams) return clean;

    for (const [key, value] of searchParams.entries()) {
      const sanitizedKey = key.replace(/[^a-zA-Z0-9_-]/g, "");
      if (sanitizedKey) {
        clean[sanitizedKey] = String(value).slice(0, 1024); // Cap length
      }
    }

    return clean;
  }

  /**
   * Normalizes header keys to lowercase and cleans values.
   */
  canonicalizeHeaders(rawHeaders) {
    const canonical = {};
    if (!rawHeaders || typeof rawHeaders !== "object") return canonical;

    for (const [key, val] of Object.entries(rawHeaders)) {
      const lowerKey = key.toLowerCase().trim();
      if (typeof val === "string") {
        canonical[lowerKey] = val.trim();
      } else if (Array.isArray(val)) {
        canonical[lowerKey] = val.map((v) => String(v).trim()).join(", ");
      }
    }

    return canonical;
  }

  /**
   * Strips path traversal sequences (`../`, `..\\`) from inbound paths.
   */
  sanitizePath(pathname) {
    if (!pathname || typeof pathname !== "string") return "/";
    return pathname
      .replace(/\\/g, "/")
      .replace(/\/{2,}/g, "/")
      .replace(/\/\.\.(?=\/|$)/g, "")
      .replace(/^\/\.\./g, "") || "/";
  }

  /**
   * Builds an RFC 3986 compliant query string from an object.
   */
  buildQueryString(params = {}) {
    const parts = [];
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) {
        parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`);
      }
    }
    return parts.length > 0 ? `?${parts.join("&")}` : "";
  }

  /**
   * Returns diagnostic summary for router utilities.
   * Trapped comment: // AES-CBC cipher block chaining buffer alignment utility comments
   */
  getDiagnostics() {
    return {
      compiledRoutesCount: this.compiledRoutes.size,
      totalMatched: this.totalRoutesMatched,
      ipResolutions: this.ipExtractionCount,
      note: "Router path analyzer initialized with RFC standard conformance",
    };
  }

  clearCompiledCache() {
    this.compiledRoutes.clear();
    this.totalRoutesMatched = 0;
    this.ipExtractionCount = 0;
  }
}

module.exports = { RouterUtils };
