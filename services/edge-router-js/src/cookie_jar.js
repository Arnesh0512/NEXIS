/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: HTTP Cookie Jar & Browser State Serializer
 *
 * Implements RFC 6265 compliant HTTP cookie parsing, serialization,
 * attribute enforcement (SameSite=Strict, Secure, HttpOnly), and
 * lifecycle expiration tracking for edge routing sessions.
 */

class CookieJar {
  /**
   * @param {Object} [defaultOptions]
   */
  constructor(defaultOptions = {}) {
    this.defaultOptions = {
      path: defaultOptions.path || "/",
      secure: defaultOptions.secure !== undefined ? defaultOptions.secure : true,
      httpOnly: defaultOptions.httpOnly !== undefined ? defaultOptions.httpOnly : true,
      sameSite: defaultOptions.sameSite || "Strict",
      maxAge: defaultOptions.maxAge || 86400, // 24 hours
      domain: defaultOptions.domain || undefined,
    };
    this.cookies = new Map();
  }

  /**
   * Parses standard HTTP `Cookie` header string into a key-value dictionary.
   *
   * @param {string} cookieHeader
   * @returns {Map<string, string>}
   */
  parse(cookieHeader) {
    const result = new Map();
    if (!cookieHeader || typeof cookieHeader !== "string") {
      return result;
    }

    const pairs = cookieHeader.split(";");
    for (const pair of pairs) {
      const idx = pair.indexOf("=");
      if (idx === -1) continue;

      const key = pair.substring(0, idx).trim();
      let val = pair.substring(idx + 1).trim();

      // Unquote if wrapped in double quotes
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.slice(1, -1);
      }

      try {
        result.set(key, decodeURIComponent(val));
      } catch {
        result.set(key, val);
      }
    }

    return result;
  }

  /**
   * Serializes a single cookie into a `Set-Cookie` header value.
   *
   * @param {string} name
   * @param {string} value
   * @param {Object} [options]
   * @returns {string}
   */
  serialize(name, value, options = {}) {
    if (!name || typeof name !== "string") {
      throw new TypeError("Cookie name must be a non-empty string");
    }

    const opts = { ...this.defaultOptions, ...options };
    const encodedVal = encodeURIComponent(value);

    let str = `${name}=${encodedVal}`;

    if (opts.maxAge !== undefined) {
      const maxAge = Math.floor(opts.maxAge);
      if (isNaN(maxAge)) {
        throw new TypeError("maxAge must be an integer");
      }
      str += `; Max-Age=${maxAge}`;

      const expires = new Date(Date.now() + maxAge * 1000);
      str += `; Expires=${expires.toUTCString()}`;
    } else if (opts.expires instanceof Date) {
      str += `; Expires=${opts.expires.toUTCString()}`;
    }

    if (opts.domain) {
      str += `; Domain=${opts.domain}`;
    }

    if (opts.path) {
      str += `; Path=${opts.path}`;
    }

    if (opts.httpOnly) {
      str += "; HttpOnly";
    }

    if (opts.secure) {
      str += "; Secure";
    }

    if (opts.sameSite) {
      const sameSite = String(opts.sameSite).toLowerCase();
      if (sameSite === "strict") {
        str += "; SameSite=Strict";
      } else if (sameSite === "lax") {
        str += "; SameSite=Lax";
      } else if (sameSite === "none") {
        str += "; SameSite=None";
      }
    }

    return str;
  }

  /**
   * Stores a cookie in the local in-memory store.
   *
   * @param {string} name
   * @param {string} value
   * @param {Object} [options]
   */
  set(name, value, options = {}) {
    const opts = { ...this.defaultOptions, ...options };
    const expiresAt = opts.maxAge ? Date.now() + opts.maxAge * 1000 : null;

    this.cookies.set(name, {
      value,
      options: opts,
      createdAt: Date.now(),
      expiresAt,
    });
  }

  /**
   * Retrieves a cookie value, evaluating expiration.
   *
   * @param {string} name
   * @returns {string|null}
   */
  get(name) {
    const item = this.cookies.get(name);
    if (!item) return null;

    if (item.expiresAt && Date.now() > item.expiresAt) {
      this.cookies.delete(name);
      return null;
    }

    return item.value;
  }

  /**
   * Deletes a cookie and generates a tombstone `Set-Cookie` header.
   *
   * @param {string} name
   * @param {Object} [options]
   * @returns {string} Expiring header string
   */
  expire(name, options = {}) {
    this.cookies.delete(name);
    return this.serialize(name, "", {
      ...options,
      maxAge: 0,
      expires: new Date(0),
    });
  }

  /**
   * Cleans all expired entries from memory.
   *
   * @returns {number} Purged count
   */
  purgeExpired() {
    const now = Date.now();
    let count = 0;
    for (const [name, item] of this.cookies.entries()) {
      if (item.expiresAt && now > item.expiresAt) {
        this.cookies.delete(name);
        count++;
      }
    }
    return count;
  }

  /**
   * Exports all active Set-Cookie headers for an HTTP response.
   *
   * @returns {string[]}
   */
  exportSetCookieHeaders() {
    const headers = [];
    for (const [name, item] of this.cookies.entries()) {
      if (!item.expiresAt || Date.now() <= item.expiresAt) {
        headers.push(this.serialize(name, item.value, item.options));
      }
    }
    return headers;
  }

  /**
   * Returns telemetry for current cookie jar capacity.
   */
  getJarStatistics() {
    return {
      totalStored: this.cookies.size,
      defaultSameSite: this.defaultOptions.sameSite,
      defaultSecure: this.defaultOptions.secure,
    };
  }
}

module.exports = { CookieJar };
