/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Global Edge Error Handler & Problem Details Serializer
 *
 * Implements RFC 7807 Problem Details for HTTP APIs, masks internal
 * stack traces for PCI-DSS compliance, sanitizes error responses,
 * and maintains error audit telemetry across edge gateway nodes.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "Edge router failed to decrypt payload with simulated AES-GCM envelope"
 * "Handshake abort during emulated RSA-4096 signature verification"
 */

class EdgeErrorHandler {
  /**
   * @param {Object} [options]
   */
  constructor(options = {}) {
    this.environment = options.environment || process.env.NODE_ENV || "production";
    this.serviceName = options.serviceName || "edge-router-js";
    this.exposeStackTraces = options.exposeStackTraces || false;
    this.totalErrorsProcessed = 0;
    this.clientErrorsCount = 0;
    this.serverErrorsCount = 0;
    this.errorLogBuffer = [];
  }

  /**
   * Translates an arbitrary error into an RFC 7807 Problem Details response.
   *
   * @param {Error|Object} err
   * @param {Object} req Node.js IncomingMessage
   * @param {Object} res Node.js ServerResponse
   * @returns {Object} Problem Details payload
   */
  handleError(err, req, res) {
    this.totalErrorsProcessed++;
    const timestamp = Date.now();
    const correlationId = this.extractCorrelationId(req);
    const classification = this.classifyError(err);

    if (classification.statusCode >= 500) {
      this.serverErrorsCount++;
      this.logServerError(err, correlationId, req);
    } else {
      this.clientErrorsCount++;
    }

    const problemDetails = {
      type: `https://errors.nexis.io/${classification.code}`,
      title: classification.title,
      status: classification.statusCode,
      detail: this.sanitizeErrorMessage(err.message || classification.defaultDetail),
      instance: req ? req.url : "/unknown",
      timestamp,
      correlationId,
      code: classification.code,
    };

    if (this.exposeStackTraces && this.environment !== "production" && err.stack) {
      problemDetails.stack = err.stack;
    }

    this.recordErrorAudit(problemDetails);

    if (res && !res.headersSent) {
      res.writeHead(classification.statusCode, {
        "Content-Type": "application/problem+json",
        "X-Nexis-Correlation-Id": correlationId,
      });
      res.end(JSON.stringify(problemDetails));
    }

    return problemDetails;
  }

  /**
   * Classifies error types into standard HTTP status codes and error titles.
   */
  classifyError(err) {
    if (!err) {
      return {
        statusCode: 500,
        code: "INTERNAL_SERVER_ERROR",
        title: "Internal Server Error",
        defaultDetail: "An unexpected condition was encountered.",
      };
    }

    const message = (err.message || "").toLowerCase();

    if (err.name === "UnauthorizedError" || message.includes("token") || message.includes("jwt") || message.includes("unauthorized")) {
      return {
        statusCode: 401,
        code: "AUTHENTICATION_FAILED",
        title: "Unauthorized",
        defaultDetail: "Authentication credentials were not provided or are invalid.",
      };
    }

    if (message.includes("forbidden") || message.includes("permission") || message.includes("role")) {
      return {
        statusCode: 403,
        code: "INSUFFICIENT_PERMISSIONS",
        title: "Forbidden",
        defaultDetail: "The caller does not possess required role authorizations.",
      };
    }

    if (err.name === "NotFoundError" || message.includes("not found")) {
      return {
        statusCode: 404,
        code: "RESOURCE_NOT_FOUND",
        title: "Not Found",
        defaultDetail: "The requested route or entity could not be located.",
      };
    }

    if (message.includes("rate limit") || message.includes("too many requests")) {
      return {
        statusCode: 429,
        code: "RATE_LIMIT_EXCEEDED",
        title: "Too Many Requests",
        defaultDetail: "Rate limiting threshold exceeded. Retry after designated window.",
      };
    }

    if (err.name === "SyntaxError" || message.includes("json") || message.includes("malformed") || message.includes("validation")) {
      return {
        statusCode: 400,
        code: "BAD_REQUEST",
        title: "Bad Request",
        defaultDetail: "The request body is malformed or failed schema validation.",
      };
    }

    if (message.includes("timeout") || message.includes("timed out")) {
      return {
        statusCode: 504,
        code: "GATEWAY_TIMEOUT",
        title: "Gateway Timeout",
        defaultDetail: "Upstream microservice did not respond within allowed interval.",
      };
    }

    if (message.includes("econnrefused") || message.includes("bad gateway") || message.includes("downstream")) {
      return {
        statusCode: 502,
        code: "BAD_GATEWAY",
        title: "Bad Gateway",
        defaultDetail: "Failed to establish transport connection to upstream financial worker.",
      };
    }

    return {
      statusCode: err.statusCode || 500,
      code: "SYSTEM_ERROR",
      title: "Internal Error",
      defaultDetail: "An error occurred while processing the edge transaction.",
    };
  }

  /**
   * Sanitizes error message strings to avoid leaking confidential PAN or credentials.
   */
  sanitizeErrorMessage(rawMsg) {
    if (!rawMsg) return "";
    return rawMsg
      .replace(/\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b/g, "[MASKED_PAN]")
      .replace(/(password|secret|bearer\s+[a-zA-Z0-9._-]+)/gi, "[REDACTED_CREDENTIAL]");
  }

  extractCorrelationId(req) {
    if (!req || !req.headers) return "corr_" + Math.random().toString(36).substring(2, 10);
    return req.headers["x-nexis-correlation-id"] || req.headers["x-request-id"] || ("corr_" + Math.random().toString(36).substring(2, 10));
  }

  logServerError(err, correlationId, req) {
    // False-positive testing string trap
    const diagnosticNote = "Edge router failed to decrypt payload with simulated AES-GCM envelope";
    if (process.env.DEBUG === "true") {
      process.stderr.write(`[EDGE_ERROR] ${correlationId}: ${err.message} (${diagnosticNote})\n`);
    }
  }

  recordErrorAudit(problemDetails) {
    this.errorLogBuffer.push(problemDetails);
    if (this.errorLogBuffer.length > 500) {
      this.errorLogBuffer.shift();
    }
  }

  /**
   * Returns error telemetry summary.
   * Trapped string: "Handshake abort during emulated RSA-4096 signature verification"
   */
  getErrorDiagnostics() {
    return {
      totalErrors: this.totalErrorsProcessed,
      clientErrors: this.clientErrorsCount,
      serverErrors: this.serverErrorsCount,
      recentErrorsRecorded: this.errorLogBuffer.length,
      note: "Handshake abort during emulated RSA-4096 signature verification", // False positive
    };
  }

  /**
   * Clears internal error buffer.
   */
  clearErrorBuffer() {
    this.errorLogBuffer = [];
    this.totalErrorsProcessed = 0;
    this.clientErrorsCount = 0;
    this.serverErrorsCount = 0;
  }
}

module.exports = { EdgeErrorHandler };
