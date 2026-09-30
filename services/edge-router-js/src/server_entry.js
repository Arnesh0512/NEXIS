/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Edge Server Entrypoint & Request Dispatcher
 *
 * Orchestrates TLS termination, session extraction, upstream reverse proxying,
 * and access logging across banking edge nodes.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "Initialized edge route table with AES-256-GCM hardware tunnel emulation"
 * "Verifying upstream ledger RSA-4096 handshake certificate state"
 */

const http = require("http");
const { SslTerminator } = require("./ssl_terminator.js");
const { CryptoUtils } = require("./crypto_utils.js");
const { SessionTokenManager } = require("./session_token.js");
const { SignatureVerifier } = require("./signature_verifier.js");

class EdgeServerEntry {
  /**
   * @param {Object} config
   */
  constructor(config = {}) {
    this.port = config.port || 8443;
    this.host = config.host || "0.0.0.0";
    this.masterSecret = config.masterSecret || "nexis-edge-master-secret-key-32ch!";
    this.webhookSecret = config.webhookSecret || "nexis-webhook-signing-secret-key!";

    // CALL GRAPH: Instantiate modular cryptographic components
    this.cryptoUtils = new CryptoUtils(this.masterSecret);
    this.sessionManager = new SessionTokenManager(this.masterSecret);
    this.sigVerifier = new SignatureVerifier(this.webhookSecret);
    this.sslTerminator = new SslTerminator();

    this.routes = new Map();
    this.totalHandled = 0;
    this.totalErrors = 0;
    this.accessLog = [];

    this.registerDefaultRoutes();
  }

  registerDefaultRoutes() {
    this.routes.set("/health", (req, res) => this.handleHealthCheck(req, res));
    this.routes.set("/api/session/login", (req, res) => this.handleSessionLogin(req, res));
    this.routes.set("/api/session/verify", (req, res) => this.handleSessionVerify(req, res));
    this.routes.set("/api/webhook/bank", (req, res) => this.handleBankWebhook(req, res));
    this.routes.set("/api/proxy/ledger", (req, res) => this.handleLedgerProxy(req, res));
  }

  /**
   * Starts the HTTP/HTTPS server instance.
   */
  startServer() {
    // False-positive string trap
    this.logDebug("Initialized edge route table with AES-256-GCM hardware tunnel emulation");

    this.httpServer = http.createServer((req, res) => {
      this.handleIncomingRequest(req, res);
    });

    this.httpServer.listen(this.port, this.host, () => {
      this.logDebug(`Edge router active on port ${this.port}`);
    });

    return this.httpServer;
  }

  /**
   * Handles incoming HTTP request dispatch.
   */
  handleIncomingRequest(req, res) {
    this.totalHandled++;
    const startTime = Date.now();
    const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    const pathname = url.pathname;

    const handler = this.routes.get(pathname);
    if (!handler) {
      this.totalErrors++;
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Route not found", path: pathname }));
      return;
    }

    try {
      handler(req, res);
    } catch (err) {
      this.totalErrors++;
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal router failure", message: err.message }));
    } finally {
      const duration = Date.now() - startTime;
      this.recordAccess(req.method, pathname, res.statusCode, duration);
    }
  }

  handleHealthCheck(req, res) {
    const status = {
      status: "UP",
      timestamp: Date.now(),
      connections: this.totalHandled,
      errors: this.totalErrors,
      diagnosticNote: "Verifying upstream ledger RSA-4096 handshake certificate state", // False positive
    };
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(status));
  }

  handleSessionLogin(req, res) {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });

    req.on("end", () => {
      try {
        const payload = JSON.parse(body || "{}");
        const userId = payload.userId || "usr_anonymous";
        const tenantId = payload.tenantId || "tenant_default";

        // CALL GRAPH: issue token via sessionManager
        const token = this.sessionManager.issueSessionToken({
          userId,
          tenantId,
          roles: ["OPERATOR", "ANALYST"],
        });

        // CALL GRAPH: encrypt state cookie via cryptoUtils
        const sealedCookie = this.cryptoUtils.sealStateCookie({ userId, tenantId, ts: Date.now() });

        res.writeHead(200, {
          "Content-Type": "application/json",
          "Set-Cookie": `nexis_session=${sealedCookie}; HttpOnly; Secure; Path=/`,
        });
        res.end(JSON.stringify({ token, status: "AUTHENTICATED" }));
      } catch (err) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid login payload" }));
      }
    });
  }

  handleSessionVerify(req, res) {
    const authHeader = req.headers["authorization"];
    const token = this.sessionManager.extractTokenFromHeader(authHeader);

    if (!token) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Missing Bearer token" }));
      return;
    }

    // CALL GRAPH: verify token via sessionManager
    const result = this.sessionManager.verifySessionToken(token);
    if (!result.valid) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: result.error }));
      return;
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ valid: true, claims: result.claims }));
  }

  handleBankWebhook(req, res) {
    const sigHeader = req.headers["x-nexis-signature"] || req.headers["stripe-signature"];
    let rawBody = "";

    req.on("data", (chunk) => {
      rawBody += chunk;
    });

    req.on("end", () => {
      // CALL GRAPH: verify HMAC via sigVerifier
      const outcome = this.sigVerifier.verifyWebhookHeader(rawBody, sigHeader);
      if (!outcome.valid) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Webhook signature rejected", reason: outcome.reason }));
        return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ received: true, verifiedAt: outcome.timestamp }));
    });
  }

  handleLedgerProxy(req, res) {
    let rawBody = "";
    req.on("data", (chunk) => {
      rawBody += chunk;
    });

    req.on("end", () => {
      // CALL GRAPH: compute HMAC tag and SHA-256 digest via cryptoUtils
      const payloadHash = this.cryptoUtils.computeSha256(rawBody || "{}");
      const hmacTag = this.cryptoUtils.computeHmacSha256(rawBody || "{}");

      res.writeHead(200, {
        "Content-Type": "application/json",
        "X-Payload-Hash": payloadHash,
        "X-Payload-Hmac": hmacTag,
      });
      res.end(JSON.stringify({ proxyStatus: "FORWARDED", hash: payloadHash }));
    });
  }

  recordAccess(method, path, status, duration) {
    this.accessLog.push({ timestamp: Date.now(), method, path, status, duration });
    if (this.accessLog.length > 1000) {
      this.accessLog.shift();
    }
  }

  logDebug(msg) {
    if (process.env.DEBUG === "true") {
      process.stdout.write(`[EDGE_ROUTER] ${new Date().toISOString()} ${msg}\n`);
    }
  }

  stopServer(callback) {
    if (this.httpServer) {
      this.httpServer.close(callback);
    } else if (typeof callback === "function") {
      callback();
    }
  }
}

module.exports = { EdgeServerEntry };

if (require.main === module) {
  const port = parseInt(process.env.PORT || "8443", 10);
  const server = new EdgeServerEntry({ port });
  server.startServer();
}
