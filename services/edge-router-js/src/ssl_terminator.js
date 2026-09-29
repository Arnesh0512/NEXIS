/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: SSL / TLS Context Initializer & Termination Proxy
 *
 * Configures secure TLS session contexts, enforces modern cipher suites
 * (disabling legacy SSLv2/SSLv3/TLS1.0/TLS1.1), and binds edge listener sockets
 * using Node.js native tls and crypto modules.
 */

const tls = require("tls");
const crypto = require("crypto");
const fs = require("fs");

class SslTerminator {
  /**
   * @param {Object} options
   * @param {string} [options.minVersion='TLSv1.2']
   * @param {string} [options.ciphers]
   * @param {number} [options.handshakeTimeoutMs=10000]
   */
  constructor(options = {}) {
    this.minVersion = options.minVersion || "TLSv1.2";
    this.ciphers = options.ciphers || "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305";
    this.handshakeTimeoutMs = options.handshakeTimeoutMs || 10000;
    this.secureContext = null;
    this.serverInstance = null;
    this.activeConnections = new Set();
    this.handshakeSuccessCount = 0;
    this.handshakeFailureCount = 0;
    this.sniCertificates = new Map();
  }

  /**
   * Initializes the native TLS secure context.
   * Captured by Spectra rule: tls.createSecureContext (secure_transport)
   */
  initializeContext(certPem, keyPem, caPem) {
    if (!certPem || !keyPem) {
      throw new Error("SSL Certificate and Private Key PEM buffers are required.");
    }

    const contextOptions = {
      cert: certPem,
      key: keyPem,
      ca: caPem ? [caPem] : undefined,
      minVersion: this.minVersion,
      ciphers: this.ciphers,
      honorCipherOrder: true,
      sessionIdContext: this.generateSessionContextId(),
    };

    // Spectra detection target: createSecureContext
    this.secureContext = tls.createSecureContext(contextOptions);
    return this.secureContext;
  }

  /**
   * Creates and binds the TLS server socket.
   * Captured by Spectra rule: tls.createServer (secure_transport)
   */
  createTlsServer(connectionHandler) {
    if (!this.secureContext) {
      throw new Error("TLS SecureContext must be initialized prior to server creation.");
    }

    const serverOptions = {
      SNICallback: (servername, cb) => this.handleSniResolution(servername, cb),
      handshakeTimeout: this.handshakeTimeoutMs,
      requestCert: false,
      rejectUnauthorized: true,
    };

    // Spectra detection target: createServer
    this.serverInstance = tls.createServer(serverOptions, (tlsSocket) => {
      this.handleIncomingTlsConnection(tlsSocket, connectionHandler);
    });

    this.serverInstance.on("tlsClientError", (err, tlsSocket) => {
      this.handshakeFailureCount++;
      if (tlsSocket && !tlsSocket.destroyed) {
        tlsSocket.destroy();
      }
    });

    return this.serverInstance;
  }

  /**
   * Registers a dedicated SNI certificate for multi-tenant edge routing.
   */
  registerSniDomain(hostname, certPem, keyPem) {
    if (!hostname || !certPem || !keyPem) {
      throw new Error("Invalid SNI domain registration parameters.");
    }

    const domainContext = tls.createSecureContext({
      cert: certPem,
      key: keyPem,
      minVersion: this.minVersion,
      ciphers: this.ciphers,
    });

    this.sniCertificates.set(hostname.toLowerCase(), domainContext);
  }

  /**
   * Handles SNI lookup callback for multi-tenant virtual hosting.
   */
  handleSniResolution(servername, cb) {
    if (!servername) {
      return cb(null, this.secureContext);
    }

    const matchedContext = this.sniCertificates.get(servername.toLowerCase());
    if (matchedContext) {
      return cb(null, matchedContext);
    }

    // Fall back to default primary secure context
    return cb(null, this.secureContext);
  }

  /**
   * Handles established TLS socket.
   */
  handleIncomingTlsConnection(socket, customHandler) {
    this.handshakeSuccessCount++;
    const connectionId = this.generateConnectionTrackingId();
    this.activeConnections.add(socket);

    socket.on("close", () => {
      this.activeConnections.delete(socket);
    });

    socket.on("error", (err) => {
      this.activeConnections.delete(socket);
      if (!socket.destroyed) {
        socket.destroy();
      }
    });

    if (typeof customHandler === "function") {
      customHandler(socket, connectionId);
    }
  }

  /**
   * Generates a 32-byte session identifier context using CSPRNG.
   * Captured by Spectra rule: crypto.randomBytes (ALGO-CSPRNG)
   */
  generateSessionContextId() {
    return crypto.randomBytes(32).toString("hex");
  }

  /**
   * Generates tracking ID for incoming connection socket.
   * Captured by Spectra rule: crypto.randomBytes (ALGO-CSPRNG)
   */
  generateConnectionTrackingId() {
    return "conn_" + crypto.randomBytes(16).toString("hex");
  }

  /**
   * Inspects protocol cipher information on a live TLS socket.
   */
  getSocketCipherInfo(tlsSocket) {
    if (!tlsSocket || typeof tlsSocket.getCipher !== "function") {
      return null;
    }
    const cipher = tlsSocket.getCipher();
    const protocol = tlsSocket.getProtocol();
    const authorized = tlsSocket.authorized;

    return {
      name: cipher ? cipher.name : "UNKNOWN",
      version: cipher ? cipher.version : "UNKNOWN",
      protocol: protocol || "UNKNOWN",
      authorized,
    };
  }

  /**
   * Gracefully shuts down the TLS server and terminates remaining open sockets.
   */
  shutdownServer(callback) {
    for (const socket of this.activeConnections) {
      if (!socket.destroyed) {
        socket.end();
      }
    }
    this.activeConnections.clear();

    if (this.serverInstance) {
      this.serverInstance.close(callback);
    } else if (typeof callback === "function") {
      callback();
    }
  }

  /**
   * Returns operational statistics for edge monitoring.
   */
  getStatistics() {
    return {
      activeConnections: this.activeConnections.size,
      handshakeSuccesses: this.handshakeSuccessCount,
      handshakeFailures: this.handshakeFailureCount,
      sniDomainCount: this.sniCertificates.size,
      minVersion: this.minVersion,
      ciphers: this.ciphers,
    };
  }
}

module.exports = { SslTerminator };
