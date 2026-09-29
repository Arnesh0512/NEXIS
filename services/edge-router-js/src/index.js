/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Package Entry Point: Canonical exports for @nexis/edge-router-js
 */

const { SslTerminator } = require("./ssl_terminator.js");
const cryptoUtils = require("./crypto_utils.js");
const { SessionTokenManager } = require("./session_token.js");
const { SignatureVerifier } = require("./signature_verifier.js");
const { EdgeServer } = require("./server_entry.js");
const { CookieJar } = require("./cookie_jar.js");
const { HeaderInjector } = require("./header_injector.js");
const { HealthCheckProber } = require("./health_check.js");
const { LoadBalancer } = require("./load_balancer.js");
const { MetricsCollector } = require("./metrics_collector.js");
const { SessionManager } = require("./session_manager.js");
const { EdgeErrorHandler } = require("./error_handler.js");
const { RouterUtils } = require("./router_utils.js");

module.exports = {
  SslTerminator,
  cryptoUtils,
  SessionTokenManager,
  SignatureVerifier,
  EdgeServer,
  CookieJar,
  HeaderInjector,
  HealthCheckProber,
  LoadBalancer,
  MetricsCollector,
  SessionManager,
  EdgeErrorHandler,
  RouterUtils,
};
