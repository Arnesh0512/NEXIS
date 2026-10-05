/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 3: Ingestion & API Gateway - Module Barrel Index
 */

const paymentEndpoints = require("./payment_endpoints.js");
const webhookIngress = require("./webhook_ingress.js");
const settlementRouter = require("./settlement_router.js");
const checkoutSession = require("./checkout_session.js");
const rateLimitingGuard = require("./rate_limiting_guard.js");

module.exports = {
  // Payment Endpoints
  ...paymentEndpoints,
  paymentEndpoints,

  // Webhook Ingress
  ...webhookIngress,
  webhookIngress,

  // Settlement Router
  ...settlementRouter,
  settlementRouter,

  // Checkout Session
  ...checkoutSession,
  checkoutSession,

  // Rate Limiting Guard
  ...rateLimitingGuard,
  rateLimitingGuard,
};
