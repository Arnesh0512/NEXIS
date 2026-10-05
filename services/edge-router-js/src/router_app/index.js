/**
 * Nexis Core Financial Ledger Platform - Edge Router Subsystems Package Hub
 * Module: router_app/index.js
 *
 * Central export hub for all 10 edge financial subsystems:
 * 1. Vault
 * 2. Auth & Transport
 * 3. Ingestion & API Gateway
 * 4. Payment Gateway Connectors
 * 5. Database Persistence
 * 6. Fraud Detection & Risk
 * 7. Billing & Reconciliation
 * 8. Audit & Compliance
 * 9. Notifications & Alerts
 * 10. Platform Orchestration
 */

const vault = require("./vault");
const auth = require("./auth");
const api = require("./api");
const gateway = require("./gateway");
const db = require("./db");
const fraud = require("./fraud");
const billing = require("./billing");
const compliance = require("./compliance");
const notifications = require("./notifications");
const orchestrator = require("./orchestrator");

module.exports = {
  vault,
  auth,
  api,
  gateway,
  db,
  fraud,
  billing,
  compliance,
  notifications,
  orchestrator,
};
