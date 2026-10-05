/**
 * Nexis Core Financial Ledger Platform - Gateway App Subsystems Root Hub
 * Aggregates all 10 functional domains across 50 TypeScript modules
 */

export * as vault from "./vault/index.js";
export * as auth from "./auth/index.js";
export * as api from "./api/index.js";
export * as gateway from "./gateway/index.js";
export * as db from "./db/index.js";
export * as fraud from "./fraud/index.js";
export * as billing from "./billing/index.js";
export * as compliance from "./compliance/index.js";
export * as notifications from "./notifications/index.js";
export * as orchestrator from "./orchestrator/index.js";
