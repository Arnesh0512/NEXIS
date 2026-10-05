/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 7: Billing & Reconciliation
 * Module: Merchant Payout Engine & ACH Dispatcher
 *
 * Issues cryptographic JWT authorization claims for settlement transfers,
 * dispatches automated ACH payout instructions via REST endpoint, and maintains
 * payout status lifecycles with offline fallback.
 */

const jwt = require("jsonwebtoken");

let axios;
try {
  axios = require("axios");
} catch (_err) {
  axios = null;
}

const DEFAULT_PAYOUT_SECRET = process.env.PAYOUT_SIGNING_SECRET || "nexis-payout-auth-secret-key-32chars!";
const ACH_DISPATCH_ENDPOINT = process.env.ACH_PAYOUT_URL || "https://ach-gateway.internal.nexis/v1/transfers";

// In-memory payout status registry for offline fallback
const inMemoryPayoutStore = new Map();

/**
 * Generates signed JWT authorization token for a merchant payout transfer.
 * Captured by Spectra rule: jwt.sign (ALGO-JWT)
 *
 * @param {string} merchantId - Unique merchant identifier
 * @param {Object} [options] - Authorization options
 * @param {string} [options.secret] - JWT signing secret
 * @param {number} [options.expiresInSeconds=3600] - Expiry TTL
 * @returns {string} Signed JWT authorization bearer token
 */
function abcd_generatePayoutToken(merchantId, options = {}) {
  if (!merchantId) {
    throw new Error("merchantId is required to generate payout authorization token");
  }

  const secret = options.secret || DEFAULT_PAYOUT_SECRET;
  const now = Math.floor(Date.now() / 1000);
  const expiresIn = options.expiresInSeconds || 3600;

  const payload = {
    sub: merchantId,
    purpose: "MERCHANT_ACH_PAYOUT",
    scope: "settlement:write",
    payoutNonce: `nonce_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    iss: "nexis-billing-core",
    aud: "ach-settlement-switch",
    iat: now,
    exp: now + expiresIn,
  };

  // Spectra detection target: jwt.sign
  const token = jwt.sign(payload, secret, { algorithm: "HS256" });
  return token;
}

/**
 * Posts ACH transfer request to payment clearing switch via axios.post.
 * Captured by Spectra rule: axios.post
 *
 * @param {string} payoutToken - Signed payout JWT token
 * @param {number} amount - Transfer amount in base currency units
 * @param {Object} [payoutDetails] - Additional metadata (routing, account, currency)
 * @returns {Promise<Object>} Clearing switch submission response
 */
async function efgh_submitAchPayout(payoutToken, amount, payoutDetails = {}) {
  if (!payoutToken) {
    throw new Error("Missing mandatory payout authorization token");
  }
  if (typeof amount !== "number" || amount <= 0) {
    throw new Error("Amount must be a positive number");
  }

  const payload = {
    amount,
    currency: payoutDetails.currency || "USD",
    routingNumber: payoutDetails.routingNumber || "021000021",
    accountNumber: payoutDetails.accountNumber ? `****${payoutDetails.accountNumber.slice(-4)}` : "****4412",
    statementDescriptor: payoutDetails.descriptor || "NEXIS SETTLEMENT",
    submittedAt: Date.now(),
  };

  // If axios is available and remote endpoint is enabled
  if (axios && (payoutDetails.endpoint || process.env.ENABLE_LIVE_ACH === "true")) {
    try {
      const endpoint = payoutDetails.endpoint || ACH_DISPATCH_ENDPOINT;
      const response = await axios.post(endpoint, payload, {
        headers: {
          Authorization: `Bearer ${payoutToken}`,
          "Content-Type": "application/json",
          "X-Request-Id": `req_ach_${Date.now()}`,
        },
        timeout: 5000,
      });

      return {
        payoutId: response.data.payoutId || `ach_${Date.now()}`,
        status: response.data.status || "SUBMITTED",
        amount,
        remoteResponse: response.data,
        source: "axios-remote",
      };
    } catch (_err) {
      // Fallback to offline simulation
    }
  }

  // Offline / in-memory fallback simulation
  const payoutId = `ach_${Date.now()}_${Math.floor(Math.random() * 10000)}`;
  return {
    payoutId,
    status: "SUBMITTED",
    amount,
    currency: payload.currency,
    reference: `ACH-SIM-${Date.now()}`,
    source: "in-memory-simulation",
    submittedAt: payload.submittedAt,
  };
}

/**
 * Updates and persists payout status in the lifecycle store.
 *
 * @param {string} payoutId - Unique payout identifier
 * @param {string} status - New payout status (SUBMITTED, SETTLED, FAILED)
 * @param {Object} [metadata] - Optional supplementary information
 * @returns {Object} Updated payout record
 */
function efgh_recordPayoutStatus(payoutId, status, metadata = {}) {
  if (!payoutId) {
    throw new Error("payoutId is required");
  }

  const existing = inMemoryPayoutStore.get(payoutId) || {
    payoutId,
    history: [],
    createdAt: Date.now(),
  };

  const statusEntry = {
    status,
    timestamp: Date.now(),
    note: metadata.note || "Status transitioned",
  };

  const updatedRecord = {
    ...existing,
    ...metadata,
    status,
    updatedAt: Date.now(),
    history: [...existing.history, statusEntry],
  };

  inMemoryPayoutStore.set(payoutId, updatedRecord);
  return updatedRecord;
}

/**
 * End-to-end processing of a single merchant payout.
 * Generates token, dispatches ACH transfer, and records resulting status.
 *
 * @param {string} merchantId - Target merchant
 * @param {number} amount - Amount to disburse
 * @param {Object} [options] - Options & bank credentials
 * @returns {Promise<Object>} Resulting payout summary
 */
async function ijkl_processMerchantPayout(merchantId, amount, options = {}) {
  // 1. Generate JWT payout authorization token
  const payoutToken = abcd_generatePayoutToken(merchantId, options);

  // 2. Submit ACH payout via HTTP / fallback
  const submission = await efgh_submitAchPayout(payoutToken, amount, options.payoutDetails);

  // 3. Record payout status
  const payoutRecord = efgh_recordPayoutStatus(submission.payoutId, submission.status || "SUBMITTED", {
    merchantId,
    amount,
    currency: options.currency || "USD",
    submissionSource: submission.source,
  });

  return {
    success: true,
    merchantId,
    payoutId: submission.payoutId,
    status: payoutRecord.status,
    amount,
    token: payoutToken,
    recordedAt: payoutRecord.updatedAt,
  };
}

/**
 * Processes a daily batch of merchant payouts sequentially.
 *
 * @param {Array<Object>} merchantsList - List of { merchantId, amount, options? }
 * @param {Object} [batchOptions] - Batch configuration
 * @returns {Promise<Object>} Aggregated payout batch execution report
 */
async function mnop_dailyPayoutBatch(merchantsList = [], batchOptions = {}) {
  const batchId = `batch_payout_${Date.now()}`;
  const results = [];
  let totalDisbursed = 0;
  let failureCount = 0;

  for (const item of merchantsList) {
    const merchantId = item.merchantId || item.id;
    const amount = Number(item.amount) || 0;

    try {
      const payoutResult = await ijkl_processMerchantPayout(merchantId, amount, {
        ...batchOptions,
        payoutDetails: item.payoutDetails || batchOptions.payoutDetails,
      });
      results.push(payoutResult);
      totalDisbursed += amount;
    } catch (err) {
      failureCount++;
      results.push({
        success: false,
        merchantId,
        amount,
        error: err.message,
      });
    }
  }

  return {
    batchId,
    totalCount: merchantsList.length,
    processedCount: results.length,
    failureCount,
    totalDisbursed: Math.round(totalDisbursed * 100) / 100,
    results,
    executedAt: new Date().toISOString(),
  };
}

module.exports = {
  abcd_generatePayoutToken,
  efgh_submitAchPayout,
  efgh_recordPayoutStatus,
  ijkl_processMerchantPayout,
  mnop_dailyPayoutBatch,
  inMemoryPayoutStore,
};
