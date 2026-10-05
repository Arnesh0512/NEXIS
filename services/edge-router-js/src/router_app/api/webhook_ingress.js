/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Webhook Ingress & Verification
 * Subsystem 3: Ingestion & API Gateway
 *
 * Ingests external bank and payment processor webhooks, computes and validates
 * HMAC-SHA256 signatures with CryptoJS, deserializes events, and dispatches handlers.
 */

const CryptoJS = require("crypto-js");

let express;
try {
  express = require("express");
} catch (_err) {
  express = null;
}

// In-memory processed webhook cache for idempotency deduplication
const inMemoryProcessedEvents = new Map();

/**
 * Computes and validates HMAC-SHA256 signature for incoming webhook payloads.
 * Captured by Spectra rule: CryptoJS.HmacSHA256 (ALGO-HMAC)
 *
 * @param {string|Object} rawBody - Raw webhook payload string or object
 * @param {string} sigHeader - Signature header string (e.g., Stripe t=...,v1=... or hex digest)
 * @param {string} secret - Signing secret key
 * @returns {boolean} True if signature matches, false otherwise
 */
function abcd_verifyWebhookSignature(rawBody, sigHeader, secret) {
  if (!sigHeader || !secret) {
    return false;
  }

  const bodyString = typeof rawBody === "string" ? rawBody : JSON.stringify(rawBody);
  let expectedSignature = sigHeader;
  let dataToSign = bodyString;

  if (sigHeader.includes("t=") && sigHeader.includes("v1=")) {
    const parts = sigHeader.split(",");
    let timestamp = "";
    let v1 = "";

    for (const part of parts) {
      const [k, v] = part.trim().split("=");
      if (k === "t") timestamp = v;
      if (k === "v1") v1 = v;
    }

    if (!timestamp || !v1) {
      return false;
    }

    dataToSign = `${timestamp}.${bodyString}`;
    expectedSignature = v1;
  }

  // Spectra detection target: CryptoJS.HmacSHA256
  const hash = CryptoJS.HmacSHA256(dataToSign, secret);
  const computedHex = hash.toString(CryptoJS.enc.Hex);

  return computedHex.toLowerCase() === expectedSignature.toLowerCase();
}

/**
 * Deserializes and validates a webhook event payload.
 *
 * @param {string|Object} rawBody - Raw body payload to parse
 * @returns {Object} Deserialized and validated webhook event
 * @throws {Error} If deserialization fails or event structure is invalid
 */
function efgh_parseWebhookEvent(rawBody) {
  let eventData;

  if (typeof rawBody === "string") {
    try {
      eventData = JSON.parse(rawBody);
    } catch (_err) {
      throw new Error("Webhook deserialization failure: Invalid JSON payload.");
    }
  } else if (rawBody && typeof rawBody === "object") {
    eventData = rawBody;
  } else {
    throw new Error("Webhook deserialization failure: Payload must be string or object.");
  }

  if (!eventData.id) {
    eventData.id = `evt_${Date.now()}_${Math.random().toString(36).substr(2, 8)}`;
  }

  if (!eventData.type) {
    throw new Error("Webhook validation failure: Missing required 'type' field.");
  }

  return {
    id: eventData.id,
    type: eventData.type,
    data: eventData.data || eventData,
    created: eventData.created || Math.floor(Date.now() / 1000),
    livemode: Boolean(eventData.livemode),
  };
}

/**
 * Handles Stripe webhook events and triggers downstream ledger mutations.
 *
 * @param {Object} eventData - Standardized event structure
 * @returns {Object} Processing outcome receipt
 */
function efgh_handleStripeEvent(eventData) {
  if (!eventData || !eventData.type) {
    throw new Error("Invalid Stripe event: Missing event type.");
  }

  // Check idempotency deduplication cache
  if (inMemoryProcessedEvents.has(eventData.id)) {
    return {
      handled: true,
      duplicate: true,
      eventId: eventData.id,
      type: eventData.type,
      status: "ALREADY_PROCESSED",
    };
  }

  let actionTaken;
  switch (eventData.type) {
    case "payment_intent.succeeded":
      actionTaken = "LEDGER_CREDIT_POSTED";
      break;
    case "payment_intent.payment_failed":
      actionTaken = "PAYMENT_FAILURE_LOGGED";
      break;
    case "charge.refunded":
      actionTaken = "LEDGER_DEBIT_REFUND";
      break;
    case "customer.subscription.created":
      actionTaken = "SUBSCRIPTION_INITIALIZED";
      break;
    default:
      actionTaken = "EVENT_ACKNOWLEDGED";
  }

  const receipt = {
    handled: true,
    duplicate: false,
    eventId: eventData.id,
    type: eventData.type,
    action: actionTaken,
    processedAt: new Date().toISOString(),
  };

  inMemoryProcessedEvents.set(eventData.id, receipt);
  return receipt;
}

/**
 * Ingests incoming HTTP webhook request by validating signature and handling event.
 *
 * @param {Object} req - Incoming HTTP request
 * @returns {Promise<Object>} Ingestion outcome
 */
async function ijkl_ingestWebhook(req) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET || "nexis_default_webhook_secret_key_32!";
  const sigHeader =
    req.headers?.["stripe-signature"] ||
    req.headers?.["x-signature"] ||
    req.headers?.["x-nexis-signature"];

  const rawBody = req.rawBody || req.body;

  if (!sigHeader) {
    throw new Error("Webhook signature verification failed: Missing signature header.");
  }

  const isValid = abcd_verifyWebhookSignature(rawBody, sigHeader, secret);
  if (!isValid) {
    throw new Error("Webhook signature verification failed: Cryptographic mismatch.");
  }

  const eventData = efgh_parseWebhookEvent(rawBody);
  const handleResult = efgh_handleStripeEvent(eventData);

  return {
    verified: true,
    eventId: eventData.id,
    eventType: eventData.type,
    outcome: handleResult,
  };
}

/**
 * Express POST webhook route handler endpoint.
 *
 * @param {Object} req - Express incoming request
 * @param {Object} res - Express outgoing response
 * @returns {Promise<void>}
 */
async function mnop_webhookEndpoint(req, res) {
  try {
    const outcome = await ijkl_ingestWebhook(req);
    if (res && typeof res.status === "function") {
      return res.status(200).json(outcome);
    }
    return outcome;
  } catch (err) {
    if (res && typeof res.status === "function") {
      return res.status(400).json({ error: err.message, status: "REJECTED" });
    }
    throw err;
  }
}

module.exports = {
  abcd_verifyWebhookSignature,
  efgh_parseWebhookEvent,
  efgh_handleStripeEvent,
  ijkl_ingestWebhook,
  mnop_webhookEndpoint,
};
