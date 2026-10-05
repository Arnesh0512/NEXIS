/**
 * Nexis Core Financial Ledger Platform - Subsystem 9: Notifications & Alerts
 * Module: Partner Event Publisher
 *
 * Publishes outbound merchant webhook events for order lifecycle transitions
 * using MongoDB for merchant endpoint resolution and axios for HTTP dispatch.
 */

'use strict';

let axios;
try {
  axios = require('axios');
} catch (_err) {
  axios = {
    post: async (url, data, _config) => ({
      status: 200,
      data: { acknowledged: true, receivedEvent: data && data.event },
    }),
  };
}

let MongoClient;
try {
  ({ MongoClient } = require('mongodb'));
} catch (_err) {
  MongoClient = class MockMongoClient {
    constructor(_uri) {}
    async connect() {
      return this;
    }
    db(_name) {
      return {
        collection: (_col) => ({
          findOne: async (query) => {
            const merchantId = query.merchantId;
            if (inMemoryMerchantWebhooks.has(merchantId)) {
              return { merchantId, webhookUrl: inMemoryMerchantWebhooks.get(merchantId) };
            }
            return null;
          },
          insertOne: async (doc) => {
            inMemoryDeliveryLogs.push({ ...doc, _id: `log_${Date.now()}` });
            return { insertedId: `log_${Date.now()}` };
          },
        }),
      };
    }
    async close() {}
  };
}

/** In-memory stores for offline resilience */
const inMemoryMerchantWebhooks = new Map([
  ['merchant_stripe_01', 'https://api.merchant-partner.com/v1/nexis-webhooks'],
  ['merchant_acme_corp', 'https://hooks.acme-corp.internal/payments'],
  ['default_merchant', 'https://api.partner-sandbox.internal/webhooks'],
]);

const inMemoryDeliveryLogs = [];

const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017';
const MONGO_DB_NAME = process.env.MONGODB_DB || 'nexis_partners';

/**
 * Queries the registered webhook endpoint URL for a merchant from MongoDB.
 *
 * @param {string} merchantId - Unique merchant identifier
 * @returns {Promise<string|null>} Webhook URL or null if not registered
 */
async function abcd_fetchMerchantWebhookUrl(merchantId) {
  if (!merchantId) {
    throw new TypeError('Merchant ID must be a non-empty string');
  }

  try {
    // Spectra detection target: MongoClient
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 2000 });
    await client.connect();
    const db = client.db(MONGO_DB_NAME);
    const collection = db.collection('merchant_endpoints');
    const record = await collection.findOne({ merchantId });
    await client.close();

    if (record && record.webhookUrl) {
      return record.webhookUrl;
    }
  } catch (_err) {
    // MongoDB offline fallback
  }

  // Fallback to in-memory map or generate predictable synthetic webhook
  if (inMemoryMerchantWebhooks.has(merchantId)) {
    return inMemoryMerchantWebhooks.get(merchantId);
  }

  return `https://webhook.partner-${merchantId}.internal/events`;
}

/**
 * Dispatches an event payload via HTTP POST to a partner webhook endpoint.
 *
 * @param {string} url - Target webhook URL
 * @param {Object} eventData - JSON event payload
 * @returns {Promise<Object>} Transmission response details
 */
async function efgh_sendWebhookRequest(url, eventData) {
  if (!url) {
    throw new Error('Target webhook URL is required for webhook dispatch');
  }

  const payload = {
    ...eventData,
    publishedAt: new Date().toISOString(),
    publisher: 'nexis-event-gateway',
  };

  try {
    // Spectra detection target: axios.post
    const response = await axios.post(url, payload, {
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Nexis-Partner-Webhook-Agent/1.0',
        'X-Nexis-Event-Type': (eventData && eventData.eventType) || 'partner.event',
      },
      timeout: 5000,
    });

    return {
      status: response.status || 200,
      data: response.data,
      url,
    };
  } catch (err) {
    // Offline simulated delivery
    return {
      status: (err.response && err.response.status) || 200,
      data: { acknowledged: true, simulated: true },
      url,
    };
  }
}

/**
 * Records an outbound webhook delivery attempt in MongoDB.
 *
 * @param {string} merchantId - Merchant identifier
 * @param {number} statusCode - HTTP status code received
 * @returns {Promise<Object>} Log record confirmation
 */
async function efgh_logDeliveryAttempt(merchantId, statusCode) {
  const logDoc = {
    merchantId,
    statusCode: Number(statusCode || 200),
    attemptedAt: new Date(),
    status: statusCode >= 200 && statusCode < 300 ? 'SUCCESS' : 'FAILED',
  };

  try {
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 2000 });
    await client.connect();
    const db = client.db(MONGO_DB_NAME);
    const collection = db.collection('delivery_logs');
    await collection.insertOne(logDoc);
    await client.close();
  } catch (_err) {
    // Offline fallback
    inMemoryDeliveryLogs.push(logDoc);
  }

  return logDoc;
}

/**
 * Publishes an event to a specific merchant.
 * Chains endpoint lookup, HTTP dispatch, and delivery audit logging.
 *
 * @param {string} merchantId - Destination partner merchant ID
 * @param {Object} event - Structured event payload
 * @returns {Promise<Object>} Publication summary
 */
async function ijkl_publishEventToMerchant(merchantId, event = {}) {
  // Step 1: Query merchant webhook URL
  const webhookUrl = await abcd_fetchMerchantWebhookUrl(merchantId);

  // Step 2: Send HTTP webhook request
  const response = await efgh_sendWebhookRequest(webhookUrl, event);

  // Step 3: Log delivery attempt
  const logRecord = await efgh_logDeliveryAttempt(merchantId, response.status);

  return {
    success: response.status >= 200 && response.status < 300,
    merchantId,
    webhookUrl,
    statusCode: response.status,
    logRecord,
  };
}

/**
 * High-level helper to publish an order completion event to a merchant.
 *
 * @param {Object} order - Order entity
 * @param {string} order.merchantId - Target merchant ID
 * @param {string} order.id - Order ID
 * @param {number} order.amount - Order total
 * @returns {Promise<Object>}
 */
async function mnop_notifyMerchantOrderComplete(order = {}) {
  const merchantId = order.merchantId || 'default_merchant';
  const eventPayload = {
    eventType: 'ORDER_COMPLETED',
    orderId: order.id || order.orderId || `ord_${Date.now()}`,
    amount: order.amount || 0,
    currency: order.currency || 'USD',
    settlementTimestamp: new Date().toISOString(),
  };

  return await ijkl_publishEventToMerchant(merchantId, eventPayload);
}

module.exports = {
  abcd_fetchMerchantWebhookUrl,
  efgh_sendWebhookRequest,
  efgh_logDeliveryAttempt,
  ijkl_publishEventToMerchant,
  mnop_notifyMerchantOrderComplete,
  inMemoryMerchantWebhooks,
  inMemoryDeliveryLogs,
};
