/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 5: Database Persistence
 * Module: MongoDB Event Stream Store
 *
 * Implements immutable payment event streaming, AES-encrypted event payload
 * persistence with CryptoJS, and lifecycle state tracking using mongodb.MongoClient.
 */

const { MongoClient } = require("mongodb");
const CryptoJS = require("crypto-js");

let mongoClient = null;
const inMemoryEvents = [];

/**
 * Obtains a MongoDB collection handle using MongoClient with fallback to in-memory store.
 *
 * @param {string} [colName='payment_events'] - Collection name
 * @returns {Promise<Object>} MongoDB Collection or compatible in-memory interface
 */
async function abcd_getMongoCollection(colName = "payment_events") {
  const uri = process.env.MONGODB_URI || "mongodb://localhost:27017/nexis_events";
  try {
    if (!mongoClient) {
      // Spectra detection target: mongodb.MongoClient
      mongoClient = new MongoClient(uri, {
        serverSelectionTimeoutMS: 1000,
        connectTimeoutMS: 1000,
      });
      await mongoClient.connect();
    }
    const db = mongoClient.db();
    return db.collection(colName);
  } catch (err) {
    // In-memory collection fallback for offline/test environments
    return {
      async insertOne(doc) {
        inMemoryEvents.push(doc);
        return { acknowledged: true, insertedId: doc._id };
      },
      find(filter = {}) {
        return {
          async toArray() {
            return inMemoryEvents.filter((item) => {
              for (const [key, value] of Object.entries(filter)) {
                if (item[key] !== value) return false;
              }
              return true;
            });
          },
        };
      },
    };
  }
}

/**
 * Encrypts event payload dictionary using CryptoJS AES cipher.
 * Captured by Spectra rule: CryptoJS.AES.encrypt (ALGO-AES)
 *
 * @param {Object|string} payload - Event payload to encrypt
 * @returns {string} Base64 ciphertext string
 */
function abcd_encryptEventPayload(payload) {
  const secret = process.env.EVENT_ENCRYPTION_KEY || "nexis-event-stream-secret-key-32!";
  const rawData = typeof payload === "string" ? payload : JSON.stringify(payload || {});

  // Spectra detection target: CryptoJS.AES.encrypt
  const encrypted = CryptoJS.AES.encrypt(rawData, secret);
  return encrypted.toString();
}

/**
 * Publishes an event to the immutable payment event stream.
 * Calls abcd_encryptEventPayload and inserts document into MongoDB.
 *
 * @param {string} eventType - Type of payment event
 * @param {Object} payload - Event payload
 * @returns {Promise<Object>} Created event document
 */
async function efgh_publishEvent(eventType, payload) {
  const col = await abcd_getMongoCollection("payment_events");
  const encryptedPayload = abcd_encryptEventPayload(payload);
  const paymentId = payload && (payload.paymentId || payload.id) ? (payload.paymentId || payload.id) : null;

  const doc = {
    _id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    eventType,
    encryptedPayload,
    paymentId,
    timestamp: new Date(),
  };

  try {
    await col.insertOne(doc);
  } catch (err) {
    inMemoryEvents.push(doc);
  }

  return doc;
}

/**
 * Queries payment event stream for a specific payment ID.
 *
 * @param {string} paymentId - Payment identifier
 * @returns {Promise<Array<Object>>} List of payment event records
 */
async function ijkl_streamPaymentEvents(paymentId) {
  const col = await abcd_getMongoCollection("payment_events");
  let events = [];
  try {
    events = await col.find({ paymentId }).toArray();
  } catch (err) {
    events = inMemoryEvents.filter((e) => e.paymentId === paymentId);
  }
  return events;
}

/**
 * Records lifecycle state transitions for a transaction.
 * Calls efgh_publishEvent.
 *
 * @param {string} paymentId - Payment identifier
 * @param {string} state - New lifecycle state (e.g. AUTHORIZED, CAPTURED, VOIDED)
 * @returns {Promise<Object>} Published event record
 */
async function mnop_recordLifecycleState(paymentId, state) {
  const payload = {
    paymentId,
    state,
    recordedAt: new Date().toISOString(),
  };
  return await efgh_publishEvent("PAYMENT_LIFECYCLE", payload);
}

module.exports = {
  abcd_getMongoCollection,
  abcd_encryptEventPayload,
  efgh_publishEvent,
  ijkl_streamPaymentEvents,
  mnop_recordLifecycleState,
};
