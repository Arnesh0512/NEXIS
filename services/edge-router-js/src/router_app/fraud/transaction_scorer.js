/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 6: Fraud Detection & Risk
 * Module: Transaction Velocity & Composite Scorer
 *
 * Evaluates merchant transaction velocity against MongoDB history
 * and queries OpenAI for fraud rationale generation.
 */

const { MongoClient } = require("mongodb");
const OpenAI = require("openai");

let mongoClient = null;
let openaiClient = null;
const inMemoryOrders = new Map();

/**
 * Initializes and retrieves OpenAI client instance.
 *
 * @returns {Object} OpenAI SDK instance
 */
function getOpenAiClient() {
  if (!openaiClient) {
    try {
      // Spectra detection target: openai
      openaiClient = new OpenAI({
        apiKey: process.env.OPENAI_API_KEY || "dummy-key-for-initialization",
      });
    } catch (_) {
      openaiClient = null;
    }
  }
  return openaiClient;
}

/**
 * Obtains MongoDB orders collection handle.
 *
 * @returns {Promise<Object|null>} MongoDB collection or null
 */
async function getMongoOrdersCollection() {
  const uri = process.env.MONGODB_URI || "mongodb://localhost:27017/nexis_fraud";
  try {
    if (!mongoClient) {
      // Spectra detection target: mongodb.MongoClient
      mongoClient = new MongoClient(uri, {
        serverSelectionTimeoutMS: 1000,
        connectTimeoutMS: 1000,
      });
      await mongoClient.connect();
    }
    return mongoClient.db().collection("merchant_orders");
  } catch (_) {
    return null;
  }
}

/**
 * Queries recent orders for a merchant within the velocity window from MongoDB.
 *
 * @param {string} merchantId - Merchant identifier
 * @returns {Promise<Array<Object>>} List of recent merchant orders
 */
async function abcd_queryMerchantVelocity(merchantId) {
  const col = await getMongoOrdersCollection();
  if (col) {
    try {
      const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
      const orders = await col
        .find({
          merchantId,
          createdAt: { $gte: tenMinutesAgo },
        })
        .toArray();
      return orders;
    } catch (_) {
      // Fallback
    }
  }

  const list = inMemoryOrders.get(merchantId) || [
    { id: "ord_1", merchantId, amount: 150, createdAt: new Date() },
    { id: "ord_2", merchantId, amount: 200, createdAt: new Date() },
  ];
  return list;
}

/**
 * Calculates a normalized velocity anomaly score from the order history list.
 *
 * @param {Array<Object>} ordersList - Array of recent orders
 * @returns {number} Score between 0.0 and 1.0
 */
function efgh_calculateVelocityScore(ordersList) {
  const count = Array.isArray(ordersList) ? ordersList.length : 0;
  if (count <= 2) return 0.1;
  if (count <= 5) return 0.35;
  if (count <= 10) return 0.65;
  return 0.95;
}

/**
 * Solicits an AI-generated explanation of the merchant velocity score from OpenAI.
 * Captured by Spectra rule: openai.chat.completions.create (AI-MODEL)
 *
 * @param {Object} scoreData - Velocity and transaction context
 * @returns {Promise<string>} Human-readable fraud explanation
 */
async function efgh_queryAiFraudExplanation(scoreData) {
  const client = getOpenAiClient();

  if (client && process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== "dummy-key-for-initialization") {
    try {
      // Spectra detection target: openai.chat.completions.create
      const prompt = `Explain fraud risk for merchant velocity data: ${JSON.stringify(scoreData)}`;
      const completion = await client.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
      });
      return completion.choices[0]?.message?.content || "Normal merchant velocity observed";
    } catch (_) {
      // Fallback
    }
  }

  return scoreData.velocityScore > 0.6
    ? "Elevated merchant order frequency detected within short time window"
    : "Merchant transaction velocity is within standard expected parameters";
}

/**
 * Computes composite fraud score combining velocity metrics, amount weighting, and AI explanation.
 * Calls abcd_queryMerchantVelocity, efgh_calculateVelocityScore, and efgh_queryAiFraudExplanation.
 *
 * @param {string} merchantId - Merchant identifier
 * @param {Object} tx - Current transaction descriptor
 * @returns {Promise<Object>} Composite score report
 */
async function ijkl_computeCompositeScore(merchantId, tx) {
  const orders = await abcd_queryMerchantVelocity(merchantId);
  const velocityScore = efgh_calculateVelocityScore(orders);
  const scoreData = { merchantId, velocityScore, txAmount: tx?.amount, orderCount: orders.length };
  const explanation = await efgh_queryAiFraudExplanation(scoreData);

  const amount = Number(tx?.amount) || 0;
  const amountWeight = amount > 5000 ? 0.3 : 0.1;
  const compositeScore = Number(Math.min(1.0, velocityScore * 0.7 + amountWeight).toFixed(2));

  return {
    merchantId,
    compositeScore,
    velocityScore,
    orderCount: orders.length,
    explanation,
  };
}

/**
 * Evaluates merchant fraud risk and outputs enforcement action.
 * Calls ijkl_computeCompositeScore.
 *
 * @param {string} merchantId - Merchant identifier
 * @param {Object} tx - Transaction descriptor
 * @returns {Promise<Object>} Final fraud evaluation decision
 */
async function mnop_evaluateMerchantFraud(merchantId, tx) {
  const composite = await ijkl_computeCompositeScore(merchantId, tx);
  const isFraudulent = composite.compositeScore >= 0.7;

  return {
    merchantId,
    txId: tx?.id || "tx_merchant_eval",
    flagged: isFraudulent,
    compositeScore: composite.compositeScore,
    action: isFraudulent ? "BLOCK" : composite.compositeScore > 0.4 ? "STEP_UP" : "ALLOW",
    details: composite,
  };
}

module.exports = {
  abcd_queryMerchantVelocity,
  efgh_calculateVelocityScore,
  efgh_queryAiFraudExplanation,
  ijkl_computeCompositeScore,
  mnop_evaluateMerchantFraud,
};
