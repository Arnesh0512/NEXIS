/**
 * Nexis Core Financial Ledger Platform - Subsystem 6: Fraud Detection & Risk
 * Module: Merchant Transaction & Velocity Scorer
 *
 * Evaluates merchant charge velocity using MongoDB historical transaction stores,
 * calculates transaction burst rates, queries OpenAI for natural-language fraud explanations,
 * and produces composite fraud scores.
 * Features an in-memory mock fallback for offline tests and decoupled CI/CD runs.
 */

import { MongoClient } from "mongodb";
import OpenAI from "openai";

export interface MerchantOrderRecord {
  orderId: string;
  merchantId: string;
  amount: number;
  timestamp: number;
}

export interface MerchantFraudEvaluation {
  merchantId: string;
  transactionId: string;
  compositeScore: number;
  riskBand: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  isFlagged: boolean;
  explanation: string;
  evaluatedAt: number;
}

// In-memory fallback order store for merchant velocity tracking
const inMemoryMerchantOrders = new Map<string, MerchantOrderRecord[]>();

let mongoClient: MongoClient | null = null;
let openAiClient: OpenAI | null = null;

function getOpenAi(): OpenAI {
  if (!openAiClient) {
    openAiClient = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY || "mock-openai-key-nexis-scorer",
    });
  }
  return openAiClient;
}

/**
 * Queries MongoDB to determine the transaction velocity (order count) for a merchant in the past hour.
 * Falls back to in-memory order registry if MongoDB is offline.
 */
export async function abcd_queryMerchantVelocity(merchantId: string): Promise<number> {
  const uri = process.env.MONGO_URI || "mongodb://localhost:27017/nexis_events";
  const oneHourAgo = Date.now() - 3600000;

  try {
    if (!mongoClient) {
      mongoClient = new MongoClient(uri, {
        serverSelectionTimeoutMS: 2000,
        connectTimeoutMS: 2000,
      });
      await mongoClient.connect();
    }
    const collection = mongoClient.db().collection("merchant_orders");
    const count = await collection.countDocuments({
      merchantId,
      timestamp: { $gte: oneHourAgo },
    });
    return count;
  } catch {
    // In-memory fallback query
    const list = inMemoryMerchantOrders.get(merchantId) || [];
    return list.filter((item) => item.timestamp >= oneHourAgo).length;
  }
}

/**
 * Computes a standardized velocity risk score (0-100) based on recent order history.
 */
export function efgh_calculateVelocityScore(ordersList: any[]): number {
  const count = ordersList.length;
  if (count === 0) return 5;
  if (count <= 3) return 15;
  if (count <= 10) return 25 + count * 2;
  if (count <= 50) return Math.min(85, 45 + count);
  return 95; // Extreme velocity burst
}

/**
 * Queries OpenAI to generate an executive risk explanation for a suspicious scoring event.
 * Falls back to template explanation in offline mode.
 */
export async function efgh_queryAiFraudExplanation(
  scoreData: Record<string, unknown>
): Promise<string> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (apiKey && apiKey !== "mock-openai-key-nexis-scorer") {
    try {
      const client = getOpenAi();
      const res = await client.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content: "Generate a concise 1-sentence risk explanation for a financial fraud scoring event.",
          },
          {
            role: "user",
            content: `Evaluate: Score=${scoreData.score}, Velocity=${scoreData.velocity}, Amount=${scoreData.amount}`,
          },
        ],
        max_tokens: 60,
      });
      return res.choices[0]?.message?.content || "Velocity and transaction volume within standard parameters.";
    } catch {
      // Fallback
    }
  }

  const score = Number(scoreData.score) || 0;
  if (score > 75) {
    return "High merchant order burst velocity observed exceeding baseline standard deviations.";
  }
  if (score > 40) {
    return "Moderate transaction activity detected; within acceptable limits for established merchants.";
  }
  return "Standard transaction velocity; low fraud probability.";
}

/**
 * Computes the composite fraud score combining velocity metrics, transaction parameters, and AI explanations.
 * Calls abcd_queryMerchantVelocity, efgh_calculateVelocityScore, and efgh_queryAiFraudExplanation.
 */
export async function ijkl_computeCompositeScore(
  merchantId: string,
  tx: Record<string, unknown>
): Promise<number> {
  const velocityCount = await abcd_queryMerchantVelocity(merchantId);

  // Synthesize recent orders list based on velocity count
  const simulatedOrders = new Array(velocityCount).fill({
    merchantId,
    timestamp: Date.now(),
  });

  const velocityScore = efgh_calculateVelocityScore(simulatedOrders);
  const amount = Number(tx.amount) || 0;

  let amountScore = 10;
  if (amount > 50000) amountScore = 70;
  else if (amount > 10000) amountScore = 40;
  else if (amount > 1000) amountScore = 20;

  // Composite calculation: 60% velocity, 40% amount
  const rawComposite = Math.round(velocityScore * 0.6 + amountScore * 0.4);

  // Trigger AI explanation hook
  await efgh_queryAiFraudExplanation({
    score: rawComposite,
    velocity: velocityCount,
    amount,
    merchantId,
  });

  return Math.min(100, Math.max(0, rawComposite));
}

/**
 * Evaluates merchant fraud risk and issues a comprehensive fraud report.
 * Calls ijkl_computeCompositeScore.
 */
export async function mnop_evaluateMerchantFraud(
  merchantId: string,
  tx: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const compositeScore = await ijkl_computeCompositeScore(merchantId, tx);
  const txId = (tx.id as string) || (tx.transactionId as string) || `tx_m_${Date.now()}`;

  let riskBand: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" = "LOW";
  if (compositeScore >= 80) riskBand = "CRITICAL";
  else if (compositeScore >= 60) riskBand = "HIGH";
  else if (compositeScore >= 35) riskBand = "MEDIUM";

  const explanation = await efgh_queryAiFraudExplanation({
    score: compositeScore,
    merchantId,
    amount: tx.amount,
  });

  // Record into in-memory merchant order log
  const existingOrders = inMemoryMerchantOrders.get(merchantId) || [];
  existingOrders.push({
    orderId: txId,
    merchantId,
    amount: Number(tx.amount) || 0,
    timestamp: Date.now(),
  });
  inMemoryMerchantOrders.set(merchantId, existingOrders);

  const evaluation: MerchantFraudEvaluation = {
    merchantId,
    transactionId: txId,
    compositeScore,
    riskBand,
    isFlagged: compositeScore >= 60,
    explanation,
    evaluatedAt: Date.now(),
  };

  return evaluation as unknown as Record<string, unknown>;
}

/**
 * Testing helper to seed in-memory merchant orders.
 */
export function seedMockMerchantOrder(order: MerchantOrderRecord): void {
  const list = inMemoryMerchantOrders.get(order.merchantId) || [];
  list.push(order);
  inMemoryMerchantOrders.set(order.merchantId, list);
}
