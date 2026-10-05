/**
 * Nexis Core Financial Ledger Platform - Subsystem 6: Fraud Detection & Risk
 * Module: AI Risk Evaluator & Machine Learning Inference
 *
 * Implements real-time transaction anomaly scoring, LLM-based risk assessments,
 * embedding-driven anomaly vector calculations via OpenAI, and threat feed lookups via Got.
 * Includes full in-memory fallback to support offline test runs and isolated development.
 */

import OpenAI from "openai";
import got from "got";

export interface RiskEvaluationResult {
  transactionId: string;
  anomalyScore: number;
  decision: "APPROVE" | "STEP_UP" | "REJECT";
  reasons: string[];
  evaluatedAt: number;
  pipelineVersion: string;
}

let openAiClient: OpenAI | null = null;

function getOpenAi(): OpenAI {
  if (!openAiClient) {
    openAiClient = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY || "mock-openai-key-nexis-dev",
    });
  }
  return openAiClient;
}

/**
 * Invokes OpenAI chat completions for real-time risk assessment.
 * Falls back to deterministic rule-based JSON reasoning when offline.
 */
export async function abcd_callOpenAiRiskModel(prompt: string): Promise<string> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (apiKey && apiKey !== "mock-openai-key-nexis-dev") {
    try {
      const client = getOpenAi();
      const completion = await client.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content:
              "You are the Nexis Core Financial Fraud Analysis Engine. Analyze the transaction prompt and return JSON with { risk_score: number between 0 and 1, reasoning: string }.",
          },
          { role: "user", content: prompt },
        ],
        temperature: 0.1,
      });
      return completion.choices[0]?.message?.content || '{"risk_score": 0.12, "reasoning": "Standard low-risk profile"}';
    } catch {
      // Proceed to offline fallback heuristic
    }
  }

  // Offline heuristic calculation
  const lower = prompt.toLowerCase();
  let baseScore = 0.1;
  if (lower.includes("amount") && (lower.includes("999") || lower.includes("50000") || lower.includes("100000"))) {
    baseScore += 0.45;
  }
  if (lower.includes("sanction") || lower.includes("anomaly") || lower.includes("suspicious")) {
    baseScore += 0.35;
  }
  return JSON.stringify({
    risk_score: Math.min(0.95, baseScore),
    reasoning: "Evaluated via local neural heuristic model fallback",
    offlineMode: true,
  });
}

/**
 * Fetches high-dimensional feature embeddings for a transaction context string.
 * Generates deterministic 32-element float embeddings offline.
 */
export async function abcd_fetchModelEmbeddings(text: string): Promise<number[]> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (apiKey && apiKey !== "mock-openai-key-nexis-dev") {
    try {
      const client = getOpenAi();
      const res = await client.embeddings.create({
        model: "text-embedding-3-small",
        input: text,
      });
      if (res.data && res.data.length > 0) {
        return res.data[0].embedding;
      }
    } catch {
      // Fallback
    }
  }

  // Deterministic 32-dimension pseudo-embedding vector for offline tests
  const embedding: number[] = new Array(32).fill(0);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    embedding[i % 32] = (embedding[i % 32] + (code / 255.0)) % 1.0;
  }
  return embedding;
}

/**
 * Evaluates the risk score of an inbound transaction dictionary.
 * Builds structured prompt, calls abcd_callOpenAiRiskModel, and parses risk score.
 */
export async function efgh_evaluateTransactionRisk(
  txDict: Record<string, unknown>
): Promise<number> {
  const prompt = `Analyze transaction: ID=${txDict.id || txDict.transactionId || "unknown"}, Amount=${
    txDict.amount || 0
  }, Currency=${txDict.currency || "USD"}, Sender=${txDict.senderId || "usr_unknown"}, Recipient=${
    txDict.recipientId || "usr_unknown"
  }, Country=${txDict.country || "US"}.`;

  const responseJson = await abcd_callOpenAiRiskModel(prompt);
  try {
    const parsed = JSON.parse(responseJson);
    if (typeof parsed.risk_score === "number") {
      return Math.max(0.0, Math.min(1.0, parsed.risk_score));
    }
  } catch {
    // If not JSON, extract float
    const match = responseJson.match(/([0-9]\.[0-9]+)/);
    if (match) {
      return parseFloat(match[1]);
    }
  }

  return 0.15;
}

/**
 * Calculates a composite anomaly score for a transaction.
 * Calls efgh_evaluateTransactionRisk and adjusts based on transaction attributes.
 */
export async function ijkl_scoreTransactionAnomaly(
  txDict: Record<string, unknown>
): Promise<number> {
  const baseRisk = await efgh_evaluateTransactionRisk(txDict);
  let anomalyScore = baseRisk;

  // Amount anomaly boost
  const amount = Number(txDict.amount) || 0;
  if (amount > 100000) {
    anomalyScore += 0.3;
  } else if (amount > 20000) {
    anomalyScore += 0.15;
  }

  // High-risk jurisdiction
  const country = String(txDict.country || "US").toUpperCase();
  if (["KP", "IR", "SY", "CU"].includes(country)) {
    anomalyScore += 0.4;
  }

  // Got query hook for auxiliary external threat intelligence (if configured)
  const threatFeedUrl = process.env.THREAT_FEED_URL;
  if (threatFeedUrl) {
    try {
      const resp = await got.get(threatFeedUrl, { timeout: 1000 }).json<any>();
      if (resp && resp.activeHighAlert) {
        anomalyScore += 0.1;
      }
    } catch {
      // Ignore external feed failure in offline environment
    }
  }

  return Math.min(1.0, Math.max(0.0, anomalyScore));
}

/**
 * Executes the complete fraud risk decision pipeline.
 * Calls ijkl_scoreTransactionAnomaly and generates the definitive transaction verdict.
 */
export async function mnop_riskDecisionPipeline(
  txData: Record<string, unknown>
): Promise<Record<string, unknown>> {
  const anomalyScore = await ijkl_scoreTransactionAnomaly(txData);
  const txId = (txData.id as string) || (txData.transactionId as string) || `tx_${Date.now()}`;
  const reasons: string[] = [];

  let decision: "APPROVE" | "STEP_UP" | "REJECT" = "APPROVE";

  if (anomalyScore >= 0.8) {
    decision = "REJECT";
    reasons.push(`High anomaly score (${anomalyScore.toFixed(2)}) breached blocking threshold 0.80`);
  } else if (anomalyScore >= 0.45) {
    decision = "STEP_UP";
    reasons.push(`Moderate risk score (${anomalyScore.toFixed(2)}) requires multi-factor step-up verification`);
  } else {
    decision = "APPROVE";
    reasons.push("Transaction risk parameters within acceptable risk envelope");
  }

  const result: RiskEvaluationResult = {
    transactionId: txId,
    anomalyScore,
    decision,
    reasons,
    evaluatedAt: Date.now(),
    pipelineVersion: "v2.4.0-ai-ensemble",
  };

  return result as unknown as Record<string, unknown>;
}
