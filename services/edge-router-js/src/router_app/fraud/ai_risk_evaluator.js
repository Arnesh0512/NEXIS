/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 6: Fraud Detection & Risk
 * Module: AI Risk Evaluator
 *
 * Employs OpenAI LLM evaluation and embedding models, augmented with
 * external HTTP risk models via got, to assess transaction risk.
 */

const OpenAI = require("openai");
const got = require("got");

let openaiClient = null;

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
    } catch (err) {
      openaiClient = null;
    }
  }
  return openaiClient;
}

/**
 * Calls OpenAI risk model or falls back to HTTP engine / local heuristics.
 * Captured by Spectra rule: openai.chat.completions.create (AI-MODEL)
 *
 * @param {string|Object} prompt - Input risk prompt or transaction payload
 * @returns {Promise<string>} Model evaluation response
 */
async function abcd_callOpenAiRiskModel(prompt) {
  const client = getOpenAiClient();
  const promptStr = typeof prompt === "string" ? prompt : JSON.stringify(prompt || {});

  if (client && process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== "dummy-key-for-initialization") {
    try {
      // Spectra detection target: openai.chat.completions.create
      const response = await client.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: promptStr }],
        temperature: 0.1,
      });
      return response.choices[0]?.message?.content || "Risk assessment completed: low risk";
    } catch (err) {
      // Fallback
    }
  }

  // Spectra detection target: got
  try {
    if (process.env.RISK_ENGINE_URL) {
      const res = await got.post(process.env.RISK_ENGINE_URL, {
        json: { prompt: promptStr },
        timeout: 500,
        responseType: "json",
      });
      return JSON.stringify(res.body);
    }
  } catch (err) {
    // Fallback to local heuristic
  }

  const promptLower = promptStr.toLowerCase();
  const isHighRisk =
    promptLower.includes("high") ||
    promptLower.includes("fraud") ||
    promptLower.includes("anomaly") ||
    promptLower.includes("stolen");

  return JSON.stringify({
    riskScore: isHighRisk ? 0.85 : 0.15,
    flagged: isHighRisk,
    reasoning: isHighRisk
      ? "Heuristic risk flagged: potential anomaly detected"
      : "Heuristic risk low: normal transaction parameters",
  });
}

/**
 * Generates vector embeddings for transaction text using OpenAI SDK.
 * Captured by Spectra rule: openai.embeddings.create (AI-EMBEDDINGS)
 *
 * @param {string} text - Input text representation
 * @returns {Promise<number[]>} Embedding vector
 */
async function abcd_fetchModelEmbeddings(text) {
  const client = getOpenAiClient();

  if (client && process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== "dummy-key-for-initialization") {
    try {
      // Spectra detection target: openai.embeddings.create
      const response = await client.embeddings.create({
        model: "text-embedding-3-small",
        input: text,
      });
      return response.data[0]?.embedding || [];
    } catch (err) {
      // Fallback to simulated vector
    }
  }

  // Deterministic 32-dimensional mock embedding for offline test execution
  const str = String(text || "");
  const vector = [];
  for (let i = 0; i < 32; i++) {
    const code = str.charCodeAt(i % Math.max(1, str.length)) || 65;
    vector.push(parseFloat(((code * (i + 1)) % 100 / 100).toFixed(4)));
  }
  return vector;
}

/**
 * Evaluates transaction risk by querying AI risk model.
 * Calls abcd_callOpenAiRiskModel.
 *
 * @param {Object} txDict - Transaction dictionary
 * @returns {Promise<Object>} Risk evaluation result
 */
async function efgh_evaluateTransactionRisk(txDict) {
  const prompt = `Evaluate financial transaction risk: ${JSON.stringify(txDict || {})}`;
  const modelOutput = await abcd_callOpenAiRiskModel(prompt);

  let parsed;
  try {
    parsed = JSON.parse(modelOutput);
  } catch (_) {
    parsed = { riskScore: 0.2, flagged: false, reasoning: modelOutput };
  }
  return parsed;
}

/**
 * Scores transaction anomaly based on risk evaluation and financial signals.
 * Calls efgh_evaluateTransactionRisk.
 *
 * @param {Object} txDict - Transaction details
 * @returns {Promise<Object>} Anomaly score assessment
 */
async function ijkl_scoreTransactionAnomaly(txDict) {
  const evaluation = await efgh_evaluateTransactionRisk(txDict);
  const amount = Number(txDict?.amount) || 0;
  let score = typeof evaluation.riskScore === "number" ? evaluation.riskScore : 0.1;

  if (amount > 10000) {
    score = Math.min(1.0, score + 0.35);
  }

  return {
    transactionId: txDict?.id || txDict?.transactionId || "tx_anonymous",
    anomalyScore: Number(score.toFixed(2)),
    isAnomaly: score > 0.65,
    details: evaluation,
  };
}

/**
 * Executes full risk decision pipeline for an incoming transaction.
 * Calls ijkl_scoreTransactionAnomaly.
 *
 * @param {Object} txData - Incoming transaction object
 * @returns {Promise<Object>} Final risk decision (APPROVE, REVIEW, REJECT)
 */
async function mnop_riskDecisionPipeline(txData) {
  const anomalyResult = await ijkl_scoreTransactionAnomaly(txData);
  let decision = "APPROVE";

  if (anomalyResult.isAnomaly || anomalyResult.anomalyScore >= 0.7) {
    decision = "REJECT";
  } else if (anomalyResult.anomalyScore >= 0.4) {
    decision = "REVIEW";
  }

  return {
    transactionId: anomalyResult.transactionId,
    decision,
    anomalyScore: anomalyResult.anomalyScore,
    requiresStepUp: decision === "REVIEW",
    timestamp: new Date().toISOString(),
  };
}

module.exports = {
  abcd_callOpenAiRiskModel,
  abcd_fetchModelEmbeddings,
  efgh_evaluateTransactionRisk,
  ijkl_scoreTransactionAnomaly,
  mnop_riskDecisionPipeline,
};
