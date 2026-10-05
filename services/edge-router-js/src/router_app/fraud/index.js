/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 6: Fraud Detection & Risk Index
 *
 * Central export hub for all fraud detection modules:
 * - ai_risk_evaluator
 * - transaction_scorer
 * - ip_reputation_checker
 * - sanctions_scraper
 * - behavior_anomaly_detector
 */

const aiRiskEvaluator = require("./ai_risk_evaluator");
const transactionScorer = require("./transaction_scorer");
const ipReputationChecker = require("./ip_reputation_checker");
const sanctionsScraper = require("./sanctions_scraper");
const behaviorAnomalyDetector = require("./behavior_anomaly_detector");

module.exports = {
  ...aiRiskEvaluator,
  ...transactionScorer,
  ...ipReputationChecker,
  ...sanctionsScraper,
  ...behaviorAnomalyDetector,
  aiRiskEvaluator,
  transactionScorer,
  ipReputationChecker,
  sanctionsScraper,
  behaviorAnomalyDetector,
};
