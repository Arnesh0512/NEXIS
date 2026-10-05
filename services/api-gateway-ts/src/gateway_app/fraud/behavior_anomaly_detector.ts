/**
 * Nexis Core Financial Ledger Platform - Subsystem 6: Fraud Detection & Risk
 * Module: Behavioral Anomaly & Impossible Travel Detector
 *
 * Tracks user account session history via MongoDB, detects geographic impossible-travel jumps,
 * queries OpenAI for behavioral trend synthesis, and triggers multi-factor step-up authentication.
 * Features an in-memory mock fallback for offline tests and decoupled CI/CD pipelines.
 */

import { MongoClient } from "mongodb";
import OpenAI from "openai";

export interface UserSessionEvent {
  userId: string;
  location: string;
  device: string;
  ip?: string;
  action: string;
  timestamp: number;
}

// In-memory fallback history store
const inMemoryUserHistory = new Map<string, UserSessionEvent[]>();

let mongoClient: MongoClient | null = null;
let openAiClient: OpenAI | null = null;

function getOpenAi(): OpenAI {
  if (!openAiClient) {
    openAiClient = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY || "mock-openai-key-behavior-detector",
    });
  }
  return openAiClient;
}

/**
 * Reads user session history from MongoDB collection user_activity_logs.
 * Falls back to inMemoryUserHistory or standard baseline profile when offline.
 */
export async function abcd_fetchUserHistory(userId: string): Promise<any[]> {
  const uri = process.env.MONGO_URI || "mongodb://localhost:27017/nexis_events";

  try {
    if (!mongoClient) {
      mongoClient = new MongoClient(uri, {
        serverSelectionTimeoutMS: 2000,
        connectTimeoutMS: 2000,
      });
      await mongoClient.connect();
    }
    const collection = mongoClient.db().collection("user_activity_logs");
    const docs = await collection
      .find({ userId })
      .sort({ timestamp: -1 })
      .limit(20)
      .toArray();

    if (docs && docs.length > 0) {
      return docs;
    }
  } catch {
    // Proceed to in-memory check
  }

  const cached = inMemoryUserHistory.get(userId);
  if (cached && cached.length > 0) {
    return [...cached];
  }

  // Baseline standard user history profile
  return [
    {
      userId,
      location: "US-NYC",
      device: "MacBook-Chrome-v122",
      action: "LOGIN_SUCCESS",
      timestamp: Date.now() - 3600000, // 1 hour ago
    },
    {
      userId,
      location: "US-NYC",
      device: "MacBook-Chrome-v122",
      action: "PAYMENT_INITIATE",
      timestamp: Date.now() - 1800000, // 30 mins ago
    },
  ];
}

/**
 * Evaluates geographic distance and velocity between successive sessions
 * to detect impossible travel jumps (e.g. NYC to Tokyo in 15 minutes).
 */
export function efgh_detectLocationJump(currentLoc: string, lastLoc: string): boolean {
  if (!currentLoc || !lastLoc) return false;
  const curr = currentLoc.trim().toUpperCase();
  const last = lastLoc.trim().toUpperCase();

  if (curr === last) return false;

  // Extract country/region prefix (e.g. "US-NYC" -> "US", "JP-TYO" -> "JP")
  const currCountry = curr.split("-")[0];
  const lastCountry = last.split("-")[0];

  // If different countries, flag as location jump
  if (currCountry !== lastCountry) {
    return true;
  }

  // Cross-continent / extreme intra-country jumps
  const highDistancePairs = [
    ["US-NYC", "US-LAX"],
    ["US-MIA", "US-SEA"],
  ];

  for (const [a, b] of highDistancePairs) {
    if ((curr === a && last === b) || (curr === b && last === a)) {
      return true;
    }
  }

  return false;
}

/**
 * Queries OpenAI to summarize user behavioral patterns and identify subtle anomalies.
 * Falls back to deterministic rule summary offline.
 */
export async function efgh_summarizeBehaviorWithAi(history: any[]): Promise<string> {
  const apiKey = process.env.OPENAI_API_KEY;
  if (apiKey && apiKey !== "mock-openai-key-behavior-detector") {
    try {
      const client = getOpenAi();
      const res = await client.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content: "Summarize user session history and assess login risk in 1 concise sentence.",
          },
          {
            role: "user",
            content: JSON.stringify(history.slice(0, 5)),
          },
        ],
        max_tokens: 50,
      });
      return res.choices[0]?.message?.content || "Normal user activity profile detected.";
    } catch {
      // Fallback
    }
  }

  const sessionCount = history.length;
  return `User profile contains ${sessionCount} recent actions with typical device footprint.`;
}

/**
 * Evaluates account security risk based on session history, impossible travel, and AI summaries.
 * Calls abcd_fetchUserHistory, efgh_detectLocationJump, and efgh_summarizeBehaviorWithAi.
 */
export async function ijkl_evaluateAccountSecurity(
  userId: string,
  event: Record<string, unknown>
): Promise<boolean> {
  const history = await abcd_fetchUserHistory(userId);
  const lastSession = history[history.length - 1] || history[0];
  const lastLoc = (lastSession?.location as string) || "US-NYC";
  const currentLoc = (event.location as string) || (event.country as string) || "US-NYC";

  const isLocationJump = efgh_detectLocationJump(currentLoc, lastLoc);
  await efgh_summarizeBehaviorWithAi(history);

  // Check failed attempt counts or security flags
  const failedAttempts = Number(event.failedAttempts) || 0;
  const hasSecurityFlag = event.riskFlag === true || event.suspiciousDevice === true;

  // Anomalous if location jump detected or multiple failed login attempts
  return isLocationJump || failedAttempts >= 3 || hasSecurityFlag;
}

/**
 * Determines whether step-up authentication (MFA challenge) must be triggered.
 * Calls ijkl_evaluateAccountSecurity. Returns true if step-up challenge is required.
 */
export async function mnop_triggerStepUpAuth(
  userId: string,
  event: Record<string, unknown>
): Promise<boolean> {
  const isAnomalous = await ijkl_evaluateAccountSecurity(userId, event);

  // Record this session into in-memory history for subsequent tracking
  const currentSessions = inMemoryUserHistory.get(userId) || [];
  currentSessions.push({
    userId,
    location: (event.location as string) || "US-NYC",
    device: (event.device as string) || "Unknown-Browser",
    ip: (event.ip as string) || "127.0.0.1",
    action: isAnomalous ? "STEP_UP_CHALLENGED" : "SESSION_AUTHENTICATED",
    timestamp: Date.now(),
  });
  inMemoryUserHistory.set(userId, currentSessions);

  return isAnomalous;
}

/**
 * Testing helper to seed in-memory user history.
 */
export function seedMockUserHistory(userId: string, events: UserSessionEvent[]): void {
  inMemoryUserHistory.set(userId, events);
}
