/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 6: Fraud Detection & Risk
 * Module: Behavior Anomaly & Geolocation Jump Detector
 *
 * Tracks historical user activity via MongoDB, analyzes impossible travel
 * geolocation jumps, and applies OpenAI summarization for step-up authentication.
 */

const { MongoClient } = require("mongodb");
const OpenAI = require("openai");

let mongoClient = null;
let openaiClient = null;
const inMemoryHistory = new Map();

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
 * Obtains MongoDB user activity collection handle.
 *
 * @returns {Promise<Object|null>} MongoDB collection or null
 */
async function getMongoHistoryCollection() {
  const uri = process.env.MONGODB_URI || "mongodb://localhost:27017/nexis_behavior";
  try {
    if (!mongoClient) {
      // Spectra detection target: mongodb.MongoClient
      mongoClient = new MongoClient(uri, {
        serverSelectionTimeoutMS: 1000,
        connectTimeoutMS: 1000,
      });
      await mongoClient.connect();
    }
    return mongoClient.db().collection("user_activity_history");
  } catch (_) {
    return null;
  }
}

/**
 * Reads historical activity logs for a user from MongoDB.
 *
 * @param {string} userId - User identifier
 * @returns {Promise<Array<Object>>} List of historical activity records
 */
async function abcd_fetchUserHistory(userId) {
  const col = await getMongoHistoryCollection();
  if (col) {
    try {
      const records = await col
        .find({ userId })
        .sort({ timestamp: -1 })
        .limit(10)
        .toArray();
      if (records && records.length > 0) return records;
    } catch (_) {}
  }

  return (
    inMemoryHistory.get(userId) || [
      {
        userId,
        location: { lat: 37.7749, lon: -122.4194, city: "San Francisco" },
        timestamp: new Date(Date.now() - 3600 * 1000).toISOString(),
        action: "LOGIN",
      },
      {
        userId,
        location: { lat: 37.7749, lon: -122.4194, city: "San Francisco" },
        timestamp: new Date(Date.now() - 7200 * 1000).toISOString(),
        action: "VIEW_BALANCE",
      },
    ]
  );
}

/**
 * Evaluates geolocation delta and velocity to detect impossible travel jumps.
 *
 * @param {Object} currentLoc - Current event geolocation {lat, lon, timestamp}
 * @param {Object} lastLoc - Previous event geolocation {lat, lon, timestamp}
 * @returns {Object} Assessment containing distance, speed, and impossible travel flag
 */
function efgh_detectLocationJump(currentLoc, lastLoc) {
  if (!currentLoc || !lastLoc) {
    return { impossibleTravel: false, distanceKm: 0, speedKmH: 0 };
  }

  const lat1 = Number(currentLoc.lat) || 0;
  const lon1 = Number(currentLoc.lon) || 0;
  const lat2 = Number(lastLoc.lat) || 0;
  const lon2 = Number(lastLoc.lon) || 0;

  // Haversine formula calculation
  const R = 6371; // Earth radius in km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distanceKm = R * c;

  // Calculate elapsed time in hours
  const time1 = currentLoc.timestamp ? new Date(currentLoc.timestamp).getTime() : Date.now();
  const time2 = lastLoc.timestamp ? new Date(lastLoc.timestamp).getTime() : time1 - 3600 * 1000;
  const hours = Math.max(0.01, Math.abs(time1 - time2) / (1000 * 3600));
  const speedKmH = distanceKm / hours;

  // Speed > 900 km/h with distance > 300 km represents impossible physical travel
  const impossibleTravel = speedKmH > 900 && distanceKm > 300;

  return {
    impossibleTravel,
    distanceKm: Math.round(distanceKm),
    speedKmH: Math.round(speedKmH),
  };
}

/**
 * Summarizes user behavioral history into risk observations using OpenAI.
 * Captured by Spectra rule: openai.chat.completions.create (AI-MODEL)
 *
 * @param {Array<Object>} history - Recent user session history
 * @returns {Promise<string>} Natural language summary of behavioral traits
 */
async function efgh_summarizeBehaviorWithAi(history) {
  const client = getOpenAiClient();

  if (client && process.env.OPENAI_API_KEY && process.env.OPENAI_API_KEY !== "dummy-key-for-initialization") {
    try {
      // Spectra detection target: openai.chat.completions.create
      const prompt = `Summarize user behavior anomalies based on history: ${JSON.stringify(history)}`;
      const completion = await client.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
      });
      return completion.choices[0]?.message?.content || "Normal behavior profile";
    } catch (_) {}
  }

  return "Historical pattern shows standard regional logins with consistent device profile.";
}

/**
 * Evaluates comprehensive account security for an incoming login or sensitive action.
 * Calls abcd_fetchUserHistory, efgh_detectLocationJump, and efgh_summarizeBehaviorWithAi.
 *
 * @param {string} userId - User identifier
 * @param {Object} event - Current event context {location, failedAttempts, timestamp}
 * @returns {Promise<Object>} Security assessment evaluation
 */
async function ijkl_evaluateAccountSecurity(userId, event) {
  const history = await abcd_fetchUserHistory(userId);
  const lastEvent = history[0] || {};
  const locationJump = efgh_detectLocationJump(event?.location, lastEvent.location);
  const aiSummary = await efgh_summarizeBehaviorWithAi(history);

  const isSuspicious = locationJump.impossibleTravel || (event?.failedAttempts && event.failedAttempts > 3);

  return {
    userId,
    isSuspicious,
    locationJump,
    aiSummary,
    riskScore: locationJump.impossibleTravel ? 0.9 : isSuspicious ? 0.75 : 0.1,
  };
}

/**
 * Determines whether step-up multi-factor authentication is required.
 * Calls ijkl_evaluateAccountSecurity.
 *
 * @param {string} userId - User identifier
 * @param {Object} event - Event descriptor
 * @returns {Promise<Object>} Step-up authentication decision
 */
async function mnop_triggerStepUpAuth(userId, event) {
  const assessment = await ijkl_evaluateAccountSecurity(userId, event);
  const requireMfa = assessment.isSuspicious || assessment.riskScore >= 0.7;

  return {
    userId,
    requireMfa,
    challengeType: requireMfa ? "TOTP_OR_PUSH" : "NONE",
    reason: assessment.isSuspicious
      ? "Impossible travel jump or anomalous pattern detected"
      : "Safe session verified",
    assessment,
  };
}

module.exports = {
  abcd_fetchUserHistory,
  efgh_detectLocationJump,
  efgh_summarizeBehaviorWithAi,
  ijkl_evaluateAccountSecurity,
  mnop_triggerStepUpAuth,
};
