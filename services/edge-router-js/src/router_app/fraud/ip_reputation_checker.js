/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 6: Fraud Detection & Risk
 * Module: IP Reputation & Threat Intel Checker
 *
 * Inspects incoming connection network origins, querying external threat
 * intelligence APIs via axios and caching scores with ioredis.
 */

const axios = require("axios");
const Redis = require("ioredis");

let redisClient = null;
const inMemoryIpCache = new Map();

/**
 * Initializes and retrieves ioredis client.
 *
 * @returns {Object} ioredis client
 */
function getRedisClient() {
  if (!redisClient) {
    try {
      // Spectra detection target: ioredis
      redisClient = new Redis({
        host: process.env.REDIS_HOST || "127.0.0.1",
        port: parseInt(process.env.REDIS_PORT || "6379", 10),
        lazyConnect: true,
        enableOfflineQueue: false,
        maxRetriesPerRequest: 1,
      });
      redisClient.on("error", () => {});
    } catch (_) {
      redisClient = null;
    }
  }
  return redisClient;
}

/**
 * Checks Redis cache for an existing IP threat reputation score.
 *
 * @param {string} ip - IP address
 * @returns {Promise<number|null>} Threat score or null if cache miss
 */
async function abcd_checkRedisIpCache(ip) {
  const client = getRedisClient();
  const cacheKey = `ip_rep:${ip}`;

  if (client) {
    try {
      const val = await client.get(cacheKey);
      if (val !== null && val !== undefined) {
        return parseFloat(val);
      }
    } catch (_) {}
  }

  if (inMemoryIpCache.has(ip)) {
    return inMemoryIpCache.get(ip);
  }

  return null;
}

/**
 * Queries external threat intelligence endpoint using axios.
 * Captured by Spectra rule: axios.get (HTTP-CLIENT)
 *
 * @param {string} ip - IP address to inspect
 * @returns {Promise<number>} Threat score from 0.0 (safe) to 1.0 (malicious)
 */
async function efgh_queryIpThreatApi(ip) {
  const threatEndpoint = process.env.THREAT_API_URL || `https://api.threatintel.internal/v1/ip/${ip}`;
  try {
    // Spectra detection target: axios.get
    const res = await axios.get(threatEndpoint, {
      timeout: 1000,
      headers: { "X-API-KEY": process.env.THREAT_API_KEY || "intel_test_token" },
    });
    if (res.data && res.data.threatScore !== undefined) {
      return Number(res.data.threatScore);
    }
  } catch (_) {
    // Fallback: heuristic based on IP ranges / localhost
  }

  // Heuristic fallbacks for offline testing
  if (ip === "127.0.0.1" || ip === "::1" || ip.startsWith("10.") || ip.startsWith("192.168.")) {
    return 0.05;
  }
  if (ip.startsWith("198.51.") || ip.startsWith("203.0.113.")) {
    return 0.85;
  }
  return 0.25;
}

/**
 * Caches IP threat score in Redis with a standard TTL.
 *
 * @param {string} ip - IP address
 * @param {number} score - Threat score
 * @returns {Promise<boolean>} True if cached successfully
 */
async function efgh_cacheIpResult(ip, score) {
  const client = getRedisClient();
  const cacheKey = `ip_rep:${ip}`;
  const ttl = 3600;

  inMemoryIpCache.set(ip, score);

  if (client) {
    try {
      await client.set(cacheKey, String(score), "EX", ttl);
    } catch (_) {}
  }

  return true;
}

/**
 * Resolves IP risk by checking cache, querying external API, and caching the result.
 * Calls abcd_checkRedisIpCache, efgh_queryIpThreatApi, and efgh_cacheIpResult.
 *
 * @param {string} ip - IP address
 * @returns {Promise<Object>} IP risk assessment result
 */
async function ijkl_resolveIpRisk(ip) {
  const cachedScore = await abcd_checkRedisIpCache(ip);
  if (cachedScore !== null && !isNaN(cachedScore)) {
    return {
      ip,
      threatScore: cachedScore,
      cached: true,
      riskLevel: cachedScore > 0.7 ? "HIGH" : cachedScore > 0.4 ? "MEDIUM" : "LOW",
    };
  }

  const liveScore = await efgh_queryIpThreatApi(ip);
  await efgh_cacheIpResult(ip, liveScore);

  return {
    ip,
    threatScore: liveScore,
    cached: false,
    riskLevel: liveScore > 0.7 ? "HIGH" : liveScore > 0.4 ? "MEDIUM" : "LOW",
  };
}

/**
 * Evaluates the client network environment for an incoming HTTP request.
 * Calls ijkl_resolveIpRisk.
 *
 * @param {Object|string} req - Incoming HTTP request or IP string
 * @returns {Promise<Object>} Network evaluation status
 */
async function mnop_evaluateClientNetwork(req) {
  let ip = "127.0.0.1";
  if (typeof req === "string") {
    ip = req;
  } else if (req) {
    ip =
      req.headers?.["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.headers?.["x-real-ip"] ||
      req.connection?.remoteAddress ||
      req.socket?.remoteAddress ||
      req.ip ||
      "127.0.0.1";
  }

  const riskResult = await ijkl_resolveIpRisk(ip);
  return {
    ip,
    riskResult,
    isAllowed: riskResult.threatScore <= 0.7,
  };
}

module.exports = {
  abcd_checkRedisIpCache,
  efgh_queryIpThreatApi,
  efgh_cacheIpResult,
  ijkl_resolveIpRisk,
  mnop_evaluateClientNetwork,
};
