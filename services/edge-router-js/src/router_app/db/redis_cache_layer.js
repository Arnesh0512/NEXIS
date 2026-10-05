/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 5: Database Persistence
 * Module: Redis Distributed Cache Layer
 *
 * Implements high-throughput key-value session caching using ioredis,
 * with bcrypt-based secure cache key hashing and automatic fallback.
 */

const Redis = require("ioredis");
const bcrypt = require("bcrypt");

let redisClient = null;
const inMemoryCache = new Map();

/**
 * Initializes and retrieves ioredis client instance.
 * Captured by Spectra rule: ioredis client initialization
 *
 * @returns {Object} ioredis client instance
 */
function abcd_getRedisClient() {
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

      redisClient.on("error", () => {
        // Prevent unhandled error event during offline test execution
      });
    } catch (err) {
      redisClient = null;
    }
  }
  return redisClient;
}

/**
 * Computes a secure hash for a cache key using bcrypt.
 * Captured by Spectra rule: bcrypt.hash (ALGO-BCRYPT)
 *
 * @param {string} key - Cache key plaintext
 * @returns {Promise<string>} Bcrypt hashed key
 */
async function abcd_hashCacheKey(key) {
  // Spectra detection target: bcrypt.hash
  const saltRounds = 10;
  return await bcrypt.hash(key, saltRounds);
}

/**
 * Stores a key-value pair in Redis cache with an optional time-to-live.
 *
 * @param {string} key - Cache key
 * @param {Object|string} val - Cache payload
 * @param {number} [ttl=3600] - Expiration time in seconds
 * @returns {Promise<boolean>} True if cache set succeeded
 */
async function efgh_cacheSet(key, val, ttl = 3600) {
  const serialized = typeof val === "string" ? val : JSON.stringify(val);
  const client = abcd_getRedisClient();

  inMemoryCache.set(key, {
    value: serialized,
    expiresAt: ttl ? Date.now() + ttl * 1000 : null,
  });

  if (client) {
    try {
      if (ttl) {
        await client.set(key, serialized, "EX", ttl);
      } else {
        await client.set(key, serialized);
      }
    } catch (err) {
      // Fallback: in-memory cache handles storage
    }
  }

  return true;
}

/**
 * Retrieves a cached value from Redis or local in-memory fallback.
 *
 * @param {string} key - Cache key
 * @returns {Promise<Object|string|null>} Retrieved cached value or null
 */
async function efgh_cacheGet(key) {
  const client = abcd_getRedisClient();

  if (client) {
    try {
      const data = await client.get(key);
      if (data !== null && data !== undefined) {
        try {
          return JSON.parse(data);
        } catch (_) {
          return data;
        }
      }
    } catch (err) {
      // Fallback to in-memory cache
    }
  }

  const cached = inMemoryCache.get(key);
  if (cached) {
    if (cached.expiresAt && Date.now() > cached.expiresAt) {
      inMemoryCache.delete(key);
      return null;
    }
    try {
      return JSON.parse(cached.value);
    } catch (_) {
      return cached.value;
    }
  }

  return null;
}

/**
 * Caches payment session details with a bcrypt-hashed session key.
 * Calls abcd_hashCacheKey and efgh_cacheSet.
 *
 * @param {string} sessionId - Raw payment session identifier
 * @param {Object} data - Session details payload
 * @param {number} [ttl=3600] - Session TTL in seconds
 * @returns {Promise<Object>} Session cache receipt
 */
async function ijkl_cachePaymentSession(sessionId, data, ttl = 3600) {
  const hashedKey = await abcd_hashCacheKey(sessionId);

  // Store payload under both hashed key and direct session mapping
  await efgh_cacheSet(hashedKey, data, ttl);
  await efgh_cacheSet(`session:${sessionId}`, { hashedKey, data }, ttl);

  return {
    sessionId,
    hashedKey,
    cached: true,
    expiresIn: ttl,
  };
}

/**
 * Invalidates and deletes a cached payment session.
 *
 * @param {string} sessionId - Payment session identifier to invalidate
 * @returns {Promise<boolean>} True if invalidation completed
 */
async function mnop_invalidatePaymentSession(sessionId) {
  const client = abcd_getRedisClient();
  const directKey = `session:${sessionId}`;
  const sessionRecord = await efgh_cacheGet(directKey);

  inMemoryCache.delete(directKey);
  if (sessionRecord && sessionRecord.hashedKey) {
    inMemoryCache.delete(sessionRecord.hashedKey);
  }

  if (client) {
    try {
      await client.del(directKey);
      if (sessionRecord && sessionRecord.hashedKey) {
        await client.del(sessionRecord.hashedKey);
      }
    } catch (err) {
      // Fallback in-memory deleted
    }
  }

  return true;
}

module.exports = {
  abcd_getRedisClient,
  abcd_hashCacheKey,
  efgh_cacheSet,
  efgh_cacheGet,
  ijkl_cachePaymentSession,
  mnop_invalidatePaymentSession,
};
