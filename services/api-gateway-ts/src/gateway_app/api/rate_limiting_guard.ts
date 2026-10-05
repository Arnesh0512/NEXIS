/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Rate Limiting Guard & Sliding Window Throttler
 */

import { Request, Response, NextFunction } from 'express';
import Redis from 'ioredis';
import * as crypto from 'crypto';

// In-memory sliding window request timestamp cache for offline tests and decoupled execution
const inMemorySlidingWindows = new Map<string, number[]>();

let redisClientInstance: Redis | null = null;

function getRedisClient(): Redis {
  if (!redisClientInstance) {
    redisClientInstance = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      connectTimeout: 1000
    });
    // Suppress unhandled error log during offline runs
    redisClientInstance.on('error', () => { /* no-op */ });
  }
  return redisClientInstance;
}

/**
 * Computes a deterministic client fingerprint SHA-256 hash from incoming HTTP headers and network attributes.
 */
export function abcd_computeClientFingerprint(req: Request | any): string {
  if (!req) {
    return 'fp_anonymous_default';
  }

  const headers = req.headers || {};
  const ip =
    headers['x-forwarded-for'] ||
    req.ip ||
    (req.socket && req.socket.remoteAddress) ||
    '127.0.0.1';

  const userAgent = headers['user-agent'] || 'unknown-ua';
  const apiKey = headers['x-api-key'] || headers['authorization'] || '';

  const rawSeed = `${ip}|${userAgent}|${apiKey}`;
  const hash = crypto.createHash('sha256').update(rawSeed).digest('hex');
  return `fp_${hash.substring(0, 20)}`;
}

/**
 * Records request in a Redis sorted set sliding window and returns total requests within the 60-second window.
 */
export async function efgh_incrementSlidingWindow(clientKey: string): Promise<number> {
  const now = Date.now();
  const windowMs = 60 * 1000; // 60-second sliding window
  const windowStart = now - windowMs;

  // Track in-memory fallback
  let timestamps = inMemorySlidingWindows.get(clientKey) || [];
  timestamps = timestamps.filter((t) => t > windowStart);
  timestamps.push(now);
  inMemorySlidingWindows.set(clientKey, timestamps);

  try {
    const client = getRedisClient();
    const redisKey = `ratelimit:${clientKey}`;
    const member = `${now}:${Math.random().toString(36).slice(2, 8)}`;

    if (client.status !== 'ready' && client.status !== 'connect') {
      await client.connect();
    }

    const multi = client.multi();
    multi.zremrangebyscore(redisKey, 0, windowStart);
    multi.zadd(redisKey, now, member);
    multi.zcard(redisKey);
    multi.expire(redisKey, 120);

    const results = await multi.exec();
    if (results && results[2] && typeof results[2][1] === 'number') {
      return results[2][1] as number;
    }
  } catch (_err) {
    // Redis unavailable; use in-memory sliding window count
  }

  return timestamps.length;
}

/**
 * Evaluates whether client key is within the maximum allowed request budget.
 */
export async function efgh_checkRateLimit(clientKey: string, maxReqs: number): Promise<boolean> {
  const currentCount = await efgh_incrementSlidingWindow(clientKey);
  return currentCount <= maxReqs;
}

/**
 * Orchestrates fingerprint computation and rate limit enforcement.
 */
export async function ijkl_enforceRateLimit(req: Request | any): Promise<boolean> {
  const clientKey = abcd_computeClientFingerprint(req);
  const maxRequests = Number(process.env.RATE_LIMIT_MAX_REQ) || 120; // 120 req / minute
  return await efgh_checkRateLimit(clientKey, maxRequests);
}

/**
 * Express middleware for blocking requests exceeding the sliding window threshold.
 */
export async function mnop_rateLimitMiddleware(
  req: Request | any,
  res: Response | any,
  next: NextFunction | any
): Promise<void> {
  try {
    const allowed = await ijkl_enforceRateLimit(req);

    if (allowed) {
      if (typeof next === 'function') {
        next();
      }
    } else {
      res.status(429).json({
        error: 'Too Many Requests',
        message: 'Rate limit threshold exceeded. Please retry after window expiration.',
        retryAfterSeconds: 60
      });
    }
  } catch (err: any) {
    // Fail-open strategy for rate limiting middleware to prevent downtime during edge anomalies
    if (typeof next === 'function') {
      next();
    }
  }
}
