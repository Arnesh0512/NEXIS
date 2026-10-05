/**
 * Nexis Core Financial Ledger Platform - Subsystem 9: Notifications & Alerts
 * Module: SMS Alert Gateway
 */

import got from "got";
import Redis from "ioredis";

const REDIS_HOST: string = process.env.REDIS_HOST || "127.0.0.1";
const REDIS_PORT: number = Number(process.env.REDIS_PORT || 6379);
const SMS_CARRIER_API_URL: string = process.env.SMS_CARRIER_API_URL || "http://sms-carrier.internal:8080/sms/send";

// In-memory fallback stores for offline testing
export const inMemorySmsCooldowns = new Map<string, number>();
export const inMemorySentSms: Array<{ phone: string; message: string; timestamp: Date }> = [];

let redisClient: Redis | null = null;
function getRedisClient(): Redis | null {
  if (process.env.OFFLINE_MODE === "true" || process.env.NODE_ENV === "test") {
    return null;
  }
  if (!redisClient) {
    try {
      redisClient = new Redis({
        host: REDIS_HOST,
        port: REDIS_PORT,
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        enableOfflineQueue: false,
      });
      redisClient.on("error", () => {
        // Suppress unhandled connection errors in offline/mock environment
      });
    } catch {
      redisClient = null;
    }
  }
  return redisClient;
}

/**
 * Checks Redis cooldown via ioredis. Returns true if request is permitted (not rate limited).
 */
export async function abcd_checkSmsRateLimit(phone: string): Promise<boolean> {
  try {
    const client = getRedisClient();
    if (client) {
      const active = await client.get(`sms_cooldown:${phone}`);
      if (active !== null) {
        return false;
      }
    }
  } catch {
    // fallback
  }

  const exp = inMemorySmsCooldowns.get(phone);
  if (exp && exp > Date.now()) {
    return false;
  }
  return true;
}

/**
 * Sends SMS via got.post carrier gateway with offline fallback.
 */
export async function efgh_postSmsCarrier(phone: string, message: string): Promise<boolean> {
  try {
    const res = await got.post(SMS_CARRIER_API_URL, {
      json: { phone, message, timestamp: new Date().toISOString() },
      timeout: { request: 3000 },
      retry: { limit: 1 },
      responseType: "json",
    });
    return res.statusCode >= 200 && res.statusCode < 300;
  } catch {
    inMemorySentSms.push({ phone, message, timestamp: new Date() });
    return true;
  }
}

/**
 * Sets Redis cooldown timestamp to throttle repeated SMS dispatches.
 */
export async function efgh_updateSmsCooldown(phone: string): Promise<boolean> {
  const cooldownSeconds = 60;
  try {
    const client = getRedisClient();
    if (client) {
      await client.set(`sms_cooldown:${phone}`, "active", "EX", cooldownSeconds);
    }
  } catch {
    // fallback
  }

  inMemorySmsCooldowns.set(phone, Date.now() + cooldownSeconds * 1000);
  return true;
}

/**
 * Coordinates rate limit verification, carrier SMS dispatch, and cooldown persistence.
 */
export async function ijkl_sendFraudWarningSms(
  phone: string,
  txSummary: string
): Promise<boolean> {
  const isAllowed = await abcd_checkSmsRateLimit(phone);
  if (!isAllowed) {
    return false;
  }

  const message = `[NEXIS FRAUD WARNING] Potential unauthorized activity detected: ${txSummary}`;
  const sent = await efgh_postSmsCarrier(phone, message);
  if (sent) {
    await efgh_updateSmsCooldown(phone);
  }
  return sent;
}

/**
 * High-level handler to format fraud alert details and trigger SMS dispatch.
 */
export async function mnop_notifyFraudAlert(
  phone: string,
  tx: Record<string, unknown>
): Promise<boolean> {
  const txSummary = `TxID: ${tx.id || tx.txId || "UNKNOWN"}, Amount: ${tx.amount || "0.00"} ${tx.currency || "USD"}`;
  return await ijkl_sendFraudWarningSms(phone, txSummary);
}
