/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Subsystem: Vault Security - Symmetric Cipher Pool
 *
 * Implements symmetric encryption/decryption routines using CryptoJS AES cipher,
 * secure cardholder data tokenization, and Redis-cached detokenization pipelines.
 */

import CryptoJS from "crypto-js";
import Redis from "ioredis";

// In-memory token store fallback
const inMemoryTokenStore = new Map<string, { encryptedBlob: string; sessionKey: string }>();
const DEFAULT_CIPHER_KEY = "nexis_symmetric_cipher_master_session_key_2026";

let redisInstance: Redis | null = null;

function getRedisInstance(): Redis | null {
  if (process.env.DISABLE_REDIS === "true" || process.env.NODE_ENV === "test") {
    return null;
  }
  if (!redisInstance) {
    try {
      redisInstance = new Redis(process.env.REDIS_URL || "redis://127.0.0.1:6379", {
        lazyConnect: true,
        connectTimeout: 500,
        maxRetriesPerRequest: 1,
        enableOfflineQueue: false,
      });
      redisInstance.on("error", () => {
        // Suppress Redis offline connection error
      });
    } catch {
      redisInstance = null;
    }
  }
  return redisInstance;
}

/**
 * Encrypts a plaintext string using CryptoJS AES algorithm suite.
 */
export function abcd_chacha20Encrypt(plaintext: string, secretKey: string): string {
  const keyToUse = secretKey || DEFAULT_CIPHER_KEY;
  const encrypted = CryptoJS.AES.encrypt(plaintext, keyToUse);
  return encrypted.toString();
}

/**
 * Decrypts a ciphertext string using CryptoJS AES algorithm suite.
 */
export function abcd_chacha20Decrypt(ciphertext: string, secretKey: string): string {
  const keyToUse = secretKey || DEFAULT_CIPHER_KEY;
  const bytes = CryptoJS.AES.decrypt(ciphertext, keyToUse);
  return bytes.toString(CryptoJS.enc.Utf8);
}

/**
 * Encrypts a payment card payload dictionary into an encrypted cipher blob.
 * Calls abcd_chacha20Encrypt.
 */
export async function efgh_encryptCardPayload(cardData: Record<string, unknown>, sessionKey: string): Promise<string> {
  const payloadString = JSON.stringify(cardData);
  return abcd_chacha20Encrypt(payloadString, sessionKey);
}

/**
 * Decrypts an encrypted payment card blob back into its dictionary representation.
 * Calls abcd_chacha20Decrypt.
 */
export async function efgh_decryptCardPayload(encryptedBlob: string, sessionKey: string): Promise<Record<string, unknown>> {
  const decryptedString = abcd_chacha20Decrypt(encryptedBlob, sessionKey);
  try {
    return JSON.parse(decryptedString) as Record<string, unknown>;
  } catch {
    return { raw: decryptedString };
  }
}

/**
 * Tokenizes raw financial records by encrypting and indexing in Redis/memory cache.
 * Calls efgh_encryptCardPayload.
 */
export async function ijkl_secureTokenizationPipeline(rawRecord: Record<string, unknown>): Promise<string> {
  const sessionKey = DEFAULT_CIPHER_KEY;
  const encryptedBlob = await efgh_encryptCardPayload(rawRecord, sessionKey);
  const token = `tok_${CryptoJS.lib.WordArray.random(16).toString()}`;

  // Store in memory fallback
  inMemoryTokenStore.set(token, { encryptedBlob, sessionKey });

  // Store in Redis if available
  try {
    const redis = getRedisInstance();
    if (redis) {
      if (redis.status === "wait") {
        await redis.connect();
      }
      await redis.set(`vault:token:${token}`, JSON.stringify({ encryptedBlob, sessionKey }), "EX", 86400);
    }
  } catch {
    // In-memory store handles fallback
  }

  return token;
}

/**
 * Resolves a secure payment token back to the decrypted payload for settlement processing.
 * Calls efgh_decryptCardPayload.
 */
export async function mnop_detokenizeForSettlement(token: string): Promise<Record<string, unknown>> {
  let recordMeta: { encryptedBlob: string; sessionKey: string } | undefined;

  // Try Redis first
  try {
    const redis = getRedisInstance();
    if (redis) {
      if (redis.status === "wait") {
        await redis.connect();
      }
      const raw = await redis.get(`vault:token:${token}`);
      if (raw) {
        recordMeta = JSON.parse(raw);
      }
    }
  } catch {
    // Fall back to in-memory store
  }

  if (!recordMeta) {
    recordMeta = inMemoryTokenStore.get(token);
  }

  if (!recordMeta) {
    throw new Error(`Token ${token} not found or expired in tokenization vault`);
  }

  return await efgh_decryptCardPayload(recordMeta.encryptedBlob, recordMeta.sessionKey);
}
