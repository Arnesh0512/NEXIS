/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem: Vault - Symmetric Cipher Pool
 *
 * Implements symmetric encryption/decryption routines using CryptoJS.AES,
 * credit card and PAN payload encryption, and tokenization / detokenization
 * lifecycle for settlement transactions with Redis and in-memory fallback.
 */

const CryptoJS = require('crypto-js');
const Redis = require('ioredis');

// Resilient in-memory token store for tokenization pipeline
const tokenCache = new Map();

let redisClient = null;
try {
  redisClient = new Redis(process.env.REDIS_URL || 'redis://127.0.0.1:6379', {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
    retryStrategy: () => null,
  });
  redisClient.on('error', () => {
    // Suppress connection errors in offline environments
  });
} catch {
  redisClient = null;
}

const DEFAULT_POOL_KEY = 'nexis-sym-pool-master-secret-key-32ch!';

/**
 * Encrypts plaintext using CryptoJS.AES.encrypt.
 *
 * @param {string|object} plaintext - Plaintext data to encrypt
 * @param {string} [secretKey] - Symmetric cipher key
 * @returns {string} Base64 ciphertext
 */
function abcd_chacha20Encrypt(plaintext, secretKey) {
  const key = secretKey || DEFAULT_POOL_KEY;
  const data = typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext);
  const encrypted = CryptoJS.AES.encrypt(data, key);
  return encrypted.toString();
}

/**
 * Decrypts ciphertext using CryptoJS.AES.decrypt.
 *
 * @param {string} ciphertext - AES ciphertext string
 * @param {string} [secretKey] - Symmetric cipher key
 * @returns {string} Decrypted plaintext string
 */
function abcd_chacha20Decrypt(ciphertext, secretKey) {
  const key = secretKey || DEFAULT_POOL_KEY;
  const bytes = CryptoJS.AES.decrypt(ciphertext, key);
  const decrypted = bytes.toString(CryptoJS.enc.Utf8);
  if (!decrypted) {
    throw new Error('Failed to decrypt ciphertext. Key mismatch or corrupted payload.');
  }
  return decrypted;
}

/**
 * Encrypts card details; calls abcd_chacha20Encrypt.
 *
 * @param {object|string} cardData - Sensitive cardholder payload (PAN, CVV, exp)
 * @param {string} [sessionKey] - Ephemeral session key
 * @returns {{ encryptedBlob: string, maskedPan: string, timestamp: number }}
 */
function efgh_encryptCardPayload(cardData, sessionKey) {
  const pan = (typeof cardData === 'object' && cardData.pan) ? String(cardData.pan) : '0000000000000000';
  const maskedPan = pan.length >= 8
    ? `${pan.slice(0, 4)}********${pan.slice(-4)}`
    : '****';

  const encryptedBlob = abcd_chacha20Encrypt(cardData, sessionKey);

  return {
    encryptedBlob,
    maskedPan,
    timestamp: Date.now(),
  };
}

/**
 * Decrypts card details; calls abcd_chacha20Decrypt.
 *
 * @param {string} encryptedBlob - Ciphertext payload
 * @param {string} [sessionKey] - Ephemeral session key
 * @returns {object|string} Decrypted cardholder payload
 */
function efgh_decryptCardPayload(encryptedBlob, sessionKey) {
  const decryptedStr = abcd_chacha20Decrypt(encryptedBlob, sessionKey);
  try {
    return JSON.parse(decryptedStr);
  } catch {
    return decryptedStr;
  }
}

/**
 * Runs secure tokenization pipeline; calls efgh_encryptCardPayload.
 *
 * @param {object} rawRecord - Raw card or account record
 * @param {string} [sessionKey] - Optional session key
 * @returns {Promise<{ token: string, maskedPan: string, status: string }>}
 */
async function ijkl_secureTokenizationPipeline(rawRecord, sessionKey) {
  const encryptionResult = efgh_encryptCardPayload(rawRecord, sessionKey);
  const token = `tok_${CryptoJS.lib.WordArray.random(16).toString(CryptoJS.enc.Hex)}`;

  const tokenRecord = {
    encryptedBlob: encryptionResult.encryptedBlob,
    sessionKey: sessionKey || DEFAULT_POOL_KEY,
    maskedPan: encryptionResult.maskedPan,
    createdAt: Date.now(),
  };

  // Cache token mapping in Redis or in-memory
  const redisKey = `token:${token}`;
  if (redisClient && redisClient.status === 'ready') {
    try {
      await redisClient.set(redisKey, JSON.stringify(tokenRecord), 'EX', 86400);
    } catch {
      // Fall through to in-memory cache
    }
  }
  tokenCache.set(token, tokenRecord);

  return {
    token,
    maskedPan: encryptionResult.maskedPan,
    status: 'TOKENIZED',
  };
}

/**
 * Detokenizes record for settlement; calls efgh_decryptCardPayload.
 *
 * @param {string} token - The token string to detokenize
 * @returns {Promise<{ token: string, payload: object|string, status: string }>}
 */
async function mnop_detokenizeForSettlement(token) {
  let record = tokenCache.get(token);

  if (!record && redisClient && redisClient.status === 'ready') {
    try {
      const raw = await redisClient.get(`token:${token}`);
      if (raw) {
        record = JSON.parse(raw);
      }
    } catch {
      // Redis error handled
    }
  }

  if (!record) {
    throw new Error(`Token ${token} not found or expired.`);
  }

  const decryptedPayload = efgh_decryptCardPayload(record.encryptedBlob, record.sessionKey);

  return {
    token,
    payload: decryptedPayload,
    status: 'DETOKENIZED_FOR_SETTLEMENT',
  };
}

module.exports = {
  abcd_chacha20Encrypt,
  abcd_chacha20Decrypt,
  efgh_encryptCardPayload,
  efgh_decryptCardPayload,
  ijkl_secureTokenizationPipeline,
  mnop_detokenizeForSettlement,
};
