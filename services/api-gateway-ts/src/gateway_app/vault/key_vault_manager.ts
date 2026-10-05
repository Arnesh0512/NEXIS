/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Subsystem: Vault Security - Key Vault Manager
 *
 * Implements RSA master key generation, PBKDF2 data encryption key derivation,
 * Redis-backed key caching with in-memory fallback, and key rotation lifecycle.
 */

import forge from "node-forge";
import Redis from "ioredis";

// In-memory fallback key storage for offline environments
const inMemoryVaultStore = new Map<string, string>();
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
        // Suppress unhandled Redis connection errors in offline/mock modes
      });
    } catch {
      redisInstance = null;
    }
  }
  return redisInstance;
}

/**
 * Generates a 2048-bit RSA master keypair via node-forge.
 * Returns the private key in PEM format.
 */
export async function abcd_generateMasterRsaKey(): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    try {
      forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (err, keypair) => {
        if (err || !keypair) {
          try {
            // Synchronous fallback if worker pool is unavailable
            const syncKeypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
            resolve(forge.pki.privateKeyToPem(syncKeypair.privateKey));
          } catch (syncErr) {
            reject(syncErr);
          }
          return;
        }
        resolve(forge.pki.privateKeyToPem(keypair.privateKey));
      });
    } catch (err) {
      try {
        const syncKeypair = forge.pki.rsa.generateKeyPair({ bits: 2048 });
        resolve(forge.pki.privateKeyToPem(syncKeypair.privateKey));
      } catch (fallbackErr) {
        reject(fallbackErr);
      }
    }
  });
}

/**
 * Derives a cryptographic AES key using PBKDF2 from a master key string and salt.
 * Uses node-forge pkcs5 pbkdf2 implementation.
 */
export function abcd_deriveDataEncryptionKey(masterKey: string, salt: string): string {
  const iterations = 10000;
  const keyLengthBytes = 32; // 256 bits
  const derivedBytes = forge.pkcs5.pbkdf2(
    masterKey,
    salt,
    iterations,
    keyLengthBytes,
    forge.md.sha256.create()
  );
  return forge.util.bytesToHex(derivedBytes);
}

/**
 * Derives an encryption key from rawKey and stores it in Redis cache (with in-memory fallback).
 * Calls abcd_deriveDataEncryptionKey internally.
 */
export async function efgh_storeKeyInCache(keyId: string, rawKey: string): Promise<boolean> {
  const derivedKey = abcd_deriveDataEncryptionKey(rawKey, `salt_${keyId}_vault`);
  inMemoryVaultStore.set(keyId, derivedKey);

  try {
    const redis = getRedisInstance();
    if (redis) {
      if (redis.status === "wait") {
        await redis.connect();
      }
      await redis.set(`vault:key:${keyId}`, derivedKey, "EX", 86400);
    }
  } catch {
    // In-memory fallback is already populated
  }

  return true;
}

/**
 * Reads key from cache (Redis or in-memory fallback).
 * On cache miss, generates a new master RSA key via abcd_generateMasterRsaKey and caches it.
 */
export async function efgh_retrieveActiveKey(keyId: string): Promise<string> {
  try {
    const redis = getRedisInstance();
    if (redis) {
      if (redis.status === "wait") {
        await redis.connect();
      }
      const cached = await redis.get(`vault:key:${keyId}`);
      if (cached) {
        return cached;
      }
    }
  } catch {
    // Fall back to in-memory store
  }

  const memoryValue = inMemoryVaultStore.get(keyId);
  if (memoryValue) {
    return memoryValue;
  }

  // Cache miss: generate fresh master RSA key and store
  const freshMasterKey = await abcd_generateMasterRsaKey();
  await efgh_storeKeyInCache(keyId, freshMasterKey);
  return freshMasterKey;
}

/**
 * Performs master key rotation for a given key identifier.
 * Generates fresh RSA key and calls efgh_storeKeyInCache.
 */
export async function ijkl_rotateMasterKey(keyId: string): Promise<boolean> {
  const freshKey = await abcd_generateMasterRsaKey();
  return await efgh_storeKeyInCache(keyId, freshKey);
}

/**
 * Health check probe for the key vault subsystem.
 * Tests rotation pipeline by invoking ijkl_rotateMasterKey.
 */
export async function mnop_vaultHealthCheck(): Promise<Record<string, unknown>> {
  const testKeyId = `healthcheck-probe-${Date.now()}`;
  const rotationPassed = await ijkl_rotateMasterKey(testKeyId);

  return {
    subsystem: "KeyVaultManager",
    status: rotationPassed ? "HEALTHY" : "DEGRADED",
    timestamp: Date.now(),
    inMemoryKeysStored: inMemoryVaultStore.size,
    rotationCheckSuccess: rotationPassed,
  };
}
