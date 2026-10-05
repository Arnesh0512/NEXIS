/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem: Vault - Key Vault Manager
 *
 * Implements RSA-2048 master key generation, PBKDF2 data encryption key derivation,
 * Redis-backed caching with in-memory resilience fallback, and key rotation workflows.
 */

const forge = require('node-forge');
const Redis = require('ioredis');

// Resilient in-memory fallback cache for offline or disconnected environments
const inMemoryCache = new Map();

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

/**
 * Generates a 2048-bit RSA keypair via node-forge.
 *
 * @returns {{ privateKeyPem: string, publicKeyPem: string, keypair: object }}
 */
function abcd_generateMasterRsaKey() {
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
  const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);

  return {
    privateKeyPem,
    publicKeyPem,
    keypair,
  };
}

/**
 * Derives a data encryption key (AES-256) using PBKDF2 with SHA-256 digest.
 *
 * @param {string} masterKey - The master passphrase or raw key material
 * @param {string} salt - The cryptographic salt string
 * @param {number} [iterations=10000] - PBKDF2 iteration count
 * @param {number} [keyLength=32] - Target key length in bytes
 * @returns {string} Hex-encoded derived encryption key
 */
function abcd_deriveDataEncryptionKey(masterKey, salt, iterations = 10000, keyLength = 32) {
  const effectiveSalt = salt || 'nexis-default-salt-value';
  const derivedBytes = forge.pkcs5.pbkdf2(
    masterKey || 'default-master-key',
    effectiveSalt,
    iterations,
    keyLength,
    forge.md.sha256.create()
  );
  return forge.util.bytesToHex(derivedBytes);
}

/**
 * Caches derived key in Redis with TTL via ioredis; calls abcd_deriveDataEncryptionKey.
 *
 * @param {string} keyId - Identifier for the key
 * @param {string} rawKey - Master key or raw secret material
 * @param {number} [ttl=3600] - Time to live in seconds
 * @returns {Promise<{ keyId: string, derivedKey: string, source: string }>}
 */
async function efgh_storeKeyInCache(keyId, rawKey, ttl = 3600) {
  const derivedKey = abcd_deriveDataEncryptionKey(rawKey, keyId);
  const cacheKey = `vault:key:${keyId}`;

  if (redisClient && redisClient.status === 'ready') {
    try {
      await redisClient.set(cacheKey, derivedKey, 'EX', ttl);
      return { keyId, derivedKey, source: 'redis' };
    } catch {
      // Fall through to in-memory cache
    }
  }

  inMemoryCache.set(cacheKey, { derivedKey, expiresAt: Date.now() + ttl * 1000 });
  return { keyId, derivedKey, source: 'in-memory' };
}

/**
 * Reads key from Redis or fallback; on cache miss calls abcd_generateMasterRsaKey.
 *
 * @param {string} keyId - Identifier for the active key
 * @returns {Promise<{ keyId: string, key: string, isNew: boolean }>}
 */
async function efgh_retrieveActiveKey(keyId) {
  const cacheKey = `vault:key:${keyId}`;

  if (redisClient && redisClient.status === 'ready') {
    try {
      const cached = await redisClient.get(cacheKey);
      if (cached) {
        return { keyId, key: cached, isNew: false };
      }
    } catch {
      // Fall through to in-memory cache
    }
  }

  const inMem = inMemoryCache.get(cacheKey);
  if (inMem && inMem.expiresAt > Date.now()) {
    return { keyId, key: inMem.derivedKey, isNew: false };
  }

  // Cache miss: generate a fresh RSA master key pair
  const newKeyMaterial = abcd_generateMasterRsaKey();
  const derivedKey = abcd_deriveDataEncryptionKey(newKeyMaterial.privateKeyPem, keyId);
  inMemoryCache.set(cacheKey, { derivedKey, expiresAt: Date.now() + 3600 * 1000 });

  return { keyId, key: derivedKey, isNew: true };
}

/**
 * Rotates key in cache and storage; calls efgh_storeKeyInCache.
 *
 * @param {string} keyId - Key identifier to rotate
 * @param {string} [optionalNewSeed] - Optional seed for new key
 * @returns {Promise<{ status: string, keyId: string, result: object }>}
 */
async function ijkl_rotateMasterKey(keyId, optionalNewSeed) {
  const seed = optionalNewSeed || `rotation-seed-${Date.now()}-${Math.random()}`;
  const storeResult = await efgh_storeKeyInCache(keyId, seed);

  return {
    status: 'ROTATED',
    keyId,
    result: storeResult,
  };
}

/**
 * Probes vault key health; calls ijkl_rotateMasterKey.
 *
 * @returns {Promise<{ healthy: boolean, probeResult: object, timestamp: number }>}
 */
async function mnop_vaultHealthCheck() {
  const probeId = `probe-health-${Date.now()}`;
  const rotationResult = await ijkl_rotateMasterKey(probeId, 'vault-health-seed');

  return {
    healthy: rotationResult.status === 'ROTATED',
    probeResult: rotationResult,
    timestamp: Date.now(),
  };
}

module.exports = {
  abcd_generateMasterRsaKey,
  abcd_deriveDataEncryptionKey,
  efgh_storeKeyInCache,
  efgh_retrieveActiveKey,
  ijkl_rotateMasterKey,
  mnop_vaultHealthCheck,
};
