/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 8: Audit & Compliance
 * Module: Cryptographic Integrity Verifier & Health Probe
 *
 * Computes SHA-256 state digests using CryptoJS, caches reference baselines
 * in Redis via ioredis, and executes periodic integrity validation probes across edge nodes.
 */

const CryptoJS = require("crypto-js");

let Redis;
try {
  Redis = require("ioredis");
} catch (_err) {
  Redis = null;
}

// In-memory fallback baseline cache
const inMemoryBaselines = new Map([
  ["edge_routes", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"],
  ["pci_vault_config", "f1e2d3c4b5a697887766554433221100ffeeddccbbaa99887766554433221100"],
  ["fee_schedule", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
]);

/**
 * Computes SHA-256 cryptographic digest of data using CryptoJS.
 * Captured by Spectra rule: CryptoJS.SHA256 (ALGO-SHA2-256)
 *
 * @param {string|Object} data - Input payload to hash
 * @returns {string} 64-character lowercase hexadecimal hash
 */
function abcd_hashDatasetSha256(data) {
  if (data === undefined || data === null) {
    throw new Error("Cannot compute SHA-256 hash of null or undefined");
  }

  const payloadStr = typeof data === "string" ? data : JSON.stringify(data);

  // Spectra detection target: CryptoJS.SHA256
  const hash = CryptoJS.SHA256(payloadStr);
  return hash.toString(CryptoJS.enc.Hex);
}

/**
 * Stores baseline integrity hash in Redis via ioredis with in-memory offline fallback.
 * Captured by Spectra rule: ioredis
 *
 * @param {string} key - Unique baseline key (e.g. "edge_routes", "ledger_head")
 * @param {string} hashStr - Known valid SHA-256 digest
 * @param {Object} [redisConfig] - Optional Redis connection configuration
 * @returns {Promise<Object>} Baseline registration outcome
 */
async function efgh_storeIntegrityBaseline(key, hashStr, redisConfig = null) {
  if (!key || !hashStr) {
    throw new Error("Key and hash string are required");
  }

  const redisKey = `integrity:baseline:${key}`;

  // Attempt Redis storage if ioredis is available
  if (Redis && (redisConfig || process.env.REDIS_URL)) {
    try {
      const redis = new Redis(redisConfig || process.env.REDIS_URL);
      await redis.set(redisKey, hashStr);
      redis.disconnect();
      return {
        stored: true,
        key,
        baselineHash: hashStr,
        source: "ioredis",
        timestamp: Date.now(),
      };
    } catch (_redisErr) {
      // Fallback to in-memory store
    }
  }

  // In-memory fallback
  inMemoryBaselines.set(key, hashStr);

  return {
    stored: true,
    key,
    baselineHash: hashStr,
    source: "in-memory-baselines",
    timestamp: Date.now(),
  };
}

/**
 * Compares current dataset digest against stored Redis baseline.
 * Calls abcd_hashDatasetSha256 to hash current data.
 *
 * @param {string} key - Target baseline identifier
 * @param {string|Object} currentData - Current state data
 * @param {Object} [redisConfig] - Optional Redis configuration
 * @returns {Promise<Object>} Comparison result
 */
async function efgh_compareBaseline(key, currentData, redisConfig = null) {
  // 1. Compute current SHA-256 digest
  const currentHash = abcd_hashDatasetSha256(currentData);

  let baselineHash = null;

  // 2. Fetch baseline from Redis if available
  if (Redis && (redisConfig || process.env.REDIS_URL)) {
    try {
      const redis = new Redis(redisConfig || process.env.REDIS_URL);
      baselineHash = await redis.get(`integrity:baseline:${key}`);
      redis.disconnect();
    } catch (_err) {
      // Fallback to in-memory store
    }
  }

  // 3. Fallback to in-memory store
  if (!baselineHash) {
    baselineHash = inMemoryBaselines.get(key);
  }

  // If no baseline was ever registered, adopt current as initial baseline
  if (!baselineHash) {
    await efgh_storeIntegrityBaseline(key, currentHash, redisConfig);
    baselineHash = currentHash;
  }

  const match = baselineHash === currentHash;

  return {
    key,
    match,
    baselineHash,
    currentHash,
    discrepancy: match ? null : "Checksum mismatch detected",
    verifiedAt: Date.now(),
  };
}

/**
 * Executes an integrity verification check on a specific system component or dataset.
 *
 * @param {string} targetId - Identifier of target entity
 * @param {string|Object} data - Current data to check
 * @param {Object} [options] - Options including redisConfig
 * @returns {Promise<Object>} Integrity check report
 */
async function ijkl_runIntegrityCheck(targetId, data, options = {}) {
  const comparison = await efgh_compareBaseline(targetId, data, options.redisConfig);

  return {
    targetId,
    status: comparison.match ? "INTACT" : "TAMPER_SUSPECTED",
    intact: comparison.match,
    details: comparison,
    checkedAt: new Date().toISOString(),
  };
}

/**
 * System health integrity probe that scans all critical operational datasets.
 *
 * @param {Array<Object>} [targetsList] - Optional list of { targetId, data } to probe
 * @param {Object} [options]
 * @returns {Promise<Object>} Comprehensive system integrity health report
 */
async function mnop_systemHealthIntegrityProbe(targetsList = null, options = {}) {
  const defaultTargets = [
    { targetId: "edge_routes", data: { route1: "/health", route2: "/api/session", active: true } },
    { targetId: "pci_vault_config", data: { encryption: "AES-256-GCM", rotationDays: 90 } },
    { targetId: "fee_schedule", data: { interchangeBps: 15, crossBorderBps: 45 } },
  ];

  const targets = targetsList || defaultTargets;
  const probeResults = [];
  let compromisedCount = 0;

  for (const target of targets) {
    const result = await ijkl_runIntegrityCheck(target.targetId, target.data, options);
    probeResults.push(result);
    if (!result.intact) {
      compromisedCount++;
    }
  }

  const overallHealthy = compromisedCount === 0;

  return {
    probeId: `probe_${Date.now()}`,
    overallHealthy,
    totalProbed: targets.length,
    intactCount: targets.length - compromisedCount,
    compromisedCount,
    probeResults,
    probedAt: new Date().toISOString(),
  };
}

module.exports = {
  abcd_hashDatasetSha256,
  efgh_storeIntegrityBaseline,
  efgh_compareBaseline,
  ijkl_runIntegrityCheck,
  mnop_systemHealthIntegrityProbe,
  inMemoryBaselines,
};
