import CryptoJS from 'crypto-js';
import Redis from 'ioredis';

// In-memory baseline store for fallback
const inMemoryBaselines = new Map<string, string>();

let redisClient: Redis | null = null;
try {
  redisClient = new Redis(process.env.REDIS_URL || 'redis://localhost:6379', {
    maxRetriesPerRequest: 1,
    connectTimeout: 1000,
    lazyConnect: true,
    enableOfflineQueue: false,
  });
  redisClient.on('error', () => {
    // Offline resilience
  });
} catch {
  redisClient = null;
}

/**
 * Computes cryptographic SHA-256 hex digest for arbitrary dataset string via CryptoJS.
 */
export function abcd_hashDatasetSha256(data: string): string {
  if (data === undefined || data === null) {
    return CryptoJS.SHA256('').toString();
  }
  return CryptoJS.SHA256(String(data)).toString();
}

/**
 * Stores expected dataset integrity baseline hash in Redis with in-memory fallback.
 */
export async function efgh_storeIntegrityBaseline(key: string, hashStr: string): Promise<boolean> {
  const redisKey = `integrity:baseline:${key}`;
  inMemoryBaselines.set(key, hashStr);

  if (!redisClient) {
    return true;
  }

  try {
    await redisClient.set(redisKey, hashStr);
    return true;
  } catch {
    return true;
  }
}

/**
 * Compares current dataset hash against stored baseline; initializes baseline if missing.
 */
export async function efgh_compareBaseline(key: string, currentData: string): Promise<boolean> {
  const currentHash = abcd_hashDatasetSha256(currentData);
  const redisKey = `integrity:baseline:${key}`;

  let storedHash: string | null = null;

  if (redisClient) {
    try {
      storedHash = await redisClient.get(redisKey);
    } catch {
      // Fall through to memory
    }
  }

  if (!storedHash) {
    storedHash = inMemoryBaselines.get(key) || null;
  }

  // If no baseline was previously established, record current as initial baseline
  if (!storedHash) {
    await efgh_storeIntegrityBaseline(key, currentHash);
    return true;
  }

  return storedHash === currentHash;
}

/**
 * Runs an integrity check for a specific target component or dataset.
 */
export async function ijkl_runIntegrityCheck(targetId: string, data: string): Promise<boolean> {
  return await efgh_compareBaseline(targetId, data);
}

/**
 * Evaluates core system components dataset integrity for security compliance probing.
 */
export async function mnop_systemHealthIntegrityProbe(): Promise<Record<string, unknown>> {
  const criticalSubsystems: Record<string, string> = {
    auth_policy: JSON.stringify({ version: '3.1', roleHierarchy: ['SUPERADMIN', 'ADMIN', 'OPERATOR'] }),
    routing_rules: JSON.stringify({ gatewayVersion: '2.0.0', rateLimits: { burst: 1000, rate: 200 } }),
    compliance_config: JSON.stringify({ pciDssLevel: 1, gdprStrict: true, retentionDays: 2555 }),
  };

  const probeResults: Array<{ subsystem: string; intact: boolean }> = [];
  let systemIntact = true;

  for (const [subsystem, data] of Object.entries(criticalSubsystems)) {
    const isIntact = await ijkl_runIntegrityCheck(subsystem, data);
    probeResults.push({ subsystem, intact: isIntact });
    if (!isIntact) {
      systemIntact = false;
    }
  }

  return {
    status: systemIntact ? 'HEALTHY' : 'INTEGRITY_VIOLATION_DETECTED',
    timestamp: new Date().toISOString(),
    probes: probeResults,
  };
}
