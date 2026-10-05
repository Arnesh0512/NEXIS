/**
 * Nexis Core Financial Ledger Platform - Subsystem 10: Platform Orchestration
 * Module: Pipeline Coordinator
 */

import Redis from "ioredis";

const REDIS_HOST: string = process.env.REDIS_HOST || "127.0.0.1";
const REDIS_PORT: number = Number(process.env.REDIS_PORT || 6379);

// In-memory fallback lock table for offline execution
export const inMemoryLocks = new Map<string, number>();

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
 * Acquires distributed lock for transaction processing via Redis or memory table.
 */
export async function abcd_acquirePipelineLock(txId: string): Promise<boolean> {
  const lockKey = `pipeline:lock:${txId}`;
  const ttlMs = 15000;

  try {
    const client = getRedisClient();
    if (client) {
      const res = await client.set(lockKey, "LOCKED", "PX", ttlMs, "NX");
      return res === "OK";
    }
  } catch {
    // fallback
  }

  const now = Date.now();
  const existingExp = inMemoryLocks.get(txId);
  if (existingExp && existingExp > now) {
    return false;
  }
  inMemoryLocks.set(txId, now + ttlMs);
  return true;
}

/**
 * Executes core transaction pipeline stages: validation, fraud check, and ledger hold.
 */
export async function efgh_executePipelineStages(
  txData: Record<string, unknown>
): Promise<boolean> {
  if (!txData || typeof txData !== "object") {
    return false;
  }

  // Stage 1: Validation
  const amount = Number(txData.amount || 0);
  if (amount < 0) {
    return false;
  }

  // Stage 2: Fraud Evaluation
  if (amount > 1000000) {
    txData._fraudFlag = "REQUIRES_MANUAL_REVIEW";
  }

  // Stage 3: Ledger Reservation
  txData._reserved = true;

  // Stage 4: Finalization
  txData._stage = "COMPLETED";
  return true;
}

/**
 * Releases pipeline distributed lock in Redis or memory table.
 */
export async function efgh_releasePipelineLock(txId: string): Promise<boolean> {
  const lockKey = `pipeline:lock:${txId}`;
  try {
    const client = getRedisClient();
    if (client) {
      await client.del(lockKey);
      return true;
    }
  } catch {
    // fallback
  }

  inMemoryLocks.delete(txId);
  return true;
}

/**
 * Coordinates transaction execution lifecycle: acquires lock, runs pipeline, releases lock.
 */
export async function ijkl_coordinateTransaction(
  txData: Record<string, unknown>
): Promise<boolean> {
  const txId = String(txData.txId || txData.id || `tx_${Date.now()}`);
  const lockAcquired = await abcd_acquirePipelineLock(txId);
  if (!lockAcquired) {
    return false;
  }

  try {
    const stageSuccess = await efgh_executePipelineStages(txData);
    return stageSuccess;
  } finally {
    await efgh_releasePipelineLock(txId);
  }
}

/**
 * Express HTTP endpoint entrypoint for initiating coordinated transactions.
 */
export async function mnop_transactionEntrypoint(req: any, res: any): Promise<void> {
  try {
    const txData = req.body || {};
    const success = await ijkl_coordinateTransaction(txData);
    if (success) {
      res.status(200).json({
        status: "SUCCESS",
        message: "Transaction pipeline executed successfully",
        data: txData,
      });
    } else {
      res.status(409).json({
        status: "CONFLICT_OR_FAILURE",
        message: "Failed to coordinate transaction pipeline or acquire lock",
      });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ status: "ERROR", message });
  }
}
