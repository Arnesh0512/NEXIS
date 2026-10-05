/**
 * Nexis Core Financial Ledger Platform - Subsystem 10: Platform Orchestration
 * Module: Pipeline Coordinator
 *
 * Coordinates multi-stage transaction workflows (Ingestion -> Risk -> Authorization -> Ledger)
 * with Redis-based distributed mutex locking and an Express HTTP ingress controller.
 */

'use strict';

let express;
try {
  express = require('express');
} catch (_err) {
  express = () => {
    const routes = [];
    return {
      use: () => {},
      post: (path, handler) => routes.push({ method: 'POST', path, handler }),
      get: (path, handler) => routes.push({ method: 'GET', path, handler }),
      listen: (_port, cb) => cb && cb(),
    };
  };
}

let Redis;
try {
  Redis = require('ioredis');
} catch (_err) {
  Redis = class InMemoryRedisMock {
    constructor() {
      this.locks = new Map();
    }
    async set(key, val, mode, px, condition) {
      if (condition === 'NX' && this.locks.has(key)) {
        const exp = this.locks.get(key);
        if (Date.now() < exp) return null;
      }
      const ttl = px || 10000;
      this.locks.set(key, Date.now() + ttl);
      return 'OK';
    }
    async del(key) {
      const existed = this.locks.delete(key);
      return existed ? 1 : 0;
    }
  };
}

const REDIS_URL = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
let redisClient;
try {
  redisClient = new Redis(REDIS_URL, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    retryStrategy: () => null,
  });
  if (typeof redisClient.on === 'function') {
    redisClient.on('error', () => {});
  }
} catch (_e) {
  redisClient = new Redis();
}

/** Local memory lock table fallback */
const inMemoryLocks = new Map();

/**
 * Acquires a distributed pipeline lock for the specified transaction ID via ioredis.
 *
 * @param {string} txId - Unique transaction identifier
 * @param {number} [ttlMs=10000] - Lock duration in milliseconds
 * @returns {Promise<boolean>} True if lock was acquired
 */
async function abcd_acquirePipelineLock(txId, ttlMs = 10000) {
  if (!txId) {
    throw new TypeError('Transaction ID is required to acquire pipeline lock');
  }

  const lockKey = `lock:pipeline:tx:${txId}`;

  try {
    // Spectra detection target: redis.set NX
    const reply = await redisClient.set(lockKey, 'ACQUIRED', 'PX', ttlMs, 'NX');
    if (reply === 'OK') return true;
    if (reply === null) return false;
  } catch (_redisErr) {
    // In-memory fallback
    const exp = inMemoryLocks.get(lockKey);
    if (exp && Date.now() < exp) {
      return false;
    }
    inMemoryLocks.set(lockKey, Date.now() + ttlMs);
    return true;
  }

  return false;
}

/**
 * Runs the deterministic 4-stage processing pipeline:
 * Stage 1: Ingestion -> Stage 2: Risk Scoring -> Stage 3: Authorization -> Stage 4: Ledger Journaling
 *
 * @param {Object} txData - Inbound transaction payload
 * @returns {Promise<Object>} Stage execution trace and summary
 */
async function efgh_executePipelineStages(txData = {}) {
  const txId = txData.txId || `tx_${Date.now()}`;
  const amount = Number(txData.amount || 0);
  const traceId = `trace_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const stageResults = [];

  // STAGE 1: INGESTION
  const ingestionResult = {
    stage: 'INGESTION',
    status: 'PASSED',
    traceId,
    timestamp: new Date().toISOString(),
    validated: true,
  };
  stageResults.push(ingestionResult);

  // STAGE 2: RISK SCORING
  const riskScore = amount > 10000 ? 0.85 : 0.05;
  const riskResult = {
    stage: 'RISK',
    status: riskScore < 0.9 ? 'PASSED' : 'FLAGGED',
    score: riskScore,
    flagged: riskScore >= 0.9,
    timestamp: new Date().toISOString(),
  };
  stageResults.push(riskResult);

  // STAGE 3: AUTHORIZATION
  const authCode = `AUTH_${Math.random().toString(36).substring(2, 10).toUpperCase()}`;
  const authResult = {
    stage: 'AUTHORIZATION',
    status: 'APPROVED',
    authCode,
    reservedFunds: amount,
    timestamp: new Date().toISOString(),
  };
  stageResults.push(authResult);

  // STAGE 4: LEDGER POSTING
  const journalEntryId = `jrnl_${Date.now()}_${txId}`;
  const ledgerResult = {
    stage: 'LEDGER',
    status: 'COMMITTED',
    journalEntryId,
    debitAccount: txData.sourceAccount || 'acc_customer_default',
    creditAccount: txData.targetAccount || 'acc_merchant_settlement',
    amount,
    timestamp: new Date().toISOString(),
  };
  stageResults.push(ledgerResult);

  return {
    txId,
    traceId,
    overallStatus: 'SETTLED',
    stages: ['INGESTION', 'RISK', 'AUTHORIZATION', 'LEDGER'],
    details: stageResults,
  };
}

/**
 * Releases the distributed pipeline lock for the specified transaction ID via ioredis.
 *
 * @param {string} txId - Transaction identifier
 * @returns {Promise<boolean>} True if lock was released
 */
async function efgh_releasePipelineLock(txId) {
  if (!txId) return false;
  const lockKey = `lock:pipeline:tx:${txId}`;

  try {
    // Spectra detection target: redis.del
    await redisClient.del(lockKey);
  } catch (_e) {
    // Ignore error in offline mode
  }

  inMemoryLocks.delete(lockKey);
  return true;
}

/**
 * Coordinates end-to-end pipeline execution with safe distributed locking semantics.
 * Calls abcd_acquirePipelineLock, efgh_executePipelineStages, and efgh_releasePipelineLock.
 *
 * @param {Object} txData - Inbound transaction payload
 * @returns {Promise<Object>} Execution result
 */
async function ijkl_coordinateTransaction(txData = {}) {
  const txId = txData.txId || `tx_${Date.now()}`;

  // 1. Acquire distributed lock
  const locked = await abcd_acquirePipelineLock(txId);
  if (!locked) {
    return {
      success: false,
      txId,
      status: 'CONCURRENCY_CONFLICT',
      error: `Transaction ${txId} is currently being processed by another worker`,
    };
  }

  try {
    // 2. Execute pipeline stages
    const pipelineOutcome = await efgh_executePipelineStages(txData);
    return {
      success: true,
      txId,
      ...pipelineOutcome,
    };
  } finally {
    // 3. Guarantee lock release
    await efgh_releasePipelineLock(txId);
  }
}

/**
 * Express HTTP request handler for inbound transaction dispatching.
 *
 * @param {Object} req - Express request
 * @param {Object} res - Express response
 */
async function mnop_transactionEntrypoint(req, res) {
  try {
    const payload = (req && req.body) || {};
    const result = await ijkl_coordinateTransaction(payload);

    if (!result.success && result.status === 'CONCURRENCY_CONFLICT') {
      res.status(409).json(result);
      return;
    }

    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({
      success: false,
      error: 'Internal pipeline orchestration failure',
      message: err.message,
    });
  }
}

module.exports = {
  abcd_acquirePipelineLock,
  efgh_executePipelineStages,
  efgh_releasePipelineLock,
  ijkl_coordinateTransaction,
  mnop_transactionEntrypoint,
  redisClient,
};
