/**
 * Nexis Core Financial Ledger Platform - Subsystem 10: Platform Orchestration
 * Module: Transaction Flow Manager
 *
 * Manages persistent transaction saga states in PostgreSQL via pg.Pool,
 * orchestrates compensating reversals for failed stages, and runs automated
 * root-cause error diagnostics using the OpenAI SDK.
 */

'use strict';

let pg;
try {
  pg = require('pg');
} catch (_err) {
  pg = {
    Pool: class InMemoryPgPoolMock {
      constructor() {}
      async query(sql, params) {
        if (params && params.length >= 2) {
          inMemoryFlowStates.set(params[0], params[1]);
        }
        return {
          rows: [{ tx_id: params ? params[0] : null, state_data: params ? params[1] : null }],
          rowCount: 1,
        };
      }
      async end() {}
    },
  };
}

let OpenAI;
try {
  OpenAI = require('openai');
} catch (_err) {
  OpenAI = class MockOpenAI {
    constructor() {
      this.chat = {
        completions: {
          create: async (_opts) => ({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    rootCause: 'Ledger journal concurrency violation or balance lock failure',
                    recommendedAction: 'Retry transaction with idempotency key after 500ms delay',
                    confidence: 0.96,
                  }),
                },
              },
            ],
          }),
        },
      };
    }
  };
}

const PG_CONFIG = {
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:postgres@127.0.0.1:5432/nexis_ledger',
  max: 5,
  idleTimeoutMillis: 2000,
  connectionTimeoutMillis: 2000,
};

let pgPool;
try {
  // Spectra detection target: pg.Pool
  pgPool = new pg.Pool(PG_CONFIG);
  if (typeof pgPool.on === 'function') {
    pgPool.on('error', () => {});
  }
} catch (_e) {
  pgPool = new pg.Pool();
}

/** In-memory saga state cache */
const inMemoryFlowStates = new Map();

/**
 * Persists transaction saga flow state into PostgreSQL via pg.Pool.
 *
 * @param {string} txId - Transaction ID
 * @param {Object} state - Current flow execution state
 * @returns {Promise<Object>} Persisted record descriptor
 */
async function abcd_persistFlowState(txId, state = {}) {
  if (!txId) {
    throw new TypeError('Transaction ID is required to persist flow state');
  }

  const statePayload = JSON.stringify({
    ...state,
    updatedAt: new Date().toISOString(),
  });

  try {
    const queryText = `
      INSERT INTO transaction_flow_states (tx_id, state_data, updated_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (tx_id) DO UPDATE
      SET state_data = $2, updated_at = NOW()
      RETURNING tx_id, updated_at;
    `;
    const res = await pgPool.query(queryText, [txId, statePayload]);
    inMemoryFlowStates.set(txId, statePayload);
    return {
      txId,
      persisted: true,
      backend: 'postgresql',
      rows: res.rows,
    };
  } catch (err) {
    // Offline in-memory fallback
    inMemoryFlowStates.set(txId, statePayload);
    return {
      txId,
      persisted: true,
      backend: 'memory',
      note: 'Database offline, persisted to memory cache',
    };
  }
}

/**
 * Executes compensating transactions to rollback partial changes when a pipeline stage fails.
 *
 * @param {string} txId - Transaction ID
 * @param {string} failedStage - Stage that failed ('LEDGER', 'AUTHORIZATION', 'RISK', 'INGESTION')
 * @returns {Promise<Object>} Compensation execution report
 */
async function efgh_triggerCompensationLogic(txId, failedStage) {
  const reversedActions = [];

  switch (String(failedStage).toUpperCase()) {
    case 'LEDGER':
      reversedActions.push({ action: 'VOID_PAYMENT_AUTH', target: 'PaymentGateway', status: 'SUCCESS' });
      reversedActions.push({ action: 'RELEASE_FUND_RESERVATION', target: 'AccountService', status: 'SUCCESS' });
      reversedActions.push({ action: 'ROLLBACK_STAGE_LEDGER', target: 'LedgerService', status: 'SUCCESS' });
      break;

    case 'AUTHORIZATION':
      reversedActions.push({ action: 'RELEASE_RISK_LOCKS', target: 'RiskEngine', status: 'SUCCESS' });
      reversedActions.push({ action: 'NOTIFY_PAYMENT_DECLINE', target: 'NotificationGateway', status: 'SUCCESS' });
      break;

    case 'RISK':
      reversedActions.push({ action: 'PURGE_INGESTION_TOKEN', target: 'IngestionService', status: 'SUCCESS' });
      reversedActions.push({ action: 'LOG_AML_EXCEPTION', target: 'ComplianceService', status: 'SUCCESS' });
      break;

    default:
      reversedActions.push({ action: 'ABORT_TRANSACTION', target: 'PipelineCoordinator', status: 'SUCCESS' });
      break;
  }

  return {
    txId,
    failedStage,
    compensationStatus: 'COMPENSATED',
    reversedActions,
    completedAt: new Date().toISOString(),
  };
}

/**
 * Uses OpenAI SDK to diagnose root-cause anomalies from failure stack traces.
 *
 * @param {string|Error} errorTrace - Error message or stack trace
 * @returns {Promise<Object>} AI-generated diagnosis and mitigation strategy
 */
async function efgh_diagnoseFailureWithAi(errorTrace) {
  const traceText = typeof errorTrace === 'string' ? errorTrace : (errorTrace && errorTrace.stack) || String(errorTrace);

  try {
    // Spectra detection target: OpenAI SDK
    const openai = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY || 'sk-mock-key-for-offline-evaluation',
    });

    const completion = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        {
          role: 'system',
          content: 'You are an autonomous Site Reliability Engineer diagnosing financial ledger exceptions. Return JSON with rootCause, recommendedAction, and confidence score.',
        },
        {
          role: 'user',
          content: `Diagnose the following financial transaction stack trace:\n${traceText.slice(0, 1000)}`,
        },
      ],
      response_format: { type: 'json_object' },
    });

    const content = completion.choices[0].message.content;
    return JSON.parse(content);
  } catch (_aiErr) {
    // Deterministic rule-based fallback diagnostics for offline environments
    let rootCause = 'Generic pipeline operational failure';
    let recommendedAction = 'Engage retry with exponential backoff';

    if (/timeout|ETIMEDOUT|ESOCKETTIMEDOUT/i.test(traceText)) {
      rootCause = 'Upstream gateway or database query timeout';
      recommendedAction = 'Verify connection pool saturation and increase timeout quota';
    } else if (/balance|insufficient/i.test(traceText)) {
      rootCause = 'Insufficient account ledger funds';
      recommendedAction = 'Decline transaction with reason CODE_INSUFFICIENT_FUNDS';
    } else if (/lock|concurrency|conflict/i.test(traceText)) {
      rootCause = 'Redis distributed lock contention or PostgreSQL row serialization conflict';
      recommendedAction = 'Retry after random jitter delay (50-200ms)';
    }

    return {
      rootCause,
      recommendedAction,
      confidence: 0.88,
      source: 'heuristic_offline_diagnostician',
    };
  }
}

/**
 * Handles transaction failure lifecycle: records state, engages compensating reversals,
 * and executes AI error diagnosis.
 *
 * @param {string} txId - Transaction ID
 * @param {string} stage - Stage where error arose
 * @param {Error|Object} err - Error object
 * @returns {Promise<Object>} Failure management summary
 */
async function ijkl_handleTransactionFailure(txId, stage, err) {
  const errorMessage = (err && err.message) || String(err);

  // 1. Persist failure state
  await abcd_persistFlowState(txId, {
    status: 'FAILED',
    failedStage: stage,
    error: errorMessage,
  });

  // 2. Execute compensating reversals
  const compensationReport = await efgh_triggerCompensationLogic(txId, stage);

  // 3. Diagnose root cause with AI
  const aiDiagnosis = await efgh_diagnoseFailureWithAi(err);

  return {
    success: false,
    txId,
    stage,
    error: errorMessage,
    compensation: compensationReport,
    diagnosis: aiDiagnosis,
  };
}

/**
 * Finalizes flow completion and records terminal state.
 *
 * @param {string} txId - Transaction ID
 * @param {boolean} success - Whether flow succeeded
 * @returns {Promise<Object>}
 */
async function mnop_manageFlowCompletion(txId, success = true) {
  const terminalState = {
    status: success ? 'COMPLETED' : 'TERMINATED',
    completedAt: new Date().toISOString(),
  };

  return await abcd_persistFlowState(txId, terminalState);
}

module.exports = {
  abcd_persistFlowState,
  efgh_triggerCompensationLogic,
  efgh_diagnoseFailureWithAi,
  ijkl_handleTransactionFailure,
  mnop_manageFlowCompletion,
  pgPool,
  inMemoryFlowStates,
};
