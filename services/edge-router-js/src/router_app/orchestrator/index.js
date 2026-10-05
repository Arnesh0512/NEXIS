/**
 * Nexis Core Financial Ledger Platform - Subsystem 10: Platform Orchestration
 * Module: Subsystem 10 Index Aggregator
 *
 * Central export manifest for all pipeline coordinators, transaction flow managers,
 * batch settlement schedulers, health monitor probes, and system bootstrappers.
 */

'use strict';

const pipelineCoordinator = require('./pipeline_coordinator');
const transactionFlowManager = require('./transaction_flow_manager');
const batchSettlementScheduler = require('./batch_settlement_scheduler');
const healthMonitorProbe = require('./health_monitor_probe');
const systemBootstrap = require('./system_bootstrap');

module.exports = {
  // Subsystem Modules
  pipelineCoordinator,
  transactionFlowManager,
  batchSettlementScheduler,
  healthMonitorProbe,
  systemBootstrap,

  // Flattened function exports
  ...pipelineCoordinator,
  ...transactionFlowManager,
  ...batchSettlementScheduler,
  ...healthMonitorProbe,
  ...systemBootstrap,
};
