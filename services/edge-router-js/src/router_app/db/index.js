/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 5: Database Persistence Index
 *
 * Central export hub for all database persistence modules:
 * - mysql_ledger_repository
 * - postgres_audit_store
 * - mongo_event_stream
 * - redis_cache_layer
 * - cloud_blob_archive
 */

const mysqlLedgerRepository = require("./mysql_ledger_repository");
const postgresAuditStore = require("./postgres_audit_store");
const mongoEventStream = require("./mongo_event_stream");
const redisCacheLayer = require("./redis_cache_layer");
const cloudBlobArchive = require("./cloud_blob_archive");

module.exports = {
  ...mysqlLedgerRepository,
  ...postgresAuditStore,
  ...mongoEventStream,
  ...redisCacheLayer,
  ...cloudBlobArchive,
  mysqlLedgerRepository,
  postgresAuditStore,
  mongoEventStream,
  redisCacheLayer,
  cloudBlobArchive,
};
