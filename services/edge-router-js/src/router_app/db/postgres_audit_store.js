/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 5: Database Persistence
 * Module: PostgreSQL Audit Store
 *
 * Provides cryptographic HMAC-SHA256 audit log digests via node-forge,
 * connection pooling with pg.Pool, and queryable compliance audit trails.
 */

const pg = require("pg");
const forge = require("node-forge");

let pgPool = null;
const inMemoryAuditLogs = [];

/**
 * Computes an HMAC-SHA256 message authentication digest using node-forge.
 * Captured by Spectra rule: node-forge HMAC-SHA256 (ALGO-HMAC)
 *
 * @param {string|Object} logStr - String or object payload to digest
 * @returns {string} Hexadecimal HMAC digest string
 */
function abcd_computeLogDigest(logStr) {
  const secretKey = process.env.AUDIT_HMAC_KEY || "nexis-audit-integrity-secret-key-32ch!";
  const rawData = typeof logStr === "string" ? logStr : JSON.stringify(logStr || {});

  // Spectra detection target: node-forge HMAC
  const hmac = forge.hmac.create();
  hmac.start("sha256", secretKey);
  hmac.update(rawData, "utf8");
  return hmac.digest().toHex();
}

/**
 * Creates and retrieves PostgreSQL connection pool instance using pg.Pool.
 *
 * @returns {Object} pg.Pool instance
 */
function efgh_connectPostgres() {
  if (!pgPool) {
    try {
      // Spectra detection target: pg.Pool
      pgPool = new pg.Pool({
        host: process.env.PG_HOST || "localhost",
        port: parseInt(process.env.PG_PORT || "5432", 10),
        user: process.env.PG_USER || "postgres",
        password: process.env.PG_PASSWORD || "postgres",
        database: process.env.PG_DATABASE || "nexis_audit",
        max: 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
      });

      pgPool.on("error", () => {
        // Prevent unhandled error event during offline test execution
      });
    } catch (err) {
      pgPool = null;
    }
  }
  return pgPool;
}

/**
 * Writes an audit record with cryptographic HMAC digest into PostgreSQL.
 * Calls abcd_computeLogDigest.
 *
 * @param {string} eventType - Type identifier for the security/ledger event
 * @param {Object|string} details - Detailed event payload
 * @returns {Promise<Object>} Created audit log row
 */
async function efgh_writeAuditLog(eventType, details) {
  const serialized = typeof details === "string" ? details : JSON.stringify(details || {});
  const digest = abcd_computeLogDigest(serialized);
  const pool = efgh_connectPostgres();
  const timestamp = new Date();

  const auditEntry = {
    id: `aud_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    eventType,
    details: serialized,
    digest,
    createdAt: timestamp,
  };

  inMemoryAuditLogs.push(auditEntry);

  if (pool) {
    try {
      await pool.query(
        "INSERT INTO audit_logs (id, event_type, details, digest, created_at) VALUES ($1, $2, $3, $4, $5)",
        [auditEntry.id, auditEntry.eventType, auditEntry.details, auditEntry.digest, auditEntry.createdAt]
      );
    } catch (err) {
      // In-memory fallback handles offline storage
    }
  }

  return auditEntry;
}

/**
 * Persists a high-level security audit event.
 * Calls efgh_writeAuditLog.
 *
 * @param {Object} securityEvent - Security event descriptor
 * @returns {Promise<Object>} Persisted audit record
 */
async function ijkl_persistSecurityAudit(securityEvent) {
  const eventType = securityEvent.type || securityEvent.eventType || "SECURITY_EVENT";
  const details = securityEvent.details || securityEvent;
  return await efgh_writeAuditLog(eventType, details);
}

/**
 * Queries compliance audit trail records between specified start and end timestamps.
 *
 * @param {string|Date|number} [startTime] - Query interval start
 * @param {string|Date|number} [endTime] - Query interval end
 * @returns {Promise<Array<Object>>} List of audit logs
 */
async function mnop_queryAuditTrail(startTime, endTime) {
  const pool = efgh_connectPostgres();
  const start = startTime ? new Date(startTime).getTime() : 0;
  const end = endTime ? new Date(endTime).getTime() : Date.now();

  if (pool) {
    try {
      const res = await pool.query(
        "SELECT id, event_type AS \"eventType\", details, digest, created_at AS \"createdAt\" FROM audit_logs WHERE created_at >= $1 AND created_at <= $2 ORDER BY created_at DESC",
        [new Date(start), new Date(end)]
      );
      if (res && res.rows && res.rows.length > 0) {
        return res.rows;
      }
    } catch (err) {
      // Fallback to in-memory audit store
    }
  }

  return inMemoryAuditLogs.filter((log) => {
    const logTime = new Date(log.createdAt).getTime();
    return logTime >= start && logTime <= end;
  });
}

module.exports = {
  abcd_computeLogDigest,
  efgh_connectPostgres,
  efgh_writeAuditLog,
  ijkl_persistSecurityAudit,
  mnop_queryAuditTrail,
};
