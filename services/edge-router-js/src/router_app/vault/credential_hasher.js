/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem: Vault - Credential Hasher
 *
 * Implements bcrypt salted password hashing, credential verification,
 * MySQL-backed persistence with resilient in-memory fallback, and admin reset flows.
 */

const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');

// In-memory fallback credential registry for offline environments and testing
const inMemoryCredentials = new Map();

let mysqlPool = null;
try {
  if (process.env.MYSQL_HOST) {
    mysqlPool = mysql.createPool({
      host: process.env.MYSQL_HOST || 'localhost',
      user: process.env.MYSQL_USER || 'nexis_app',
      password: process.env.MYSQL_PASSWORD || '',
      database: process.env.MYSQL_DATABASE || 'nexis_vault',
      waitForConnections: true,
      connectionLimit: 5,
      connectTimeout: 1000,
    });
  }
} catch {
  mysqlPool = null;
}

/**
 * Hashes raw password using bcrypt with configurable salt rounds.
 *
 * @param {string} rawPassword - Plaintext password
 * @param {number} [saltRounds=10] - Number of bcrypt hashing rounds
 * @returns {Promise<string>} Bcrypt password hash
 */
async function abcd_hashPassword(rawPassword, saltRounds = 10) {
  if (!rawPassword || typeof rawPassword !== 'string') {
    throw new Error('rawPassword must be a non-empty string');
  }
  return bcrypt.hash(rawPassword, saltRounds);
}

/**
 * Compares raw password against bcrypt hash.
 *
 * @param {string} rawPassword - Plaintext password candidate
 * @param {string} hash - Bcrypt hash string
 * @returns {Promise<boolean>} True if password matches hash
 */
async function abcd_verifyPassword(rawPassword, hash) {
  if (!rawPassword || !hash) {
    return false;
  }
  try {
    return await bcrypt.compare(rawPassword, hash);
  } catch {
    return false;
  }
}

/**
 * Inserts or updates credential in MySQL; calls abcd_hashPassword.
 *
 * @param {string} userId - User identifier
 * @param {string} rawPassword - Plaintext password to hash and store
 * @returns {Promise<{ userId: string, stored: boolean, source: string }>}
 */
async function efgh_storeUserCredential(userId, rawPassword) {
  const hash = await abcd_hashPassword(rawPassword);

  if (mysqlPool) {
    try {
      await mysqlPool.query(
        'REPLACE INTO user_credentials (user_id, password_hash, updated_at) VALUES (?, ?, NOW())',
        [userId, hash]
      );
      return { userId, stored: true, source: 'mysql' };
    } catch {
      // Fall through to in-memory store
    }
  }

  inMemoryCredentials.set(userId, { hash, updatedAt: Date.now() });
  return { userId, stored: true, source: 'in-memory' };
}

/**
 * Queries MySQL or in-memory fallback; calls abcd_verifyPassword.
 *
 * @param {string} userId - User identifier
 * @param {string} rawPassword - Plaintext password attempt
 * @returns {Promise<{ userId: string, verified: boolean }>}
 */
async function efgh_checkUserLogin(userId, rawPassword) {
  let hash = null;

  if (mysqlPool) {
    try {
      const [rows] = await mysqlPool.query(
        'SELECT password_hash FROM user_credentials WHERE user_id = ? LIMIT 1',
        [userId]
      );
      if (Array.isArray(rows) && rows.length > 0) {
        hash = rows[0].password_hash;
      }
    } catch {
      // Fall through to in-memory store
    }
  }

  if (!hash) {
    const memRecord = inMemoryCredentials.get(userId);
    if (memRecord) {
      hash = memRecord.hash;
    }
  }

  if (!hash) {
    return { userId, verified: false };
  }

  const verified = await abcd_verifyPassword(rawPassword, hash);
  return { userId, verified };
}

/**
 * Executes full credential verification flow; calls efgh_checkUserLogin.
 *
 * @param {object} loginReq - Login request containing userId and password
 * @returns {Promise<{ authenticated: boolean, userId: string, message: string }>}
 */
async function ijkl_credentialVerificationFlow(loginReq) {
  const userId = loginReq.userId || loginReq.username;
  const password = loginReq.password;

  if (!userId || !password) {
    return {
      authenticated: false,
      userId: userId || 'unknown',
      message: 'Missing username or password',
    };
  }

  const result = await efgh_checkUserLogin(userId, password);

  return {
    authenticated: result.verified,
    userId,
    message: result.verified ? 'Authentication successful' : 'Invalid credentials',
  };
}

/**
 * Admin reset handler; calls efgh_storeUserCredential.
 *
 * @param {string} userId - Target user identifier
 * @param {string} newPass - New plaintext password
 * @returns {Promise<{ resetSuccess: boolean, userId: string, timestamp: number }>}
 */
async function mnop_adminResetCredential(userId, newPass) {
  const storeResult = await efgh_storeUserCredential(userId, newPass);

  return {
    resetSuccess: storeResult.stored,
    userId,
    timestamp: Date.now(),
  };
}

module.exports = {
  abcd_hashPassword,
  abcd_verifyPassword,
  efgh_storeUserCredential,
  efgh_checkUserLogin,
  ijkl_credentialVerificationFlow,
  mnop_adminResetCredential,
};
