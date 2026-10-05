/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem: Auth & Transport - Token Issuer
 *
 * Implements JWT token pair generation (access and refresh tokens), session renewal,
 * Redis-backed token revocation/blacklisting with resilient in-memory fallback,
 * and user session termination routines.
 */

const jwt = require('jsonwebtoken');
const Redis = require('ioredis');

// Resilient in-memory token blacklist for offline environments
const inMemoryBlacklist = new Set();

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

const JWT_DEFAULT_SECRET = process.env.JWT_SECRET || 'nexis-core-jwt-secret-signing-key-32ch!';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'nexis-core-jwt-refresh-secret-key-32ch!';

/**
 * Signs a JWT access token with HS256 via jsonwebtoken.
 *
 * @param {string} userId - User identifier
 * @param {string[]} [roles=['USER']] - Assigned user roles
 * @param {string} [secret] - Secret signing key
 * @returns {string} Signed JWT access token
 */
function abcd_encodeAccessToken(userId, roles = ['USER'], secret) {
  const signingKey = secret || JWT_DEFAULT_SECRET;
  const payload = {
    sub: userId,
    userId,
    roles: Array.isArray(roles) ? roles : [roles],
    tokenType: 'ACCESS',
  };

  return jwt.sign(payload, signingKey, {
    algorithm: 'HS256',
    expiresIn: '15m',
    issuer: 'nexis-edge-auth',
  });
}

/**
 * Signs a JWT refresh token via jsonwebtoken.
 *
 * @param {string} userId - User identifier
 * @param {string} [secret] - Secret signing key
 * @returns {string} Signed JWT refresh token
 */
function abcd_encodeRefreshToken(userId, secret) {
  const signingKey = secret || JWT_REFRESH_SECRET;
  const payload = {
    sub: userId,
    userId,
    tokenType: 'REFRESH',
  };

  return jwt.sign(payload, signingKey, {
    algorithm: 'HS256',
    expiresIn: '7d',
    issuer: 'nexis-edge-auth',
  });
}

/**
 * Issues an authentication token pair; calls abcd_encodeAccessToken and abcd_encodeRefreshToken.
 *
 * @param {string} userId - User identifier
 * @param {string[]} [roles=['USER']] - Assigned roles
 * @param {string} [secret] - Optional custom signing secret
 * @returns {{ accessToken: string, refreshToken: string, tokenType: string, expiresIn: number }}
 */
function efgh_issueAuthPair(userId, roles = ['USER'], secret) {
  const accessToken = abcd_encodeAccessToken(userId, roles, secret);
  const refreshToken = abcd_encodeRefreshToken(userId, secret);

  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: 900,
  };
}

/**
 * Stores revoked token in Redis via ioredis or in-memory fallback.
 *
 * @param {string} tokenStr - Raw token string to revoke
 * @param {number} [ttlSeconds=604800] - Time to live in seconds (default 7 days)
 * @returns {Promise<{ blacklisted: boolean, token: string, source: string }>}
 */
async function efgh_blacklistToken(tokenStr, ttlSeconds = 604800) {
  const key = `blacklist:${tokenStr}`;

  if (redisClient && redisClient.status === 'ready') {
    try {
      await redisClient.set(key, 'REVOKED', 'EX', ttlSeconds);
      return { blacklisted: true, token: tokenStr, source: 'redis' };
    } catch {
      // Fall through to in-memory blacklist
    }
  }

  inMemoryBlacklist.add(tokenStr);
  return { blacklisted: true, token: tokenStr, source: 'in-memory' };
}

/**
 * Checks if a token is present in the blacklist.
 *
 * @param {string} tokenStr
 * @returns {Promise<boolean>}
 */
async function isTokenBlacklisted(tokenStr) {
  if (inMemoryBlacklist.has(tokenStr)) {
    return true;
  }
  if (redisClient && redisClient.status === 'ready') {
    try {
      const result = await redisClient.get(`blacklist:${tokenStr}`);
      return result === 'REVOKED';
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Renews session using a valid refresh token; calls efgh_issueAuthPair.
 *
 * @param {string} refreshToken - The refresh token
 * @param {string} [secret] - Optional secret
 * @returns {Promise<{ renewed: boolean, authPair: object }>}
 */
async function ijkl_renewTokenSession(refreshToken, secret) {
  const signingKey = secret || JWT_REFRESH_SECRET;

  if (await isTokenBlacklisted(refreshToken)) {
    throw new Error('Refresh token has been revoked / blacklisted.');
  }

  let decoded;
  try {
    decoded = jwt.verify(refreshToken, signingKey, { algorithms: ['HS256'] });
  } catch (err) {
    throw new Error(`Invalid or expired refresh token: ${err.message}`);
  }

  if (decoded.tokenType !== 'REFRESH') {
    throw new Error('Token is not a valid refresh token.');
  }

  const authPair = efgh_issueAuthPair(decoded.userId || decoded.sub, decoded.roles || ['USER'], secret);

  return {
    renewed: true,
    authPair,
  };
}

/**
 * Revokes user sessions; calls efgh_blacklistToken.
 *
 * @param {string} userId - User identifier whose tokens are being terminated
 * @param {string[]} [activeTokens=[]] - Array of active tokens to revoke
 * @returns {Promise<{ terminated: boolean, userId: string, revokedCount: number }>}
 */
async function mnop_terminateUserSessions(userId, activeTokens = []) {
  let count = 0;
  for (const token of activeTokens) {
    await efgh_blacklistToken(token);
    count++;
  }

  // Also blacklist a synthetic marker for the user
  await efgh_blacklistToken(`user_marker_${userId}_${Date.now()}`);
  count++;

  return {
    terminated: true,
    userId,
    revokedCount: count,
  };
}

module.exports = {
  abcd_encodeAccessToken,
  abcd_encodeRefreshToken,
  efgh_issueAuthPair,
  efgh_blacklistToken,
  ijkl_renewTokenSession,
  mnop_terminateUserSessions,
};
