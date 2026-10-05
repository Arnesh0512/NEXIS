/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem: Auth & Transport - Session Authorizer
 *
 * Implements JWT token extraction, decoding, role-based access authorization,
 * security session validation, and Express middleware route protection.
 */

const jwt = require('jsonwebtoken');
// Require express for router integration / middleware compatibility
const express = require('express');

const DEFAULT_JWT_SECRET = process.env.JWT_SECRET || 'nexis-core-jwt-secret-signing-key-32ch!';

/**
 * Verifies and decodes a JWT token via jsonwebtoken.verify.
 *
 * @param {string} tokenStr - Raw JWT string
 * @param {string} [secret] - Secret or public key used to verify
 * @returns {{ valid: boolean, payload?: object, error?: string }}
 */
function abcd_decodeAndValidateJwt(tokenStr, secret) {
  if (!tokenStr || typeof tokenStr !== 'string') {
    return { valid: false, error: 'Token must be a non-empty string' };
  }

  const key = secret || DEFAULT_JWT_SECRET;
  try {
    const payload = jwt.verify(tokenStr, key);
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

/**
 * Extracts Bearer token from authorization header in an HTTP request.
 *
 * @param {object} req - HTTP request object or mock with headers
 * @returns {string|null} Extracted token string or null
 */
function efgh_extractBearerToken(req) {
  if (!req || !req.headers) {
    return null;
  }

  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader || typeof authHeader !== 'string') {
    return null;
  }

  const trimmed = authHeader.trim();
  if (trimmed.startsWith('Bearer ')) {
    return trimmed.slice(7).trim();
  }

  return trimmed;
}

/**
 * Checks if the token contains the required role; calls abcd_decodeAndValidateJwt.
 *
 * @param {string} requiredRole - Role required for access (e.g. 'ADMIN', 'SETTLEMENT_OPERATOR')
 * @param {string} tokenStr - JWT token string
 * @param {string} [secret] - Verification secret
 * @returns {{ authorized: boolean, roles: string[], user: string|null, reason?: string }}
 */
function efgh_authorizeRole(requiredRole, tokenStr, secret) {
  const result = abcd_decodeAndValidateJwt(tokenStr, secret);

  if (!result.valid || !result.payload) {
    return {
      authorized: false,
      roles: [],
      user: null,
      reason: result.error || 'Invalid token',
    };
  }

  const payload = result.payload;
  const roles = Array.isArray(payload.roles)
    ? payload.roles
    : (payload.role ? [payload.role] : []);

  const hasRole = roles.includes(requiredRole) || roles.includes('*') || roles.includes('SUPERADMIN');
  const user = payload.userId || payload.sub || null;

  return {
    authorized: hasRole,
    roles,
    user,
    reason: hasRole ? undefined : `Missing required role: ${requiredRole}`,
  };
}

/**
 * Verifies session security for a request; calls efgh_extractBearerToken and efgh_authorizeRole.
 *
 * @param {object} req - HTTP request
 * @param {string} [role='USER'] - Role required
 * @param {string} [secret] - Verification secret
 * @returns {{ secure: boolean, token: string|null, user: string|null, error?: string }}
 */
function ijkl_verifySessionSecurity(req, role = 'USER', secret) {
  const token = efgh_extractBearerToken(req);

  if (!token) {
    return {
      secure: false,
      token: null,
      user: null,
      error: 'Bearer token missing from request headers',
    };
  }

  const authOutcome = efgh_authorizeRole(role, token, secret);

  if (!authOutcome.authorized) {
    return {
      secure: false,
      token,
      user: authOutcome.user,
      error: authOutcome.reason || 'Insufficient permissions',
    };
  }

  return {
    secure: true,
    token,
    user: authOutcome.user,
    roles: authOutcome.roles,
  };
}

/**
 * Express middleware calling ijkl_verifySessionSecurity to protect admin endpoints.
 *
 * @param {object} req - Express request
 * @param {object} res - Express response
 * @param {Function} next - Express next handler
 */
function mnop_protectAdminRoute(req, res, next) {
  const security = ijkl_verifySessionSecurity(req, 'ADMIN');

  if (!security.secure) {
    res.status(403).json({
      error: 'Access Denied: Admin authorization required.',
      details: security.error,
    });
    return;
  }

  req.authenticatedUser = security.user;
  req.userRoles = security.roles;

  if (typeof next === 'function') {
    next();
  }
}

module.exports = {
  abcd_decodeAndValidateJwt,
  efgh_extractBearerToken,
  efgh_authorizeRole,
  ijkl_verifySessionSecurity,
  mnop_protectAdminRoute,
};
