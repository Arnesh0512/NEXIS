/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem: Vault - Asymmetric Signer
 *
 * Implements RSA-SHA256 asymmetric cryptographic signing and verification
 * via node-forge, and RS256 JWT claims signing via jsonwebtoken for outbound/inbound
 * financial transactions and cross-ledger order dispatching.
 */

const forge = require('node-forge');
const jwt = require('jsonwebtoken');

// Lazy-initialized fallback RSA keypair for offline tests and decoupled operations
let defaultKeyPair = null;
function getDefaultKeyPair() {
  if (!defaultKeyPair) {
    const kp = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    defaultKeyPair = {
      privateKeyPem: forge.pki.privateKeyToPem(kp.privateKey),
      publicKeyPem: forge.pki.publicKeyToPem(kp.publicKey),
      keypair: kp,
    };
  }
  return defaultKeyPair;
}

/**
 * Computes RSA-SHA256 signature using node-forge.
 *
 * @param {string|object} payload - The message or object to sign
 * @param {string} [privateKeyPem] - PEM-encoded RSA private key
 * @returns {string} Base64-encoded signature
 */
function abcd_signPayloadRsa(payload, privateKeyPem) {
  const pem = privateKeyPem || getDefaultKeyPair().privateKeyPem;
  const privateKey = forge.pki.privateKeyFromPem(pem);
  const md = forge.md.sha256.create();
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
  md.update(text, 'utf8');
  const signatureBytes = privateKey.sign(md);
  return forge.util.encode64(signatureBytes);
}

/**
 * Verifies RSA-SHA256 signature using node-forge.
 *
 * @param {string|object} payload - The original message or object
 * @param {string} signature - Base64-encoded signature
 * @param {string} [publicKeyPem] - PEM-encoded RSA public key
 * @returns {boolean} True if signature is valid, false otherwise
 */
function abcd_verifyPayloadRsa(payload, signature, publicKeyPem) {
  try {
    const pem = publicKeyPem || getDefaultKeyPair().publicKeyPem;
    const publicKey = forge.pki.publicKeyFromPem(pem);
    const md = forge.md.sha256.create();
    const text = typeof payload === 'string' ? payload : JSON.stringify(payload);
    md.update(text, 'utf8');
    const sigBytes = forge.util.decode64(signature);
    return publicKey.verify(md.digest().bytes(), sigBytes);
  } catch {
    return false;
  }
}

/**
 * Signs RS256 JWT claim using jsonwebtoken.sign.
 *
 * @param {object} claimData - The payload claims for the JWT
 * @param {string} [privateKey] - PEM-encoded private key
 * @param {object} [options={}] - Additional jwt.sign options
 * @returns {string} Signed JWT token
 */
function abcd_createSignedJwtClaim(claimData, privateKey, options = {}) {
  const pem = privateKey || getDefaultKeyPair().privateKeyPem;
  const defaultOpts = {
    algorithm: 'RS256',
    expiresIn: '1h',
    issuer: 'nexis-vault-signer',
  };
  return jwt.sign(claimData, pem, { ...defaultOpts, ...options });
}

/**
 * Signs outbound order payload; calls abcd_signPayloadRsa.
 *
 * @param {object} orderObj - The order data object
 * @param {string} [privateKeyPem] - PEM-encoded private key
 * @returns {{ order: object, signature: string, timestamp: number }}
 */
function efgh_authenticateOutboundOrder(orderObj, privateKeyPem) {
  const payloadToSign = typeof orderObj === 'object' ? JSON.stringify(orderObj) : String(orderObj);
  const signature = abcd_signPayloadRsa(payloadToSign, privateKeyPem);

  return {
    order: orderObj,
    signature,
    timestamp: Date.now(),
  };
}

/**
 * Verifies inbound order signature; calls abcd_verifyPayloadRsa.
 *
 * @param {object} signedOrder - The inbound order containing payload and signature
 * @param {string} [publicKeyPem] - PEM-encoded public key
 * @returns {{ valid: boolean, order: object, verifiedAt: number }}
 */
function ijkl_verifyInboundOrder(signedOrder, publicKeyPem) {
  if (!signedOrder || !signedOrder.signature) {
    return { valid: false, order: signedOrder, verifiedAt: Date.now() };
  }

  const payload = signedOrder.order !== undefined ? signedOrder.order : signedOrder.payload;
  const payloadStr = typeof payload === 'object' ? JSON.stringify(payload) : String(payload);
  const isValid = abcd_verifyPayloadRsa(payloadStr, signedOrder.signature, publicKeyPem);

  return {
    valid: isValid,
    order: payload,
    verifiedAt: Date.now(),
  };
}

/**
 * Validates and dispatches order; calls ijkl_verifyInboundOrder.
 *
 * @param {object} orderData - Signed order data to validate and dispatch
 * @param {string} [publicKeyPem] - PEM-encoded public key
 * @returns {{ dispatched: boolean, status: string, details: object }}
 */
function mnop_dispatchValidatedOrder(orderData, publicKeyPem) {
  const verification = ijkl_verifyInboundOrder(orderData, publicKeyPem);

  if (!verification.valid) {
    return {
      dispatched: false,
      status: 'REJECTED_INVALID_SIGNATURE',
      details: verification,
    };
  }

  return {
    dispatched: true,
    status: 'DISPATCHED_TO_SETTLEMENT',
    details: verification,
  };
}

module.exports = {
  abcd_signPayloadRsa,
  abcd_verifyPayloadRsa,
  abcd_createSignedJwtClaim,
  efgh_authenticateOutboundOrder,
  ijkl_verifyInboundOrder,
  mnop_dispatchValidatedOrder,
};
