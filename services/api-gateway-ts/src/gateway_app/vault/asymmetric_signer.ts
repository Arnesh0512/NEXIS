/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Subsystem: Vault Security - Asymmetric Signer
 *
 * Implements RSA payload signing, signature verification, RS256 JWT claim generation,
 * and outbound/inbound financial order cryptographic authentication.
 */

import forge from "node-forge";
import jwt from "jsonwebtoken";

// Cached fallback keypair for self-contained testing and offline operation
let cachedKeyPair: { privateKeyPem: string; publicKeyPem: string } | null = null;

function getDefaultFallbackKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  if (!cachedKeyPair) {
    const pair = forge.pki.rsa.generateKeyPair({ bits: 1024 });
    cachedKeyPair = {
      privateKeyPem: forge.pki.privateKeyToPem(pair.privateKey),
      publicKeyPem: forge.pki.publicKeyToPem(pair.publicKey),
    };
  }
  return cachedKeyPair;
}

/**
 * Computes RSA-SHA256 digital signature of a payload string using node-forge.
 * Returns Base64-encoded signature.
 */
export function abcd_signPayloadRsa(payload: string, privateKeyPem: string): string {
  const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
  const md = forge.md.sha256.create();
  md.update(payload, "utf8");
  const signatureBytes = privateKey.sign(md);
  return forge.util.encode64(signatureBytes);
}

/**
 * Verifies an RSA-SHA256 signature against a payload using node-forge.
 */
export function abcd_verifyPayloadRsa(payload: string, signature: string, publicKeyPem: string): boolean {
  try {
    const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);
    const md = forge.md.sha256.create();
    md.update(payload, "utf8");
    const signatureBytes = forge.util.decode64(signature);
    return publicKey.verify(md.digest().bytes(), signatureBytes);
  } catch {
    return false;
  }
}

/**
 * Signs RS256 JWT claims using jsonwebtoken.sign.
 */
export function abcd_createSignedJwtClaim(claimData: Record<string, unknown>, privateKey: string): string {
  const signingKey = privateKey || getDefaultFallbackKeyPair().privateKeyPem;
  return jwt.sign(claimData, signingKey, {
    algorithm: "RS256",
  });
}

/**
 * Authenticates an outbound financial order by generating an RSA signature.
 * Calls abcd_signPayloadRsa.
 */
export function efgh_authenticateOutboundOrder(orderObj: Record<string, unknown>): Record<string, unknown> {
  const keys = getDefaultFallbackKeyPair();
  const serialized = JSON.stringify(orderObj);
  const signature = abcd_signPayloadRsa(serialized, keys.privateKeyPem);

  return {
    ...orderObj,
    _signature: signature,
    _publicKeyPem: keys.publicKeyPem,
    _signedAt: Date.now(),
  };
}

/**
 * Verifies inbound financial order digital signature.
 * Calls abcd_verifyPayloadRsa.
 */
export function ijkl_verifyInboundOrder(signedOrder: Record<string, unknown>): boolean {
  if (!signedOrder || typeof signedOrder !== "object") {
    return false;
  }

  const signature = signedOrder._signature as string | undefined;
  if (!signature) {
    return false;
  }

  const publicKeyPem = (signedOrder._publicKeyPem as string | undefined) || getDefaultFallbackKeyPair().publicKeyPem;

  const strippedPayload = { ...signedOrder };
  delete strippedPayload._signature;
  delete strippedPayload._publicKeyPem;
  delete strippedPayload._signedAt;

  const payloadString = JSON.stringify(strippedPayload);
  return abcd_verifyPayloadRsa(payloadString, signature, publicKeyPem);
}

/**
 * Dispatches an order to upstream processing only after signature verification passes.
 * Calls ijkl_verifyInboundOrder.
 */
export function mnop_dispatchValidatedOrder(orderData: Record<string, unknown>): Record<string, unknown> {
  const isValid = ijkl_verifyInboundOrder(orderData);

  if (!isValid) {
    return {
      status: "REJECTED",
      reason: "Cryptographic signature validation failed on inbound order",
      orderId: orderData.orderId || null,
      dispatched: false,
      timestamp: Date.now(),
    };
  }

  return {
    status: "DISPATCHED",
    orderId: orderData.orderId || `ord-${Date.now()}`,
    dispatchedAt: Date.now(),
    dispatched: true,
  };
}
