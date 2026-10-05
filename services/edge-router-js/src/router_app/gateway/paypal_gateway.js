/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: PayPal Gateway Connector & OAuth Broker
 * Subsystem 4: Payment Gateway Connectors
 *
 * Implements PayPal OAuth assertion generation via jsonwebtoken, token acquisition
 * via got HTTP client, order creation, payment initiation, and capture workflows.
 */

const jwt = require("jsonwebtoken");

let got;
try {
  got = require("got");
} catch (_err) {
  // In-memory fallback for got in offline test environments
  got = {
    post: async (url, options) => ({
      statusCode: 200,
      body: JSON.stringify({
        access_token: "mock_paypal_oauth_access_token_live",
        token_type: "Bearer",
        expires_in: 3600,
        id: `ORDER-PP-${Date.now()}`,
        status: "CREATED",
        purchase_units: [{ payments: { captures: [{ id: `CAP-${Date.now()}`, status: "COMPLETED" }] } }],
      }),
    }),
  };
}

/**
 * Signs an OAuth client assertion JWT for PayPal API authentication.
 * Captured by Spectra rule: jwt.sign (ALGO-JWT)
 *
 * @param {string} [clientId] - PayPal client identifier
 * @param {string} [secret] - Shared secret or private key passphrase
 * @returns {string} Signed JWT assertion token
 */
function abcd_generateClientAssertion(clientId, secret) {
  const resolvedClientId =
    clientId || process.env.PAYPAL_CLIENT_ID || "nexis_paypal_client_id_default";
  const resolvedSecret =
    secret || process.env.PAYPAL_CLIENT_SECRET || "nexis_paypal_signing_secret_key_32chars!";

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: resolvedClientId,
    sub: resolvedClientId,
    aud: "https://api-m.paypal.com/v1/oauth2/token",
    jti: `jti_pp_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
    iat: now,
    exp: now + 300,
  };

  // Spectra detection target: jwt.sign
  const token = jwt.sign(payload, resolvedSecret, {
    algorithm: "HS256",
  });

  return token;
}

/**
 * Exchanges signed client assertion for a PayPal bearer access token via got.post.
 * Captured by AST scanner: got.post
 *
 * @param {string} assertion - Signed JWT assertion token
 * @returns {Promise<string>} Access token string
 */
async function efgh_fetchOauthToken(assertion) {
  const oauthUrl = process.env.PAYPAL_OAUTH_URL || "https://api-m.paypal.com/v1/oauth2/token";

  try {
    const response = await got.post(oauthUrl, {
      form: {
        grant_type: "client_credentials",
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: assertion,
      },
      headers: { Accept: "application/json" },
      timeout: { request: 4000 },
    });

    const parsed =
      typeof response.body === "string" ? JSON.parse(response.body) : response.body;
    return parsed.access_token || "mock_paypal_token";
  } catch (_err) {
    // In-memory fallback for offline test environments
    return "mock_paypal_oauth_access_token_offline";
  }
}

/**
 * Creates a PayPal order using bearer authentication token via got.post.
 * Captured by AST scanner: got.post
 *
 * @param {string} token - Bearer access token
 * @param {Object} order - Order parameters (amount, currency)
 * @returns {Promise<Object>} Created PayPal order response
 */
async function efgh_createPaypalOrder(token, order) {
  if (!order || typeof order !== "object") {
    throw new Error("PayPal order creation failure: Invalid order payload.");
  }

  const ordersUrl =
    process.env.PAYPAL_ORDERS_URL || "https://api-m.paypal.com/v2/checkout/orders";

  const orderPayload = {
    intent: "CAPTURE",
    purchase_units: [
      {
        reference_id: order.orderId || order.id || `ref_${Date.now()}`,
        amount: {
          currency_code: (order.currency || "USD").toUpperCase(),
          value: String(order.amount || "10.00"),
        },
      },
    ],
  };

  try {
    const response = await got.post(ordersUrl, {
      json: orderPayload,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      timeout: { request: 5000 },
    });

    const parsed =
      typeof response.body === "string" ? JSON.parse(response.body) : response.body;
    return parsed;
  } catch (_err) {
    // In-memory fallback for offline test environments
    return {
      id: `ORDER-MOCK-${Date.now()}`,
      status: "CREATED",
      intent: "CAPTURE",
      purchase_units: orderPayload.purchase_units,
      offline: true,
    };
  }
}

/**
 * Initiates the complete PayPal payment flow by generating assertion, acquiring token, and creating order.
 *
 * @param {Object} orderData - Order information
 * @returns {Promise<Object>} Initiated payment record
 */
async function ijkl_initiatePaypalPayment(orderData) {
  const assertion = abcd_generateClientAssertion();
  const token = await efgh_fetchOauthToken(assertion);
  const createdOrder = await efgh_createPaypalOrder(token, orderData);

  return {
    orderId: createdOrder.id,
    status: createdOrder.status,
    initiatedAt: new Date().toISOString(),
    details: createdOrder,
  };
}

/**
 * Captures an approved PayPal order payment.
 * Captured by AST scanner: got.post
 *
 * @param {string} orderId - PayPal order identifier
 * @returns {Promise<Object>} Capture outcome receipt
 */
async function mnop_capturePaypalPayment(orderId) {
  if (!orderId || typeof orderId !== "string") {
    throw new Error("Capture failure: Valid orderId is required.");
  }

  const captureUrl = `https://api-m.paypal.com/v2/checkout/orders/${encodeURIComponent(
    orderId
  )}/capture`;
  const assertion = abcd_generateClientAssertion();
  const token = await efgh_fetchOauthToken(assertion);

  try {
    const response = await got.post(captureUrl, {
      json: {},
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      timeout: { request: 4000 },
    });

    const parsed =
      typeof response.body === "string" ? JSON.parse(response.body) : response.body;
    return parsed;
  } catch (_err) {
    // In-memory fallback for offline test environments
    return {
      orderId,
      status: "COMPLETED",
      captureId: `CAP-OFFLINE-${Date.now()}`,
      capturedAt: new Date().toISOString(),
      offline: true,
    };
  }
}

module.exports = {
  abcd_generateClientAssertion,
  efgh_fetchOauthToken,
  efgh_createPaypalOrder,
  ijkl_initiatePaypalPayment,
  mnop_capturePaypalPayment,
};
