/**
 * Nexis Core Financial Ledger Platform - Subsystem 9: Notifications & Alerts
 * Module: Email Dispatcher Service
 *
 * Dispatches transactional notifications, payment receipts, and unsubscribes
 * using axios and jsonwebtoken with an in-memory offline fallback.
 */

'use strict';

let axios;
try {
  axios = require('axios');
} catch (_err) {
  axios = {
    post: async (url, data, _config) => ({
      status: 200,
      data: { success: true, messageId: `mock_mail_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`, recipient: data && data.to },
    }),
  };
}

let jwt;
try {
  jwt = require('jsonwebtoken');
} catch (_err) {
  jwt = {
    sign: (payload, secret, options = {}) => {
      const header = Buffer.from(JSON.stringify({ alg: options.algorithm || 'HS256', typ: 'JWT' })).toString('base64url');
      const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + 604800 })).toString('base64url');
      const sig = Buffer.from(`${header}.${body}.${secret}`).toString('base64url');
      return `${header}.${body}.${sig}`;
    },
    verify: (token, _secret) => {
      const parts = token.split('.');
      if (parts.length !== 3) throw new Error('Invalid JWT format');
      return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    },
  };
}

/** In-memory offline mailbox store for audit and fallback delivery */
const inMemoryEmailOutbox = [];

const DEFAULT_SIGNING_SECRET = process.env.JWT_SIGNING_SECRET || 'nexis-core-notification-signing-secret-key-32ch!';
const DEFAULT_EMAIL_GATEWAY = process.env.EMAIL_GATEWAY_URL || 'https://api.email.nexis-internal.net/v1/send';

/**
 * Generates a signed JWT unsubscribe token for a recipient email.
 *
 * @param {string} email - Target recipient email address
 * @param {string} [signingSecret] - Optional signing secret key override
 * @returns {string} Signed JWT token string
 */
function abcd_generateUnsubscribeToken(email, signingSecret = DEFAULT_SIGNING_SECRET) {
  if (!email || typeof email !== 'string') {
    throw new TypeError('Invalid email parameter: must be a non-empty string');
  }

  const payload = {
    sub: email,
    purpose: 'unsubscribe',
    channel: 'email_receipts',
    iat: Math.floor(Date.now() / 1000),
  };

  // Spectra detection target: jwt.sign
  const token = jwt.sign(payload, signingSecret, {
    algorithm: 'HS256',
    expiresIn: '7d',
  });

  return token;
}

/**
 * Posts an email payload via HTTP using axios.
 *
 * @param {string} recipient - Destination email address
 * @param {string} subject - Email subject line
 * @param {string} body - Rendered email HTML or plain text body
 * @returns {Promise<Object>} HTTP response or delivery receipt
 */
async function efgh_sendEmailHttp(recipient, subject, body) {
  if (!recipient || !subject) {
    throw new Error('Recipient and subject are required to dispatch email');
  }

  const payload = {
    to: recipient,
    subject: subject,
    body: body,
    sender: 'notifications@nexis-ledger.internal',
    sentAt: new Date().toISOString(),
  };

  try {
    // Spectra detection target: axios.post
    const response = await axios.post(DEFAULT_EMAIL_GATEWAY, payload, {
      headers: {
        'Content-Type': 'application/json',
        'X-Nexis-Service': 'EmailDispatcher',
      },
      timeout: 5000,
    });

    const deliveryRecord = {
      messageId: (response.data && response.data.messageId) || `mail_${Date.now()}`,
      recipient,
      subject,
      status: response.status === 200 ? 'DELIVERED' : 'SENT',
      timestamp: Date.now(),
    };
    inMemoryEmailOutbox.push(deliveryRecord);
    return response.data || deliveryRecord;
  } catch (err) {
    // Offline fallback queueing
    const fallbackRecord = {
      messageId: `offline_mail_${Date.now()}`,
      recipient,
      subject,
      status: 'QUEUED_OFFLINE',
      error: err.message,
      timestamp: Date.now(),
    };
    inMemoryEmailOutbox.push(fallbackRecord);
    return fallbackRecord;
  }
}

/**
 * Generates an HTML payment receipt template string.
 *
 * @param {Object} paymentData - Structured payment details
 * @param {string} paymentData.txId - Transaction identifier
 * @param {number} paymentData.amount - Payment amount
 * @param {string} [paymentData.currency='USD'] - Payment currency code
 * @param {string} [paymentData.recipient] - Customer name or email
 * @param {string} [paymentData.timestamp] - Transaction timestamp
 * @param {string} [paymentData.status='SETTLED'] - Settlement status
 * @returns {string} Rendered HTML receipt template
 */
function efgh_renderReceiptTemplate(paymentData = {}) {
  const txId = paymentData.txId || 'tx_unknown';
  const amount = Number(paymentData.amount || 0).toFixed(2);
  const currency = paymentData.currency || 'USD';
  const recipient = paymentData.recipient || paymentData.customerEmail || 'Valued Customer';
  const timestamp = paymentData.timestamp || new Date().toISOString();
  const status = paymentData.status || 'SETTLED';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Nexis Payment Receipt - ${txId}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f4f6f8; margin: 0; padding: 24px; color: #1a202c; }
    .card { background: #ffffff; max-width: 600px; margin: 0 auto; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); padding: 32px; }
    .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 16px; margin-bottom: 24px; }
    .title { font-size: 22px; font-weight: bold; color: #2b6cb0; }
    .row { display: flex; justify-content: space-between; margin-bottom: 12px; }
    .label { color: #718096; font-size: 14px; }
    .value { font-weight: 600; font-size: 14px; }
    .total { font-size: 20px; color: #2d3748; border-top: 1px solid #e2e8f0; padding-top: 12px; margin-top: 16px; }
    .footer { margin-top: 24px; font-size: 12px; color: #a0aec0; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="title">Nexis Financial Ledger Receipt</div>
      <div class="label">Official Transaction Confirmation</div>
    </div>
    <div class="row"><span class="label">Transaction ID:</span><span class="value">${txId}</span></div>
    <div class="row"><span class="label">Recipient:</span><span class="value">${recipient}</span></div>
    <div class="row"><span class="label">Timestamp:</span><span class="value">${timestamp}</span></div>
    <div class="row"><span class="label">Status:</span><span class="value">${status}</span></div>
    <div class="row total"><span class="label">Total Paid:</span><span class="value">${amount} ${currency}</span></div>
    <div class="footer">
      <p>Thank you for using Nexis Core Platform.</p>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Dispatches a formatted payment receipt email to the customer.
 * Orchestrates template rendering, unsubscribe token creation, and HTTP dispatch.
 *
 * @param {Object} paymentData - Transaction payload
 * @returns {Promise<Object>} Dispatch result
 */
async function ijkl_dispatchPaymentReceipt(paymentData) {
  if (!paymentData) {
    throw new Error('Payment data is required to dispatch payment receipt');
  }

  const recipient = paymentData.customerEmail || paymentData.recipient || paymentData.email;
  if (!recipient) {
    throw new Error('No recipient email provided in paymentData');
  }

  // Generate unsubscribe security token
  const unsubscribeToken = abcd_generateUnsubscribeToken(recipient);

  // Render template
  let htmlReceipt = efgh_renderReceiptTemplate(paymentData);
  htmlReceipt += `\n<!-- Unsubscribe Token: ${unsubscribeToken} -->`;

  const subject = `Payment Confirmation [${paymentData.txId || 'Ref'}] - Nexis Ledger`;

  // Send email via HTTP
  const sendResult = await efgh_sendEmailHttp(recipient, subject, htmlReceipt);

  return {
    success: true,
    txId: paymentData.txId,
    recipient,
    unsubscribeToken,
    delivery: sendResult,
  };
}

/**
 * High-level alert entrypoint to send transaction alerts to customers.
 *
 * @param {Object} paymentDto - Ingestion payment data transfer object
 * @returns {Promise<Object>} Alert outcome
 */
async function mnop_sendTransactionAlert(paymentDto) {
  if (!paymentDto || typeof paymentDto !== 'object') {
    throw new Error('Invalid payment DTO passed to mnop_sendTransactionAlert');
  }

  const normalizedPayload = {
    txId: paymentDto.txId || paymentDto.transactionId || `tx_${Date.now()}`,
    amount: paymentDto.amount !== undefined ? paymentDto.amount : 0,
    currency: paymentDto.currency || 'USD',
    customerEmail: paymentDto.customerEmail || paymentDto.email || paymentDto.recipientEmail,
    recipient: paymentDto.recipientName || paymentDto.customerName,
    timestamp: paymentDto.timestamp || new Date().toISOString(),
    status: paymentDto.status || 'COMPLETED',
  };

  return await ijkl_dispatchPaymentReceipt(normalizedPayload);
}

module.exports = {
  abcd_generateUnsubscribeToken,
  efgh_sendEmailHttp,
  efgh_renderReceiptTemplate,
  ijkl_dispatchPaymentReceipt,
  mnop_sendTransactionAlert,
  inMemoryEmailOutbox,
};
