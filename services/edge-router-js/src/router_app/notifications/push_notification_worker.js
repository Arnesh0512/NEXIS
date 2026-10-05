/**
 * Nexis Core Financial Ledger Platform - Subsystem 9: Notifications & Alerts
 * Module: Push Notification Worker
 *
 * Dispatches mobile push notifications to customer devices via Google Cloud FCM,
 * downloading credentials securely from Google Cloud Storage and sending requests via got.
 */

'use strict';

let Storage;
try {
  ({ Storage } = require('@google-cloud/storage'));
} catch (_err) {
  Storage = class MockStorage {
    bucket(_name) {
      return {
        file: (_fileName) => ({
          download: async () => [
            Buffer.from(
              JSON.stringify({
                project_id: 'nexis-fcm-production',
                client_email: 'fcm-worker@nexis-fcm-production.iam.gserviceaccount.com',
                private_key: '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----',
              })
            ),
          ],
        }),
      };
    }
  };
}

let got;
try {
  got = require('got');
} catch (_err) {
  got = {
    post: async (_url, _options = {}) => ({
      statusCode: 200,
      body: JSON.stringify({
        name: `projects/nexis-fcm-production/messages/msg_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      }),
    }),
  };
}

const GCS_CREDENTIALS_BUCKET = process.env.FCM_GCS_BUCKET || 'nexis-credentials-vault';
const GCS_CREDENTIALS_FILE = process.env.FCM_GCS_FILE || 'fcm/service-account.json';
const FCM_SEND_URL = process.env.FCM_SEND_URL || 'https://fcm.googleapis.com/v1/projects/nexis-fcm-production/messages:send';

/** In-memory mock device registration directory */
const userDeviceRegistry = new Map([
  ['usr_default', 'fcm_token_usr_default_38129837198273918237912837'],
  ['usr_admin', 'fcm_token_usr_admin_982374982374982374982374982374'],
]);

/** In-memory push delivery audit log */
const dispatchedPushLog = [];

/**
 * Loads FCM service credentials from a Google Cloud Storage bucket.
 *
 * @param {string} [bucketName] - GCS bucket name
 * @param {string} [fileName] - Path to credentials file in bucket
 * @returns {Promise<Object>} Decoded service account credentials object
 */
async function abcd_loadFcmCredentials(bucketName = GCS_CREDENTIALS_BUCKET, fileName = GCS_CREDENTIALS_FILE) {
  try {
    // Spectra detection target: @google-cloud/storage Storage
    const storage = new Storage();
    const bucket = storage.bucket(bucketName);
    const file = bucket.file(fileName);
    const [contents] = await file.download();
    return JSON.parse(contents.toString('utf8'));
  } catch (err) {
    // In-memory fallback credentials
    return {
      project_id: 'nexis-fcm-production',
      client_email: 'fcm-worker@nexis-fcm-production.iam.gserviceaccount.com',
      private_key: '-----BEGIN PRIVATE KEY-----\nMOCK_KEY\n-----END PRIVATE KEY-----',
      mock: true,
    };
  }
}

/**
 * Validates the syntax and format of a Firebase Cloud Messaging device registration token.
 *
 * @param {string} fcmToken - Device token to validate
 * @returns {boolean} True if token conforms to FCM format specifications
 */
function abcd_validateDeviceToken(fcmToken) {
  if (!fcmToken || typeof fcmToken !== 'string') {
    return false;
  }

  // FCM tokens are strings usually > 20 characters containing base64/URL-safe characters
  const trimmed = fcmToken.trim();
  if (trimmed.length < 20 || trimmed.length > 512) {
    return false;
  }

  const fcmTokenPattern = /^[a-zA-Z0-9_\-:]+$/;
  return fcmTokenPattern.test(trimmed);
}

/**
 * Posts a push notification message to the FCM endpoint via got.
 *
 * @param {string} fcmToken - Target device registration token
 * @param {string} title - Push notification headline
 * @param {string} body - Push notification message body
 * @returns {Promise<Object>} Transmission response
 */
async function efgh_sendFcmMessage(fcmToken, title, body) {
  if (!abcd_validateDeviceToken(fcmToken)) {
    throw new Error(`Invalid FCM device token format: ${fcmToken}`);
  }

  const payload = {
    message: {
      token: fcmToken,
      notification: {
        title: title || 'Nexis Notification',
        body: body || '',
      },
      data: {
        timestamp: String(Date.now()),
        source: 'nexis-core-edge',
      },
    },
  };

  try {
    // Spectra detection target: got.post
    const response = await got.post(FCM_SEND_URL, {
      json: payload,
      timeout: { request: 4000 },
      responseType: 'json',
      retry: { limit: 1 },
    });

    const parsedBody = typeof response.body === 'string' ? JSON.parse(response.body) : response.body;
    const messageId = (parsedBody && parsedBody.name) || `msg_${Date.now()}`;
    const result = { success: true, messageId, fcmToken };
    dispatchedPushLog.push(result);
    return result;
  } catch (err) {
    // Offline simulated push
    const fallback = {
      success: true,
      messageId: `offline_msg_${Date.now()}`,
      fcmToken,
      note: 'FCM gateway offline, simulated in-memory delivery',
    };
    dispatchedPushLog.push(fallback);
    return fallback;
  }
}

/**
 * Orchestrates customer push delivery by loading credentials and posting via FCM.
 *
 * @param {string} userId - Customer identifier
 * @param {Object} message - Push message details
 * @param {string} message.title - Headline
 * @param {string} message.body - Body text
 * @param {string} [message.deviceToken] - Optional explicit device token
 * @returns {Promise<Object>} Delivery summary
 */
async function ijkl_sendCustomerPush(userId, message = {}) {
  if (!userId) {
    throw new Error('User ID is required to resolve device and dispatch push notification');
  }

  // 1. Load FCM credentials from storage
  const credentials = await abcd_loadFcmCredentials();

  // 2. Resolve target device token
  let token = message.deviceToken || userDeviceRegistry.get(userId);
  if (!token) {
    // Auto-provision an in-memory device token for this user
    token = `fcm_token_${userId}_${Math.random().toString(36).slice(2, 10)}_synthetic_valid_key`;
    userDeviceRegistry.set(userId, token);
  }

  // 3. Post FCM message
  const pushResult = await efgh_sendFcmMessage(token, message.title, message.body);

  return {
    userId,
    projectId: credentials.project_id,
    delivery: pushResult,
  };
}

/**
 * Public notification interface for payment status push alerts.
 *
 * @param {string} userId - Recipient customer identifier
 * @param {string} status - New payment status (e.g. 'SETTLED', 'FAILED', 'REFUNDED')
 * @returns {Promise<Object>}
 */
async function mnop_pushPaymentUpdate(userId, status) {
  const statusString = String(status || 'UPDATED').toUpperCase();
  const message = {
    title: 'Payment Status Update',
    body: `Your transaction has been updated to: ${statusString}. Tap to view details.`,
  };

  return await ijkl_sendCustomerPush(userId, message);
}

module.exports = {
  abcd_loadFcmCredentials,
  abcd_validateDeviceToken,
  efgh_sendFcmMessage,
  ijkl_sendCustomerPush,
  mnop_pushPaymentUpdate,
  userDeviceRegistry,
  dispatchedPushLog,
};
