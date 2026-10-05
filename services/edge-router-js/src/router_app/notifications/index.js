/**
 * Nexis Core Financial Ledger Platform - Subsystem 9: Notifications & Alerts
 * Module: Subsystem 9 Index Aggregator
 *
 * Central export manifest for all notification dispatchers, alert gateways,
 * push notification workers, and partner webhook publishers.
 */

'use strict';

const emailDispatcher = require('./email_dispatcher');
const smsAlertGateway = require('./sms_alert_gateway');
const slackWebhookAlerter = require('./slack_webhook_alerter');
const pushNotificationWorker = require('./push_notification_worker');
const partnerEventPublisher = require('./partner_event_publisher');

module.exports = {
  // Subsystem Modules
  emailDispatcher,
  smsAlertGateway,
  slackWebhookAlerter,
  pushNotificationWorker,
  partnerEventPublisher,

  // Flattened function exports
  ...emailDispatcher,
  ...smsAlertGateway,
  ...slackWebhookAlerter,
  ...pushNotificationWorker,
  ...partnerEventPublisher,
};
