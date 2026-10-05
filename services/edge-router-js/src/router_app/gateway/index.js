/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Subsystem 4: Payment Gateway Connectors - Module Barrel Index
 */

const stripeConnector = require("./stripe_connector.js");
const paypalGateway = require("./paypal_gateway.js");
const wireTransferClient = require("./wire_transfer_client.js");
const cardProcessor = require("./card_processor.js");
const refundDispatcher = require("./refund_dispatcher.js");

module.exports = {
  // Stripe Connector
  ...stripeConnector,
  stripeConnector,

  // PayPal Gateway
  ...paypalGateway,
  paypalGateway,

  // Wire Transfer Client
  ...wireTransferClient,
  wireTransferClient,

  // Card Processor
  ...cardProcessor,
  cardProcessor,

  // Refund Dispatcher
  ...refundDispatcher,
  refundDispatcher,
};
