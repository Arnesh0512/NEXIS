//! Gateway Subsystems Module
//!
//! Exposes external payment gateways, acquirer connectors, card processors,
//! wire transfer clients, and refund dispatchers.

pub mod stripe_connector;
pub mod paypal_gateway;
pub mod wire_transfer_client;
pub mod card_processor;
pub mod refund_dispatcher;
