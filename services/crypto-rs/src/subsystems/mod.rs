//! Nexis Core Cryptographic Engine & Financial Subsystems
//!
//! Root module declaring all 10 functional subsystem domains:
//! - vault: Cryptographic key management & cipher pools
//! - auth: Token issuing, session management & MFA
//! - api: High-throughput payment endpoints & routing
//! - gateway: External provider gateways (Stripe, PayPal, Card, Wire)
//! - db: Multi-database repositories (MySQL, Postgres, Mongo, Redis, GCS)
//! - fraud: AI risk evaluation, scoring & sanction screening
//! - billing: Invoicing, merchant payout & tax compliance
//! - compliance: PCI tokenization, audit signing & GDPR
//! - notifications: Email, SMS, Slack, FCM push & partner events
//! - orchestrator: Pipeline coordination, flows, batch settlement & bootstrap

pub mod vault;
pub mod auth;
pub mod api;
pub mod gateway;
pub mod db;
pub mod fraud;
pub mod billing;
pub mod compliance;
pub mod notifications;
pub mod orchestrator;
