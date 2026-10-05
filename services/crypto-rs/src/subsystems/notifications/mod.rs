//! Notifications Subsystem Module Declarations
//!
//! Exposes email, SMS, Slack, push notification, and partner webhook dispatchers
//! for the Nexis Core distributed financial platform.

pub mod email_dispatcher;
pub mod sms_alert_gateway;
pub mod slack_webhook_alerter;
pub mod push_notification_worker;
pub mod partner_event_publisher;
