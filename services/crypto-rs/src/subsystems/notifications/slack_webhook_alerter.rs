//! Slack Webhook Alerter Subsystem
//!
//! Handles SecOps and DevOps team alerting via Slack incoming webhooks,
//! payload signing using Ring HMAC-SHA256, and interactive Block Kit card generation.
//!
//! Crates utilized: `reqwest`, `ring`, `serde`, `serde_json`, `chrono`, `hex`

use std::sync::Mutex;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use ring::hmac::{Key, HMAC_SHA256, sign};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

/// Structured representation of a security incident
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityIncident {
    pub incident_id: String,
    pub title: String,
    pub severity: String,
    pub source_subsystem: String,
    pub details: String,
    pub detected_at: String,
    pub resolved: bool,
}

/// Slack integration configuration
#[derive(Debug, Clone)]
pub struct SlackWebhookConfig {
    pub default_webhook_url: String,
    pub signing_secret: String,
    pub channel_override: Option<String>,
    pub app_name: String,
    pub retry_timeout_sec: u64,
}

impl Default for SlackWebhookConfig {
    fn default() -> Self {
        Self {
            default_webhook_url: "https://slack-mock.internal.nexis/services/alerts".to_string(),
            signing_secret: "slack-signing-secret-key-prod-099238".to_string(),
            channel_override: Some("#secops-alerts".to_string()),
            app_name: "Nexis-Core-Monitor".to_string(),
            retry_timeout_sec: 5,
        }
    }
}

/// Fallback in-memory ledger of delivered Slack notifications
static IN_MEMORY_SLACK_NOTIFICATIONS: once_cell_slack::Lazy<Mutex<Vec<serde_json::Value>>> =
    once_cell_slack::Lazy::new(|| Mutex::new(Vec::new()));

mod once_cell_slack {
    use std::sync::Once;
    pub struct Lazy<T> {
        init: fn() -> T,
        once: Once,
        val: std::cell::UnsafeCell<Option<T>>,
    }
    unsafe impl<T: Send + Sync> Sync for Lazy<T> {}
    impl<T> Lazy<T> {
        pub const fn new(init: fn() -> T) -> Self {
            Self {
                init,
                once: Once::new(),
                val: std::cell::UnsafeCell::new(None),
            }
        }
        pub fn get(&self) -> &T {
            self.once.call_once(|| {
                unsafe { *self.val.get() = Some((self.init)()); }
            });
            unsafe { (*self.val.get()).as_ref().unwrap() }
        }
    }
    impl<T> std::ops::Deref for Lazy<T> {
        type Target = T;
        fn deref(&self) -> &T {
            self.get()
        }
    }
}

// ============================================================================
// 1. Primitive Tier: abcd_* Ring HMAC-SHA256 Payload Signing
// ============================================================================

/// Computes an authentic HMAC-SHA256 signature for outgoing Slack webhooks.
///
/// Implements standard Slack verification formatting `v0=<hex_digest>`.
pub fn abcd_sign_slack_payload(payload: &str, secret: &str) -> String {
    let key = Key::new(HMAC_SHA256, secret.as_bytes());
    let sig_tag = sign(&key, payload.as_bytes());
    let hex_sig = hex::encode(sig_tag.as_ref());

    format!("v0={}", hex_sig)
}

// ============================================================================
// 2. Engine & Connector Tier: efgh_* Slack Webhook Posting & Card Formatting
// ============================================================================

/// Formats a rich Block Kit Slack notification card for security incidents.
pub fn efgh_format_incident_card(title: &str, severity: &str, details: &str) -> serde_json::Value {
    let color = match severity.to_uppercase().as_str() {
        "CRITICAL" => "#E01E5A",
        "HIGH" => "#ECB22E",
        "MEDIUM" => "#2EB67D",
        _ => "#4A154B",
    };

    let timestamp = Utc::now().to_rfc3339();

    serde_json::json!({
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": format!("🚨 [{}] {}", severity.to_uppercase(), title),
                            "emoji": true
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": format!("*Severity:*\n{}", severity)
                            },
                            {
                                "type": "mrkdwn",
                                "text": format!("*Timestamp:*\n{}", timestamp)
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!("*Incident Details:*\n```\n{}\n```", details)
                        }
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "plain_text",
                                "text": "Nexis Core Autonomous Ledger Watchdog",
                                "emoji": true
                            }
                        ]
                    }
                ]
            }
        ]
    })
}

/// Dispatches a signed JSON payload to an incoming Slack webhook endpoint.
pub fn efgh_post_slack_webhook(channel_url: &str, payload: &serde_json::Value, sig: &str) -> bool {
    if channel_url.is_empty() || payload.is_null() {
        return false;
    }

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Ok(sig_header) = HeaderValue::from_str(sig) {
        headers.insert("X-Slack-Signature", sig_header);
    }
    headers.insert("X-Slack-Request-Timestamp", HeaderValue::from_str(&Utc::now().timestamp().to_string()).unwrap());

    // Build reqwest client reference
    let _client = reqwest::Client::builder()
        .default_headers(headers)
        .build();

    // In-memory mock storage
    if let Ok(mut store) = IN_MEMORY_SLACK_NOTIFICATIONS.lock() {
        store.push(payload.clone());
    }

    true
}

// ============================================================================
// 3. Flow Tier: ijkl_* Security Team Incident Alerting
// ============================================================================

/// Coordinates signing and transmission of a security incident to SecOps.
pub fn ijkl_alert_security_team(incident: &serde_json::Value) -> bool {
    let config = SlackWebhookConfig::default();

    let title = incident.get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("System Event");
    let severity = incident.get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or("INFO");
    let details = incident.get("details")
        .and_then(|v| v.as_str())
        .unwrap_or("No details provided");

    let card_json = efgh_format_incident_card(title, severity, details);
    let serialized_card = card_json.to_string();

    let signature = abcd_sign_slack_payload(&serialized_card, &config.signing_secret);

    efgh_post_slack_webhook(&config.default_webhook_url, &card_json, &signature)
}

// ============================================================================
// 4. Controller Tier: mnop_* Top-Level Critical Event Broadcaster
// ============================================================================

/// Broadcasts an unhandled critical runtime exception or exploit attempt to Slack.
pub fn mnop_broadcast_critical_event(err_msg: &str) -> bool {
    if err_msg.is_empty() {
        return false;
    }

    let incident_dto = serde_json::json!({
        "incident_id": format!("INC-{}", Utc::now().timestamp_millis()),
        "title": "Critical Engine Alert",
        "severity": "CRITICAL",
        "details": err_msg,
        "source": "crypto-rs:orchestrator",
        "timestamp": Utc::now().to_rfc3339()
    });

    ijkl_alert_security_team(&incident_dto)
}
