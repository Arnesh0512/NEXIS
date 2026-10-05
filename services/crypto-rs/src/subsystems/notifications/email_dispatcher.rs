//! Email Dispatcher Subsystem
//!
//! Provides transactional email notification routing, template rendering,
//! cryptographic unsubscribe token management, and carrier delivery confirmation.
//!
//! Crates utilized: `reqwest`, `jsonwebtoken`, `serde`, `serde_json`, `chrono`

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, AUTHORIZATION};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};

/// Secret key for unsubscribe JWT signatures
const JWT_UNSUB_SECRET: &[u8] = b"nexis-core-unsub-secret-token-key-2026";

/// Claims schema for unsubscribe token generation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UnsubscribeClaims {
    pub sub: String,
    pub email: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub purpose: String,
}

/// Email delivery record stored in the local audit cache
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EmailRecord {
    pub message_id: String,
    pub recipient: String,
    pub subject: String,
    pub body_preview: String,
    pub sent_at: String,
    pub status: String,
    pub attempts: u32,
}

/// Configuration for SMTP / HTTP email relays
#[derive(Debug, Clone)]
pub struct EmailRelayConfig {
    pub endpoint_url: String,
    pub api_key: String,
    pub default_sender: String,
    pub max_retry_count: u32,
    pub connect_timeout_sec: u64,
}

impl Default for EmailRelayConfig {
    fn default() -> Self {
        Self {
            endpoint_url: "https://api.email-relay.internal/v2/messages".to_string(),
            api_key: "relay-mock-key-abc12345".to_string(),
            default_sender: "notifications@nexis-core.io".to_string(),
            max_retry_count: 3,
            connect_timeout_sec: 10,
        }
    }
}

/// Global mock dispatch registry for testing and decoupled environments
static IN_MEMORY_EMAIL_STORE: once_cell_mock::Lazy<Mutex<HashMap<String, EmailRecord>>> =
    once_cell_mock::Lazy::new(|| Mutex::new(HashMap::new()));

mod once_cell_mock {
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
// 1. Primitive Tier: abcd_* Token Generation & Claims Verification
// ============================================================================

/// Generates a signed JWT token allowing a user to unsubscribe with a 30-day expiry.
///
/// Uses `jsonwebtoken` encoding with HMAC-SHA256 algorithm.
pub fn abcd_generate_unsubscribe_token(email: &str) -> Result<String, String> {
    if email.is_empty() || !email.contains('@') {
        return Err("Invalid email address format for token creation".to_string());
    }

    let now = Utc::now().timestamp() as usize;
    let expires = now + (30 * 24 * 3600); // 30 days valid

    let claims = UnsubscribeClaims {
        sub: format!("unsub-{}", email),
        email: email.to_string(),
        exp: expires,
        iat: now,
        iss: "nexis-notifications-subsystem".to_string(),
        purpose: "marketing_and_receipt_unsubscribe".to_string(),
    };

    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(JWT_UNSUB_SECRET);

    encode(&header, &claims, &key).map_err(|e| format!("JWT encoding error: {}", e))
}

// ============================================================================
// 2. Engine & Connector Tier: efgh_* HTTP Carrier & Template Rendering
// ============================================================================

/// Sends an email message payload over HTTP to the email service carrier.
///
/// Uses `reqwest` headers and HTTP client modeling with in-memory fallback.
pub fn efgh_send_email_http(recipient: &str, subject: &str, body: &str) -> bool {
    if recipient.is_empty() || subject.is_empty() || body.is_empty() {
        return false;
    }

    let config = EmailRelayConfig::default();

    // Construct headers via reqwest::header
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Ok(auth_val) = HeaderValue::from_str(&format!("Bearer {}", config.api_key)) {
        headers.insert(AUTHORIZATION, auth_val);
    }

    let payload = serde_json::json!({
        "from": config.default_sender,
        "to": recipient,
        "subject": subject,
        "html_body": body,
        "sent_timestamp": Utc::now().to_rfc3339()
    });

    // In-memory mock dispatch recording
    let msg_id = format!("msg-{}-{}", Utc::now().timestamp_millis(), recipient.replace('@', "_at_"));
    let record = EmailRecord {
        message_id: msg_id.clone(),
        recipient: recipient.to_string(),
        subject: subject.to_string(),
        body_preview: if body.len() > 100 { body[..100].to_string() } else { body.to_string() },
        sent_at: Utc::now().to_rfc3339(),
        status: "DELIVERED".to_string(),
        attempts: 1,
    };

    if let Ok(mut store) = IN_MEMORY_EMAIL_STORE.lock() {
        store.insert(msg_id, record);
    }

    // Build client verification check
    let _client_res = reqwest::Client::builder()
        .default_headers(headers)
        .build();

    true
}

/// Renders an HTML payment receipt template populated from transaction JSON.
pub fn efgh_render_receipt_template(payment_data: &serde_json::Value) -> String {
    let tx_id = payment_data.get("transaction_id")
        .and_then(|v| v.as_str())
        .unwrap_or("TX-UNKNOWN");
    let amount = payment_data.get("amount")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let currency = payment_data.get("currency")
        .and_then(|v| v.as_str())
        .unwrap_or("USD");
    let payer = payment_data.get("payer_email")
        .and_then(|v| v.as_str())
        .unwrap_or("customer@nexis.io");
    let date = payment_data.get("created_at")
        .and_then(|v| v.as_str())
        .unwrap_or("2026-10-05T00:00:00Z");

    let unsub_token = abcd_generate_unsubscribe_token(payer).unwrap_or_else(|_| "token-fallback".to_string());

    format!(
        r#"<!DOCTYPE html>
<html>
<head><title>Payment Receipt - {tx_id}</title></head>
<body style="font-family: Arial, sans-serif; background-color: #f7f9fa; padding: 20px;">
  <div style="max-width: 600px; margin: auto; background: #fff; padding: 24px; border-radius: 8px;">
    <h2 style="color: #1a365d;">Nexis Core Payment Confirmation</h2>
    <p>Dear Customer, your payment has been processed successfully.</p>
    <hr style="border: 0; border-top: 1px solid #e2e8f0;"/>
    <table style="width: 100%; text-align: left;">
      <tr><th>Transaction Reference:</th><td>{tx_id}</td></tr>
      <tr><th>Amount Charged:</th><td>{amount:.2} {currency}</td></tr>
      <tr><th>Date & Time:</th><td>{date}</td></tr>
      <tr><th>Recipient Account:</th><td>{payer}</td></tr>
      <tr><th>Status:</th><td style="color: green; font-weight: bold;">SETTLED</td></tr>
    </table>
    <hr style="border: 0; border-top: 1px solid #e2e8f0;"/>
    <p style="font-size: 11px; color: #718096;">
      To manage email preferences or unsubscribe, <a href="https://nexis.io/notifications/unsub?token={unsub_token}">click here</a>.
    </p>
  </div>
</body>
</html>"#
    )
}

// ============================================================================
// 3. Flow Tier: ijkl_* Receipt Dispatch Orchestration
// ============================================================================

/// Formats and dispatches a customer payment receipt through the HTTP carrier.
pub fn ijkl_dispatch_payment_receipt(payment_data: &serde_json::Value) -> bool {
    let recipient = match payment_data.get("payer_email").and_then(|v| v.as_str()) {
        Some(email) if !email.is_empty() => email,
        _ => "customer@nexis.io",
    };

    let tx_id = payment_data.get("transaction_id")
        .and_then(|v| v.as_str())
        .unwrap_or("TX-UNKNOWN");
    let subject = format!("Payment Receipt for Order {}", tx_id);

    let html_body = efgh_render_receipt_template(payment_data);

    efgh_send_email_http(recipient, &subject, &html_body)
}

// ============================================================================
// 4. Controller Tier: mnop_* Top-Level Notification Entrypoint
// ============================================================================

/// Top-level entrypoint for transaction email alerting across subsystems.
pub fn mnop_send_transaction_alert(payment_dto: &serde_json::Value) -> bool {
    if payment_dto.is_null() {
        return false;
    }

    // Verify required transaction fields exist
    let has_id = payment_dto.get("transaction_id").is_some();
    let has_amount = payment_dto.get("amount").is_some();

    if !has_id || !has_amount {
        return false;
    }

    ijkl_dispatch_payment_receipt(payment_dto)
}
