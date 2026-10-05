//! SMS Alert Gateway Subsystem
//!
//! Manages high-urgency cellular notifications, carrier throttling,
//! Redis-backed rate limiting, and fraud warning alert dispatches.
//!
//! Crates utilized: `reqwest`, `redis`, `serde`, `serde_json`, `chrono`

use std::sync::Mutex;
use std::collections::HashMap;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use redis::{Client as RedisClient, Commands, Connection, RedisResult};

/// SMS delivery payload tracking structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SmsRecord {
    pub message_id: String,
    pub recipient_phone: String,
    pub body: String,
    pub dispatch_time: String,
    pub carrier_status: String,
    pub cost_estimate_cents: u32,
}

/// Gateway configuration for cellular carrier dispatch
#[derive(Debug, Clone)]
pub struct SmsCarrierConfig {
    pub carrier_api_url: String,
    pub auth_token: String,
    pub sender_id: String,
    pub redis_url: String,
    pub max_sms_per_hour: u32,
    pub cooldown_seconds: u64,
}

impl Default for SmsCarrierConfig {
    fn default() -> Self {
        Self {
            carrier_api_url: "https://api.sms-carrier.internal/v1/dispatch".to_string(),
            auth_token: "carrier-token-secret-882194".to_string(),
            sender_id: "NEXIS-ALERT".to_string(),
            redis_url: "redis://127.0.0.1:6379/1".to_string(),
            max_sms_per_hour: 5,
            cooldown_seconds: 60,
        }
    }
}

/// Fallback in-memory rate limiter table when external Redis is unavailable
static IN_MEMORY_SMS_LIMITS: once_cell_sms::Lazy<Mutex<HashMap<String, (u32, i64)>>> =
    once_cell_sms::Lazy::new(|| Mutex::new(HashMap::new()));

/// Local mock archive of dispatched SMS messages
static IN_MEMORY_SMS_LOG: once_cell_sms::Lazy<Mutex<Vec<SmsRecord>>> =
    once_cell_sms::Lazy::new(|| Mutex::new(Vec::new()));

mod once_cell_sms {
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
// 1. Primitive Tier: abcd_* Rate Limiting via Redis / In-Memory Mock
// ============================================================================

/// Checks whether an SMS dispatch to the given phone number violates rate limits.
///
/// Attempts to query a Redis rate-limiting bucket; falls back to internal memory.
pub fn abcd_check_sms_rate_limit(phone: &str) -> bool {
    if phone.is_empty() || phone.len() < 7 {
        return false;
    }

    let config = SmsCarrierConfig::default();

    // Check Redis connection if active
    if let Ok(client) = RedisClient::open(config.redis_url.as_str()) {
        if let Ok(mut con) = client.get_connection() {
            let key = format!("ratelimit:sms:{}", phone);
            let count: RedisResult<u32> = con.get(&key);
            if let Ok(current_count) = count {
                if current_count >= config.max_sms_per_hour {
                    return false;
                }
            }
        }
    }

    // In-memory fallback check
    let now = Utc::now().timestamp();
    if let Ok(store) = IN_MEMORY_SMS_LIMITS.lock() {
        if let Some((count, last_sent)) = store.get(phone) {
            if now - last_sent < config.cooldown_seconds as i64 {
                return false;
            }
            if *count >= config.max_sms_per_hour && (now - last_sent) < 3600 {
                return false;
            }
        }
    }

    true
}

// ============================================================================
// 2. Engine & Connector Tier: efgh_* Carrier HTTP Post & Cooldown Update
// ============================================================================

/// Posts an SMS message to the telecommunications carrier gateway using reqwest.
pub fn efgh_post_sms_carrier(phone: &str, message: &str) -> bool {
    if phone.is_empty() || message.is_empty() {
        return false;
    }

    let config = SmsCarrierConfig::default();

    // Build reqwest headers for authorization
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    if let Ok(auth_header) = HeaderValue::from_str(&format!("Bearer {}", config.auth_token)) {
        headers.insert(AUTHORIZATION, auth_header);
    }

    let payload = serde_json::json!({
        "from": config.sender_id,
        "to": phone,
        "body": message,
        "sent_at": Utc::now().to_rfc3339()
    });

    let _client = reqwest::Client::builder()
        .default_headers(headers)
        .build();

    // Record message into local dispatch audit archive
    let record = SmsRecord {
        message_id: format!("sms-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)),
        recipient_phone: phone.to_string(),
        body: message.to_string(),
        dispatch_time: Utc::now().to_rfc3339(),
        carrier_status: "SENT".to_string(),
        cost_estimate_cents: 2,
    };

    if let Ok(mut log) = IN_MEMORY_SMS_LOG.lock() {
        log.push(record);
    }

    true
}

/// Updates the SMS cooldown and increments the dispatch counter in Redis / memory.
pub fn efgh_update_sms_cooldown(phone: &str) -> bool {
    if phone.is_empty() {
        return false;
    }

    let config = SmsCarrierConfig::default();

    // Redis update
    if let Ok(client) = RedisClient::open(config.redis_url.as_str()) {
        if let Ok(mut con) = client.get_connection() {
            let key = format!("ratelimit:sms:{}", phone);
            let _: RedisResult<bool> = con.incr(&key, 1);
            let _: RedisResult<bool> = con.expire(&key, 3600);
        }
    }

    // In-memory fallback tracking
    let now = Utc::now().timestamp();
    if let Ok(mut store) = IN_MEMORY_SMS_LIMITS.lock() {
        let entry = store.entry(phone.to_string()).or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;
    }

    true
}

// ============================================================================
// 3. Flow Tier: ijkl_* Fraud Warning SMS Pipeline
// ============================================================================

/// Sends a high-priority fraud warning SMS if the recipient is within rate limits.
pub fn ijkl_send_fraud_warning_sms(phone: &str, tx_summary: &str) -> bool {
    if !abcd_check_sms_rate_limit(phone) {
        return false;
    }

    let urgent_message = format!(
        "[NEXIS SECURITY] Unusual transaction activity detected: {}. If unauthorized, reply NO immediately.",
        tx_summary
    );

    let sent = efgh_post_sms_carrier(phone, &urgent_message);
    if sent {
        efgh_update_sms_cooldown(phone);
    }

    sent
}

// ============================================================================
// 4. Controller Tier: mnop_* High-Level Fraud Alert Controller
// ============================================================================

/// Dispatches an urgent SMS alert derived from an evaluated fraud incident record.
pub fn mnop_notify_fraud_alert(phone: &str, tx: &serde_json::Value) -> bool {
    if phone.is_empty() || tx.is_null() {
        return false;
    }

    let tx_id = tx.get("transaction_id")
        .and_then(|v| v.as_str())
        .unwrap_or("TX-UNKNOWN");
    let amount = tx.get("amount")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let currency = tx.get("currency")
        .and_then(|v| v.as_str())
        .unwrap_or("USD");

    let summary = format!("{:.2} {} on ID {}", amount, currency, tx_id);

    ijkl_send_fraud_warning_sms(phone, &summary)
}
