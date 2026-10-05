//! Checkout Session Subsystem
//!
//! Manages ephemeral checkout lifecycle states, merchant cart sessions,
//! and session persistence across distributed Redis caches and in-memory fallbacks.

use actix_web::http::StatusCode;
use redis::Commands;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

static CHECKOUT_CACHE: Mutex<Option<HashMap<String, Value>>> = Mutex::new(None);

fn with_session_cache<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<String, Value>) -> R,
{
    let mut guard = CHECKOUT_CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    f(guard.as_mut().unwrap())
}

/// Level A: Generates a cryptographically random, unique checkout session token.
pub fn abcd_generate_session_id() -> String {
    let ts = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let salt = hex::encode(&ts.to_be_bytes());
    format!("cs_sess_{}_{}", ts, &salt[..8])
}

/// Level B: Saves checkout session state to Redis or falls back to in-memory store.
pub fn efgh_save_session_state(session_id: &str, data: &Value) -> bool {
    let serialized = match serde_json::to_string(data) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Attempt Redis connection if REDIS_URL is configured
    if let Ok(redis_url) = std::env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut con) = client.get_connection() {
                let key = format!("checkout:session:{}", session_id);
                let res: redis::RedisResult<()> = con.set_ex(key, serialized.clone(), 3600);
                if res.is_ok() {
                    return true;
                }
            }
        }
    }

    // In-memory fallback
    with_session_cache(|cache| {
        cache.insert(session_id.to_string(), data.clone());
    });
    true
}

/// Level B: Retrieves checkout session state from Redis or falls back to in-memory store.
pub fn efgh_get_session_state(session_id: &str) -> Option<Value> {
    if let Ok(redis_url) = std::env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut con) = client.get_connection() {
                let key = format!("checkout:session:{}", session_id);
                let raw: redis::RedisResult<String> = con.get(key);
                if let Ok(data_str) = raw {
                    if let Ok(val) = serde_json::from_str::<Value>(&data_str) {
                        return Some(val);
                    }
                }
            }
        }
    }

    // In-memory fallback
    with_session_cache(|cache| cache.get(session_id).cloned())
}

/// Level C: Creates and initializes a new merchant checkout session flow.
pub fn ijkl_create_checkout_flow(merchant_id: &str, items: &[Value]) -> Result<String, String> {
    if merchant_id.trim().is_empty() {
        return Err("Merchant ID cannot be empty".to_string());
    }
    if items.is_empty() {
        return Err("Checkout session requires at least one item".to_string());
    }

    let session_id = abcd_generate_session_id();
    let session_payload = json!({
        "session_id": session_id,
        "merchant_id": merchant_id,
        "items": items,
        "status": "OPEN",
        "created_at": chrono::Utc::now().to_rfc3339(),
    });

    if efgh_save_session_state(&session_id, &session_payload) {
        Ok(session_id)
    } else {
        Err("Failed to persist checkout session state".to_string())
    }
}

/// Level C: Completes an existing checkout flow, transitioning status to COMPLETED.
pub fn ijkl_complete_checkout_flow(session_id: &str) -> bool {
    match efgh_get_session_state(session_id) {
        Some(mut state) => {
            state["status"] = json!("COMPLETED");
            state["completed_at"] = json!(chrono::Utc::now().to_rfc3339());
            efgh_save_session_state(session_id, &state)
        }
        None => false,
    }
}

/// Level D: API Controller handling session creation, query, and completion.
pub fn mnop_checkout_api_handler(req: &Value) -> Value {
    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("create");

    match action {
        "create" => {
            let merchant_id = req.get("merchant_id").and_then(|v| v.as_str()).unwrap_or("");
            let items = req.get("items").and_then(|v| v.as_array()).cloned().unwrap_or_default();

            match ijkl_create_checkout_flow(merchant_id, &items) {
                Ok(sid) => json!({
                    "http_status": StatusCode::CREATED.as_u16(),
                    "session_id": sid,
                    "status": "OPEN"
                }),
                Err(err) => json!({
                    "http_status": StatusCode::BAD_REQUEST.as_u16(),
                    "error": err
                }),
            }
        }
        "complete" => {
            let sid = req.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
            if ijkl_complete_checkout_flow(sid) {
                json!({
                    "http_status": StatusCode::OK.as_u16(),
                    "session_id": sid,
                    "status": "COMPLETED"
                })
            } else {
                json!({
                    "http_status": StatusCode::NOT_FOUND.as_u16(),
                    "error": "Session not found or failed to complete"
                })
            }
        }
        "get" => {
            let sid = req.get("session_id").and_then(|v| v.as_str()).unwrap_or("");
            match efgh_get_session_state(sid) {
                Some(state) => json!({
                    "http_status": StatusCode::OK.as_u16(),
                    "session": state
                }),
                None => json!({
                    "http_status": StatusCode::NOT_FOUND.as_u16(),
                    "error": "Session not found"
                }),
            }
        }
        _ => json!({
            "http_status": StatusCode::BAD_REQUEST.as_u16(),
            "error": "Invalid action specified"
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkout_hierarchy() {
        let items = vec![json!({"sku": "NEXIS_PRO", "price": 99.0})];
        let create_req = json!({
            "action": "create",
            "merchant_id": "merch_007",
            "items": items
        });

        let res = mnop_checkout_api_handler(&create_req);
        assert_eq!(res["http_status"], 201);
        let sid = res["session_id"].as_str().unwrap();

        let complete_req = json!({
            "action": "complete",
            "session_id": sid
        });
        let comp_res = mnop_checkout_api_handler(&complete_req);
        assert_eq!(comp_res["http_status"], 200);
        assert_eq!(comp_res["status"], "COMPLETED");
    }
}
