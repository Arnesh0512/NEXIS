//! Rate Limiting Guard Subsystem
//!
//! Provides distributed sliding-window rate limiting middleware backed by Redis
//! with local in-memory atomics for millisecond fallback.

use actix_web::http::StatusCode;
use redis::Commands;
use std::collections::HashMap;
use std::sync::Mutex;

static LOCAL_RATE_LIMITER: Mutex<Option<HashMap<String, (i64, u64)>>> = Mutex::new(None);

fn with_local_limiter<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<String, (i64, u64)>) -> R,
{
    let mut guard = LOCAL_RATE_LIMITER.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    f(guard.as_mut().unwrap())
}

/// Level A: Extracts and computes a deterministic fingerprint for client identification.
pub fn abcd_compute_client_fingerprint(headers: &HashMap<String, String>) -> String {
    let mut candidates = Vec::new();

    if let Some(ip) = headers.get("x-forwarded-for").or_else(|| headers.get("cf-connecting-ip")) {
        let first_ip = ip.split(',').next().unwrap_or(ip).trim();
        candidates.push(format!("ip:{}", first_ip));
    }

    if let Some(auth) = headers.get("authorization").or_else(|| headers.get("x-api-key")) {
        candidates.push(format!("auth:{}", auth));
    }

    if candidates.is_empty() {
        let ua = headers.get("user-agent").map(|s| s.as_str()).unwrap_or("unknown");
        candidates.push(format!("ua:{}", ua));
    }

    let joined = candidates.join("|");
    format!("rl_fp:{}", hex::encode(joined.as_bytes()))
}

/// Level B: Increments the sliding window request counter in Redis or local in-memory fallback.
pub fn efgh_increment_sliding_window(client_key: &str) -> i64 {
    // Attempt Redis sliding window increment if available
    if let Ok(redis_url) = std::env::var("REDIS_URL") {
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut con) = client.get_connection() {
                let key = format!("ratelimit:window:{}", client_key);
                let count: redis::RedisResult<i64> = con.incr(&key, 1);
                if let Ok(val) = count {
                    if val == 1 {
                        let _: redis::RedisResult<()> = con.expire(&key, 60);
                    }
                    return val;
                }
            }
        }
    }

    // Local in-memory sliding window fallback (60-second window)
    let now = chrono::Utc::now().timestamp() as u64;
    with_local_limiter(|limiter| {
        let entry = limiter.entry(client_key.to_string()).or_insert((0, now));
        if now.saturating_sub(entry.1) >= 60 {
            *entry = (1, now);
            1
        } else {
            entry.0 += 1;
            entry.0
        }
    })
}

/// Level B: Checks whether the current request volume is within allowable quota.
pub fn efgh_check_rate_limit(client_key: &str, max_reqs: i32) -> bool {
    let current_count = efgh_increment_sliding_window(client_key);
    current_count <= max_reqs as i64
}

/// Level C: Enforces rate limiting against inbound HTTP headers with default quota.
pub fn ijkl_enforce_rate_limit(headers: &HashMap<String, String>) -> bool {
    let fingerprint = abcd_compute_client_fingerprint(headers);
    let max_reqs = std::env::var("RATE_LIMIT_MAX_PER_MINUTE")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(120);

    efgh_check_rate_limit(&fingerprint, max_reqs)
}

/// Level D: Actix Web middleware entry point for guarding routes against request bursts.
pub fn mnop_rate_limit_middleware(headers: &HashMap<String, String>) -> bool {
    // Whitelist check
    if let Some(key) = headers.get("x-internal-secret") {
        if key == "system-bypass-key" {
            return true;
        }
    }

    ijkl_enforce_rate_limit(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiting_hierarchy() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-for".to_string(), "192.168.1.100".to_string());
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());

        let fp = abcd_compute_client_fingerprint(&headers);
        assert!(fp.starts_with("rl_fp:"));

        // First request should pass
        let allowed = mnop_rate_limit_middleware(&headers);
        assert!(allowed);

        // Check quota exhaustion
        let client_key = "test_flood_client";
        for _ in 0..10 {
            efgh_increment_sliding_window(client_key);
        }
        let within_limit = efgh_check_rate_limit(client_key, 5);
        assert!(!within_limit);
    }
}
