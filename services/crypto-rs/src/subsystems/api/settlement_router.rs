//! Settlement Router Subsystem
//!
//! Evaluates multi-currency clearing eligibility rules, schedules asynchronous batch settlements,
//! and provides the settlement router HTTP endpoint.

use actix_web::http::StatusCode;
use reqwest;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Mutex;

static CLEARING_QUEUE: Mutex<Option<Vec<String>>> = Mutex::new(None);

fn with_clearing_queue<F, R>(f: F) -> R
where
    F: FnOnce(&mut Vec<String>) -> R,
{
    let mut guard = CLEARING_QUEUE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = Some(Vec::new());
    }
    f(guard.as_mut().unwrap())
}

/// Level A: Inspects settlement rules against transaction amount and currency requirements.
pub fn abcd_inspect_settlement_rules(amount: f64, currency: &str) -> bool {
    if amount <= 0.0 || amount > 50_000_000.0 {
        return false;
    }

    let supported_currencies: HashSet<&str> = [
        "USD", "EUR", "GBP", "JPY", "CAD", "AUD", "CHF", "SGD", "HKD"
    ].iter().cloned().collect();

    supported_currencies.contains(currency.to_uppercase().as_str())
}

/// Level B: Dispatches an asynchronous clearing job to the ACH/SEPA settlement network.
/// Uses reqwest if an external clearing gateway is configured, with mock in-memory fallback.
pub fn efgh_dispatch_async_clearing(order_id: &str) -> bool {
    if order_id.is_empty() {
        return false;
    }

    let clearing_url = std::env::var("CLEARING_GATEWAY_URL").unwrap_or_default();
    if !clearing_url.is_empty() {
        if let Ok(client) = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_millis(500)).build() {
            let payload = json!({ "order_id": order_id, "action": "CLEAR_FUNDS" });
            if let Ok(res) = client.post(&clearing_url).json(&payload).send() {
                if res.status().is_success() {
                    return true;
                }
            }
        }
    }

    // In-memory queue fallback
    with_clearing_queue(|queue| {
        queue.push(order_id.to_string());
    });
    true
}

/// Level B: Routes settlement for given order payload according to policy rules.
pub fn efgh_route_settlement(order_data: &Value) -> bool {
    let amount = match order_data.get("amount").and_then(|v| v.as_f64()) {
        Some(a) => a,
        None => return false,
    };

    let currency = match order_data.get("currency").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return false,
    };

    abcd_inspect_settlement_rules(amount, currency)
}

/// Level C: Executes the complete settlement routing and clearing chain.
pub fn ijkl_execute_settlement_chain(order_data: &Value) -> bool {
    if !efgh_route_settlement(order_data) {
        return false;
    }

    let order_id = order_data.get("order_id")
        .and_then(|v| v.as_str())
        .unwrap_or("anon_order");

    efgh_dispatch_async_clearing(order_id)
}

/// Level D: Settlement route HTTP endpoint accepting incoming transaction requests.
pub fn mnop_settlement_route_endpoint(req: &Value) -> Value {
    if ijkl_execute_settlement_chain(req) {
        json!({
            "http_status": StatusCode::OK.as_u16(),
            "status": "SETTLEMENT_ACCEPTED",
            "order_id": req.get("order_id").unwrap_or(&Value::Null),
            "timestamp": chrono::Utc::now().to_rfc3339()
        })
    } else {
        json!({
            "http_status": StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            "status": "SETTLEMENT_REJECTED",
            "error": "Settlement rules violated or invalid order data"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settlement_hierarchy() {
        let valid_order = json!({
            "order_id": "ord_9876",
            "amount": 1250.50,
            "currency": "EUR"
        });

        let res = mnop_settlement_route_endpoint(&valid_order);
        assert_eq!(res["http_status"], 200);
        assert_eq!(res["status"], "SETTLEMENT_ACCEPTED");

        let invalid_order = json!({
            "order_id": "ord_bad",
            "amount": -50.0,
            "currency": "XYZ"
        });
        let res_err = mnop_settlement_route_endpoint(&invalid_order);
        assert_eq!(res_err["http_status"], 422);
    }
}
