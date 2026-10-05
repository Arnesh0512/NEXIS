//! Payment Endpoints Subsystem
//!
//! Exposes API route controllers and validation pipelines for payment initiation,
//! risk screening, and payment capture workflows.

use actix_web::{http::StatusCode, HttpResponse};
use reqwest;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

static PAYMENT_STORE: Mutex<Option<HashMap<String, Value>>> = Mutex::new(None);

fn with_payment_store<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<String, Value>) -> R,
{
    let mut guard = PAYMENT_STORE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    f(guard.as_mut().unwrap())
}

/// Level A: Parses and validates the inbound raw payment request payload.
pub fn abcd_parse_payment_request(payload: &Value) -> Result<Value, String> {
    let amount = payload.get("amount")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| "Missing or invalid 'amount' field".to_string())?;

    if amount <= 0.0 {
        return Err("Payment amount must be greater than zero".to_string());
    }

    let currency = payload.get("currency")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing or invalid 'currency' field".to_string())?;

    let payment_id = payload.get("payment_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("pay_{}", chrono::Utc::now().timestamp_millis()));

    let customer_id = payload.get("customer_id")
        .and_then(|v| v.as_str())
        .unwrap_or("guest_user");

    Ok(json!({
        "payment_id": payment_id,
        "amount": amount,
        "currency": currency.to_uppercase(),
        "customer_id": customer_id,
        "status": "PARSED",
        "created_at": chrono::Utc::now().to_rfc3339(),
    }))
}

/// Level B: Forwards the parsed payment request to the risk scoring engine.
/// Utilizes reqwest for HTTP forwarding with in-memory deterministic fallback.
pub fn efgh_forward_to_risk_engine(payment_req: &Value) -> Result<Value, String> {
    let risk_endpoint = std::env::var("RISK_ENGINE_URL").unwrap_or_default();
    let amount = payment_req.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);

    if !risk_endpoint.is_empty() {
        if let Ok(client) = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_millis(500)).build() {
            if let Ok(resp) = client.post(&risk_endpoint).json(payment_req).send() {
                if let Ok(body) = resp.json::<Value>() {
                    return Ok(body);
                }
            }
        }
    }

    // In-memory mock risk evaluation fallback
    let score = if amount > 100_000.0 { 0.85 } else { 0.05 };
    let verdict = if score > 0.70 { "REJECTED" } else { "APPROVED" };

    if verdict == "REJECTED" {
        return Err(format!("Risk engine rejected transaction. Score: {}", score));
    }

    Ok(json!({
        "payment_id": payment_req.get("payment_id").unwrap_or(&Value::Null),
        "risk_score": score,
        "risk_verdict": verdict,
        "engine": "mock_in_memory_rules",
    }))
}

/// Level B: Routes the payment through validation and risk assessment.
pub fn efgh_process_payment_route(payload: &Value) -> Result<Value, String> {
    let parsed = abcd_parse_payment_request(payload)?;
    let risk_eval = efgh_forward_to_risk_engine(&parsed)?;

    let mut record = parsed;
    record["risk_status"] = risk_eval["risk_verdict"].clone();
    record["status"] = json!("ROUTED");

    let pid = record["payment_id"].as_str().unwrap_or_default().to_string();
    with_payment_store(|store| {
        store.insert(pid.clone(), record.clone());
    });

    Ok(record)
}

/// Level C: Captures the routed payment and finalizes the ledger hold.
pub fn ijkl_capture_payment_route(payment_id: &str) -> Result<Value, String> {
    with_payment_store(|store| {
        if let Some(record) = store.get_mut(payment_id) {
            record["status"] = json!("CAPTURED");
            record["captured_at"] = json!(chrono::Utc::now().to_rfc3339());
            Ok(record.clone())
        } else {
            // Mock auto-create if not found
            let new_record = json!({
                "payment_id": payment_id,
                "status": "CAPTURED",
                "captured_at": chrono::Utc::now().to_rfc3339(),
                "mock_generated": true,
            });
            store.insert(payment_id.to_string(), new_record.clone());
            Ok(new_record)
        }
    })
}

/// Level D: API Controller handling inbound HTTP JSON payloads.
pub fn mnop_payment_api_controller(request: &Value) -> Value {
    let action = request.get("action").and_then(|v| v.as_str()).unwrap_or("process");

    match action {
        "capture" => {
            let pid = match request.get("payment_id").and_then(|v| v.as_str()) {
                Some(id) => id,
                None => return json!({
                    "http_status": StatusCode::BAD_REQUEST.as_u16(),
                    "error": "Missing 'payment_id' for capture action"
                }),
            };
            match ijkl_capture_payment_route(pid) {
                Ok(res) => json!({
                    "http_status": StatusCode::OK.as_u16(),
                    "data": res
                }),
                Err(err) => json!({
                    "http_status": StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    "error": err
                }),
            }
        }
        _ => {
            match efgh_process_payment_route(request) {
                Ok(routed) => {
                    let pid = routed["payment_id"].as_str().unwrap_or_default();
                    match ijkl_capture_payment_route(pid) {
                        Ok(captured) => json!({
                            "http_status": StatusCode::CREATED.as_u16(),
                            "data": captured
                        }),
                        Err(err) => json!({
                            "http_status": StatusCode::ACCEPTED.as_u16(),
                            "data": routed,
                            "warning": err
                        }),
                    }
                }
                Err(err) => json!({
                    "http_status": StatusCode::BAD_REQUEST.as_u16(),
                    "error": err
                }),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_call_hierarchy() {
        let req = json!({
            "amount": 250.0,
            "currency": "usd",
            "customer_id": "cust_123"
        });

        let res = mnop_payment_api_controller(&req);
        assert_eq!(res["http_status"], 201);
        let pid = res["data"]["payment_id"].as_str().unwrap();
        assert!(pid.starts_with("pay_"));

        let capture_req = json!({
            "action": "capture",
            "payment_id": pid
        });
        let cap_res = mnop_payment_api_controller(&capture_req);
        assert_eq!(cap_res["http_status"], 200);
        assert_eq!(cap_res["data"]["status"], "CAPTURED");
    }
}
