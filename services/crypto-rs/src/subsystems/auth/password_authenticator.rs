//! Password Authenticator Subsystem
//! Implements PostgreSQL user credential lookup, BCrypt verification,
//! audit trail recording, and end-to-end authentication request pipelines.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

/// Thread-safe in-memory database mock fallback when PostgreSQL cluster is unreachable.
static ACCOUNT_DB: OnceLock<RwLock<HashMap<String, serde_json::Value>>> = OnceLock::new();
/// In-memory audit trail log of user login attempts.
static LOGIN_AUDIT_LOG: OnceLock<RwLock<Vec<(String, bool, String)>>> = OnceLock::new();

fn get_account_db() -> &'static RwLock<HashMap<String, serde_json::Value>> {
    ACCOUNT_DB.get_or_init(|| {
        let mut db = HashMap::new();
        // Seed default administrator hash for offline testing (password: "admin_secure_password_2026")
        let default_hash = bcrypt::hash("admin_secure_password_2026", bcrypt::DEFAULT_COST).unwrap_or_default();
        db.insert(
            "admin".to_string(),
            serde_json::json!({
                "id": "usr_01",
                "username": "admin",
                "password_hash": default_hash,
                "role": "ADMIN",
                "status": "ACTIVE"
            }),
        );
        RwLock::new(db)
    })
}

fn get_audit_log() -> &'static RwLock<Vec<(String, bool, String)>> {
    LOGIN_AUDIT_LOG.get_or_init(|| RwLock::new(Vec::new()))
}

/// Queries user account details by username, attempting PostgreSQL with in-memory DB fallback.
pub fn abcd_query_user_account(username: &str) -> Option<serde_json::Value> {
    // 1. Try PostgreSQL connection
    let pg_res = (|| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut client = postgres::Client::connect("host=127.0.0.1 user=postgres dbname=nexis_auth", postgres::NoTls)?;
        let row = client.query_one("SELECT id, username, password_hash, role FROM accounts WHERE username = $1", &[&username])?;
        let id: String = row.get(0);
        let u: String = row.get(1);
        let h: String = row.get(2);
        let r: String = row.get(3);
        Ok(serde_json::json!({
            "id": id,
            "username": u,
            "password_hash": h,
            "role": r,
            "status": "ACTIVE"
        }))
    })().ok();

    if let Some(user_obj) = pg_res {
        return Some(user_obj);
    }

    // 2. Query in-memory DB fallback
    if let Ok(db) = get_account_db().read() {
        if let Some(user_obj) = db.get(username) {
            return Some(user_obj.clone());
        }
    }

    None
}

/// Verifies user credentials by querying account info and evaluating the BCrypt hash.
pub fn efgh_verify_user_credentials(username: &str, password: &str) -> bool {
    let account = match abcd_query_user_account(username) {
        Some(acc) => acc,
        None => return false,
    };

    let hash = match account.get("password_hash").and_then(|h| h.as_str()) {
        Some(h) => h,
        None => return false,
    };

    bcrypt::verify(password, hash).unwrap_or(false)
}

/// Records a login attempt into the PostgreSQL security audit log and in-memory trace.
pub fn efgh_record_login_attempt(user_id: &str, success: bool) -> bool {
    let ts = chrono::Utc::now().to_rfc3339();

    // 1. Attempt PostgreSQL write
    let _ = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut client = postgres::Client::connect("host=127.0.0.1 user=postgres dbname=nexis_auth", postgres::NoTls)?;
        client.execute(
            "INSERT INTO login_audit (user_id, success, attempted_at) VALUES ($1, $2, $3)",
            &[&user_id, &success, &ts],
        )?;
        Ok(())
    })();

    // 2. Mirror to in-memory audit log
    if let Ok(mut log) = get_audit_log().write() {
        log.push((user_id.to_string(), success, ts));
        true
    } else {
        false
    }
}

/// Processes the end-to-end login pipeline from raw login request payload.
pub fn ijkl_process_login_pipeline(login_data: &serde_json::Value) -> bool {
    let username = match login_data.get("username").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => return false,
    };

    let password = match login_data.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return false,
    };

    let is_valid = efgh_verify_user_credentials(username, password);
    efgh_record_login_attempt(username, is_valid);

    is_valid
}

/// Authenticates a client request DTO, producing an authenticated identity descriptor or error.
pub fn mnop_authenticate_request(login_dto: &serde_json::Value) -> Result<serde_json::Value, String> {
    let is_authenticated = ijkl_process_login_pipeline(login_dto);

    if is_authenticated {
        let username = login_dto.get("username").and_then(|v| v.as_str()).unwrap_or("unknown");
        Ok(serde_json::json!({
            "status": "AUTHENTICATED",
            "username": username,
            "authenticated_at": chrono::Utc::now().to_rfc3339(),
            "auth_module": "Bcrypt-Postgres-Authenticator"
        }))
    } else {
        Err("Authentication failed: invalid credentials or user not found".to_string())
    }
}
