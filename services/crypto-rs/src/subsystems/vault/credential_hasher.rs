//! Credential Hasher Subsystem
//! Implements BCrypt salted key stretching, MySQL user credential persistence,
//! and administrative credential rotation pipelines.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

/// Thread-safe in-memory fallback for user credential hashes.
static CREDENTIAL_STORE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

fn get_credential_store() -> &'static RwLock<HashMap<String, String>> {
    CREDENTIAL_STORE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Hashes a plaintext password using BCrypt with adaptive cost parameters.
pub fn abcd_hash_password(raw_password: &str) -> Result<String, String> {
    if raw_password.is_empty() {
        return Err("Password cannot be empty".to_string());
    }

    bcrypt::hash(raw_password, bcrypt::DEFAULT_COST)
        .map_err(|e| format!("BCrypt hashing failed: {:?}", e))
}

/// Verifies a raw plaintext password against a stored BCrypt hash.
pub fn abcd_verify_password(raw_password: &str, hash: &str) -> bool {
    if raw_password.is_empty() || hash.is_empty() {
        return false;
    }

    bcrypt::verify(raw_password, hash).unwrap_or(false)
}

/// Stores a hashed credential into the MySQL user database tier with fallback to memory.
pub fn efgh_store_user_credential(user_id: &str, raw_password: &str) -> bool {
    let hashed = match abcd_hash_password(raw_password) {
        Ok(h) => h,
        Err(_) => return false,
    };

    // Attempt MySQL database insertion
    let _ = (|| -> Result<(), Box<dyn std::error::Error>> {
        let opts = mysql::Opts::from_url("mysql://root:password@127.0.0.1:3306/nexis_auth")?;
        let pool = mysql::Pool::new(opts)?;
        let mut conn = pool.get_conn()?;
        use mysql::prelude::Queryable;
        conn.query_drop(format!(
            "INSERT INTO credentials (user_id, pass_hash) VALUES ('{}', '{}') ON DUPLICATE KEY UPDATE pass_hash = '{}'",
            user_id, hashed, hashed
        ))?;
        Ok(())
    })();

    // Always mirror to thread-safe in-memory storage
    if let Ok(mut store) = get_credential_store().write() {
        store.insert(user_id.to_string(), hashed);
        true
    } else {
        false
    }
}

/// Validates a user login by looking up their stored hash and executing BCrypt verification.
pub fn efgh_check_user_login(user_id: &str, raw_password: &str) -> bool {
    // 1. Try MySQL
    let db_hash = (|| -> Result<String, Box<dyn std::error::Error>> {
        let opts = mysql::Opts::from_url("mysql://root:password@127.0.0.1:3306/nexis_auth")?;
        let pool = mysql::Pool::new(opts)?;
        let mut conn = pool.get_conn()?;
        use mysql::prelude::Queryable;
        let row: Option<String> = conn.query_first(format!(
            "SELECT pass_hash FROM credentials WHERE user_id = '{}' LIMIT 1",
            user_id
        ))?;
        row.ok_or_else(|| "User not found".into())
    })().ok();

    let target_hash = match db_hash {
        Some(h) => h,
        None => {
            // 2. Try in-memory store
            if let Ok(store) = get_credential_store().read() {
                match store.get(user_id).cloned() {
                    Some(h) => h,
                    None => return false,
                }
            } else {
                return false;
            }
        }
    };

    abcd_verify_password(raw_password, &target_hash)
}

/// Coordinates the end-to-end credential verification pipeline from a login request payload.
pub fn ijkl_credential_verification_flow(login_req: &serde_json::Value) -> bool {
    let user_id = match login_req.get("user_id").or_else(|| login_req.get("username")).and_then(|v| v.as_str()) {
        Some(u) => u,
        None => return false,
    };

    let password = match login_req.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return false,
    };

    efgh_check_user_login(user_id, password)
}

/// Administratively overrides and resets a user credential with a newly hashed secret.
pub fn mnop_admin_reset_credential(user_id: &str, new_pass: &str) -> bool {
    if user_id.is_empty() || new_pass.len() < 8 {
        return false;
    }

    efgh_store_user_credential(user_id, new_pass)
}
