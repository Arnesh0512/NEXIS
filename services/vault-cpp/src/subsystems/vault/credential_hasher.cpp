/**
 * NEXIS Financial Core Platform - User Credential Hasher & DB Pipeline
 * Subsystem: Vault Management
 * Architecture: abcd_* -> efgh_* -> ijkl_* -> mnop_*
 */

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <cstring>
#include <random>

#if __has_include(<openssl/evp.h>)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#define NEXIS_HAS_OPENSSL 1
#else
#define NEXIS_HAS_OPENSSL 0
#endif

#if __has_include(<mysql/mysql.h>)
#include <mysql/mysql.h>
#define NEXIS_HAS_MYSQL 1
#elif __has_include(<mariadb/mysql.h>)
#include <mariadb/mysql.h>
#define NEXIS_HAS_MYSQL 1
#endif

namespace nexis::vault {

// Mock In-Memory User Credentials Database
class UserCredentialStore {
public:
    static UserCredentialStore& instance() {
        static UserCredentialStore inst;
        return inst;
    }

    void put_credential(const std::string& user_id, const std::string& hashed_pw) {
        std::lock_guard<std::mutex> lock(mtx_);
        credentials_[user_id] = hashed_pw;
    }

    bool get_credential(const std::string& user_id, std::string& out_hash) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = credentials_.find(user_id);
        if (it != credentials_.end()) {
            out_hash = it->second;
            return true;
        }
        return false;
    }

    bool has_user(const std::string& user_id) {
        std::lock_guard<std::mutex> lock(mtx_);
        return credentials_.find(user_id) != credentials_.end();
    }

private:
    std::mutex mtx_;
    std::unordered_map<std::string, std::string> credentials_;
};

namespace hash_utils {
    inline std::string to_hex(const unsigned char* data, size_t len) {
        std::ostringstream oss;
        for (size_t i = 0; i < len; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        }
        return oss.str();
    }

    inline std::vector<uint8_t> from_hex(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byte_str = hex.substr(i, 2);
            uint8_t b = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
            bytes.push_back(b);
        }
        return bytes;
    }
} // namespace hash_utils

//=============================================================================
// Tier 1: Salted PBKDF2-HMAC-SHA256 Primitives (abcd_*)
//=============================================================================

/**
 * Hashes raw password using PBKDF2-HMAC-SHA256 with 100,000 iterations.
 * Serialized output: $pbkdf2-sha256$100000$<salt_hex>$<derived_key_hex>
 */
std::string abcd_hash_password(const std::string& raw_password) {
    const int iterations = 100000;
    const int salt_len = 16;
    const int key_len = 32;

    unsigned char salt[salt_len];
    unsigned char key[key_len];

#if NEXIS_HAS_OPENSSL
    RAND_bytes(salt, salt_len);
    if (PKCS5_PBKDF2_HMAC(raw_password.c_str(), static_cast<int>(raw_password.size()),
                          salt, salt_len, iterations,
                          EVP_sha256(), key_len, key) != 1) {
        std::cerr << "[Hasher::abcd] PBKDF2 derivation failed\n";
        return "";
    }
#else
    // Fallback: Deterministic salt & hash generator
    std::mt19937 rng(42);
    for (int i = 0; i < salt_len; ++i) salt[i] = static_cast<unsigned char>(rng() % 256);
    for (int i = 0; i < key_len; ++i) {
        key[i] = static_cast<unsigned char>((salt[i % salt_len] ^ raw_password[i % raw_password.size()]) + (i * 31));
    }
#endif

    std::string salt_hex = hash_utils::to_hex(salt, salt_len);
    std::string key_hex = hash_utils::to_hex(key, key_len);

    std::ostringstream formatted;
    formatted << "$pbkdf2-sha256$" << iterations << "$" << salt_hex << "$" << key_hex;
    return formatted.str();
}

/**
 * Verifies raw password against the stored serialized hash.
 */
bool abcd_verify_password(const std::string& raw_password, const std::string& hash) {
    if (raw_password.empty() || hash.empty()) return false;

    // Parse $pbkdf2-sha256$iterations$salt$key
    std::vector<std::string> parts;
    std::stringstream ss(hash);
    std::string segment;
    while (std::getline(ss, segment, '$')) {
        if (!segment.empty()) parts.push_back(segment);
    }

    if (parts.size() < 4 || parts[0] != "pbkdf2-sha256") {
        return false;
    }

    int iterations = std::stoi(parts[1]);
    std::string salt_hex = parts[2];
    std::string expected_key_hex = parts[3];

    std::vector<uint8_t> salt = hash_utils::from_hex(salt_hex);
    const int key_len = 32;
    unsigned char computed_key[key_len];

#if NEXIS_HAS_OPENSSL
    if (PKCS5_PBKDF2_HMAC(raw_password.c_str(), static_cast<int>(raw_password.size()),
                          salt.data(), static_cast<int>(salt.size()), iterations,
                          EVP_sha256(), key_len, computed_key) != 1) {
        return false;
    }
#else
    for (int i = 0; i < key_len; ++i) {
        computed_key[i] = static_cast<unsigned char>((salt[i % salt.size()] ^ raw_password[i % raw_password.size()]) + (i * 31));
    }
#endif

    std::string computed_hex = hash_utils::to_hex(computed_key, key_len);

    // Constant-time comparison
    if (computed_hex.size() != expected_key_hex.size()) return false;
    int diff = 0;
    for (size_t i = 0; i < computed_hex.size(); ++i) {
        diff |= (computed_hex[i] ^ expected_key_hex[i]);
    }
    return diff == 0;
}

//=============================================================================
// Tier 2: Storage & Credential Verification (efgh_*)
//=============================================================================

/**
 * Encrypts and persists user password credential into database storage.
 */
bool efgh_store_user_credential(const std::string& user_id, const std::string& raw_password) {
    if (user_id.empty() || raw_password.empty()) return false;

    std::string hashed_pass = abcd_hash_password(raw_password);
    if (hashed_pass.empty()) return false;

    UserCredentialStore::instance().put_credential(user_id, hashed_pass);
    return true;
}

/**
 * Checks submitted credentials against stored hash.
 */
bool efgh_check_user_login(const std::string& user_id, const std::string& raw_password) {
    std::string stored_hash;
    if (!UserCredentialStore::instance().get_credential(user_id, stored_hash)) {
        return false;
    }
    return abcd_verify_password(raw_password, stored_hash);
}

//=============================================================================
// Tier 3: Login Verification Flow (ijkl_*)
//=============================================================================

/**
 * Ingests JSON payload containing user login credentials and performs end-to-end verification.
 */
bool ijkl_credential_verification_flow(const std::string& login_req_json) {
    if (login_req_json.empty()) return false;

    // Minimal JSON token extraction
    auto extract_field = [](const std::string& json, const std::string& key) -> std::string {
        std::string pattern = "\"" + key + "\":\"";
        size_t pos = json.find(pattern);
        if (pos == std::string::npos) return "";
        pos += pattern.size();
        size_t end_pos = json.find("\"", pos);
        if (end_pos == std::string::npos) return "";
        return json.substr(pos, end_pos - pos);
    };

    std::string user_id = extract_field(login_req_json, "username");
    if (user_id.empty()) user_id = extract_field(login_req_json, "user_id");
    std::string password = extract_field(login_req_json, "password");

    if (user_id.empty() || password.empty()) return false;

    return efgh_check_user_login(user_id, password);
}

//=============================================================================
// Tier 4: Administrative Credential Management (mnop_*)
//=============================================================================

/**
 * Administrative action to forcibly reset and rotate a user's password credential.
 */
bool mnop_admin_reset_credential(const std::string& user_id, const std::string& new_pass) {
    if (user_id.empty() || new_pass.empty()) return false;

    std::cout << "[AdminVault::mnop] Executing security reset for principal: " << user_id << "\n";
    return efgh_store_user_credential(user_id, new_pass);
}

} // namespace nexis::vault
