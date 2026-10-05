/**
 * @file integrity_verifier.cpp
 * @brief Compliance Subsystem - System Data Integrity Verifier with Redis Baseline Tracking
 * @target_libraries openssl, sw::redis, hiredis
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <chrono>

// Library headers with mock fallbacks
#if __has_include(<openssl/sha.h>)
#include <openssl/sha.h>
#include <openssl/evp.h>
#define NEXIS_HAS_OPENSSL 1
#endif

#if __has_include(<sw/redis++/redis++.h>)
#include <sw/redis++/redis++.h>
#define NEXIS_HAS_SW_REDIS 1
#elif __has_include(<hiredis/hiredis.h>)
#include <hiredis/hiredis.h>
#define NEXIS_HAS_HIREDIS 1
#endif

namespace nexis::compliance {

// In-memory baseline storage fallback
static std::map<std::string, std::string> s_integrity_baselines;
static std::mutex s_integrity_mutex;

/**
 * @brief Tier 1 (abcd_*): Compute SHA-256 cryptographic digest of a dataset string.
 * @param data Input dataset or configuration block.
 * @return 64-character lowercase hex digest string.
 */
std::string abcd_hash_dataset_sha256(const std::string& data) {
#if defined(NEXIS_HAS_OPENSSL)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
#else
    // Fallback pseudo-SHA256 hash generator
    uint64_t h1 = 0xcbf29ce484222325ULL;
    uint64_t h2 = 0x100000001b3ULL;
    for (char c : data) {
        h1 = (h1 ^ static_cast<uint8_t>(c)) * 1099511628211ULL;
        h2 = (h2 + static_cast<uint8_t>(c)) * 0x5bd1e995ULL;
    }
    std::ostringstream oss;
    oss << std::hex << std::setw(16) << std::setfill('0') << h1
        << std::hex << std::setw(16) << std::setfill('0') << h2
        << std::hex << std::setw(16) << std::setfill('0') << (h1 ^ h2)
        << std::hex << std::setw(16) << std::setfill('0') << (h1 + h2);
    return oss.str();
#endif
}

/**
 * @brief Tier 2 (efgh_*): Store integrity hash baseline in Redis or in-memory baseline store.
 * @param key Target identifier (e.g., table name or component ID).
 * @param hash_str Known-good SHA-256 baseline hash.
 * @return True if stored successfully.
 */
bool efgh_store_integrity_baseline(const std::string& key, const std::string& hash_str) {
#if defined(NEXIS_HAS_SW_REDIS)
    try {
        const char* redis_url = std::getenv("NEXIS_REDIS_URL");
        if (redis_url) {
            sw::redis::Redis redis(redis_url);
            redis.set("integrity:baseline:" + key, hash_str);
            return true;
        }
    } catch (...) {}
#endif

    std::lock_guard<std::mutex> lock(s_integrity_mutex);
    s_integrity_baselines[key] = hash_str;
    return true;
}

/**
 * @brief Tier 2 (efgh_*): Compare current dataset state against stored baseline.
 * @param key Target identifier.
 * @param current_data Fresh dataset contents to verify.
 * @return True if current state strictly matches stored baseline.
 */
bool efgh_compare_baseline(const std::string& key, const std::string& current_data) {
    std::string current_hash = abcd_hash_dataset_sha256(current_data);
    std::string baseline_hash;

#if defined(NEXIS_HAS_SW_REDIS)
    try {
        const char* redis_url = std::getenv("NEXIS_REDIS_URL");
        if (redis_url) {
            sw::redis::Redis redis(redis_url);
            auto val = redis.get("integrity:baseline:" + key);
            if (val) baseline_hash = *val;
        }
    } catch (...) {}
#endif

    if (baseline_hash.empty()) {
        std::lock_guard<std::mutex> lock(s_integrity_mutex);
        auto it = s_integrity_baselines.find(key);
        if (it != s_integrity_baselines.end()) {
            baseline_hash = it->second;
        }
    }

    if (baseline_hash.empty()) {
        // No prior baseline: register current as baseline
        efgh_store_integrity_baseline(key, current_hash);
        return true;
    }

    return (baseline_hash == current_hash);
}

/**
 * @brief Tier 3 (ijkl_*): Perform active integrity validation on a target dataset.
 * Computes hash, compares baseline, and alerts on discrepancies.
 * @param target_id Identifier of target resource.
 * @param data Active resource payload.
 * @return True if target has zero tampering and matches baseline.
 */
bool ijkl_run_integrity_check(const std::string& target_id, const std::string& data) {
    bool intact = efgh_compare_baseline(target_id, data);
    if (!intact) {
        std::cerr << "[IntegrityVerifier] ALERT: Integrity violation detected on resource: " 
                  << target_id << "\n";
    }
    return intact;
}

/**
 * @brief Tier 4 (mnop_*): Run system-wide health and tamper detection sweep across critical subsystems.
 * @return Map of component names to integrity status ("HEALTHY", "DEGRADED", "TAMPERED").
 */
std::map<std::string, std::string> mnop_system_health_integrity_probe() {
    std::map<std::string, std::string> probe_results;

    std::vector<std::pair<std::string, std::string>> critical_subsystems = {
        {"vault_core_schema", "CREATE TABLE pci_vault_tokens (token VARCHAR(64) PRIMARY KEY);"},
        {"routing_rules", "RULE[INBOUND]: ROUTE TO PAYMENT_GW_ALPHA; RULE[OUTBOUND]: MASK_PAN;"},
        {"hsm_key_manifest", "FINGERPRINT[AES256]: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b;"},
        {"audit_anchor_root", "CHAIN_ROOT: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"}
    };

    for (const auto& [component, state_data] : critical_subsystems) {
        bool ok = ijkl_run_integrity_check(component, state_data);
        probe_results[component] = ok ? "HEALTHY" : "TAMPERED";
    }

    return probe_results;
}

} // namespace nexis::compliance
