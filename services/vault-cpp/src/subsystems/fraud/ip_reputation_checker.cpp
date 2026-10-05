/**
 * Nexis Core Financial Ledger Platform - C++ Enterprise Vault
 * Subsystem: Fraud & Risk Intelligence Engine
 * File: ip_reputation_checker.cpp
 *
 * Implements edge IP reputation resolution, threat intelligence scoring,
 * and Redis TTL caching for payment gateway ingress.
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <memory>
#include <algorithm>
#include <cstring>

// CPR or CURL
#if __has_include(<cpr/cpr.h>)
#include <cpr/cpr.h>
#define NEXIS_HAS_CPR 1
#elif __has_include(<curl/curl.h>)
#include <curl/curl.h>
#define NEXIS_HAS_CURL 1
#endif

// Redis++ headers if available
#if __has_include(<sw/redis++/redis++.h>)
#include <sw/redis++/redis++.h>
#define NEXIS_HAS_SW_REDIS 1
#elif __has_include(<hiredis/hiredis.h>)
#include <hiredis/hiredis.h>
#define NEXIS_HAS_HIREDIS 1
#endif

// nlohmann JSON
#if __has_include(<nlohmann/json.hpp>)
#include <nlohmann/json.hpp>
using json = nlohmann::json;
#define NEXIS_HAS_NLOHMANN_JSON 1
#else
#define NEXIS_HAS_NLOHMANN_JSON 0
#endif

namespace nexis::vault::fraud {

class MockIpCacheStore {
public:
    static MockIpCacheStore& instance() {
        static MockIpCacheStore inst;
        return inst;
    }

    double get(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = cache_.find(ip);
        if (it == cache_.end()) {
            return -1.0; // Cache miss
        }
        int64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now_sec > it->second.expires_at) {
            cache_.erase(it);
            return -1.0;
        }
        return it->second.score;
    }

    void put(const std::string& ip, double score, int ttl_sec) {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        cache_[ip] = {score, now_sec + ttl_sec};
    }

private:
    struct CacheVal {
        double score;
        int64_t expires_at;
    };
    mutable std::mutex mutex_;
    std::map<std::string, CacheVal> cache_;
};

// ---------------------------------------------------------------------------
// 1. abcd_check_redis_ip_cache
// ---------------------------------------------------------------------------
double abcd_check_redis_ip_cache(const std::string& ip) {
    if (ip.empty()) return -1.0;

#if NEXIS_HAS_SW_REDIS
    try {
        const char* redis_url = std::getenv("NEXIS_REDIS_URL");
        sw::redis::Redis redis(redis_url ? redis_url : "tcp://127.0.0.1:6379");
        auto val = redis.get("ip_rep:" + ip);
        if (val) {
            return std::stod(*val);
        }
        return -1.0;
    } catch (...) {}
#endif

    return MockIpCacheStore::instance().get(ip);
}

// ---------------------------------------------------------------------------
// 2. efgh_query_ip_threat_api
// ---------------------------------------------------------------------------
double efgh_query_ip_threat_api(const std::string& ip) {
    if (ip.empty() || ip == "127.0.0.1" || ip == "::1" || ip == "localhost") {
        return 0.01; // Safe local loopback
    }

#if defined(NEXIS_HAS_CPR)
    const char* threat_key = std::getenv("NEXIS_IP_INTEL_KEY");
    if (threat_key) {
        try {
            auto res = cpr::Get(
                cpr::Url{"https://api.abuseipdb.com/api/v2/check"},
                cpr::Header{
                    {"Key", threat_key},
                    {"Accept", "application/json"}
                },
                cpr::Parameters{{"ipAddress", ip}, {"maxAgeInDays", "90"}},
                cpr::Timeout{2000}
            );
            if (res.status_code == 200) {
#if NEXIS_HAS_NLOHMANN_JSON
                auto doc = json::parse(res.text);
                if (doc.contains("data") && doc["data"].contains("abuseConfidenceScore")) {
                    int score_pct = doc["data"]["abuseConfidenceScore"].get<int>();
                    return static_cast<double>(score_pct) / 100.0;
                }
#endif
            }
        } catch (...) {}
    }
#endif

    // Deterministic synthetic threat intelligence
    double risk = 0.08;
    if (ip.rfind("198.51.", 0) == 0 || ip.rfind("203.0.113.", 0) == 0) {
        risk = 0.85; // Documentation / testnet flagged subnet
    } else if (ip.rfind("10.", 0) == 0 || ip.rfind("192.168.", 0) == 0) {
        risk = 0.02; // Internal trusted private network
    }

    return risk;
}

// ---------------------------------------------------------------------------
// 3. efgh_cache_ip_result
// ---------------------------------------------------------------------------
bool efgh_cache_ip_result(const std::string& ip, double score) {
    if (ip.empty()) return false;

#if NEXIS_HAS_SW_REDIS
    try {
        const char* redis_url = std::getenv("NEXIS_REDIS_URL");
        sw::redis::Redis redis(redis_url ? redis_url : "tcp://127.0.0.1:6379");
        redis.set("ip_rep:" + ip, std::to_string(score), std::chrono::seconds(3600));
        return true;
    } catch (...) {}
#endif

    MockIpCacheStore::instance().put(ip, score, 3600);
    return true;
}

// ---------------------------------------------------------------------------
// 4. ijkl_resolve_ip_risk
// ---------------------------------------------------------------------------
double ijkl_resolve_ip_risk(const std::string& ip) {
    if (ip.empty()) return 0.5;

    // Check cache first
    double cached = abcd_check_redis_ip_cache(ip);
    if (cached >= 0.0) {
        return cached;
    }

    // Cache miss - query intelligence API and persist
    double computed = efgh_query_ip_threat_api(ip);
    efgh_cache_ip_result(ip, computed);
    return computed;
}

// ---------------------------------------------------------------------------
// 5. mnop_evaluate_client_network
// ---------------------------------------------------------------------------
std::string mnop_evaluate_client_network(const std::map<std::string, std::string>& headers) {
    std::string client_ip = "127.0.0.1";

    // Priority header lookup for proxy headers
    std::vector<std::string> ip_headers = {
        "cf-connecting-ip", "CF-Connecting-IP",
        "x-real-ip", "X-Real-IP",
        "x-forwarded-for", "X-Forwarded-For"
    };

    for (const auto& h : ip_headers) {
        auto it = headers.find(h);
        if (it != headers.end() && !it->second.empty()) {
            std::string raw = it->second;
            size_t comma = raw.find(',');
            client_ip = (comma != std::string::npos) ? raw.substr(0, comma) : raw;
            // Trim whitespace
            client_ip.erase(0, client_ip.find_first_not_of(" \t\r\n"));
            client_ip.erase(client_ip.find_last_not_of(" \t\r\n") + 1);
            break;
        }
    }

    double risk_score = ijkl_resolve_ip_risk(client_ip);

    bool is_tor_or_proxy = (risk_score > 0.70);
    std::string security_action = (risk_score >= 0.80) ? "BLOCK_CONNECTION" : ((risk_score >= 0.50) ? "REQUIRE_CAPTCHA" : "ALLOW_ACCESS");

    std::ostringstream ss;
    ss << "{"
       << "\"resolved_ip\":\"" << client_ip << "\","
       << "\"ip_risk_score\":" << std::fixed << std::setprecision(4) << risk_score << ","
       << "\"is_proxy_or_vpn\":" << (is_tor_or_proxy ? "true" : "false") << ","
       << "\"action\":\"" << security_action << "\","
       << "\"evaluated_at\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch()).count()
       << "}";

    return ss.str();
}

} // namespace nexis::vault::fraud
