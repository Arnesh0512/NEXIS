#include <iostream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <vector>

#if __has_include(<sw/redis++/redis++.h>)
#include <sw/redis++/redis++.h>
#define NEXIS_HAS_REDIS_PLUS_PLUS 1
#elif __has_include(<hiredis/hiredis.h>)
#include <hiredis/hiredis.h>
#define NEXIS_HAS_HIREDIS 1
#endif

#if __has_include(<cpr/cpr.h>)
#include <cpr/cpr.h>
#define NEXIS_HAS_CPR 1
#elif __has_include(<curl/curl.h>)
#include <curl/curl.h>
#define NEXIS_HAS_CURL 1
#endif

namespace nexis::vault::notifications {

// In-memory fallback state for rate limiting and dispatched SMS auditing
struct RateLimitEntry {
    int count = 0;
    std::chrono::steady_clock::time_point window_start = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point last_sent = std::chrono::steady_clock::now() - std::chrono::hours(1);
};

class MockSmsGatewayState {
private:
    std::mutex mtx_;
    std::unordered_map<std::string, RateLimitEntry> rate_limits_;
    std::vector<std::pair<std::string, std::string>> carrier_outbox_;
    std::string carrier_url_ = "https://api.twilio.com/2010-04-01/Accounts/ACmock/Messages.json";
    int max_messages_per_window_ = 3;
    std::chrono::seconds window_duration_{300}; // 5 min
    std::chrono::seconds cooldown_period_{30};   // 30 sec between consecutive SMS

public:
    static MockSmsGatewayState& instance() {
        static MockSmsGatewayState inst;
        return inst;
    }

    bool check_limit(const std::string& phone) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto now = std::chrono::steady_clock::now();
        auto& entry = rate_limits_[phone];

        // Reset window if expired
        if (now - entry.window_start > window_duration_) {
            entry.window_start = now;
            entry.count = 0;
        }

        // Check consecutive cooldown
        if (now - entry.last_sent < cooldown_period_) {
            std::cout << "[SmsGateway::abcd] Cooldown active for " << phone << "\n";
            return false;
        }

        return (entry.count < max_messages_per_window_);
    }

    void update_cooldown(const std::string& phone) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto now = std::chrono::steady_clock::now();
        auto& entry = rate_limits_[phone];
        entry.last_sent = now;
        entry.count++;
    }

    void record_sent(const std::string& phone, const std::string& message) {
        std::lock_guard<std::mutex> lock(mtx_);
        carrier_outbox_.emplace_back(phone, message);
    }

    const std::string& carrier_url() const { return carrier_url_; }
};

/**
 * Level 1: Rate Limit Check
 * abcd_check_sms_rate_limit
 * Queries Redis or falls back to in-memory rate limiter.
 */
bool abcd_check_sms_rate_limit(const std::string& phone) {
    if (phone.empty()) return false;

#if NEXIS_HAS_REDIS_PLUS_PLUS
    try {
        auto redis = sw::redis::Redis("tcp://127.0.0.1:6379");
        std::string key = "sms:ratelimit:" + phone;
        auto val = redis.get(key);
        if (val && std::stoi(*val) >= 3) {
            std::cout << "[SmsGateway::abcd] Redis rate limit exceeded for " << phone << "\n";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[SmsGateway::abcd] Redis check failed: " << e.what() << ", falling back to in-memory.\n";
    }
#endif

    return MockSmsGatewayState::instance().check_limit(phone);
}

/**
 * Level 2a: Carrier HTTP Dispatch
 * efgh_post_sms_carrier
 * Dispatches payload to external SMS carrier.
 */
bool efgh_post_sms_carrier(const std::string& phone, const std::string& message) {
    auto& state = MockSmsGatewayState::instance();
    bool success = false;

#if defined(NEXIS_HAS_CPR)
    try {
        auto response = cpr::Post(
            cpr::Url{state.carrier_url()},
            cpr::Authentication{"AC_mock_account", "mock_auth_token", cpr::AuthMode::BASIC},
            cpr::Payload{{"To", phone}, {"From", "+18005550199"}, {"Body", message}},
            cpr::Timeout{3500}
        );
        success = (response.status_code == 200 || response.status_code == 201);
    } catch (...) {
        success = false;
    }
#else
    // In-memory mock carrier delivery
    success = (!phone.empty() && !message.empty());
#endif

    state.record_sent(phone, message);
    std::cout << "[SmsGateway::efgh] Carrier POST to " << phone 
              << " | Result: " << (success ? "SENT" : "FAILED") << "\n";
    return success;
}

/**
 * Level 2b: Update Cooldown
 * efgh_update_sms_cooldown
 * Persists cooldown state to Redis or in-memory map.
 */
bool efgh_update_sms_cooldown(const std::string& phone) {
#if NEXIS_HAS_REDIS_PLUS_PLUS
    try {
        auto redis = sw::redis::Redis("tcp://127.0.0.1:6379");
        std::string key = "sms:ratelimit:" + phone;
        redis.incr(key);
        redis.expire(key, std::chrono::seconds(300));
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[SmsGateway::efgh] Redis update cooldown failed: " << e.what() << "\n";
    }
#endif

    MockSmsGatewayState::instance().update_cooldown(phone);
    return true;
}

/**
 * Level 3: Fraud SMS Coordinator
 * ijkl_send_fraud_warning_sms
 */
bool ijkl_send_fraud_warning_sms(const std::string& phone, const std::string& tx_summary) {
    if (!abcd_check_sms_rate_limit(phone)) {
        std::cerr << "[SmsGateway::ijkl] SMS Rate limit rejected for: " << phone << "\n";
        return false;
    }

    std::ostringstream ss;
    ss << "[NEXIS SECURITY ALERT] Suspicious activity detected on your account. Transaction: "
       << tx_summary << ". If this was not you, reply STOP or call +1-800-NEXIS-SEC immediately.";
    std::string text_body = ss.str();

    bool sent = efgh_post_sms_carrier(phone, text_body);
    if (sent) {
        efgh_update_sms_cooldown(phone);
    }
    return sent;
}

/**
 * Level 4: Top-Level Entrypoint
 * mnop_notify_fraud_alert
 */
bool mnop_notify_fraud_alert(const std::string& phone, const std::string& tx_json) {
    std::cout << "[SmsGateway::mnop] Received fraud alert request for " << phone << "\n";
    if (phone.empty()) {
        std::cerr << "[SmsGateway::mnop] Missing recipient phone number.\n";
        return false;
    }

    // Extract basic summary from JSON
    std::string summary = "TX-REF-AUTH";
    size_t tx_id_pos = tx_json.find("\"tx_id\":\"");
    if (tx_id_pos != std::string::npos) {
        size_t start = tx_id_pos + 9;
        size_t end = tx_json.find("\"", start);
        if (end != std::string::npos) {
            summary = tx_json.substr(start, end - start);
        }
    }

    return ijkl_send_fraud_warning_sms(phone, summary);
}

} // namespace nexis::vault::notifications
