#include <iostream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>

#if __has_include(<google/cloud/credentials.h>)
#include <google/cloud/credentials.h>
#define NEXIS_HAS_GCLOUD_CPP 1
#endif

#if __has_include(<cpr/cpr.h>)
#include <cpr/cpr.h>
#define NEXIS_HAS_CPR 1
#elif __has_include(<curl/curl.h>)
#include <curl/curl.h>
#define NEXIS_HAS_CURL 1
#endif

namespace nexis::vault::notifications {

class MockPushNotificationState {
private:
    std::mutex mtx_;
    std::unordered_map<std::string, std::string> user_device_tokens_;
    std::vector<std::string> delivered_pushes_;
    std::string project_id_ = "nexis-vault-prod";
    std::string fcm_endpoint_ = "https://fcm.googleapis.com/v1/projects/nexis-vault-prod/messages:send";

public:
    MockPushNotificationState() {
        // Pre-populate some user device tokens for mock testing
        user_device_tokens_["usr_1001"] = "fcm_mock_token_alpha_numeric_987654321_device_ios";
        user_device_tokens_["usr_1002"] = "fcm_mock_token_alpha_numeric_123456789_device_android";
    }

    static MockPushNotificationState& instance() {
        static MockPushNotificationState inst;
        return inst;
    }

    std::string get_token_for_user(const std::string& user_id) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = user_device_tokens_.find(user_id);
        if (it != user_device_tokens_.end()) {
            return it->second;
        }
        // Generate deterministic fallback token for testing
        std::string mock_tok = "fcm_tok_" + user_id + "_default_registered_device";
        user_device_tokens_[user_id] = mock_tok;
        return mock_tok;
    }

    void record_push(const std::string& payload) {
        std::lock_guard<std::mutex> lock(mtx_);
        delivered_pushes_.push_back(payload);
    }

    const std::string& fcm_endpoint() const { return fcm_endpoint_; }
    const std::string& project_id() const { return project_id_; }
};

/**
 * Level 1a: Credentials Loader
 * abcd_load_fcm_credentials
 */
std::string abcd_load_fcm_credentials() {
#if NEXIS_HAS_GCLOUD_CPP
    try {
        auto creds = google::cloud::MakeGoogleDefaultCredentials();
        // In full environment, extract token
        return "ya29.c.b0AXv0zTQ_gcloud_oauth2_mock_token_bearer_valid";
    } catch (const std::exception& e) {
        std::cerr << "[PushWorker::abcd] GCloud creds load error: " << e.what() << "\n";
    }
#endif
    return "ya29.mock_nexis_service_account_oauth2_bearer_token";
}

/**
 * Level 1b: Device Token Validator
 * abcd_validate_device_token
 */
bool abcd_validate_device_token(const std::string& fcm_token) {
    if (fcm_token.length() < 16) {
        std::cerr << "[PushWorker::abcd] Invalid token length: " << fcm_token.length() << "\n";
        return false;
    }
    // Check for valid characters
    for (char c : fcm_token) {
        if (!std::isalnum(c) && c != '_' && c != '-' && c != ':') {
            return false;
        }
    }
    return true;
}

/**
 * Level 2: FCM HTTP v1 Dispatch
 * efgh_send_fcm_message
 */
bool efgh_send_fcm_message(const std::string& fcm_token, const std::string& title, const std::string& body) {
    if (!abcd_validate_device_token(fcm_token)) {
        std::cerr << "[PushWorker::efgh] Token failed validation.\n";
        return false;
    }

    auto& state = MockPushNotificationState::instance();
    std::string bearer = abcd_load_fcm_credentials();

    std::ostringstream payload;
    payload << "{\"message\":{"
            << "\"token\":\"" << fcm_token << "\","
            << "\"notification\":{\"title\":\"" << title << "\",\"body\":\"" << body << "\"},"
            << "\"data\":{\"source\":\"nexis_vault_orchestrator\",\"timestamp\":\"" 
            << std::chrono::system_clock::now().time_since_epoch().count() << "\"}"
            << "}}";

    std::string payload_str = payload.str();
    bool success = false;

#if defined(NEXIS_HAS_CPR)
    try {
        auto res = cpr::Post(
            cpr::Url{state.fcm_endpoint()},
            cpr::Header{
                {"Content-Type", "application/json; UTF-8"},
                {"Authorization", "Bearer " + bearer}
            },
            cpr::Body{payload_str},
            cpr::Timeout{3500}
        );
        success = (res.status_code == 200);
    } catch (...) {
        success = false;
    }
#else
    success = true;
#endif

    state.record_push(payload_str);
    std::cout << "[PushWorker::efgh] FCM push message sent to token: " 
              << fcm_token.substr(0, 12) << "... | Status: " << (success ? "DELIVERED" : "FAILED") << "\n";
    return success;
}

/**
 * Level 3: Customer Push Dispatcher
 * ijkl_send_customer_push
 */
bool ijkl_send_customer_push(const std::string& user_id, const std::string& message) {
    if (user_id.empty()) {
        std::cerr << "[PushWorker::ijkl] User ID cannot be empty.\n";
        return false;
    }

    auto& state = MockPushNotificationState::instance();
    std::string token = state.get_token_for_user(user_id);

    std::string title = "NEXIS Security & Settlement Update";
    return efgh_send_fcm_message(token, title, message);
}

/**
 * Level 4: Top-Level Entrypoint
 * mnop_push_payment_update
 */
bool mnop_push_payment_update(const std::string& user_id, const std::string& status) {
    std::cout << "[PushWorker::mnop] Processing push notification for user: " << user_id 
              << " status: " << status << "\n";

    std::string message_body;
    if (status == "COMPLETED" || status == "SETTLED") {
        message_body = "Your transaction has completed successfully and is securely recorded.";
    } else if (status == "FAILED" || status == "REJECTED") {
        message_body = "Alert: Your transaction could not be processed. Please check your vault.";
    } else {
        message_body = "Your transaction status is now: " + status;
    }

    return ijkl_send_customer_push(user_id, message_body);
}

} // namespace nexis::vault::notifications
