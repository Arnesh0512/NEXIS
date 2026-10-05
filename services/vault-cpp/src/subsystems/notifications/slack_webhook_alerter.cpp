#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <mutex>

#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#if __has_include(<cpr/cpr.h>)
#include <cpr/cpr.h>
#define NEXIS_HAS_CPR 1
#elif __has_include(<curl/curl.h>)
#include <curl/curl.h>
#define NEXIS_HAS_CURL 1
#endif

namespace nexis::vault::notifications {

class MockSlackWebhookState {
private:
    std::mutex mtx_;
    std::vector<std::string> delivered_webhooks_;
    std::string default_webhook_url_ = "https://slack-mock.internal.nexis/services/alerts";
    std::string signing_secret_ = "nexis_slack_signing_secret_998822";

public:
    static MockSlackWebhookState& instance() {
        static MockSlackWebhookState inst;
        return inst;
    }

    void record_delivery(const std::string& payload) {
        std::lock_guard<std::mutex> lock(mtx_);
        delivered_webhooks_.push_back(payload);
    }

    const std::string& webhook_url() const { return default_webhook_url_; }
    const std::string& signing_secret() const { return signing_secret_; }
};

/**
 * Level 1: OpenSSL HMAC-SHA256 Payload Signing
 * abcd_sign_slack_payload
 */
std::string abcd_sign_slack_payload(const std::string& payload, const std::string& secret) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    HMAC(
        EVP_sha256(),
        secret.data(),
        static_cast<int>(secret.length()),
        reinterpret_cast<const unsigned char*>(payload.data()),
        payload.length(),
        digest,
        &digest_len
    );

    std::ostringstream ss;
    ss << "v0=";
    for (unsigned int i = 0; i < digest_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
    }
    return ss.str();
}

/**
 * Level 2a: Network Dispatch
 * efgh_post_slack_webhook
 */
bool efgh_post_slack_webhook(const std::string& channel_url, const std::string& payload_json, const std::string& sig) {
    auto& state = MockSlackWebhookState::instance();
    bool success = false;

#if defined(NEXIS_HAS_CPR)
    try {
        auto res = cpr::Post(
            cpr::Url{channel_url},
            cpr::Header{
                {"Content-Type", "application/json"},
                {"X-Slack-Signature", sig}
            },
            cpr::Body{payload_json},
            cpr::Timeout{3000}
        );
        success = (res.status_code == 200);
    } catch (...) {
        success = false;
    }
#else
    // In-memory fallback
    success = !payload_json.empty();
#endif

    state.record_delivery(payload_json);
    std::cout << "[SlackAlerter::efgh] Webhook POST to " << channel_url 
              << " | Sig: " << sig.substr(0, 10) << "... | Status: " 
              << (success ? "OK" : "FAILED") << "\n";
    return success;
}

/**
 * Level 2b: Slack Block Kit Incident Card Formatter
 * efgh_format_incident_card
 */
std::string efgh_format_incident_card(const std::string& title, const std::string& severity, const std::string& details) {
    std::string color = (severity == "CRITICAL" || severity == "FATAL") ? "#FF0000" : "#FFA500";
    
    std::ostringstream ss;
    ss << "{"
       << "\"attachments\":[{"
       << "\"color\":\"" << color << "\","
       << "\"blocks\":["
       << "{\"type\":\"header\",\"text\":{\"type\":\"plain_text\",\"text\":\"" << title << "\",\"emoji\":true}},"
       << "{\"type\":\"section\",\"fields\":["
       << "{\"type\":\"mrkdwn\",\"text\":\"*Severity:*\\n`" << severity << "`\"},"
       << "{\"type\":\"mrkdwn\",\"text\":\"*Source:*\\n`NEXIS-Vault-Core`\"}"
       << "]},"
       << "{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"*Incident Details:*\\n```" 
       << details << "```\"}}"
       << "]}"
       << "]}";
    return ss.str();
}

/**
 * Level 3: Security Team Incident Coordinator
 * ijkl_alert_security_team(const std::string& incident_json)
 */
bool ijkl_alert_security_team(const std::string& incident_json) {
    auto& state = MockSlackWebhookState::instance();

    // Parse simple fields or use sensible defaults
    std::string title = "[NEXIS VAULT ALERT] Security Incident Detected";
    std::string severity = "HIGH";
    std::string details = incident_json;

    size_t sev_pos = incident_json.find("\"severity\":\"");
    if (sev_pos != std::string::npos) {
        size_t start = sev_pos + 12;
        size_t end = incident_json.find("\"", start);
        if (end != std::string::npos) {
            severity = incident_json.substr(start, end - start);
        }
    }

    size_t title_pos = incident_json.find("\"title\":\"");
    if (title_pos != std::string::npos) {
        size_t start = title_pos + 9;
        size_t end = incident_json.find("\"", start);
        if (end != std::string::npos) {
            title = incident_json.substr(start, end - start);
        }
    }

    std::string block_card = efgh_format_incident_card(title, severity, details);
    std::string signature = abcd_sign_slack_payload(block_card, state.signing_secret());
    return efgh_post_slack_webhook(state.webhook_url(), block_card, signature);
}

/**
 * Level 4: Top-Level Entrypoint
 * mnop_broadcast_critical_event
 */
bool mnop_broadcast_critical_event(const std::string& err_msg) {
    std::cout << "[SlackAlerter::mnop] Broadcasting critical event to Slack SecOps channel.\n";
    if (err_msg.empty()) {
        std::cerr << "[SlackAlerter::mnop] Empty error message provided.\n";
        return false;
    }

    std::ostringstream incident_json;
    incident_json << "{\"title\":\"CRITICAL VAULT EXCEPTION\","
                  << "\"severity\":\"CRITICAL\","
                  << "\"details\":\"" << err_msg << "\","
                  << "\"timestamp\":\"" << std::chrono::system_clock::now().time_since_epoch().count() << "\"}";

    return ijkl_alert_security_team(incident_json.str());
}

} // namespace nexis::vault::notifications
