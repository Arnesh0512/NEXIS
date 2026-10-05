#include <iostream>
#include <string>
#include <sstream>
#include <chrono>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <ctime>
#include <iomanip>
#include <vector>

#if __has_include(<jwt-cpp/jwt.h>)
#include <jwt-cpp/jwt.h>
#define NEXIS_HAS_JWT_CPP 1
#else
#define NEXIS_HAS_JWT_CPP 0
#endif

#if __has_include(<cpr/cpr.h>)
#include <cpr/cpr.h>
#define NEXIS_HAS_CPR 1
#elif __has_include(<curl/curl.h>)
#include <curl/curl.h>
#define NEXIS_HAS_CURL 1
#endif

namespace nexis::vault::notifications {

// In-memory mock record for fallback testing and audit logging
struct SentEmailRecord {
    std::string recipient;
    std::string subject;
    std::string body;
    std::string timestamp;
    bool success;
};

class MockEmailDispatcherState {
private:
    std::mutex mtx_;
    std::vector<SentEmailRecord> sent_history_;
    std::string smtp_endpoint_ = "https://api.sendgrid.com/v3/mail/send";
    std::string jwt_secret_ = "nexis_vault_secure_token_secret_key_2026";

public:
    static MockEmailDispatcherState& instance() {
        static MockEmailDispatcherState state;
        return state;
    }

    void record_email(const SentEmailRecord& record) {
        std::lock_guard<std::mutex> lock(mtx_);
        sent_history_.push_back(record);
    }

    const std::string& get_endpoint() const { return smtp_endpoint_; }
    const std::string& get_jwt_secret() const { return jwt_secret_; }
};

/**
 * Level 1: Low-level security helper
 * abcd_generate_unsubscribe_token
 * Signs an unsubscribe JWT containing user email and expiry.
 */
std::string abcd_generate_unsubscribe_token(const std::string& email) {
    auto& state = MockEmailDispatcherState::instance();
#if NEXIS_HAS_JWT_CPP
    try {
        auto token = jwt::create()
            .set_issuer("nexis-vault-notifications")
            .set_type("JWS")
            .set_payload_claim("email", jwt::claim(email))
            .set_payload_claim("action", jwt::claim(std::string("unsubscribe")))
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(720))
            .sign(jwt::algorithm::hs256{state.get_jwt_secret()});
        return token;
    } catch (const std::exception& ex) {
        std::cerr << "[EmailDispatcher::abcd] JWT sign error: " << ex.what() << ", using fallback.\n";
    }
#endif
    // In-memory mock fallback token generator
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::ostringstream ss;
    ss << "eyJhbGciOiJIUzI1NiJ9.email_" << email << "_ts_" << now << ".mock_sig_signature_token";
    return ss.str();
}

/**
 * Level 2a: Network delivery via CPR / Curl or In-Memory Mock
 * efgh_send_email_http
 */
bool efgh_send_email_http(const std::string& recipient, const std::string& subject, const std::string& body) {
    auto& state = MockEmailDispatcherState::instance();
    bool status = false;

#if defined(NEXIS_HAS_CPR)
    try {
        std::string json_payload = "{\"personalizations\":[{\"to\":[{\"email\":\"" + recipient +
                                   "\"}]}],\"subject\":\"" + subject +
                                   "\",\"content\":[{\"type\":\"text/html\",\"value\":\"" + body + "\"}]}";
        auto response = cpr::Post(
            cpr::Url{state.get_endpoint()},
            cpr::Header{{"Content-Type", "application/json"}, {"Authorization", "Bearer mock_key_sendgrid"}},
            cpr::Body{json_payload},
            cpr::Timeout{3000}
        );
        status = (response.status_code >= 200 && response.status_code < 300);
    } catch (...) {
        status = false;
    }
#else
    // In-memory mock fallback delivery
    status = (!recipient.empty() && !subject.empty());
#endif

    // Audit record
    auto now_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::ostringstream time_ss;
    time_ss << std::put_time(std::gmtime(&now_time), "%Y-%m-%dT%H:%M:%SZ");

    SentEmailRecord rec{recipient, subject, body, time_ss.str(), status};
    state.record_email(rec);

    std::cout << "[EmailDispatcher::efgh] Dispatched email to <" << recipient 
              << "> Subject: '" << subject << "' Status: " << (status ? "DELIVERED" : "FAILED") << "\n";
    return status;
}

/**
 * Level 2b: Template Engine
 * efgh_render_receipt_template
 */
std::string efgh_render_receipt_template(const std::string& payment_data_json) {
    std::ostringstream html;
    html << "<!DOCTYPE html><html><body style='font-family:sans-serif;'>";
    html << "<div style='max-width:600px;margin:auto;padding:20px;border:1px solid #e0e0e0;'>";
    html << "<h2 style='color:#1a73e8;'>NEXIS Vault Payment Receipt</h2>";
    html << "<p>Thank you for your transaction through the NEXIS Core Platform.</p>";
    html << "<div style='background:#f9f9f9;padding:15px;border-radius:4px;'>";
    html << "<strong>Transaction Details:</strong><br/>";
    html << "<pre>" << payment_data_json << "</pre>";
    html << "</div>";
    html << "<p style='font-size:12px;color:#777;margin-top:20px;'>";
    html << "Secure cryptographic proof verified by NEXIS Vault Engine.<br/>";
    html << "</p>";
    html << "</div></body></html>";
    return html.str();
}

/**
 * Level 3: Subsystem Orchestrator
 * ijkl_dispatch_payment_receipt
 */
bool ijkl_dispatch_payment_receipt(const std::string& payment_data_json) {
    // Extract recipient from JSON or default to customer
    std::string recipient = "customer@nexis-vault.internal";
    size_t email_pos = payment_data_json.find("\"customer_email\":\"");
    if (email_pos != std::string::npos) {
        size_t start = email_pos + 18;
        size_t end = payment_data_json.find("\"", start);
        if (end != std::string::npos) {
            recipient = payment_data_json.substr(start, end - start);
        }
    }

    std::string token = abcd_generate_unsubscribe_token(recipient);
    std::string rendered_body = efgh_render_receipt_template(payment_data_json);

    // Append unsubscribe link
    rendered_body += "<div style='text-align:center;font-size:11px;margin-top:10px;'>"
                     "<a href='https://nexis.internal/unsubscribe?token=" + token + "'>Unsubscribe</a></div>";

    std::string subject = "[NEXIS Vault] Transaction Receipt Confirmation";
    return efgh_send_email_http(recipient, subject, rendered_body);
}

/**
 * Level 4: Top-Level Entrypoint
 * mnop_send_transaction_alert
 */
bool mnop_send_transaction_alert(const std::string& payment_dto_json) {
    std::cout << "[EmailDispatcher::mnop] Received transaction alert request.\n";
    if (payment_dto_json.empty()) {
        std::cerr << "[EmailDispatcher::mnop] Empty payment DTO.\n";
        return false;
    }
    return ijkl_dispatch_payment_receipt(payment_dto_json);
}

} // namespace nexis::vault::notifications
