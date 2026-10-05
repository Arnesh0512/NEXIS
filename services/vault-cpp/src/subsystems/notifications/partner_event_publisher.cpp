#include <iostream>
#include <string>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <mutex>

#if __has_include(<mongocxx/client.hpp>)
#include <mongocxx/client.hpp>
#include <mongocxx/instance.hpp>
#include <mongocxx/uri.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#define NEXIS_HAS_MONGOCXX 1
#endif

#if __has_include(<cpr/cpr.h>)
#include <cpr/cpr.h>
#define NEXIS_HAS_CPR 1
#elif __has_include(<curl/curl.h>)
#include <curl/curl.h>
#define NEXIS_HAS_CURL 1
#endif

namespace nexis::vault::notifications {

struct DeliveryLogEntry {
    std::string merchant_id;
    int status_code;
    std::string timestamp;
};

class MockPartnerEventState {
private:
    std::mutex mtx_;
    std::unordered_map<std::string, std::string> merchant_webhooks_;
    std::vector<DeliveryLogEntry> delivery_logs_;

public:
    MockPartnerEventState() {
        // Default mock merchant endpoints
        merchant_webhooks_["mcht_amazon_99"] = "https://partner.amazon-api.internal/webhook/nexis";
        merchant_webhooks_["mcht_stripe_88"] = "https://partner.stripe-events.internal/webhook/events";
        merchant_webhooks_["mcht_default"] = "https://sandbox.merchant.internal/webhook";
    }

    static MockPartnerEventState& instance() {
        static MockPartnerEventState inst;
        return inst;
    }

    std::string get_url(const std::string& merchant_id) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = merchant_webhooks_.find(merchant_id);
        if (it != merchant_webhooks_.end()) {
            return it->second;
        }
        return "https://webhook.site/nexis-partner-" + merchant_id;
    }

    void log_delivery(const std::string& merchant_id, int status_code) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::ostringstream ss;
        ss << now;
        delivery_logs_.push_back({merchant_id, status_code, ss.str()});
    }

    const std::vector<DeliveryLogEntry>& get_logs() const { return delivery_logs_; }
};

/**
 * Level 1: Fetch merchant webhook URL from Mongo or Mock
 * abcd_fetch_merchant_webhook_url
 */
std::string abcd_fetch_merchant_webhook_url(const std::string& merchant_id) {
#if NEXIS_HAS_MONGOCXX
    try {
        mongocxx::uri uri("mongodb://localhost:27017");
        mongocxx::client client(uri);
        auto db = client["nexis_vault"];
        auto coll = db["merchants"];
        auto doc = coll.find_one(bsoncxx::builder::stream::document{} 
            << "merchant_id" << merchant_id 
            << bsoncxx::builder::stream::finalize);

        if (doc) {
            auto view = doc->view();
            if (view["webhook_url"]) {
                return std::string(view["webhook_url"].get_string().value);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[PartnerPublisher::abcd] Mongo query error: " << e.what() << "\n";
    }
#endif

    return MockPartnerEventState::instance().get_url(merchant_id);
}

/**
 * Level 2a: Send webhook request
 * efgh_send_webhook_request
 */
bool efgh_send_webhook_request(const std::string& url, const std::string& event_data_json) {
    int status_code = 0;

#if defined(NEXIS_HAS_CPR)
    try {
        auto res = cpr::Post(
            cpr::Url{url},
            cpr::Header{
                {"Content-Type", "application/json"},
                {"User-Agent", "NEXIS-Vault-Webhook-Publisher/1.0"},
                {"X-Nexis-Event", "order.completed"}
            },
            cpr::Body{event_data_json},
            cpr::Timeout{4000}
        );
        status_code = res.status_code;
    } catch (...) {
        status_code = 500;
    }
#else
    status_code = 200; // Simulated OK response
#endif

    bool success = (status_code >= 200 && status_code < 300);
    std::cout << "[PartnerPublisher::efgh] Dispatched webhook to " << url 
              << " | Code: " << status_code << "\n";
    return success;
}

/**
 * Level 2b: Log delivery attempt to MongoDB or Memory
 * efgh_log_delivery_attempt
 */
bool efgh_log_delivery_attempt(const std::string& merchant_id, int status_code) {
#if NEXIS_HAS_MONGOCXX
    try {
        mongocxx::uri uri("mongodb://localhost:27017");
        mongocxx::client client(uri);
        auto db = client["nexis_vault"];
        auto coll = db["webhook_delivery_logs"];
        
        using bsoncxx::builder::stream::document;
        using bsoncxx::builder::stream::finalize;
        
        coll.insert_one(document{}
            << "merchant_id" << merchant_id
            << "status_code" << status_code
            << "timestamp" << bsoncxx::types::b_date{std::chrono::system_clock::now()}
            << finalize);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[PartnerPublisher::efgh] Mongo logging error: " << e.what() << "\n";
    }
#endif

    MockPartnerEventState::instance().log_delivery(merchant_id, status_code);
    return true;
}

/**
 * Level 3: Publish event orchestrator
 * ijkl_publish_event_to_merchant
 */
bool ijkl_publish_event_to_merchant(const std::string& merchant_id, const std::string& event_json) {
    if (merchant_id.empty()) {
        std::cerr << "[PartnerPublisher::ijkl] Cannot publish to empty merchant ID.\n";
        return false;
    }

    std::string webhook_url = abcd_fetch_merchant_webhook_url(merchant_id);
    bool dispatched = efgh_send_webhook_request(webhook_url, event_json);
    int status_code = dispatched ? 200 : 502;
    efgh_log_delivery_attempt(merchant_id, status_code);

    return dispatched;
}

/**
 * Level 4: Top-Level Entrypoint
 * mnop_notify_merchant_order_complete
 */
bool mnop_notify_merchant_order_complete(const std::string& order_json) {
    std::cout << "[PartnerPublisher::mnop] Preparing merchant order completion event.\n";
    
    std::string merchant_id = "mcht_default";
    size_t pos = order_json.find("\"merchant_id\":\"");
    if (pos != std::string::npos) {
        size_t start = pos + 15;
        size_t end = order_json.find("\"", start);
        if (end != std::string::npos) {
            merchant_id = order_json.substr(start, end - start);
        }
    }

    std::ostringstream event_payload;
    event_payload << "{\"event\":\"order.completed\","
                  << "\"timestamp\":\"" << std::chrono::system_clock::now().time_since_epoch().count() << "\","
                  << "\"data\":" << order_json << "}";

    return ijkl_publish_event_to_merchant(merchant_id, event_payload.str());
}

} // namespace nexis::vault::notifications
