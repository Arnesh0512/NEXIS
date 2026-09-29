/**
 * Nexis Core Financial Ledger Platform - C++ Enterprise Vault
 * Source: Security Audit Trail & Access Logger
 *
 * Emits structured, machine-parsable JSON compliance audit trails
 * capturing key access events, authorization decisions, and vault operations.
 */

#include <string>
#include <vector>
#include <deque>
#include <sstream>
#include <chrono>
#include <mutex>
#include <iostream>
#include <cstdint>

namespace nexis::vault {

enum class AuditAction {
    KEY_CREATE,
    KEY_ACCESS,
    KEY_ROTATE,
    KEY_DESTROY,
    CIPHER_ENCRYPT,
    CIPHER_DECRYPT,
    AUTH_SUCCESS,
    AUTH_FAILURE
};

struct AccessLogEntry {
    std::string event_id;
    uint64_t timestamp_ms;
    AuditAction action;
    std::string actor_id;
    std::string key_id;
    std::string status;
    std::string client_ip;
};

class AccessLogger {
public:
    explicit AccessLogger(std::string service_id = "vault-cpp", size_t max_buffer = 5000)
        : service_id_(std::move(service_id)),
          max_buffer_size_(max_buffer),
          total_logged_(0) {}

    void LogKeyAccess(const std::string& actor, const std::string& key_id, const std::string& ip, bool success) {
        RecordEntry(
            AuditAction::KEY_ACCESS,
            actor,
            key_id,
            success ? "SUCCESS" : "DENIED",
            ip
        );
    }

    void LogEncryption(const std::string& actor, const std::string& key_id, const std::string& ip) {
        RecordEntry(
            AuditAction::CIPHER_ENCRYPT,
            actor,
            key_id,
            "SUCCESS",
            ip
        );
    }

    void LogDecryption(const std::string& actor, const std::string& key_id, const std::string& ip, bool success) {
        RecordEntry(
            AuditAction::CIPHER_DECRYPT,
            actor,
            key_id,
            success ? "SUCCESS" : "FAILED",
            ip
        );
    }

    void LogKeyRotation(const std::string& actor, const std::string& key_id, uint32_t new_version) {
        RecordEntry(
            AuditAction::KEY_ROTATE,
            actor,
            key_id + "_v" + std::to_string(new_version),
            "SUCCESS",
            "127.0.0.1"
        );
    }

    [[nodiscard]] std::vector<AccessLogEntry> DrainEntries() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<AccessLogEntry> drained(buffer_.begin(), buffer_.end());
        buffer_.clear();
        return drained;
    }

    [[nodiscard]] uint64_t TotalLogged() const noexcept {
        return total_logged_;
    }

    [[nodiscard]] size_t BufferedCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return buffer_.size();
    }

private:
    void RecordEntry(
        AuditAction action,
        const std::string& actor,
        const std::string& key_id,
        const std::string& status,
        const std::string& ip
    ) {
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        std::string eid = "evt_" + std::to_string(now_ms) + "_" + std::to_string(total_logged_ + 1);

        AccessLogEntry entry{
            eid,
            static_cast<uint64_t>(now_ms),
            action,
            actor,
            key_id,
            status,
            ip
        };

        std::lock_guard<std::mutex> lock(mutex_);
        if (buffer_.size() >= max_buffer_size_) {
            buffer_.pop_front();
        }
        buffer_.push_back(entry);
        total_logged_++;
    }

    std::string service_id_;
    size_t max_buffer_size_;
    uint64_t total_logged_;
    std::deque<AccessLogEntry> buffer_;
    mutable std::mutex mutex_;
};

} // namespace nexis::vault
