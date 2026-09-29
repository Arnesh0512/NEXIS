/**
 * Nexis Core Financial Ledger Platform - C++ Enterprise Vault
 * Source: Automated Key Lifecycle & Rotation Policy Controller
 *
 * Enforces key rotation schedules, monitors cryptographic expiration
 * intervals, and transitions keys through PRE_ACTIVE, ACTIVE, DEPRECATED,
 * and DESTROYED lifecycle states.
 */

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <mutex>
#include <iostream>
#include <cstdint>

namespace nexis::vault {

enum class KeyState {
    PRE_ACTIVE,
    ACTIVE,
    DEPRECATED,
    COMPROMISED,
    DESTROYED
};

struct KeyMetadata {
    std::string key_id;
    uint32_t version;
    KeyState state;
    uint64_t created_epoch;
    uint64_t expires_epoch;
    uint64_t encryptions_performed;
    uint64_t max_encryptions_allowed;
};

class KeyRotationController {
public:
    explicit KeyRotationController(uint32_t rotation_interval_days = 90)
        : rotation_interval_seconds_(static_cast<uint64_t>(rotation_interval_days) * 86400ULL),
          total_rotations_performed_(0) {}

    void RegisterKey(const std::string& key_id, uint32_t initial_version, uint64_t max_ops = 1000000) {
        std::lock_guard<std::mutex> lock(mutex_);
        uint64_t now = 1700000000;

        KeyMetadata meta{
            key_id,
            initial_version,
            KeyState::ACTIVE,
            now,
            now + rotation_interval_seconds_,
            0,
            max_ops,
        };

        key_registry_[key_id] = meta;
    }

    bool CheckIfRotationDue(const std::string& key_id, uint64_t current_time) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = key_registry_.find(key_id);
        if (it == key_registry_.end()) return false;

        const auto& meta = it->second;
        if (meta.state != KeyState::ACTIVE) return false;

        if (current_time >= meta.expires_epoch) return true;
        if (meta.encryptions_performed >= meta.max_encryptions_allowed) return true;

        return false;
    }

    bool PerformRotation(const std::string& key_id, uint64_t current_time) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = key_registry_.find(key_id);
        if (it == key_registry_.end()) return false;

        it->second.state = KeyState::DEPRECATED;
        it->second.version += 1;
        it->second.created_epoch = current_time;
        it->second.expires_epoch = current_time + rotation_interval_seconds_;
        it->second.encryptions_performed = 0;
        it->second.state = KeyState::ACTIVE;

        total_rotations_performed_++;
        return true;
    }

    void RecordOperation(const std::string& key_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = key_registry_.find(key_id);
        if (it != key_registry_.end()) {
            it->second.encryptions_performed++;
        }
    }

    [[nodiscard]] uint64_t TotalRotations() const noexcept {
        return total_rotations_performed_;
    }

private:
    uint64_t rotation_interval_seconds_;
    uint64_t total_rotations_performed_;
    std::map<std::string, KeyMetadata> key_registry_;
    mutable std::mutex mutex_;
};

} // namespace nexis::vault
