/**
 * Nexis Core Financial Ledger Platform - C++ Enterprise Vault
 * Header: Vault Configuration Management & Parameter Parser
 *
 * Implements configuration models, environment variable ingestion,
 * and security policy threshold constraints for the C++ vault server.
 */

#ifndef VAULT_CONFIG_HPP
#define VAULT_CONFIG_HPP

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <cstdlib>

namespace nexis::vault {

struct NetworkConfig {
    std::string listen_address{"0.0.0.0"};
    uint16_t listen_port{9000};
    uint32_t connection_backlog{128};
    uint32_t socket_timeout_ms{5000};
    bool enable_tcp_keepalive{true};
};

struct SecurityPolicyConfig {
    uint32_t min_rsa_key_bits{2048};
    bool require_fips_mode{true};
    bool enable_post_quantum{true};
    std::string default_pqc_kem{"ML-KEM-768"};
    std::string default_pqc_sig{"ML-DSA-65"};
    uint32_t key_rotation_days{90};
    uint32_t max_unauthenticated_sessions{10};
};

struct StorageConfig {
    std::string data_directory{"/var/lib/nexis/vault"};
    std::string audit_log_path{"/var/log/nexis/vault_audit.log"};
    uint64_t max_storage_quota_bytes{10737418240ULL}; // 10 GB
    bool fsync_on_write{true};
};

class VaultConfiguration {
public:
    VaultConfiguration() {
        LoadDefaults();
    }

    void LoadDefaults() {
        network_ = NetworkConfig{};
        security_ = SecurityPolicyConfig{};
        storage_ = StorageConfig{};
    }

    void LoadFromEnvironment() {
        if (const char* port_str = std::getenv("VAULT_PORT")) {
            network_.listen_port = static_cast<uint16_t>(std::atoi(port_str));
        }
        if (const char* addr_str = std::getenv("VAULT_LISTEN_ADDR")) {
            network_.listen_address = addr_str;
        }
        if (const char* data_dir = std::getenv("VAULT_DATA_DIR")) {
            storage_.data_directory = data_dir;
        }
        if (const char* fips_env = std::getenv("VAULT_FIPS_ENFORCE")) {
            security_.require_fips_mode = (std::string(fips_env) == "true" || std::string(fips_env) == "1");
        }
        if (const char* pqc_env = std::getenv("VAULT_PQC_ENABLE")) {
            security_.enable_post_quantum = (std::string(pqc_env) == "true" || std::string(pqc_env) == "1");
        }
    }

    [[nodiscard]] const NetworkConfig& Network() const noexcept { return network_; }
    [[nodiscard]] const SecurityPolicyConfig& Security() const noexcept { return security_; }
    [[nodiscard]] const StorageConfig& Storage() const noexcept { return storage_; }

    NetworkConfig& MutableNetwork() noexcept { return network_; }
    SecurityPolicyConfig& MutableSecurity() noexcept { return security_; }
    StorageConfig& MutableStorage() noexcept { return storage_; }

    [[nodiscard]] bool Validate() const {
        if (network_.listen_port == 0) return false;
        if (security_.min_rsa_key_bits < 2048) return false;
        if (storage_.data_directory.empty()) return false;
        return true;
    }

private:
    NetworkConfig network_;
    SecurityPolicyConfig security_;
    StorageConfig storage_;
};

} // namespace nexis::vault

#endif // VAULT_CONFIG_HPP
