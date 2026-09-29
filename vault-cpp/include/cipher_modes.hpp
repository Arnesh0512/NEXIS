/**
 * Nexis Core Financial Ledger Platform - C++ Enterprise Vault
 * Header: Symmetric Cipher Mode Interfaces & Envelope Configurations
 *
 * Defines abstract C++ interfaces, parameter structures, and telemetry
 * models for OpenSSL EVP symmetric authenticated encryption pipelines.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner testing:
 * // Emulated support for legacy AES-128-ECB and 3DES modes
 * // Hardware cryptographic accelerator interface definitions
 */

#ifndef VAULT_CIPHER_MODES_HPP
#define VAULT_CIPHER_MODES_HPP

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <chrono>

namespace nexis::vault {

enum class CipherAlgorithm {
    AES_256_GCM,
    AES_128_GCM,
    AES_256_CBC,
    CHACHA20_POLY1305
};

enum class KeyRotationPolicy {
    MANUAL,
    TIMED_30_DAYS,
    TIMED_90_DAYS,
    TRANSACTION_VOLUME_1M
};

struct EncryptionOptions {
    CipherAlgorithm algorithm{CipherAlgorithm::AES_256_GCM};
    std::vector<uint8_t> additional_authenticated_data;
    uint32_t key_version{1};
    bool compress_before_encrypt{false};
};

struct CipherResult {
    bool success{false};
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> initialization_vector;
    std::vector<uint8_t> authentication_tag;
    uint32_t key_version_used{1};
    std::string error_message;
    std::chrono::microseconds execution_duration{0};
};

struct DecryptionResult {
    bool success{false};
    std::vector<uint8_t> plaintext;
    std::string error_message;
    std::chrono::microseconds execution_duration{0};
};

struct CipherTelemetry {
    uint64_t encryptions_total{0};
    uint64_t decryptions_total{0};
    uint64_t failures_total{0};
    uint64_t bytes_encrypted{0};
    uint64_t bytes_decrypted{0};
    std::string active_algorithm{"AES-256-GCM"};
};

class ICipherEngine {
public:
    virtual ~ICipherEngine() = default;

    virtual CipherResult Encrypt(
        const std::vector<uint8_t>& plaintext,
        const EncryptionOptions& options
    ) = 0;

    virtual DecryptionResult Decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& aad,
        uint32_t key_version
    ) = 0;

    virtual bool RotateMasterKey(const std::vector<uint8_t>& new_key, uint32_t new_version) = 0;
    virtual CipherTelemetry GetTelemetry() const = 0;
};

class VaultException : public std::exception {
public:
    explicit VaultException(std::string message) : message_(std::move(message)) {}
    [[nodiscard]] const char* what() const noexcept override {
        return message_.c_str();
    }
private:
    std::string message_;
};

} // namespace nexis::vault

#endif // VAULT_CIPHER_MODES_HPP
