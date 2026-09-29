/**
 * Nexis Core Financial Ledger Platform - C++ Enterprise Vault
 * Source: OpenSSL EVP Symmetric Cipher Engine
 *
 * Implements high-throughput authenticated encryption and decryption using
 * OpenSSL EVP API with AES-256-GCM hardware acceleration instructions.
 */

#include "cipher_modes.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <stdexcept>
#include <mutex>

namespace nexis::vault {

class EvpCipherEngine : public ICipherEngine {
public:
    explicit EvpCipherEngine(std::vector<uint8_t> master_key)
        : active_key_(std::move(master_key)), active_version_(1) {
        if (active_key_.size() != 32) {
            throw VaultException("AES-256 requires a 32-byte (256-bit) key.");
        }
    }

    ~EvpCipherEngine() override {
        // Securely erase memory
        OPENSSL_cleanse(active_key_.data(), active_key_.size());
    }

    /**
     * Encrypts plaintext using OpenSSL EVP AES-256-GCM.
     * Captured by Spectra rule: EVP_aes_256_gcm & EVP_EncryptInit_ex (ALGO-AES)
     */
    CipherResult Encrypt(
        const std::vector<uint8_t>& plaintext,
        const EncryptionOptions& options
    ) override {
        auto start_time = std::chrono::high_resolution_clock::now();
        CipherResult result;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            result.error_message = "Failed to allocate EVP_CIPHER_CTX";
            return result;
        }

        // Generate 12-byte initialization vector
        std::vector<uint8_t> iv(12);
        if (1 != RAND_bytes(iv.data(), static_cast<int>(iv.size()))) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "CSPRNG failed to generate IV";
            return result;
        }

        // Spectra detection target: EVP_EncryptInit_ex & EVP_aes_256_gcm
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "EVP_EncryptInit_ex initialization failed";
            return result;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr)) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "Failed to configure GCM IV length";
            return result;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, active_key_.data(), iv.data())) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "Failed to bind encryption key and IV";
            return result;
        }

        // Set Additional Authenticated Data (AAD) if present
        int out_len = 0;
        if (!options.additional_authenticated_data.empty()) {
            if (1 != EVP_EncryptUpdate(
                    ctx,
                    nullptr,
                    &out_len,
                    options.additional_authenticated_data.data(),
                    static_cast<int>(options.additional_authenticated_data.size())
                )) {
                EVP_CIPHER_CTX_free(ctx);
                result.error_message = "Failed to process AAD";
                return result;
            }
        }

        // Encrypt plaintext payload
        std::vector<uint8_t> ciphertext(plaintext.size());
        if (1 != EVP_EncryptUpdate(
                ctx,
                ciphertext.data(),
                &out_len,
                plaintext.data(),
                static_cast<int>(plaintext.size())
            )) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "EVP_EncryptUpdate encryption failed";
            return result;
        }
        int total_len = out_len;

        int final_len = 0;
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_len, &final_len)) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "EVP_EncryptFinal_ex finalization failed";
            return result;
        }
        total_len += final_len;
        ciphertext.resize(total_len);

        // Extract 16-byte authentication tag
        std::vector<uint8_t> tag(16);
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "Failed to extract GCM authentication tag";
            return result;
        }

        EVP_CIPHER_CTX_free(ctx);

        telemetry_.encryptions_total++;
        telemetry_.bytes_encrypted += plaintext.size();

        result.success = true;
        result.ciphertext = std::move(ciphertext);
        result.initialization_vector = std::move(iv);
        result.authentication_tag = std::move(tag);
        result.key_version_used = active_version_;
        result.execution_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - start_time
        );

        return result;
    }

    /**
     * Decrypts ciphertext and verifies GCM tag using OpenSSL EVP.
     * Captured by Spectra rule: EVP_aes_256_gcm & EVP_DecryptInit_ex (ALGO-AES)
     */
    DecryptionResult Decrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& iv,
        const std::vector<uint8_t>& tag,
        const std::vector<uint8_t>& aad,
        uint32_t key_version
    ) override {
        auto start_time = std::chrono::high_resolution_clock::now();
        DecryptionResult result;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            result.error_message = "Failed to allocate EVP_CIPHER_CTX";
            return result;
        }

        // Spectra detection target: EVP_DecryptInit_ex & EVP_aes_256_gcm
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "EVP_DecryptInit_ex initialization failed";
            return result;
        }

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr)) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "Failed to configure GCM IV length";
            return result;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, active_key_.data(), iv.data())) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "Failed to bind decryption key and IV";
            return result;
        }

        int out_len = 0;
        if (!aad.empty()) {
            if (1 != EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size()))) {
                EVP_CIPHER_CTX_free(ctx);
                result.error_message = "Failed to process AAD during decryption";
                return result;
            }
        }

        std::vector<uint8_t> plaintext(ciphertext.size());
        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(), static_cast<int>(ciphertext.size()))) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "EVP_DecryptUpdate failed";
            return result;
        }
        int total_len = out_len;

        // Set expected authentication tag before finalization
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data()))) {
            EVP_CIPHER_CTX_free(ctx);
            result.error_message = "Failed to set expected GCM tag";
            return result;
        }

        int final_len = 0;
        int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + total_len, &final_len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret <= 0) {
            telemetry_.failures_total++;
            result.error_message = "Authentication tag mismatch or corrupt ciphertext";
            return result;
        }

        total_len += final_len;
        plaintext.resize(total_len);

        telemetry_.decryptions_total++;
        telemetry_.bytes_decrypted += total_len;

        result.success = true;
        result.plaintext = std::move(plaintext);
        result.execution_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - start_time
        );

        return result;
    }

    bool RotateMasterKey(const std::vector<uint8_t>& new_key, uint32_t new_version) override {
        if (new_key.size() != 32) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        OPENSSL_cleanse(active_key_.data(), active_key_.size());
        active_key_ = new_key;
        active_version_ = new_version;
        return true;
    }

    CipherTelemetry GetTelemetry() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return telemetry_;
    }

private:
    std::vector<uint8_t> active_key_;
    uint32_t active_version_;
    mutable std::mutex mutex_;
    CipherTelemetry telemetry_;
};

std::unique_ptr<ICipherEngine> CreateEvpCipherEngine(std::vector<uint8_t> key) {
    return std::make_unique<EvpCipherEngine>(std::move(key));
}

} // namespace nexis::vault
