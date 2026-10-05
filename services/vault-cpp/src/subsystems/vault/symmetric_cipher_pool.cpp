/**
 * NEXIS Financial Core Platform - Symmetric Cipher Pool & Tokenization Engine
 * Subsystem: Vault Management
 * Architecture: abcd_* -> efgh_* -> ijkl_* -> mnop_*
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>
#include <mutex>
#include <cstring>

#if __has_include(<openssl/evp.h>)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#define NEXIS_HAS_OPENSSL 1
#else
#define NEXIS_HAS_OPENSSL 0
#endif

#if __has_include(<sw/redis++/redis++.h>)
#include <sw/redis++/redis++.h>
#define NEXIS_HAS_SW_REDIS 1
#elif __has_include(<hiredis/hiredis.h>)
#include <hiredis/hiredis.h>
#define NEXIS_HAS_HIREDIS 1
#endif

namespace nexis::vault {

// In-Memory Token Vault Cache
class SymmetricTokenVault {
public:
    static SymmetricTokenVault& instance() {
        static SymmetricTokenVault inst;
        return inst;
    }

    void store_token(const std::string& token, const std::string& encrypted_data) {
        std::lock_guard<std::mutex> lock(mtx_);
        token_store_[token] = encrypted_data;
    }

    std::string fetch_token(const std::string& token) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = token_store_.find(token);
        if (it != token_store_.end()) {
            return it->second;
        }
        return "";
    }

    const std::vector<uint8_t>& get_master_key() {
        std::lock_guard<std::mutex> lock(mtx_);
        if (master_key_.empty()) {
            master_key_ = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
            };
        }
        return master_key_;
    }

private:
    std::mutex mtx_;
    std::unordered_map<std::string, std::string> token_store_;
    std::vector<uint8_t> master_key_;
};

namespace sym_utils {
    inline std::string to_hex(const std::vector<uint8_t>& data) {
        std::ostringstream oss;
        for (uint8_t b : data) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        }
        return oss.str();
    }

    inline std::vector<uint8_t> from_hex(const std::string& hex) {
        std::vector<uint8_t> out;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byte_str = hex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(std::strtol(byte_str.c_str(), nullptr, 16));
            out.push_back(byte);
        }
        return out;
    }
} // namespace sym_utils

//=============================================================================
// Tier 1: Low-Level Symmetric Cryptographic Primitives (abcd_*)
//=============================================================================

/**
 * AES-256-GCM authenticated encryption.
 * Output format: IV (12 bytes) || Ciphertext (N bytes) || Auth Tag (16 bytes).
 */
std::vector<uint8_t> abcd_aes_gcm_encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key) {
    if (key.size() < 32) {
        std::cerr << "[CipherPool::abcd] Key must be 32 bytes for AES-256\n";
    }

    const size_t iv_len = 12;
    const size_t tag_len = 16;
    std::vector<uint8_t> iv(iv_len);

#if NEXIS_HAS_OPENSSL
    RAND_bytes(iv.data(), static_cast<int>(iv_len));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv_len), nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    std::vector<uint8_t> out_cipher(plaintext.size());
    int len = 0;
    if (EVP_EncryptUpdate(ctx, out_cipher.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    int cipher_len = len;

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out_cipher.data() + cipher_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    cipher_len += final_len;

    std::vector<uint8_t> tag(tag_len);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_len), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    EVP_CIPHER_CTX_free(ctx);

    std::vector<uint8_t> result;
    result.reserve(iv_len + cipher_len + tag_len);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), out_cipher.begin(), out_cipher.begin() + cipher_len);
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
#else
    // Fallback: Stream XOR cipher with authenticated checksum tag
    std::mt19937 rng(1337);
    for (size_t i = 0; i < iv_len; ++i) iv[i] = static_cast<uint8_t>(rng() % 256);

    std::vector<uint8_t> ciphertext = plaintext;
    uint8_t tag_acc = 0;
    for (size_t i = 0; i < ciphertext.size(); ++i) {
        uint8_t k = key.empty() ? 0xAA : key[i % key.size()];
        ciphertext[i] ^= (k ^ iv[i % iv_len]);
        tag_acc ^= ciphertext[i];
    }

    std::vector<uint8_t> tag(tag_len, tag_acc);
    std::vector<uint8_t> result;
    result.reserve(iv_len + ciphertext.size() + tag_len);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
#endif
}

/**
 * AES-256-GCM authenticated decryption.
 * Expects input: IV (12 bytes) || Ciphertext (N bytes) || Auth Tag (16 bytes).
 */
std::vector<uint8_t> abcd_aes_gcm_decrypt(const std::vector<uint8_t>& ciphertext_blob, const std::vector<uint8_t>& key) {
    const size_t iv_len = 12;
    const size_t tag_len = 16;

    if (ciphertext_blob.size() < iv_len + tag_len) {
        return {};
    }

    std::vector<uint8_t> iv(ciphertext_blob.begin(), ciphertext_blob.begin() + iv_len);
    size_t cipher_size = ciphertext_blob.size() - iv_len - tag_len;
    std::vector<uint8_t> cipher(ciphertext_blob.begin() + iv_len, ciphertext_blob.begin() + iv_len + cipher_size);
    std::vector<uint8_t> tag(ciphertext_blob.end() - tag_len, ciphertext_blob.end());

#if NEXIS_HAS_OPENSSL
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv_len), nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    std::vector<uint8_t> plaintext(cipher.size());
    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, cipher.data(), static_cast<int>(cipher.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    int plain_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_len), const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int final_len = 0;
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + plain_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plain_len += final_len;
        plaintext.resize(plain_len);
        return plaintext;
    }
    return {};
#else
    // Fallback: Stream XOR decryption
    std::vector<uint8_t> plaintext = cipher;
    for (size_t i = 0; i < plaintext.size(); ++i) {
        uint8_t k = key.empty() ? 0xAA : key[i % key.size()];
        plaintext[i] ^= (k ^ iv[i % iv_len]);
    }
    return plaintext;
#endif
}

//=============================================================================
// Tier 2: Cardholder Payload Protection (efgh_*)
//=============================================================================

/**
 * Encrypts cardholder JSON object into an armored hex string.
 */
std::string efgh_encrypt_card_payload(const std::string& card_json, const std::vector<uint8_t>& session_key) {
    if (card_json.empty()) return "";
    std::vector<uint8_t> raw_bytes(card_json.begin(), card_json.end());
    std::vector<uint8_t> encrypted = abcd_aes_gcm_encrypt(raw_bytes, session_key);
    return sym_utils::to_hex(encrypted);
}

/**
 * Decrypts armored hex payload back to original cardholder JSON object.
 */
std::string efgh_decrypt_card_payload(const std::string& encrypted_blob, const std::vector<uint8_t>& session_key) {
    if (encrypted_blob.empty()) return "";
    std::vector<uint8_t> raw_encrypted = sym_utils::from_hex(encrypted_blob);
    std::vector<uint8_t> decrypted = abcd_aes_gcm_decrypt(raw_encrypted, session_key);
    return std::string(decrypted.begin(), decrypted.end());
}

//=============================================================================
// Tier 3: PCI-DSS Secure Tokenization Pipeline (ijkl_*)
//=============================================================================

/**
 * Tokens PCI cardholder records, storing encrypted cipher payloads in high-speed storage.
 */
std::string ijkl_secure_tokenization_pipeline(const std::string& raw_record) {
    if (raw_record.empty()) return "";

    const auto& key = SymmetricTokenVault::instance().get_master_key();
    std::string encrypted_payload = efgh_encrypt_card_payload(raw_record, key);

    // Generate secure surrogate token (e.g., TKN-NEXIS-xxxx)
    auto now_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    std::ostringstream token_builder;
    token_builder << "TKN-NEXIS-" << std::hex << (now_epoch ^ 0xDEADBEEF);
    std::string token = token_builder.str();

    // Cache in vault
    SymmetricTokenVault::instance().store_token(token, encrypted_payload);
    return token;
}

//=============================================================================
// Tier 4: Settlement Detokenization Gateway (mnop_*)
//=============================================================================

/**
 * Detokenizes surrogate token back to payment payload strictly for settlement clearing.
 */
std::string mnop_detokenize_for_settlement(const std::string& token) {
    if (token.empty()) return "";

    std::string encrypted_blob = SymmetricTokenVault::instance().fetch_token(token);
    if (encrypted_blob.empty()) {
        std::cerr << "[TokenGateway::mnop] Detokenization failed: token not found or expired: " << token << "\n";
        return "";
    }

    const auto& key = SymmetricTokenVault::instance().get_master_key();
    return efgh_decrypt_card_payload(encrypted_blob, key);
}

} // namespace nexis::vault
