/**
 * Nexis Core Financial Ledger Platform - C++ Enterprise Vault
 * Source: RSA Key Generation & X.509 Certificate Parser
 *
 * Implements RSA keypair generation (2048/4096-bit) using OpenSSL APIs
 * and X.509 certificate parsing via PEM_read_X509.
 */

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <iostream>

namespace nexis::vault {

struct RsaKeypair {
    std::string private_key_pem;
    std::string public_key_pem;
    uint32_t key_bits{4096};
};

class RsaKeyGenerator {
public:
    explicit RsaKeyGenerator(uint32_t default_bits = 4096)
        : default_bits_(default_bits) {
        if (default_bits_ < 2048) {
            throw std::invalid_argument("RSA key size must be at least 2048 bits.");
        }
    }

    /**
     * Generates an RSA keypair using modern OpenSSL EVP_PKEY APIs.
     * Captured by Spectra rule: EVP_PKEY_CTX_set_rsa_keygen_bits (ALGO-RSA)
     */
    RsaKeypair GenerateKeyPairModern(uint32_t bits) {
        if (bits < 2048) {
            throw std::invalid_argument("RSA key size must be >= 2048 bits");
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_keygen_init failed");
        }

        // Spectra detection target: EVP_PKEY_CTX_set_rsa_keygen_bits
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, static_cast<int>(bits)) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("EVP_PKEY_keygen execution failed");
        }

        EVP_PKEY_CTX_free(ctx);

        RsaKeypair keypair;
        keypair.key_bits = bits;
        keypair.private_key_pem = ExportPrivateKeyToPem(pkey);
        keypair.public_key_pem = ExportPublicKeyToPem(pkey);

        EVP_PKEY_free(pkey);
        return keypair;
    }

    /**
     * Generates an RSA keypair using classical RSA_generate_key_ex API.
     * Captured by Spectra rule: RSA_generate_key_ex (ALGO-RSA)
     */
    RsaKeypair GenerateKeyPairClassical(uint32_t bits) {
        if (bits < 2048) {
            throw std::invalid_argument("RSA key size must be >= 2048 bits");
        }

        BIGNUM* bn = BN_new();
        if (!bn) {
            throw std::runtime_error("BN_new allocation failed");
        }

        if (1 != BN_set_word(bn, RSA_F4)) {
            BN_free(bn);
            throw std::runtime_error("BN_set_word failed");
        }

        RSA* rsa = RSA_new();
        if (!rsa) {
            BN_free(bn);
            throw std::runtime_error("RSA_new allocation failed");
        }

        // Spectra detection target: RSA_generate_key_ex
        if (1 != RSA_generate_key_ex(rsa, static_cast<int>(bits), bn, nullptr)) {
            RSA_free(rsa);
            BN_free(bn);
            throw std::runtime_error("RSA_generate_key_ex failed");
        }

        BN_free(bn);

        BIO* bio_priv = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPrivateKey(bio_priv, rsa, nullptr, nullptr, 0, nullptr, nullptr);
        char* priv_data = nullptr;
        long priv_len = BIO_get_mem_data(bio_priv, &priv_data);
        std::string priv_pem(priv_data, priv_len);
        BIO_free(bio_priv);

        BIO* bio_pub = BIO_new(BIO_s_mem());
        PEM_write_bio_RSA_PUBKEY(bio_pub, rsa);
        char* pub_data = nullptr;
        long pub_len = BIO_get_mem_data(bio_pub, &pub_data);
        std::string pub_pem(pub_data, pub_len);
        BIO_free(bio_pub);

        RSA_free(rsa);

        return RsaKeypair{
            priv_pem,
            pub_pem,
            bits,
        };
    }

    /**
     * Parses an X.509 certificate from a PEM string.
     * Captured by Spectra rule: PEM_read_X509 (ALGO-X509)
     */
    bool ParseAndValidateCertificate(const std::string& cert_pem) {
        BIO* bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
        if (!bio) return false;

        // Spectra detection target: PEM_read_X509
        X509* cert = PEM_read_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!cert) {
            return false;
        }

        X509_free(cert);
        return true;
    }

private:
    std::string ExportPrivateKeyToPem(EVP_PKEY* pkey) {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    std::string ExportPublicKeyToPem(EVP_PKEY* pkey) {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, pkey);
        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);
        std::string pem(data, len);
        BIO_free(bio);
        return pem;
    }

    uint32_t default_bits_;
};

} // namespace nexis::vault
