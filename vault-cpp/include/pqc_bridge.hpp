/**
 * Nexis Core Financial Ledger Platform - C++ Enterprise Vault
 * Header: Post-Quantum Cryptographic C++ Bridge Interface
 *
 * Exposes RAII containers and high-level C++ wrappers for ML-KEM
 * and ML-DSA post-quantum key encapsulation and digital signatures.
 */

#ifndef VAULT_PQC_BRIDGE_HPP
#define VAULT_PQC_BRIDGE_HPP

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <chrono>

namespace nexis::vault {

struct PqcKeypair {
    std::string algorithm{"ML-KEM-768"};
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
    uint64_t created_at{0};
};

struct PqcEncapsulationResult {
    bool success{false};
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> shared_secret;
    std::string error_message;
    std::chrono::microseconds duration{0};
};

struct PqcSignatureResult {
    bool success{false};
    std::vector<uint8_t> signature;
    std::string error_message;
    std::chrono::microseconds duration{0};
};

struct PqcTelemetry {
    uint64_t keypairs_generated{0};
    uint64_t encapsulations_total{0};
    uint64_t decapsulations_total{0};
    uint64_t signatures_total{0};
    uint64_t verifications_total{0};
    std::string active_algorithm{"ML-KEM-768"};
};

class IPqcBridge {
public:
    virtual ~IPqcBridge() = default;

    virtual bool Initialize(const std::string& kem_algorithm) = 0;

    virtual PqcKeypair GenerateKemKeypair() = 0;

    virtual PqcEncapsulationResult Encapsulate(
        const std::vector<uint8_t>& peer_public_key
    ) = 0;

    virtual std::vector<uint8_t> Decapsulate(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& private_key
    ) = 0;

    virtual PqcSignatureResult Sign(
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& private_key
    ) = 0;

    virtual bool Verify(
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& public_key
    ) = 0;

    virtual PqcTelemetry GetTelemetry() const = 0;
};

} // namespace nexis::vault

#endif // VAULT_PQC_BRIDGE_HPP
