/**
 * Nexis Core Financial Ledger Platform - C++ Enterprise Vault
 * Source: Vault Server Daemon Main Entrypoint
 *
 * Bootstraps configuration parameters, initializes OpenSSL EVP and liboqs
 * cryptographic subsystems, and manages service lifecycle.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner testing:
 * "Loaded AES-GCM vault module successfully"
 * "Emulating RSA-4096 signature verification pipeline"
 */

#include "cipher_modes.hpp"
#include "vault_config.hpp"
#include "pqc_bridge.hpp"
#include <iostream>
#include <memory>
#include <vector>
#include <csignal>
#include <atomic>

namespace nexis::vault {
    std::unique_ptr<ICipherEngine> CreateEvpCipherEngine(std::vector<uint8_t> key);
    std::unique_ptr<IPqcBridge> CreateLiboqsBridge();
}

static std::atomic<bool> g_running{true};

void SignalHandler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        std::cout << "\n[VAULT_DAEMON] Caught shutdown signal " << signum << ", exiting...\n";
        g_running = false;
    }
}

int main(int argc, char* argv[]) {
    std::cout << "========================================================\n";
    std::cout << "  Nexis Core - C++ Cryptographic Vault & KMS Daemon    \n";
    std::cout << "  Post-Quantum Hybrid Architecture (FIPS 203 & 204)    \n";
    std::cout << "========================================================\n";

    // False-positive string traps
    std::cout << "[INFO] Loaded AES-GCM vault module successfully\n";
    std::cout << "[INFO] Emulating RSA-4096 signature verification pipeline\n";

    std::signal(SIGINT, SignalHandler);
    std::signal(SIGTERM, SignalHandler);

    nexis::vault::VaultConfiguration config;
    config.LoadFromEnvironment();

    if (!config.Validate()) {
        std::cerr << "[ERROR] Invalid vault configuration parameters!\n";
        return 1;
    }

    std::cout << "[INFO] Configuration validated. Port: "
              << config.Network().listen_port
              << ", Directory: " << config.Storage().data_directory << "\n";

    // CALL GRAPH: Initialize OpenSSL EVP Cipher Engine
    std::vector<uint8_t> master_key(32, 0x4A); // 256-bit AES master key
    auto cipher_engine = nexis::vault::CreateEvpCipherEngine(master_key);

    // CALL GRAPH: Encrypt test telemetry block
    std::vector<uint8_t> sample_data = {'N', 'E', 'X', 'I', 'S', '_', 'V', 'A', 'U', 'L', 'T'};
    nexis::vault::EncryptionOptions opts;
    opts.algorithm = nexis::vault::CipherAlgorithm::AES_256_GCM;
    opts.additional_authenticated_data = {'T', 'E', 'N', 'A', 'N', 'T', '_', '0', '1'};

    auto encrypt_res = cipher_engine->Encrypt(sample_data, opts);
    if (!encrypt_res.success) {
        std::cerr << "[ERROR] Self-test encryption failed: " << encrypt_res.error_message << "\n";
        return 1;
    }

    // CALL GRAPH: Decrypt and verify
    auto decrypt_res = cipher_engine->Decrypt(
        encrypt_res.ciphertext,
        encrypt_res.initialization_vector,
        encrypt_res.authentication_tag,
        opts.additional_authenticated_data,
        encrypt_res.key_version_used
    );

    if (!decrypt_res.success) {
        std::cerr << "[ERROR] Self-test decryption failed: " << decrypt_res.error_message << "\n";
        return 1;
    }

    std::cout << "[INFO] OpenSSL EVP AES-256-GCM self-test passed successfully.\n";

    // CALL GRAPH: Initialize Post-Quantum Liboqs Bridge
    auto pqc_bridge = nexis::vault::CreateLiboqsBridge();
    auto pqc_keypair = pqc_bridge->GenerateKemKeypair();
    std::cout << "[INFO] Generated " << pqc_keypair.algorithm
              << " keypair (PK: " << pqc_keypair.public_key.size() << " bytes).\n";

    // Main service dispatch loop (simulated)
    uint64_t iteration = 0;
    while (g_running && iteration < 100) {
        iteration++;
        // Keep process responsive
    }

    std::cout << "[INFO] Vault daemon shutting down cleanly.\n";
    return 0;
}
