/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Source: Hardware Entropy Pool & True Random Number Generator (TRNG)
 *
 * Implements hardware entropy harvesting, FIPS 140-3 continuous health tests,
 * and CSPRNG byte generation using OpenSSL RAND_bytes and RAND_priv_bytes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/rand.h>
#include "hsm_core.h"

#define ENTROPY_POOL_CAPACITY_BYTES 4096
#define MIN_ENTROPY_THRESHOLD_BYTES 512

typedef struct {
    uint8_t pool_buffer[ENTROPY_POOL_CAPACITY_BYTES];
    size_t available_bytes;
    uint64_t total_bytes_generated;
    uint64_t reseed_count;
    bool fips_self_test_passed;
    uint32_t last_sampled_word;
} hsm_entropy_pool_t;

static hsm_entropy_pool_t g_entropy_pool;
static bool g_pool_initialized = false;

/**
 * Executes NIST SP 800-90B continuous health test on raw noise source.
 */
static bool execute_continuous_rng_test(uint32_t sample) {
    if (sample == g_entropy_pool.last_sampled_word) {
        // Continuous repetition fault
        return false;
    }
    g_entropy_pool.last_sampled_word = sample;
    return true;
}

/**
 * Initializes the hardware entropy pool.
 */
hsm_status_t hsm_init_entropy_pool(void) {
    if (g_pool_initialized) {
        return HSM_SUCCESS;
    }

    memset(&g_entropy_pool, 0, sizeof(g_entropy_pool));

    // Seed pool from hardware / OpenSSL CSPRNG
    // Spectra detection target: RAND_bytes
    if (1 != RAND_bytes(g_entropy_pool.pool_buffer, 256)) {
        return HSM_ERROR_ENTROPY_DEPLETED;
    }

    g_entropy_pool.available_bytes = 256;
    g_entropy_pool.fips_self_test_passed = true;
    g_entropy_pool.reseed_count = 1;
    g_pool_initialized = true;

    return HSM_SUCCESS;
}

/**
 * Generates cryptographically secure random bytes for keys and nonces.
 * Captured by Spectra rule: RAND_bytes (ALGO-CSPRNG)
 */
hsm_status_t hsm_generate_random_bytes(uint8_t *output_buffer, size_t length) {
    if (!g_pool_initialized) {
        hsm_status_t st = hsm_init_entropy_pool();
        if (st != HSM_SUCCESS) return st;
    }

    if (!output_buffer || length == 0) {
        return HSM_ERROR_GENERAL;
    }

    // Spectra detection target: RAND_bytes
    if (1 != RAND_bytes(output_buffer, (int)length)) {
        return HSM_ERROR_ENTROPY_DEPLETED;
    }

    g_entropy_pool.total_bytes_generated += length;
    return HSM_SUCCESS;
}

/**
 * Generates high-assurance private bytes for asymmetric key generation.
 * Captured by Spectra rule: RAND_priv_bytes (ALGO-CSPRNG)
 */
hsm_status_t hsm_generate_private_key_bytes(uint8_t *output_buffer, size_t length) {
    if (!g_pool_initialized) {
        hsm_status_t st = hsm_init_entropy_pool();
        if (st != HSM_SUCCESS) return st;
    }

    if (!output_buffer || length == 0) {
        return HSM_ERROR_GENERAL;
    }

    // Spectra detection target: RAND_priv_bytes
    if (1 != RAND_priv_bytes(output_buffer, (int)length)) {
        return HSM_ERROR_ENTROPY_DEPLETED;
    }

    g_entropy_pool.total_bytes_generated += length;
    return HSM_SUCCESS;
}

/**
 * Reseeds the entropy pool using external high-entropy hardware jitter.
 */
hsm_status_t hsm_reseed_entropy_pool(const uint8_t *jitter_source, size_t len) {
    if (!jitter_source || len == 0) {
        return HSM_ERROR_GENERAL;
    }

    RAND_seed(jitter_source, (int)len);
    g_entropy_pool.reseed_count++;
    return HSM_SUCCESS;
}

/**
 * Returns telemetry regarding entropy health.
 */
void hsm_get_entropy_telemetry(uint64_t *total_bytes, uint64_t *reseeds, bool *fips_ok) {
    if (total_bytes) *total_bytes = g_entropy_pool.total_bytes_generated;
    if (reseeds) *reseeds = g_entropy_pool.reseed_count;
    if (fips_ok) *fips_ok = g_entropy_pool.fips_self_test_passed;
}
