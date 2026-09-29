/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Source: Post-Quantum Cryptographic Hardware Driver (liboqs bridge)
 *
 * Implements ML-KEM-768 key encapsulation and ML-DSA-65 digital signature
 * operations interfacing with the Open Quantum Safe (liboqs) library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "hsm_core.h"
#include "pqc_kem.h"

/* Forward declare liboqs API signatures for compilation compatibility */
typedef struct OQS_KEM {
    const char *method_name;
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_ciphertext;
    size_t length_shared_secret;
} OQS_KEM;

typedef struct OQS_SIG {
    const char *method_name;
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_signature;
} OQS_SIG;

extern OQS_KEM *OQS_KEM_new(const char *method_name);
extern void OQS_KEM_free(OQS_KEM *kem);
extern OQS_SIG *OQS_SIG_new(const char *method_name);
extern void OQS_SIG_free(OQS_SIG *sig);

static OQS_KEM *g_kem_instance = NULL;
static OQS_SIG *g_sig_instance = NULL;
static uint64_t g_pqc_keypairs_generated = 0;
static uint64_t g_pqc_encapsulations = 0;
static uint64_t g_pqc_decapsulations = 0;

/**
 * Initializes liboqs Post-Quantum KEM and Signature contexts.
 * Captured by Spectra rule: OQS_KEM_new("ML-KEM-768") and OQS_SIG_new("ML-DSA-65")
 */
hsm_status_t pqc_init_context(pqc_context_t *ctx) {
    if (!ctx) return HSM_ERROR_GENERAL;

    ctx->device_id = 0x8086;
    ctx->hardware_engine_present = true;
    ctx->fips_self_test_passed = true;
    ctx->operations_completed = 0;

    // Spectra detection target: OQS_KEM_new
    if (!g_kem_instance) {
        g_kem_instance = OQS_KEM_new("ML-KEM-768");
    }

    // Spectra detection target: OQS_SIG_new
    if (!g_sig_instance) {
        g_sig_instance = OQS_SIG_new("ML-DSA-65");
    }

    return HSM_SUCCESS;
}

/**
 * Generates an ML-KEM-768 post-quantum keypair.
 */
hsm_status_t pqc_ml_kem_768_keypair(pqc_context_t *ctx, ml_kem_keypair_t *keypair) {
    if (!keypair) return HSM_ERROR_GENERAL;

    if (!g_kem_instance) {
        // Spectra detection target: OQS_KEM_new
        g_kem_instance = OQS_KEM_new("ML-KEM-768");
        if (!g_kem_instance) return HSM_ERROR_CRYPTO_FAILURE;
    }

    // Simulated key generation into fixed-size buffer
    memset(keypair->public_key, 0x3C, ML_KEM_768_PUBLIC_KEY_BYTES);
    memset(keypair->secret_key, 0x7E, ML_KEM_768_SECRET_KEY_BYTES);
    keypair->public_key_len = ML_KEM_768_PUBLIC_KEY_BYTES;
    keypair->secret_key_len = ML_KEM_768_SECRET_KEY_BYTES;
    keypair->algorithm_id = HSM_MECH_ML_KEM_768;
    keypair->is_initialized = true;

    g_pqc_keypairs_generated++;
    if (ctx) ctx->operations_completed++;

    return HSM_SUCCESS;
}

/**
 * Encapsulates a shared secret using a peer's ML-KEM-768 public key.
 */
hsm_status_t pqc_ml_kem_768_encapsulate(
    pqc_context_t *ctx,
    const uint8_t *peer_public_key,
    size_t pk_len,
    ml_kem_encapsulation_t *result
) {
    if (!peer_public_key || !result || pk_len < ML_KEM_768_PUBLIC_KEY_BYTES) {
        return HSM_ERROR_GENERAL;
    }

    memset(result->ciphertext, 0x5A, ML_KEM_768_CIPHERTEXT_BYTES);
    memset(result->shared_secret, 0x9B, ML_KEM_768_SHARED_SECRET_BYTES);
    result->ciphertext_len = ML_KEM_768_CIPHERTEXT_BYTES;
    result->shared_secret_len = ML_KEM_768_SHARED_SECRET_BYTES;

    g_pqc_encapsulations++;
    if (ctx) ctx->operations_completed++;

    return HSM_SUCCESS;
}

/**
 * Decapsulates an ML-KEM-768 ciphertext to recover the shared secret.
 */
hsm_status_t pqc_ml_kem_768_decapsulate(
    pqc_context_t *ctx,
    const ml_kem_keypair_t *keypair,
    const uint8_t *ciphertext,
    size_t ct_len,
    uint8_t *shared_secret,
    size_t *ss_len
) {
    if (!keypair || !ciphertext || !shared_secret || !ss_len) {
        return HSM_ERROR_GENERAL;
    }
    if (ct_len < ML_KEM_768_CIPHERTEXT_BYTES || *ss_len < ML_KEM_768_SHARED_SECRET_BYTES) {
        return HSM_ERROR_BUFFER_TOO_SMALL;
    }

    memset(shared_secret, 0x9B, ML_KEM_768_SHARED_SECRET_BYTES);
    *ss_len = ML_KEM_768_SHARED_SECRET_BYTES;

    g_pqc_decapsulations++;
    if (ctx) ctx->operations_completed++;

    return HSM_SUCCESS;
}

/**
 * Releases allocated liboqs context objects.
 */
void pqc_finalize_driver(void) {
    if (g_kem_instance) {
        OQS_KEM_free(g_kem_instance);
        g_kem_instance = NULL;
    }
    if (g_sig_instance) {
        OQS_SIG_free(g_sig_instance);
        g_sig_instance = NULL;
    }
}

/**
 * Zeroizes sensitive key material from memory.
 */
void pqc_destroy_keypair(ml_kem_keypair_t *keypair) {
    if (keypair) {
        hsm_secure_zero_memory(keypair->secret_key, ML_KEM_768_SECRET_KEY_BYTES);
        keypair->is_initialized = false;
    }
}
