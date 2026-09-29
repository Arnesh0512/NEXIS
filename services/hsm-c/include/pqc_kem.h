/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Header: Post-Quantum Cryptographic Interface (ML-KEM & ML-DSA)
 *
 * Defines API signatures and parameter buffers for hardware-accelerated
 * FIPS 203 (ML-KEM-768) key encapsulation and FIPS 204 (ML-DSA-65) signatures.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner testing:
 * // Classical Diffie-Hellman and RSA-2048 fallback headers
 * // ML-KEM buffer sizes aligned for PCIe DMA bus transfer
 */

#ifndef HSM_PQC_KEM_H
#define HSM_PQC_KEM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "hsm_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ML-KEM Parameter Lengths (FIPS 203 Standard) */
#define ML_KEM_512_PUBLIC_KEY_BYTES 800
#define ML_KEM_512_SECRET_KEY_BYTES 1632
#define ML_KEM_512_CIPHERTEXT_BYTES 768
#define ML_KEM_512_SHARED_SECRET_BYTES 32

#define ML_KEM_768_PUBLIC_KEY_BYTES 1184
#define ML_KEM_768_SECRET_KEY_BYTES 2400
#define ML_KEM_768_CIPHERTEXT_BYTES 1088
#define ML_KEM_768_SHARED_SECRET_BYTES 32

#define ML_KEM_1024_PUBLIC_KEY_BYTES 1568
#define ML_KEM_1024_SECRET_KEY_BYTES 3168
#define ML_KEM_1024_CIPHERTEXT_BYTES 1568
#define ML_KEM_1024_SHARED_SECRET_BYTES 32

/* ML-DSA Parameter Lengths (FIPS 204 Standard) */
#define ML_DSA_44_PUBLIC_KEY_BYTES 1312
#define ML_DSA_44_SECRET_KEY_BYTES 2560
#define ML_DSA_44_SIGNATURE_BYTES 2420

#define ML_DSA_65_PUBLIC_KEY_BYTES 1952
#define ML_DSA_65_SECRET_KEY_BYTES 4032
#define ML_DSA_65_SIGNATURE_BYTES 3309

#define ML_DSA_87_PUBLIC_KEY_BYTES 2592
#define ML_DSA_87_SECRET_KEY_BYTES 4896
#define ML_DSA_87_SIGNATURE_BYTES 4627

/* PQC Operation Types */
typedef enum {
    PQC_OP_KEM_KEYGEN = 0x01,
    PQC_OP_KEM_ENCAPSULATE = 0x02,
    PQC_OP_KEM_DECAPSULATE = 0x03,
    PQC_OP_SIG_KEYGEN = 0x04,
    PQC_OP_SIG_SIGN = 0x05,
    PQC_OP_SIG_VERIFY = 0x06
} pqc_operation_t;

/* ML-KEM Keypair Buffer Container */
typedef struct {
    uint8_t public_key[ML_KEM_768_PUBLIC_KEY_BYTES];
    uint8_t secret_key[ML_KEM_768_SECRET_KEY_BYTES];
    size_t public_key_len;
    size_t secret_key_len;
    uint32_t algorithm_id;
    bool is_initialized;
} ml_kem_keypair_t;

/* ML-KEM Encapsulation Result */
typedef struct {
    uint8_t ciphertext[ML_KEM_768_CIPHERTEXT_BYTES];
    uint8_t shared_secret[ML_KEM_768_SHARED_SECRET_BYTES];
    size_t ciphertext_len;
    size_t shared_secret_len;
} ml_kem_encapsulation_t;

/* ML-DSA Keypair Buffer Container */
typedef struct {
    uint8_t public_key[ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t secret_key[ML_DSA_65_SECRET_KEY_BYTES];
    size_t public_key_len;
    size_t secret_key_len;
    uint32_t algorithm_id;
    bool is_initialized;
} ml_dsa_keypair_t;

/* PQC Hardware Acceleration Context */
typedef struct {
    uint32_t device_id;
    bool hardware_engine_present;
    bool fips_self_test_passed;
    uint64_t operations_completed;
    uint64_t total_execution_time_ns;
} pqc_context_t;

/* PQC Function Declarations */
hsm_status_t pqc_init_context(pqc_context_t *ctx);
hsm_status_t pqc_ml_kem_768_keypair(pqc_context_t *ctx, ml_kem_keypair_t *keypair);
hsm_status_t pqc_ml_kem_768_encapsulate(
    pqc_context_t *ctx,
    const uint8_t *peer_public_key,
    size_t pk_len,
    ml_kem_encapsulation_t *result
);
hsm_status_t pqc_ml_kem_768_decapsulate(
    pqc_context_t *ctx,
    const ml_kem_keypair_t *keypair,
    const uint8_t *ciphertext,
    size_t ct_len,
    uint8_t *shared_secret,
    size_t *ss_len
);

hsm_status_t pqc_ml_dsa_65_keypair(pqc_context_t *ctx, ml_dsa_keypair_t *keypair);
hsm_status_t pqc_ml_dsa_65_sign(
    pqc_context_t *ctx,
    const ml_dsa_keypair_t *keypair,
    const uint8_t *message,
    size_t msg_len,
    uint8_t *signature,
    size_t *sig_len
);
hsm_status_t pqc_ml_dsa_65_verify(
    pqc_context_t *ctx,
    const uint8_t *public_key,
    size_t pk_len,
    const uint8_t *message,
    size_t msg_len,
    const uint8_t *signature,
    size_t sig_len,
    bool *is_valid
);

void pqc_destroy_keypair(ml_kem_keypair_t *keypair);

#ifdef __cplusplus
}
#endif

#endif /* HSM_PQC_KEM_H */
