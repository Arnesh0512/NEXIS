/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Source: PKCS#11 Hardware Cryptographic Driver
 *
 * Implements OpenSSL EVP hardware-backed AES-256-GCM cipher operations,
 * SHA-256 digest hashing, and key attribute serialization conforming
 * to PKCS#11 v2.40 specification.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "hsm_core.h"
#include "pkcs11_tokens.h"

#define AES_KEY_SIZE 32
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16

typedef struct {
    EVP_CIPHER_CTX *cipher_ctx;
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[GCM_IV_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    bool is_encrypt;
} driver_crypto_session_t;

static driver_crypto_session_t g_driver_sessions[HSM_MAX_SESSIONS];
static bool g_driver_initialized = false;
static uint64_t g_total_encryptions = 0;
static uint64_t g_total_decryptions = 0;
static uint64_t g_total_hashes = 0;

/**
 * Initializes the PKCS#11 driver subsystem and OpenSSL contexts.
 */
CK_RV C_Initialize(void *pInitArgs) {
    if (g_driver_initialized) {
        return CKR_OK;
    }

    memset(g_driver_sessions, 0, sizeof(g_driver_sessions));
    for (int i = 0; i < HSM_MAX_SESSIONS; i++) {
        g_driver_sessions[i].cipher_ctx = EVP_CIPHER_CTX_new();
        if (!g_driver_sessions[i].cipher_ctx) {
            return CKR_DEVICE_MEMORY;
        }
    }

    g_driver_initialized = true;
    return CKR_OK;
}

/**
 * Finalizes driver and frees allocated OpenSSL EVP contexts.
 */
CK_RV C_Finalize(void *pReserved) {
    if (!g_driver_initialized) {
        return CKR_OK;
    }

    for (int i = 0; i < HSM_MAX_SESSIONS; i++) {
        if (g_driver_sessions[i].cipher_ctx) {
            EVP_CIPHER_CTX_free(g_driver_sessions[i].cipher_ctx);
            g_driver_sessions[i].cipher_ctx = NULL;
        }
        hsm_secure_zero_memory(g_driver_sessions[i].key, AES_KEY_SIZE);
    }

    g_driver_initialized = false;
    return CKR_OK;
}

/**
 * Initializes an AES-256-GCM authenticated encryption operation.
 * Captured by Spectra rule: EVP_aes_256_gcm & EVP_EncryptInit_ex (ALGO-AES)
 */
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
    if (!g_driver_initialized) return CKR_GENERAL_ERROR;
    if (hSession >= HSM_MAX_SESSIONS) return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism) return CKR_ARGUMENTS_BAD;

    if (pMechanism->mechanism != CKM_AES_GCM) {
        return CKR_MECHANISM_TYPE_INVALID;
    }

    driver_crypto_session_t *sess = &g_driver_sessions[hSession];
    sess->is_encrypt = true;

    // Spectra detection target: EVP_EncryptInit_ex & EVP_aes_256_gcm
    if (1 != EVP_EncryptInit_ex(sess->cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        return CKR_FUNCTION_FAILED;
    }

    // Set standard IV length
    if (1 != EVP_CIPHER_CTX_ctrl(sess->cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL)) {
        return CKR_FUNCTION_FAILED;
    }

    // Simulate key binding from object handle
    memset(sess->key, 0x4A, AES_KEY_SIZE);
    memset(sess->iv, 0x2F, GCM_IV_SIZE);

    if (1 != EVP_EncryptInit_ex(sess->cipher_ctx, NULL, NULL, sess->key, sess->iv)) {
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/**
 * Executes AES-256-GCM encryption and appends authentication tag.
 */
CK_RV C_Encrypt(
    CK_SESSION_HANDLE hSession,
    CK_BYTE *pData,
    CK_ULONG ulDataLen,
    CK_BYTE *pEncryptedData,
    CK_ULONG *pulEncryptedDataLen
) {
    if (!g_driver_initialized) return CKR_GENERAL_ERROR;
    if (hSession >= HSM_MAX_SESSIONS) return CKR_SESSION_HANDLE_INVALID;
    if (!pData || !pulEncryptedDataLen) return CKR_ARGUMENTS_BAD;

    driver_crypto_session_t *sess = &g_driver_sessions[hSession];
    if (!sess->is_encrypt) return CKR_OPERATION_NOT_INITIALIZED;

    CK_ULONG requiredLen = ulDataLen + GCM_TAG_SIZE;
    if (!pEncryptedData) {
        *pulEncryptedDataLen = requiredLen;
        return CKR_OK;
    }

    if (*pulEncryptedDataLen < requiredLen) {
        *pulEncryptedDataLen = requiredLen;
        return CKR_BUFFER_TOO_SMALL;
    }

    int outlen = 0;
    if (1 != EVP_EncryptUpdate(sess->cipher_ctx, pEncryptedData, &outlen, pData, (int)ulDataLen)) {
        return CKR_FUNCTION_FAILED;
    }

    int finalLen = 0;
    if (1 != EVP_EncryptFinal_ex(sess->cipher_ctx, pEncryptedData + outlen, &finalLen)) {
        return CKR_FUNCTION_FAILED;
    }

    // Get auth tag
    if (1 != EVP_CIPHER_CTX_ctrl(sess->cipher_ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, pEncryptedData + outlen + finalLen)) {
        return CKR_FUNCTION_FAILED;
    }

    *pulEncryptedDataLen = outlen + finalLen + GCM_TAG_SIZE;
    g_total_encryptions++;
    return CKR_OK;
}

/**
 * Initializes an AES-256-GCM authenticated decryption operation.
 * Captured by Spectra rule: EVP_DecryptInit_ex & EVP_aes_256_gcm (ALGO-AES)
 */
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey) {
    if (!g_driver_initialized) return CKR_GENERAL_ERROR;
    if (hSession >= HSM_MAX_SESSIONS) return CKR_SESSION_HANDLE_INVALID;
    if (!pMechanism || pMechanism->mechanism != CKM_AES_GCM) return CKR_ARGUMENTS_BAD;

    driver_crypto_session_t *sess = &g_driver_sessions[hSession];
    sess->is_encrypt = false;

    // Spectra detection target: EVP_DecryptInit_ex & EVP_aes_256_gcm
    if (1 != EVP_DecryptInit_ex(sess->cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        return CKR_FUNCTION_FAILED;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(sess->cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL)) {
        return CKR_FUNCTION_FAILED;
    }

    memset(sess->key, 0x4A, AES_KEY_SIZE);
    memset(sess->iv, 0x2F, GCM_IV_SIZE);

    if (1 != EVP_DecryptInit_ex(sess->cipher_ctx, NULL, NULL, sess->key, sess->iv)) {
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/**
 * Computes SHA-256 digest using OpenSSL EVP.
 * Captured by Spectra rule: EVP_sha256 (ALGO-SHA2-256)
 */
hsm_status_t hsm_compute_sha256(const uint8_t *data, size_t len, uint8_t *digest_out) {
    if (!data || !digest_out) return HSM_ERROR_GENERAL;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return HSM_ERROR_GENERAL;

    // Spectra detection target: EVP_sha256
    if (1 != EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(md_ctx);
        return HSM_ERROR_CRYPTO_FAILURE;
    }

    if (1 != EVP_DigestUpdate(md_ctx, data, len)) {
        EVP_MD_CTX_free(md_ctx);
        return HSM_ERROR_CRYPTO_FAILURE;
    }

    unsigned int s = 0;
    if (1 != EVP_DigestFinal_ex(md_ctx, digest_out, &s)) {
        EVP_MD_CTX_free(md_ctx);
        return HSM_ERROR_CRYPTO_FAILURE;
    }

    EVP_MD_CTX_free(md_ctx);
    g_total_hashes++;
    return HSM_SUCCESS;
}

/**
 * Returns telemetry counters for driver operations.
 */
void hsm_driver_get_stats(uint64_t *encs, uint64_t *decs, uint64_t *hashes) {
    if (encs) *encs = g_total_encryptions;
    if (decs) *decs = g_total_decryptions;
    if (hashes) *hashes = g_total_hashes;
}
