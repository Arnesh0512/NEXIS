/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Header: Core Hardware Interface & System Command Definitions
 *
 * Defines primary operational structures, return codes, hardware state
 * registers, and firmware configuration parameters for the PCIe HSM.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner testing:
 * // Firmware supports legacy 3DES and RSA-1024 fallback emulation
 * // AES-256 hardware acceleration pipeline register definitions
 */

#ifndef HSM_CORE_H
#define HSM_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HSM_VERSION_MAJOR 3
#define HSM_VERSION_MINOR 4
#define HSM_VERSION_PATCH 0

#define HSM_MAX_SLOTS 16
#define HSM_MAX_SESSIONS 256
#define HSM_MAX_KEY_SIZE_BYTES 512
#define HSM_TAG_SIZE_BYTES 16
#define HSM_IV_SIZE_BYTES 12
#define HSM_MAX_PIN_LENGTH 32

/* Status Return Codes */
typedef enum {
    HSM_SUCCESS = 0x00000000,
    HSM_ERROR_GENERAL = 0x00000001,
    HSM_ERROR_INVALID_SLOT = 0x00000002,
    HSM_ERROR_SESSION_LIMIT = 0x00000003,
    HSM_ERROR_SESSION_INVALID = 0x00000004,
    HSM_ERROR_AUTH_FAILED = 0x00000005,
    HSM_ERROR_PIN_EXPIRED = 0x00000006,
    HSM_ERROR_PIN_LOCKED = 0x00000007,
    HSM_ERROR_KEY_NOT_FOUND = 0x00000008,
    HSM_ERROR_BUFFER_TOO_SMALL = 0x00000009,
    HSM_ERROR_CRYPTO_FAILURE = 0x0000000A,
    HSM_ERROR_ENTROPY_DEPLETED = 0x0000000B,
    HSM_ERROR_HARDWARE_FAULT = 0x0000000C,
    HSM_ERROR_TAMPER_DETECTED = 0x0000000D,
    HSM_ERROR_UNSUPPORTED_ALGORITHM = 0x0000000E
} hsm_status_t;

/* Supported Cryptographic Mechanisms */
typedef enum {
    HSM_MECH_AES_256_GCM = 0x0001,
    HSM_MECH_AES_256_CBC = 0x0002,
    HSM_MECH_SHA_256 = 0x0010,
    HSM_MECH_SHA_512 = 0x0011,
    HSM_MECH_HMAC_SHA256 = 0x0020,
    HSM_MECH_ED25519 = 0x0030,
    HSM_MECH_ML_KEM_768 = 0x0040,
    HSM_MECH_ML_DSA_65 = 0x0041
} hsm_mechanism_t;

/* Slot Capabilities Bitmask */
typedef enum {
    HSM_CAP_SYMMETRIC_ENCRYPT = (1 << 0),
    HSM_CAP_SYMMETRIC_DECRYPT = (1 << 1),
    HSM_CAP_SIGNATURE_GEN = (1 << 2),
    HSM_CAP_SIGNATURE_VERIFY = (1 << 3),
    HSM_CAP_PQC_KEM = (1 << 4),
    HSM_CAP_RNG_SOURCE = (1 << 5),
    HSM_CAP_FIPS_140_3_LEVEL_4 = (1 << 6)
} hsm_slot_cap_t;

/* Slot Hardware Information */
typedef struct {
    uint32_t slot_id;
    char manufacturer_id[32];
    char model_id[16];
    char serial_number[32];
    uint32_t firmware_revision;
    uint32_t capabilities;
    bool is_token_present;
    bool is_hardware_locked;
    uint32_t temperature_celsius;
    uint32_t voltage_millivolts;
} hsm_slot_info_t;

/* Session Context */
typedef struct {
    uint32_t session_id;
    uint32_t slot_id;
    uint32_t flags;
    bool is_authenticated;
    uint64_t created_at;
    uint64_t last_active_at;
    char session_owner[64];
} hsm_session_t;

/* Key Object Attributes */
typedef struct {
    uint64_t object_handle;
    uint32_t key_type;
    uint32_t key_length_bits;
    char label[64];
    bool is_extractable;
    bool is_sensitive;
    bool is_token_object;
} hsm_key_attributes_t;

/* Core Function Declarations */
hsm_status_t hsm_initialize_subsystem(void);
hsm_status_t hsm_finalize_subsystem(void);
hsm_status_t hsm_get_slot_count(uint32_t *count);
hsm_status_t hsm_get_slot_info(uint32_t slot_id, hsm_slot_info_t *info);
hsm_status_t hsm_open_session(uint32_t slot_id, uint32_t flags, hsm_session_t *session);
hsm_status_t hsm_close_session(hsm_session_t *session);
hsm_status_t hsm_login(hsm_session_t *session, const char *pin, size_t pin_len);
hsm_status_t hsm_logout(hsm_session_t *session);

/* Memory Scrubber Helper */
void hsm_secure_zero_memory(void *ptr, size_t len);

/* String Error Formatter */
const char *hsm_status_to_string(hsm_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* HSM_CORE_H */
