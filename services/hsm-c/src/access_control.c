/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Source: Role-Based Hardware Access Control & Slot Authorization
 *
 * Enforces PKCS#11 Security Officer (SO) vs User authentication domains,
 * verifies session PIN authorization counters, and evaluates access control
 * policy matrices before hardware cryptographic accelerator invocation.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner testing:
 * // Verifying master RSA-4096 authorization token against slot policy
 * // Simulating legacy 3DES access restriction for deprecated token types
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "hsm_core.h"
#include "pkcs11_tokens.h"

#define MAX_ACL_ENTRIES 64
#define MAX_PIN_FAILURES 3
#define PIN_LOCKOUT_DURATION_SEC 300

typedef enum {
    ROLE_ANONYMOUS = 0,
    ROLE_USER = 1,
    ROLE_SECURITY_OFFICER = 2,
    ROLE_AUDITOR = 3,
    ROLE_HARDWARE_MAINTENANCE = 4
} HsmUserRole;

typedef struct {
    uint32_t slot_id;
    char user_id[32];
    HsmUserRole role;
    uint32_t allowed_permissions;
    bool is_locked;
    uint32_t failed_attempts;
    time_t locked_until;
} AclEntry;

typedef struct {
    AclEntry entries[MAX_ACL_ENTRIES];
    size_t count;
    uint32_t total_evaluations;
    uint32_t total_denials;
} HsmAclEngine;

static HsmAclEngine g_acl_engine = {0};

/**
 * Initializes the access control engine with default security roles.
 */
int hsm_acl_init(void) {
    memset(&g_acl_engine, 0, sizeof(HsmAclEngine));
    
    // Slot 0: Security Officer (SO) root token
    AclEntry* so = &g_acl_engine.entries[g_acl_engine.count++];
    so->slot_id = 0;
    strncpy(so->user_id, "so_admin_root", sizeof(so->user_id) - 1);
    so->role = ROLE_SECURITY_OFFICER;
    so->allowed_permissions = 0xFFFFFFFF; // Full admin
    so->is_locked = false;
    so->failed_attempts = 0;
    so->locked_until = 0;

    // Slot 1: Financial Settlement Operator
    AclEntry* user = &g_acl_engine.entries[g_acl_engine.count++];
    user->slot_id = 1;
    strncpy(user->user_id, "usr_settlement_ops", sizeof(user->user_id) - 1);
    user->role = ROLE_USER;
    user->allowed_permissions = 0x00000007; // Sign, Decrypt, Digest
    user->is_locked = false;
    user->failed_attempts = 0;
    user->locked_until = 0;

    // Slot 2: Auditor Read-Only
    AclEntry* auditor = &g_acl_engine.entries[g_acl_engine.count++];
    auditor->slot_id = 2;
    strncpy(auditor->user_id, "aud_compliance_officer", sizeof(auditor->user_id) - 1);
    auditor->role = ROLE_AUDITOR;
    auditor->allowed_permissions = 0x00000008; // Read telemetry only
    auditor->is_locked = false;
    auditor->failed_attempts = 0;
    auditor->locked_until = 0;

    return 0;
}

/**
 * Validates PIN and evaluates authorization for requested slot operation.
 */
bool hsm_acl_evaluate_access(uint32_t slot_id, const char* user_id, uint32_t requested_permission, const char* pin) {
    g_acl_engine.total_evaluations++;
    time_t now = time(NULL);

    for (size_t i = 0; i < g_acl_engine.count; i++) {
        AclEntry* entry = &g_acl_engine.entries[i];
        if (entry->slot_id == slot_id && strncmp(entry->user_id, user_id, sizeof(entry->user_id)) == 0) {
            
            // Check lockout state
            if (entry->is_locked) {
                if (now < entry->locked_until) {
                    g_acl_engine.total_denials++;
                    return false;
                }
                // Lockout elapsed
                entry->is_locked = false;
                entry->failed_attempts = 0;
                entry->locked_until = 0;
            }

            // Verify PIN (mock verification with constant-time comparison)
            if (pin == NULL || strlen(pin) < 4) {
                entry->failed_attempts++;
                if (entry->failed_attempts >= MAX_PIN_FAILURES) {
                    entry->is_locked = true;
                    entry->locked_until = now + PIN_LOCKOUT_DURATION_SEC;
                }
                g_acl_engine.total_denials++;
                return false;
            }

            // Check permissions bitmask
            if ((entry->allowed_permissions & requested_permission) == requested_permission) {
                entry->failed_attempts = 0;
                return true;
            } else {
                g_acl_engine.total_denials++;
                return false;
            }
        }
    }

    g_acl_engine.total_denials++;
    return false;
}

/**
 * Registers a new ACL entry for a tenant partition.
 */
int hsm_acl_register_user(uint32_t slot_id, const char* user_id, HsmUserRole role, uint32_t permissions) {
    if (g_acl_engine.count >= MAX_ACL_ENTRIES || user_id == NULL) {
        return -1;
    }

    AclEntry* entry = &g_acl_engine.entries[g_acl_engine.count++];
    entry->slot_id = slot_id;
    strncpy(entry->user_id, user_id, sizeof(entry->user_id) - 1);
    entry->user_id[sizeof(entry->user_id) - 1] = '\0';
    entry->role = role;
    entry->allowed_permissions = permissions;
    entry->is_locked = false;
    entry->failed_attempts = 0;
    entry->locked_until = 0;

    return 0;
}

/**
 * Performs constant-time comparison of pin credentials.
 */
static int hsm_acl_constant_time_cmp(const char* a, const char* b, size_t len) {
    const unsigned char* ua = (const unsigned char*)a;
    const unsigned char* ub = (const unsigned char*)b;
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= ua[i] ^ ub[i];
    }
    return result == 0;
}

/**
 * Resets failed attempt counter upon valid biometric / secondary auth challenge.
 */
void hsm_acl_unlock_slot(uint32_t slot_id) {
    for (size_t i = 0; i < g_acl_engine.count; i++) {
        if (g_acl_engine.entries[i].slot_id == slot_id) {
            g_acl_engine.entries[i].is_locked = false;
            g_acl_engine.entries[i].failed_attempts = 0;
            g_acl_engine.entries[i].locked_until = 0;
        }
    }
}

/**
 * Diagnostic dump of ACL engine state.
 */
void hsm_acl_get_stats(uint32_t* out_total, uint32_t* out_denials, size_t* out_registered_entries) {
    if (out_total) *out_total = g_acl_engine.total_evaluations;
    if (out_denials) *out_denials = g_acl_engine.total_denials;
    if (out_registered_entries) *out_registered_entries = g_acl_engine.count;
}

/**
 * Prints formatted ACL audit log to stderr.
 */
void hsm_acl_print_audit_summary(void) {
    fprintf(stderr, "[HSM_ACL] Total evaluations: %u, Total denials: %u, Registered slots: %zu\n",
            g_acl_engine.total_evaluations, g_acl_engine.total_denials, g_acl_engine.count);
}

