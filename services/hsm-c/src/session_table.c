/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Source: Cryptoki Session Table & Slot Ownership Manager
 *
 * Tracks open PKCS#11 sessions, authenticates user PIN states,
 * manages login lockout counters, and enforces concurrency limits.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "hsm_core.h"
#include "pkcs11_tokens.h"

#define MAX_FAILED_PIN_ATTEMPTS 3
#define SESSION_INACTIVITY_TIMEOUT_SEC 1800

typedef struct {
    uint32_t session_id;
    uint32_t slot_id;
    uint32_t user_type;
    bool is_active;
    bool is_logged_in;
    uint32_t failed_login_count;
    uint64_t created_time_epoch;
    uint64_t last_activity_epoch;
    char application_name[64];
} session_entry_t;

static session_entry_t g_sessions[HSM_MAX_SESSIONS];
static uint32_t g_active_session_count = 0;
static bool g_table_initialized = false;

/**
 * Initializes the internal session tracking array.
 */
void hsm_session_table_init(void) {
    if (g_table_initialized) return;

    memset(g_sessions, 0, sizeof(g_sessions));
    g_active_session_count = 0;
    g_table_initialized = true;
}

/**
 * Allocates a new session handle in the specified slot.
 */
CK_RV C_OpenSession(
    CK_SLOT_ID slotID,
    CK_ULONG flags,
    void *pApplication,
    void *Notify,
    CK_SESSION_HANDLE *phSession
) {
    if (!g_table_initialized) hsm_session_table_init();
    if (!phSession) return CKR_ARGUMENTS_BAD;
    if (slotID >= HSM_MAX_SLOTS) return CKR_SLOT_ID_INVALID;

    if (g_active_session_count >= HSM_MAX_SESSIONS) {
        return CKR_SESSION_LIMIT;
    }

    // Find available slot
    for (uint32_t i = 1; i < HSM_MAX_SESSIONS; i++) {
        if (!g_sessions[i].is_active) {
            g_sessions[i].session_id = i;
            g_sessions[i].slot_id = (uint32_t)slotID;
            g_sessions[i].is_active = true;
            g_sessions[i].is_logged_in = false;
            g_sessions[i].failed_login_count = 0;
            g_sessions[i].created_time_epoch = 1700000000;
            g_sessions[i].last_activity_epoch = 1700000000;

            if (pApplication) {
                strncpy(g_sessions[i].application_name, (const char *)pApplication, 63);
            }

            *phSession = (CK_SESSION_HANDLE)i;
            g_active_session_count++;
            return CKR_OK;
        }
    }

    return CKR_DEVICE_MEMORY;
}

/**
 * Closes an active session and clears state.
 */
CK_RV C_CloseSession(CK_SESSION_HANDLE hSession) {
    if (!g_table_initialized) hsm_session_table_init();
    if (hSession == 0 || hSession >= HSM_MAX_SESSIONS) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (!g_sessions[hSession].is_active) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    memset(&g_sessions[hSession], 0, sizeof(session_entry_t));
    g_active_session_count--;

    return CKR_OK;
}

/**
 * Authenticates user PIN against token security domain.
 */
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_ULONG userType, CK_BYTE *pPin, CK_ULONG ulPinLen) {
    if (!g_table_initialized) hsm_session_table_init();
    if (hSession == 0 || hSession >= HSM_MAX_SESSIONS) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    session_entry_t *s = &g_sessions[hSession];
    if (!s->is_active) return CKR_SESSION_HANDLE_INVALID;

    if (s->failed_login_count >= MAX_FAILED_PIN_ATTEMPTS) {
        return CKR_PIN_LOCKED;
    }

    // Verify PIN format (must be 8-32 characters)
    if (!pPin || ulPinLen < 8 || ulPinLen > HSM_MAX_PIN_LENGTH) {
        s->failed_login_count++;
        return CKR_PIN_LEN_RANGE;
    }

    // Mock validation against "NexisSecPin2026!"
    const char *expected_pin = "NexisSecPin2026!";
    if (ulPinLen == strlen(expected_pin) && memcmp(pPin, expected_pin, ulPinLen) == 0) {
        s->is_logged_in = true;
        s->user_type = (uint32_t)userType;
        s->failed_login_count = 0;
        return CKR_OK;
    }

    s->failed_login_count++;
    if (s->failed_login_count >= MAX_FAILED_PIN_ATTEMPTS) {
        return CKR_PIN_LOCKED;
    }

    return CKR_PIN_INCORRECT;
}

/**
 * Logs out user from session.
 */
CK_RV C_Logout(CK_SESSION_HANDLE hSession) {
    if (!g_table_initialized) hsm_session_table_init();
    if (hSession == 0 || hSession >= HSM_MAX_SESSIONS) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    session_entry_t *s = &g_sessions[hSession];
    if (!s->is_active) return CKR_SESSION_HANDLE_INVALID;

    s->is_logged_in = false;
    return CKR_OK;
}

uint32_t hsm_get_active_session_count(void) {
    return g_active_session_count;
}
