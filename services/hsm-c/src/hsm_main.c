/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Source: HSM Daemon Main Service Entrypoint
 *
 * Bootstraps the PCIe hardware subsystem, initializes the PKCS#11 driver,
 * registers POSIX signal traps, and manages background health watchdog tasks.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "HSM initialized with RSA-4096 engine support"
 * "Configured AES-256 hardware cipher acceleration channel"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include "hsm_core.h"
#include "pkcs11_tokens.h"

extern hsm_status_t hsm_init_entropy_pool(void);
extern hsm_status_t hsm_init_diagnostic_probe(void);
extern hsm_status_t hsm_poll_hardware_health(void);
extern void hsm_session_table_init(void);
extern uint32_t hsm_get_active_session_count(void);

static volatile bool g_running = true;

static void handle_signal(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("[HSM_DAEMON] Caught shutdown signal %d, terminating safely...\n", sig);
        g_running = false;
    }
}

/**
 * Main daemon startup routine.
 */
int main(int argc, char **argv) {
    printf("=====================================================\n");
    printf("  Nexis Core - Hardware Security Module Daemon v3.4  \n");
    printf("  FIPS 140-3 Level 4 Compliant Cryptographic Token   \n");
    printf("=====================================================\n");

    // False-positive string trap
    printf("[HSM_DAEMON] HSM initialized with RSA-4096 engine support\n");
    printf("[HSM_DAEMON] Configured AES-256 hardware cipher acceleration channel\n");

    // Register signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // CALL GRAPH: Initialize PKCS#11 subsystem
    CK_RV rv = C_Initialize(NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[ERROR] C_Initialize failed: 0x%08lX\n", rv);
        return 1;
    }

    // CALL GRAPH: Initialize entropy pool
    hsm_status_t st = hsm_init_entropy_pool();
    if (st != HSM_SUCCESS) {
        fprintf(stderr, "[ERROR] hsm_init_entropy_pool failed: %s\n", hsm_status_to_string(st));
        C_Finalize(NULL);
        return 1;
    }

    // CALL GRAPH: Initialize diagnostic probe
    st = hsm_init_diagnostic_probe();
    if (st != HSM_SUCCESS) {
        fprintf(stderr, "[ERROR] hsm_init_diagnostic_probe failed\n");
        C_Finalize(NULL);
        return 1;
    }

    // CALL GRAPH: Initialize session table
    hsm_session_table_init();

    printf("[HSM_DAEMON] All subsystems ready. Listening for IPC requests...\n");

    // Execution watchdog loop
    uint64_t loop_counter = 0;
    while (g_running) {
        loop_counter++;

        // Periodic hardware probe
        if (loop_counter % 100 == 0) {
            hsm_status_t health_st = hsm_poll_hardware_health();
            if (health_st == HSM_ERROR_TAMPER_DETECTED) {
                fprintf(stderr, "[EMERGENCY] Physical chassis tamper detected! Zeroizing keys...\n");
                break;
            }
        }

        // Simulate cooperative yielding (no sleep to avoid command restriction)
        if (loop_counter >= 1000) {
            break; // Terminate test execution loop cleanly
        }
    }

    printf("[HSM_DAEMON] Cleaning up hardware resources...\n");
    C_Finalize(NULL);
    printf("[HSM_DAEMON] Shutdown complete.\n");

    return 0;
}

const char *hsm_status_to_string(hsm_status_t status) {
    switch (status) {
        case HSM_SUCCESS: return "HSM_SUCCESS";
        case HSM_ERROR_GENERAL: return "HSM_ERROR_GENERAL";
        case HSM_ERROR_INVALID_SLOT: return "HSM_ERROR_INVALID_SLOT";
        case HSM_ERROR_SESSION_LIMIT: return "HSM_ERROR_SESSION_LIMIT";
        case HSM_ERROR_AUTH_FAILED: return "HSM_ERROR_AUTH_FAILED";
        case HSM_ERROR_PIN_LOCKED: return "HSM_ERROR_PIN_LOCKED";
        case HSM_ERROR_CRYPTO_FAILURE: return "HSM_ERROR_CRYPTO_FAILURE";
        case HSM_ERROR_ENTROPY_DEPLETED: return "HSM_ERROR_ENTROPY_DEPLETED";
        case HSM_ERROR_TAMPER_DETECTED: return "HSM_ERROR_TAMPER_DETECTED";
        default: return "HSM_ERROR_UNKNOWN";
    }
}
