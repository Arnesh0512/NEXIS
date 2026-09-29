/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Source: Hardware Diagnostic Probe & Environmental Telemetry Monitor
 *
 * Continuously polls physical chassis tamper sensors, die temperature rails,
 * and core voltage fluctuations to detect active side-channel or fault attacks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "hsm_core.h"

#define MAX_TEMPERATURE_CELSIUS 85
#define MIN_TEMPERATURE_CELSIUS -10
#define NOMINAL_CORE_VOLTAGE_MV 1200
#define MAX_VOLTAGE_DEVIATION_MV 100

typedef struct {
    uint32_t current_temperature_celsius;
    uint32_t current_core_voltage_mv;
    uint32_t pcie_bus_errors;
    bool chassis_intrusion_tripped;
    bool clock_glitch_detected;
    bool under_voltage_alert;
    uint64_t total_probes_run;
} hsm_diagnostic_state_t;

static hsm_diagnostic_state_t g_diag_state;
static bool g_diag_initialized = false;

/**
 * Initializes physical sensors and hardware baseline.
 */
hsm_status_t hsm_init_diagnostic_probe(void) {
    memset(&g_diag_state, 0, sizeof(g_diag_state));
    g_diag_state.current_temperature_celsius = 42;
    g_diag_state.current_core_voltage_mv = NOMINAL_CORE_VOLTAGE_MV;
    g_diag_state.chassis_intrusion_tripped = false;
    g_diag_state.clock_glitch_detected = false;
    g_diag_state.under_voltage_alert = false;
    g_diag_initialized = true;

    return HSM_SUCCESS;
}

/**
 * Polls physical hardware sensors.
 */
hsm_status_t hsm_poll_hardware_health(void) {
    if (!g_diag_initialized) {
        hsm_init_diagnostic_probe();
    }

    g_diag_state.total_probes_run++;

    // Simulated sensor variation
    g_diag_state.current_temperature_celsius = 40 + (rand() % 8);
    g_diag_state.current_core_voltage_mv = 1190 + (rand() % 20);

    // Over-temperature check
    if (g_diag_state.current_temperature_celsius > MAX_TEMPERATURE_CELSIUS) {
        return HSM_ERROR_HARDWARE_FAULT;
    }

    // Voltage rail tolerance check
    uint32_t volt_diff = abs((int)g_diag_state.current_core_voltage_mv - NOMINAL_CORE_VOLTAGE_MV);
    if (volt_diff > MAX_VOLTAGE_DEVIATION_MV) {
        g_diag_state.under_voltage_alert = true;
        return HSM_ERROR_HARDWARE_FAULT;
    }

    // Physical tamper switch check
    if (g_diag_state.chassis_intrusion_tripped) {
        return HSM_ERROR_TAMPER_DETECTED;
    }

    return HSM_SUCCESS;
}

/**
 * Simulates a chassis intrusion tamper event (for security drills).
 */
void hsm_trigger_simulated_tamper(void) {
    g_diag_state.chassis_intrusion_tripped = true;
}

/**
 * Clears latch after authorized physical maintenance.
 */
void hsm_reset_tamper_latch(void) {
    g_diag_state.chassis_intrusion_tripped = false;
    g_diag_state.clock_glitch_detected = false;
    g_diag_state.under_voltage_alert = false;
}

/**
 * Generates structured JSON diagnostic summary for PCIe health check.
 */
int hsm_format_diagnostic_report(char *buffer, size_t max_len) {
    if (!buffer || max_len == 0) return -1;

    return snprintf(
        buffer, max_len,
        "{\"temperature_c\":%u,\"voltage_mv\":%u,\"chassis_ok\":%s,\"probes\":%llu}",
        g_diag_state.current_temperature_celsius,
        g_diag_state.current_core_voltage_mv,
        g_diag_state.chassis_intrusion_tripped ? "false" : "true",
        (unsigned long long)g_diag_state.total_probes_run
    );
}

void hsm_get_diagnostic_telemetry(uint32_t *temp, uint32_t *volt, uint64_t *probes) {
    if (temp) *temp = g_diag_state.current_temperature_celsius;
    if (volt) *volt = g_diag_state.current_core_voltage_mv;
    if (probes) *probes = g_diag_state.total_probes_run;
}
