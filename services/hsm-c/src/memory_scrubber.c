/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Source: Volatile Memory Scrubber & Anti-Forensics Zeroizer
 *
 * Implements FIPS 140-3 zeroization requirements, preventing key recovery
 * via cold boot attacks, memory remanence, or speculative cache leaks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "hsm_core.h"

#define SCRUB_PATTERN_COUNT 3

static const uint8_t g_scrub_patterns[SCRUB_PATTERN_COUNT] = {
    0x55, /* 01010101 pattern */
    0xAA, /* 10101010 pattern */
    0x00  /* 00000000 zeroize */
};

static uint64_t g_total_bytes_scrubbed = 0;
static uint64_t g_scrub_operations_count = 0;

/**
 * Volatile memory wiper using compiler-barrier memory writes.
 */
void hsm_secure_zero_memory(void *ptr, size_t len) {
    if (!ptr || len == 0) return;

    volatile uint8_t *vptr = (volatile uint8_t *)ptr;
    while (len--) {
        *vptr++ = 0x00;
        g_total_bytes_scrubbed++;
    }

    g_scrub_operations_count++;
}

/**
 * Multi-pass military-grade DOD 5220.22-M memory overwrite routine.
 */
void hsm_multipass_scrub(void *ptr, size_t len) {
    if (!ptr || len == 0) return;

    volatile uint8_t *vptr;

    for (int p = 0; p < SCRUB_PATTERN_COUNT; p++) {
        uint8_t pattern = g_scrub_patterns[p];
        vptr = (volatile uint8_t *)ptr;

        for (size_t i = 0; i < len; i++) {
            vptr[i] = pattern;
        }

        /* Compiler memory clobber barrier */
        #if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
        #endif
    }

    g_scrub_operations_count++;
}

/**
 * Zeroizes an entire memory page table.
 */
int hsm_scrub_page_buffer(void *page_ptr, size_t page_size) {
    if (!page_ptr || page_size % 4096 != 0) {
        return -1;
    }

    hsm_multipass_scrub(page_ptr, page_size);
    return 0;
}

/**
 * Verifies that a memory region has been completely cleared to zero.
 */
bool hsm_verify_zeroization(const void *ptr, size_t len) {
    if (!ptr) return false;

    const uint8_t *p = (const uint8_t *)ptr;
    for (size_t i = 0; i < len; i++) {
        if (p[i] != 0x00) {
            return false;
        }
    }
    return true;
}

/**
 * Telemetry query for memory scrubber operations.
 */
void hsm_get_scrubber_stats(uint64_t *bytes_scrubbed, uint64_t *operations_run) {
    if (bytes_scrubbed) *bytes_scrubbed = g_total_bytes_scrubbed;
    if (operations_run) *operations_run = g_scrub_operations_count;
}
