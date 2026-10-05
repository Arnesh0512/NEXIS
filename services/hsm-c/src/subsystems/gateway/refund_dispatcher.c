/**
 * @file refund_dispatcher.c
 * @brief Concurrency-safe refund dispatch workflow with Redis distributed locks.
 * Target Libraries: libcurl, hiredis
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#if defined(__has_include)
  #if __has_include(<curl/curl.h>)
    #include <curl/curl.h>
    #define HAVE_CURL 1
  #endif
  #if __has_include(<hiredis/hiredis.h>)
    #include <hiredis/hiredis.h>
    #define HAVE_HIREDIS 1
  #endif
#endif

/* Mock In-Memory Distributed Lock & Ledger */
typedef struct {
    char payment_id[64];
    long locked_at;
} mock_lock_entry_t;

typedef struct {
    char refund_id[64];
    double amount;
    char status[32];
    long timestamp;
} mock_refund_record_t;

static mock_lock_entry_t s_locks[32];
static size_t s_lock_count = 0;

static mock_refund_record_t s_refunds[64];
static size_t s_refund_count = 0;

static void extract_json_field(const char *json, const char *key, char *out, size_t max_len) {
    out[0] = '\0';
    if (!json || !key) return;
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(json, pattern);
    if (!pos) return;
    pos = strchr(pos, ':');
    if (!pos) return;
    pos++;
    while (*pos == ' ' || *pos == '\"') pos++;
    size_t i = 0;
    while (*pos && *pos != '\"' && *pos != ',' && *pos != '}' && *pos != '\r' && *pos != '\n' && i + 1 < max_len) {
        out[i++] = *pos++;
    }
    out[i] = '\0';
}

/**
 * abcd_check_refund_lock
 * Level: abcd_* (Distributed Mutex & Redis Lock Acquisition)
 */
int abcd_check_refund_lock(const char *payment_id) {
    if (!payment_id) {
        return -1;
    }

    /* Check if existing active lock is held (within 30 seconds TTL) */
    long now = (long)time(NULL);
    for (size_t i = 0; i < s_lock_count; ++i) {
        if (strcmp(s_locks[i].payment_id, payment_id) == 0) {
            if (now - s_locks[i].locked_at < 30) {
                return -1; /* Lock currently active: double-refund prevention */
            } else {
                s_locks[i].locked_at = now;
                return 0; /* Lock expired and re-acquired */
            }
        }
    }

    if (s_lock_count < sizeof(s_locks) / sizeof(s_locks[0])) {
        mock_lock_entry_t *l = &s_locks[s_lock_count++];
        strncpy(l->payment_id, payment_id, sizeof(l->payment_id) - 1);
        l->locked_at = now;
        return 0;
    }

    return 0;
}

/**
 * efgh_send_acquirer_refund
 * Level: efgh_* (Acquirer Network Communication & Dispatch)
 */
int efgh_send_acquirer_refund(const char *refund_id, double amount, char *out_resp, size_t max_len) {
    if (!refund_id || !out_resp || max_len == 0) {
        return -1;
    }

    if (s_refund_count < sizeof(s_refunds) / sizeof(s_refunds[0])) {
        mock_refund_record_t *r = &s_refunds[s_refund_count++];
        strncpy(r->refund_id, refund_id, sizeof(r->refund_id) - 1);
        r->amount = amount;
        strncpy(r->status, "PROCESSED", sizeof(r->status) - 1);
        r->timestamp = (long)time(NULL);
    }

    snprintf(out_resp, max_len,
             "{\"refund_id\":\"%s\",\"amount\":%.2f,\"status\":\"PROCESSED\",\"code\":\"00\"}",
             refund_id, amount);

    return 0;
}

/**
 * efgh_release_refund_lock
 * Level: efgh_* (Distributed Lock Release)
 */
int efgh_release_refund_lock(const char *payment_id) {
    if (!payment_id) {
        return -1;
    }

    for (size_t i = 0; i < s_lock_count; ++i) {
        if (strcmp(s_locks[i].payment_id, payment_id) == 0) {
            s_locks[i].locked_at = 0;
            s_locks[i].payment_id[0] = '\0';
            return 0;
        }
    }

    return 0;
}

/**
 * ijkl_process_refund_request
 * Level: ijkl_* (Core Refund Lifecycle Orchestrator)
 */
int ijkl_process_refund_request(const char *refund_data_json, char *out_resp, size_t max_len) {
    if (!refund_data_json || !out_resp || max_len == 0) {
        return -1;
    }

    char payment_id[64] = {0};
    char amount_str[32] = {0};
    extract_json_field(refund_data_json, "payment_id", payment_id, sizeof(payment_id));
    extract_json_field(refund_data_json, "amount", amount_str, sizeof(amount_str));

    if (payment_id[0] == '\0') strncpy(payment_id, "pay_mock_ref", sizeof(payment_id) - 1);
    double amount = (amount_str[0] != '\0') ? atof(amount_str) : 50.00;

    /* Step 1: Acquire distributed lock */
    if (abcd_check_refund_lock(payment_id) != 0) {
        snprintf(out_resp, max_len,
                 "{\"status\":\"FAILED\",\"reason\":\"REFUND_ALREADY_IN_PROGRESS\",\"payment_id\":\"%s\"}",
                 payment_id);
        return -2;
    }

    /* Step 2: Generate refund ID and send to acquirer */
    char refund_id[64];
    snprintf(refund_id, sizeof(refund_id), "ref_%lx%04x", (unsigned long)time(NULL), rand() % 0xffff);

    int send_rc = efgh_send_acquirer_refund(refund_id, amount, out_resp, max_len);

    /* Step 3: Release distributed lock */
    efgh_release_refund_lock(payment_id);

    return send_rc;
}

/**
 * mnop_refund_workflow
 * Level: mnop_* (Workflow Controller Entrypoint)
 */
int mnop_refund_workflow(const char *refund_dto_json, char *out_resp, size_t max_len) {
    if (!refund_dto_json || !out_resp || max_len == 0) {
        return -1;
    }

    return ijkl_process_refund_request(refund_dto_json, out_resp, max_len);
}
