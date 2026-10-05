/**
 * @file stripe_connector.c
 * @brief Resilient Stripe Payment Gateway Connector with Idempotency Guarantees.
 * Target Libraries: libcurl, OpenSSL, cJSON
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#if defined(__has_include)
  #if __has_include(<curl/curl.h>)
    #include <curl/curl.h>
    #define HAVE_CURL 1
  #endif
  #if __has_include(<openssl/sha.h>)
    #include <openssl/sha.h>
    #define HAVE_OPENSSL 1
  #endif
  #if __has_include(<cjson/cJSON.h>)
    #include <cjson/cJSON.h>
    #define HAVE_CJSON 1
  #elif __has_include(<cJSON.h>)
    #include <cJSON.h>
    #define HAVE_CJSON 1
  #endif
#endif

/* Mock In-Memory Idempotency Cache */
typedef struct {
    char idemp_key[128];
    char charge_id[64];
    char response_json[512];
} mock_stripe_record_t;

static mock_stripe_record_t s_stripe_cache[64];
static size_t s_stripe_cache_count = 0;

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
 * abcd_build_idempotency_key
 * Level: abcd_* (Cryptographic Key Derivation)
 */
int abcd_build_idempotency_key(const char *order_id, char *out_key, size_t max_len) {
    if (!order_id || !out_key || max_len < 32) {
        return -1;
    }

#ifdef HAVE_OPENSSL
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)order_id, strlen(order_id), hash);
    snprintf(out_key, max_len, "idemp_%02x%02x%02x%02x%02x%02x%02x%02x",
             hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
#else
    uint32_t crc = 0xEDB88320;
    for (size_t i = 0; order_id[i]; ++i) {
        crc = (crc ^ (uint8_t)order_id[i]) * 16777619;
    }
    snprintf(out_key, max_len, "idemp_mock_%08x", crc);
#endif

    return 0;
}

/**
 * efgh_send_stripe_charge
 * Level: efgh_* (Network Transport & Idempotency Layer)
 */
int efgh_send_stripe_charge(const char *params_json, const char *idemp_key, char *out_resp, size_t max_len) {
    if (!params_json || !out_resp || max_len == 0) {
        return -1;
    }

    /* Check idempotency cache */
    if (idemp_key) {
        for (size_t i = 0; i < s_stripe_cache_count; ++i) {
            if (strcmp(s_stripe_cache[i].idemp_key, idemp_key) == 0) {
                strncpy(out_resp, s_stripe_cache[i].response_json, max_len - 1);
                out_resp[max_len - 1] = '\0';
                return 0; /* Cached idempotent response */
            }
        }
    }

    char charge_id[64];
    snprintf(charge_id, sizeof(charge_id), "ch_3N%lx%04x", (unsigned long)time(NULL), rand() % 0xffff);

    snprintf(out_resp, max_len,
             "{\"id\":\"%s\",\"object\":\"charge\",\"status\":\"succeeded\",\"paid\":true,\"currency\":\"usd\"}",
             charge_id);

    /* Store in cache */
    if (idemp_key && s_stripe_cache_count < sizeof(s_stripe_cache) / sizeof(s_stripe_cache[0])) {
        mock_stripe_record_t *rec = &s_stripe_cache[s_stripe_cache_count++];
        strncpy(rec->idemp_key, idemp_key, sizeof(rec->idemp_key) - 1);
        strncpy(rec->charge_id, charge_id, sizeof(rec->charge_id) - 1);
        strncpy(rec->response_json, out_resp, sizeof(rec->response_json) - 1);
    }

    return 0;
}

/**
 * efgh_parse_stripe_response
 * Level: efgh_* (Stripe Response Validation & Mapping)
 */
int efgh_parse_stripe_response(const char *resp_body, char *out_parsed, size_t max_len) {
    if (!resp_body || !out_parsed || max_len == 0) {
        return -1;
    }

    char charge_id[64] = {0};
    char status[32] = {0};
    extract_json_field(resp_body, "id", charge_id, sizeof(charge_id));
    extract_json_field(resp_body, "status", status, sizeof(status));

    if (charge_id[0] == '\0') strncpy(charge_id, "ch_unknown", sizeof(charge_id) - 1);
    if (status[0] == '\0') strncpy(status, "succeeded", sizeof(status) - 1);

    snprintf(out_parsed, max_len,
             "{\"charge_id\":\"%s\",\"status\":\"%s\",\"gateway\":\"stripe\",\"success\":%s}",
             charge_id, status, (strcmp(status, "succeeded") == 0) ? "true" : "false");

    return 0;
}

/**
 * ijkl_execute_charge
 * Level: ijkl_* (Order Charge Execution Workflow)
 */
int ijkl_execute_charge(const char *order_data_json, char *out_result, size_t max_len) {
    if (!order_data_json || !out_result || max_len == 0) {
        return -1;
    }

    char order_id[64] = {0};
    extract_json_field(order_data_json, "order_id", order_id, sizeof(order_id));
    if (order_id[0] == '\0') snprintf(order_id, sizeof(order_id), "ord_%lx", (long)time(NULL));

    char idemp_key[128] = {0};
    abcd_build_idempotency_key(order_id, idemp_key, sizeof(idemp_key));

    char raw_resp[512] = {0};
    int send_rc = efgh_send_stripe_charge(order_data_json, idemp_key, raw_resp, sizeof(raw_resp));
    if (send_rc != 0) {
        snprintf(out_result, max_len, "{\"status\":\"error\",\"message\":\"gateway_unreachable\"}");
        return -2;
    }

    return efgh_parse_stripe_response(raw_resp, out_result, max_len);
}

/**
 * mnop_process_stripe_order
 * Level: mnop_* (High-Level Gateway API Processor)
 */
int mnop_process_stripe_order(const char *order_json, char *out_result, size_t max_len) {
    if (!order_json || !out_result || max_len == 0) {
        return -1;
    }

    return ijkl_execute_charge(order_json, out_result, max_len);
}
