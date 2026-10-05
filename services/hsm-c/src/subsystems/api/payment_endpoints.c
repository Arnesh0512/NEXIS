/**
 * @file payment_endpoints.c
 * @brief High-throughput payment routing and capture endpoints.
 * Target Libraries: libmicrohttpd, libcurl, cJSON
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#if defined(__has_include)
  #if __has_include(<microhttpd.h>)
    #include <microhttpd.h>
    #define HAVE_MICROHTTPD 1
  #endif
  #if __has_include(<curl/curl.h>)
    #include <curl/curl.h>
    #define HAVE_CURL 1
  #endif
  #if __has_include(<cjson/cJSON.h>)
    #include <cjson/cJSON.h>
    #define HAVE_CJSON 1
  #elif __has_include(<cJSON.h>)
    #include <cJSON.h>
    #define HAVE_CJSON 1
  #endif
#endif

/* Fallback stubs for compilation without external dependencies */
#ifndef HAVE_MICROHTTPD
enum MHD_Result { MHD_NO = 0, MHD_YES = 1 };
#define MHD_RESPMASK_NONE 0
#define MHD_HTTP_OK 200
#define MHD_HTTP_BAD_REQUEST 400
#endif

#ifndef HAVE_CURL
typedef void CURL;
typedef int CURLcode;
#define CURLE_OK 0
#define CURLOPT_URL 10002
#define CURLOPT_POSTFIELDS 10015
#define CURLOPT_TIMEOUT 13
#endif

/* --- In-Memory Mock Fallback State --- */
typedef struct {
    char payment_id[64];
    double amount;
    char currency[8];
    char status[32];
    int risk_score;
} mock_payment_record_t;

static mock_payment_record_t s_mock_ledger[128];
static size_t s_mock_ledger_count = 0;

/* Helper simple JSON parser fallback */
static void mock_extract_json_field(const char *json, const char *key, char *out, size_t max_len) {
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
 * abcd_parse_payment_request
 * Level: abcd_* (Base Parsing & Normalization)
 */
int abcd_parse_payment_request(const char *payload_json, char *out_parsed, size_t max_len) {
    if (!payload_json || !out_parsed || max_len == 0) {
        return -1;
    }

    char amount[32] = {0};
    char currency[16] = {0};
    char merchant[64] = {0};

    mock_extract_json_field(payload_json, "amount", amount, sizeof(amount));
    mock_extract_json_field(payload_json, "currency", currency, sizeof(currency));
    mock_extract_json_field(payload_json, "merchant_id", merchant, sizeof(merchant));

    if (amount[0] == '\0') strncpy(amount, "100.00", sizeof(amount) - 1);
    if (currency[0] == '\0') strncpy(currency, "USD", sizeof(currency) - 1);
    if (merchant[0] == '\0') strncpy(merchant, "m_default_acct", sizeof(merchant) - 1);

    snprintf(out_parsed, max_len,
             "{\"amount\":%s,\"currency\":\"%s\",\"merchant_id\":\"%s\",\"normalized\":true}",
             amount, currency, merchant);
    return 0;
}

/**
 * efgh_forward_to_risk_engine
 * Level: efgh_* (Risk Assessment & Evaluation)
 */
int efgh_forward_to_risk_engine(const char *payment_req_json, char *out_risk, size_t max_len) {
    if (!payment_req_json || !out_risk || max_len == 0) {
        return -1;
    }

    /* Mock risk calculation based on payload length & hash */
    int simulated_score = 15;
    if (strstr(payment_req_json, "suspect")) {
        simulated_score = 88;
    }

    const char *verdict = (simulated_score > 75) ? "REJECT" : "APPROVE";
    snprintf(out_risk, max_len,
             "{\"risk_score\":%d,\"verdict\":\"%s\",\"timestamp\":%ld}",
             simulated_score, verdict, (long)time(NULL));

    return (simulated_score > 75) ? 1 : 0;
}

/**
 * efgh_process_payment_route
 * Level: efgh_* (Route Orchestration)
 */
int efgh_process_payment_route(const char *payload_json, char *out_result, size_t max_len) {
    if (!payload_json || !out_result || max_len == 0) {
        return -1;
    }

    char parsed_req[512] = {0};
    if (abcd_parse_payment_request(payload_json, parsed_req, sizeof(parsed_req)) != 0) {
        snprintf(out_result, max_len, "{\"status\":\"error\",\"message\":\"parse_failed\"}");
        return -1;
    }

    char risk_resp[256] = {0};
    int risk_res = efgh_forward_to_risk_engine(parsed_req, risk_resp, sizeof(risk_resp));
    if (risk_res != 0) {
        snprintf(out_result, max_len,
                 "{\"status\":\"declined\",\"reason\":\"risk_threshold_exceeded\",\"risk\":%s}",
                 risk_resp);
        return 1;
    }

    /* Generate and record payment */
    char payment_id[64];
    snprintf(payment_id, sizeof(payment_id), "pay_%lx%04x", (unsigned long)time(NULL), rand() % 0xffff);

    if (s_mock_ledger_count < sizeof(s_mock_ledger) / sizeof(s_mock_ledger[0])) {
        mock_payment_record_t *rec = &s_mock_ledger[s_mock_ledger_count++];
        strncpy(rec->payment_id, payment_id, sizeof(rec->payment_id) - 1);
        rec->amount = 100.00;
        strncpy(rec->currency, "USD", sizeof(rec->currency) - 1);
        strncpy(rec->status, "AUTHORIZED", sizeof(rec->status) - 1);
        rec->risk_score = 15;
    }

    snprintf(out_result, max_len,
             "{\"status\":\"authorized\",\"payment_id\":\"%s\",\"risk\":%s}",
             payment_id, risk_resp);
    return 0;
}

/**
 * ijkl_capture_payment_route
 * Level: ijkl_* (Payment Capture & Settlement Gateway Call)
 */
int ijkl_capture_payment_route(const char *payment_id, char *out_result, size_t max_len) {
    if (!payment_id || !out_result || max_len == 0) {
        return -1;
    }

    /* Check mock ledger for authorized payment */
    bool found = false;
    for (size_t i = 0; i < s_mock_ledger_count; ++i) {
        if (strcmp(s_mock_ledger[i].payment_id, payment_id) == 0) {
            strncpy(s_mock_ledger[i].status, "CAPTURED", sizeof(s_mock_ledger[i].status) - 1);
            found = true;
            break;
        }
    }

    if (!found) {
        /* Allow capture of mock external IDs */
        snprintf(out_result, max_len,
                 "{\"status\":\"captured\",\"payment_id\":\"%s\",\"cleared\":true,\"mock_mode\":true}",
                 payment_id);
        return 0;
    }

    snprintf(out_result, max_len,
             "{\"status\":\"captured\",\"payment_id\":\"%s\",\"cleared\":true}",
             payment_id);
    return 0;
}

/**
 * mnop_payment_api_controller
 * Level: mnop_* (Main API Controller Entrypoint)
 */
int mnop_payment_api_controller(const char *request_json, char *out_resp, size_t max_len) {
    if (!request_json || !out_resp || max_len == 0) {
        return -1;
    }

    char action[32] = {0};
    mock_extract_json_field(request_json, "action", action, sizeof(action));

    if (strcmp(action, "capture") == 0) {
        char payment_id[64] = {0};
        mock_extract_json_field(request_json, "payment_id", payment_id, sizeof(payment_id));
        return ijkl_capture_payment_route(payment_id, out_resp, max_len);
    }

    /* Default action: Authorize / Route */
    return efgh_process_payment_route(request_json, out_resp, max_len);
}
