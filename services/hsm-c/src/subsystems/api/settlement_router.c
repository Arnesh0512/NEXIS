/**
 * @file settlement_router.c
 * @brief Multi-currency clearing and settlement routing engine.
 * Target Libraries: libcurl, libmicrohttpd
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
  #if __has_include(<microhttpd.h>)
    #include <microhttpd.h>
    #define HAVE_MICROHTTPD 1
  #endif
#endif

/* Fallbacks */
#ifndef HAVE_CURL
typedef void CURL;
#define CURLE_OK 0
#endif

#ifndef HAVE_MICROHTTPD
#define MHD_HTTP_OK 200
#define MHD_HTTP_BAD_REQUEST 400
#endif

/* Mock Clearing Queue */
typedef struct {
    char order_id[64];
    int route_id;
    double amount;
    char currency[8];
    long queued_at;
} mock_settlement_record_t;

static mock_settlement_record_t s_clearing_queue[128];
static size_t s_clearing_count = 0;

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
 * abcd_inspect_settlement_rules
 * Level: abcd_* (Rule Inspection & Corridor Assessment)
 */
int abcd_inspect_settlement_rules(double amount, const char *currency) {
    if (amount <= 0.0 || !currency) {
        return -1;
    }

    if (amount > 10000000.0) {
        return -2; /* Exceeds maximum clearing limit */
    }

    /* Route 101: Domestic USD (ACH / FedNow)
     * Route 102: SEPA EUR
     * Route 103: BACS / Faster Payments GBP
     * Route 104: Cross-border SWIFT
     */
    if (strcmp(currency, "USD") == 0) {
        return 101;
    } else if (strcmp(currency, "EUR") == 0) {
        return 102;
    } else if (strcmp(currency, "GBP") == 0) {
        return 103;
    } else {
        return 104;
    }
}

/**
 * efgh_dispatch_async_clearing
 * Level: efgh_* (Clearinghouse Transmission Dispatch)
 */
int efgh_dispatch_async_clearing(const char *order_id) {
    if (!order_id || order_id[0] == '\0') {
        return -1;
    }

#ifdef HAVE_CURL
    /* Optional cURL call to mock clearing house webhook */
    CURL *curl = curl_easy_init();
    if (curl) {
        /* Configured in real environment, safely cleanup */
        curl_easy_cleanup(curl);
    }
#endif

    return 0;
}

/**
 * efgh_route_settlement
 * Level: efgh_* (Route Resolution & Dispatch Integration)
 */
int efgh_route_settlement(const char *order_data_json) {
    if (!order_data_json) {
        return -1;
    }

    char amount_str[32] = {0};
    char currency[16] = {0};
    char order_id[64] = {0};

    extract_json_field(order_data_json, "amount", amount_str, sizeof(amount_str));
    extract_json_field(order_data_json, "currency", currency, sizeof(currency));
    extract_json_field(order_data_json, "order_id", order_id, sizeof(order_id));

    double amount = (amount_str[0] != '\0') ? atof(amount_str) : 250.00;
    if (currency[0] == '\0') strncpy(currency, "USD", sizeof(currency) - 1);
    if (order_id[0] == '\0') snprintf(order_id, sizeof(order_id), "ord_%lx", (long)time(NULL));

    int route_id = abcd_inspect_settlement_rules(amount, currency);
    if (route_id < 0) {
        return route_id;
    }

    int dispatch_rc = efgh_dispatch_async_clearing(order_id);
    if (dispatch_rc != 0) {
        return -3;
    }

    if (s_clearing_count < sizeof(s_clearing_queue) / sizeof(s_clearing_queue[0])) {
        mock_settlement_record_t *rec = &s_clearing_queue[s_clearing_count++];
        strncpy(rec->order_id, order_id, sizeof(rec->order_id) - 1);
        rec->route_id = route_id;
        rec->amount = amount;
        strncpy(rec->currency, currency, sizeof(rec->currency) - 1);
        rec->queued_at = (long)time(NULL);
    }

    return route_id;
}

/**
 * ijkl_execute_settlement_chain
 * Level: ijkl_* (Settlement Execution Pipeline)
 */
int ijkl_execute_settlement_chain(const char *order_data_json) {
    if (!order_data_json) {
        return -1;
    }

    int route_id = efgh_route_settlement(order_data_json);
    if (route_id < 0) {
        return route_id;
    }

    return 0;
}

/**
 * mnop_settlement_route_endpoint
 * Level: mnop_* (Public API Routing Controller)
 */
int mnop_settlement_route_endpoint(const char *req_json, char *out_resp, size_t max_len) {
    if (!req_json || !out_resp || max_len == 0) {
        return -1;
    }

    int rc = ijkl_execute_settlement_chain(req_json);
    if (rc == 0) {
        char order_id[64] = {0};
        extract_json_field(req_json, "order_id", order_id, sizeof(order_id));
        if (order_id[0] == '\0') strncpy(order_id, "ord_auto", sizeof(order_id) - 1);

        snprintf(out_resp, max_len,
                 "{\"status\":\"queued\",\"order_id\":\"%s\",\"settlement_state\":\"DISPATCHED\",\"code\":200}",
                 order_id);
        return 0;
    } else {
        snprintf(out_resp, max_len,
                 "{\"status\":\"error\",\"error_code\":%d,\"message\":\"Settlement routing failed\",\"code\":400}",
                 rc);
        return -1;
    }
}
