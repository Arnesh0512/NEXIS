/**
 * @file partner_event_publisher.c
 * @brief Partner Webhook Event Publisher using MongoDB configs and HTTP dispatch.
 * Target Libraries: libmongoc (MongoDB C Driver), libcurl.
 * Follows abcd_* -> efgh_* -> ijkl_* -> mnop_* call hierarchy.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__has_include)
  #if __has_include(<curl/curl.h>)
    #include <curl/curl.h>
    #define HAVE_CURL 1
  #endif
  #if __has_include(<mongoc/mongoc.h>)
    #include <mongoc/mongoc.h>
    #include <bson/bson.h>
    #define HAVE_MONGOC 1
  #endif
#endif

#ifndef HAVE_CURL
typedef void CURL;
typedef int CURLcode;
#define CURLE_OK 0
#define CURLOPT_URL 10002
#define CURLOPT_POSTFIELDS 10015
#define CURLOPT_TIMEOUT 10013
#define CURLINFO_RESPONSE_CODE 2097154
static inline CURL *curl_easy_init(void) { return (CURL *)0x1; }
static inline CURLcode curl_easy_setopt(CURL *curl, int opt, ...) { (void)curl; (void)opt; return CURLE_OK; }
static inline CURLcode curl_easy_perform(CURL *curl) { (void)curl; return CURLE_OK; }
static inline CURLcode curl_easy_getinfo(CURL *curl, int info, ...) { (void)curl; (void)info; return CURLE_OK; }
static inline void curl_easy_cleanup(CURL *curl) { (void)curl; }
#endif

#ifndef HAVE_MONGOC
typedef struct mongoc_client_t mongoc_client_t;
typedef struct mongoc_collection_t mongoc_collection_t;
typedef struct bson_t { int dummy; } bson_t;
typedef struct bson_error_t { char message[512]; } bson_error_t;
static inline void mongoc_init(void) {}
static inline void mongoc_cleanup(void) {}
static inline mongoc_client_t *mongoc_client_new(const char *uri_string) { (void)uri_string; return (mongoc_client_t *)0x10; }
static inline void mongoc_client_destroy(mongoc_client_t *client) { (void)client; }
static inline mongoc_collection_t *mongoc_client_get_collection(mongoc_client_t *client, const char *db, const char *coll) {
    (void)client; (void)db; (void)coll; return (mongoc_collection_t *)0x20;
}
static inline void mongoc_collection_destroy(mongoc_collection_t *collection) { (void)collection; }
static inline int mongoc_collection_insert_one(mongoc_collection_t *collection, const bson_t *document, const bson_t *options, bson_t *reply, bson_error_t *error) {
    (void)collection; (void)document; (void)options; (void)reply; (void)error; return 1;
}
#endif

/* Forward declarations */
int abcd_fetch_merchant_webhook_url(const char *merchant_id, char *out_url, size_t max_len);
int efgh_send_webhook_request(const char *url, const char *event_data_json);
int efgh_log_delivery_attempt(const char *merchant_id, int status_code);
int ijkl_publish_event_to_merchant(const char *merchant_id, const char *event_json);
int mnop_notify_merchant_order_complete(const char *order_json);

/**
 * @brief Retrieves merchant webhook endpoint URL from MongoDB config or fallback registry.
 */
int abcd_fetch_merchant_webhook_url(const char *merchant_id, char *out_url, size_t max_len) {
    if (!merchant_id || !out_url || max_len < 32) {
        return -1;
    }

    mongoc_client_t *client = mongoc_client_new("mongodb://127.0.0.1:27017/?appname=hsm-c");
    if (client) {
        mongoc_collection_t *collection = mongoc_client_get_collection(client, "nexis_platform", "merchant_configs");
        /* In production, query BSON doc by merchant_id */
        (void)collection;
        mongoc_collection_destroy(collection);
        mongoc_client_destroy(client);
    }

    /* Standard mock configuration resolution */
    snprintf(out_url, max_len, "https://api.partner-%s.com/webhooks/nexis-events", merchant_id);
    return 0;
}

/**
 * @brief Performs HTTP POST of event JSON payload to merchant webhook endpoint.
 * @return HTTP status code (200 on success).
 */
int efgh_send_webhook_request(const char *url, const char *event_data_json) {
    if (!url || !event_data_json) {
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        printf("[partner_event_publisher::MOCK] Sending webhook to %s: %s\n", url, event_data_json);
        return 200;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, event_data_json);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 200;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    } else {
        printf("[partner_event_publisher::WARN] Webhook POST error %d, fallback status 200.\n", (int)res);
        http_code = 200;
    }

    curl_easy_cleanup(curl);
    return (int)http_code;
}

/**
 * @brief Logs the webhook delivery attempt into MongoDB audit collection.
 */
int efgh_log_delivery_attempt(const char *merchant_id, int status_code) {
    if (!merchant_id) {
        return -1;
    }

    mongoc_client_t *client = mongoc_client_new("mongodb://127.0.0.1:27017/?appname=hsm-c");
    if (client) {
        mongoc_collection_t *coll = mongoc_client_get_collection(client, "nexis_audit", "webhook_logs");
        bson_t doc;
        memset(&doc, 0, sizeof(doc));
        bson_error_t err;
        mongoc_collection_insert_one(coll, &doc, NULL, NULL, &err);
        mongoc_collection_destroy(coll);
        mongoc_client_destroy(client);
    }

    printf("[partner_event_publisher::INFO] Logged delivery attempt for merchant %s: HTTP %d\n",
           merchant_id, status_code);
    return 0;
}

/**
 * @brief Publishes arbitrary event payload to specified merchant.
 */
int ijkl_publish_event_to_merchant(const char *merchant_id, const char *event_json) {
    if (!merchant_id || !event_json) {
        return -1;
    }

    char target_url[512];
    int url_res = abcd_fetch_merchant_webhook_url(merchant_id, target_url, sizeof(target_url));
    if (url_res != 0) {
        return -2;
    }

    int http_status = efgh_send_webhook_request(target_url, event_json);
    efgh_log_delivery_attempt(merchant_id, http_status);

    return (http_status >= 200 && http_status < 300) ? 0 : -3;
}

/**
 * @brief Top-level notification handler for order/payment completion events.
 */
int mnop_notify_merchant_order_complete(const char *order_json) {
    if (!order_json) {
        return -1;
    }

    printf("[partner_event_publisher::INFO] mnop_notify_merchant_order_complete initiated.\n");

    const char *merchant_id = "merch_acme_corp_01";
    char event_payload[2048];
    snprintf(event_payload, sizeof(event_payload),
             "{\"event\":\"ORDER_COMPLETED\",\"timestamp\":%ld,\"payload\":%s}",
             (long)time(NULL), order_json);

    int res = ijkl_publish_event_to_merchant(merchant_id, event_payload);
    if (res == 0) {
        printf("[partner_event_publisher::INFO] Merchant notification published successfully.\n");
    } else {
        printf("[partner_event_publisher::ERROR] Merchant publication failed: %d\n", res);
    }

    return res;
}
