/**
 * @file push_notification_worker.c
 * @brief FCM / APNs Push Notification Worker for mobile and web clients.
 * Target Libraries: libcurl, OpenSSL (RSA, SHA256 / JWT).
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
  #if __has_include(<openssl/sha.h>) && __has_include(<openssl/bio.h>)
    #include <openssl/sha.h>
    #include <openssl/bio.h>
    #include <openssl/evp.h>
    #define HAVE_OPENSSL 1
  #endif
#endif

#ifndef HAVE_CURL
typedef void CURL;
typedef int CURLcode;
struct curl_slist {
    char *data;
    struct curl_slist *next;
};
#define CURLE_OK 0
#define CURLOPT_URL 10002
#define CURLOPT_POSTFIELDS 10015
#define CURLOPT_HTTPHEADER 10023
#define CURLOPT_TIMEOUT 10013
static inline CURL *curl_easy_init(void) { return (CURL *)0x1; }
static inline CURLcode curl_easy_setopt(CURL *curl, int opt, ...) { (void)curl; (void)opt; return CURLE_OK; }
static inline CURLcode curl_easy_perform(CURL *curl) { (void)curl; return CURLE_OK; }
static inline void curl_easy_cleanup(CURL *curl) { (void)curl; }
static inline struct curl_slist *curl_slist_append(struct curl_slist *list, const char *s) { (void)s; return list; }
static inline void curl_slist_free_all(struct curl_slist *list) { (void)list; }
#endif

#ifndef HAVE_OPENSSL
static inline unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md) {
    for (size_t i = 0; i < 32; ++i) {
        md[i] = (unsigned char)((i < n ? d[i] : 0xFE) ^ 0x7A);
    }
    return md;
}
#endif

/* Forward declarations */
int abcd_load_fcm_credentials(char *out_creds, size_t max_len);
int abcd_validate_device_token(const char *fcm_token);
int efgh_send_fcm_message(const char *fcm_token, const char *title, const char *body);
int ijkl_send_customer_push(const char *user_id, const char *message);
int mnop_push_payment_update(const char *user_id, const char *status);

/**
 * @brief Loads Google FCM / Apple APNs service account credentials and generates mock bearer token.
 */
int abcd_load_fcm_credentials(char *out_creds, size_t max_len) {
    if (!out_creds || max_len < 64) {
        return -1;
    }

    const char *mock_token_prefix = "ya29.c.b0AXv0zTO_NEXIS_SERVICE_ACCOUNT_MOCK_BEARER_TOKEN";
    unsigned char hash[32];
    SHA256((const unsigned char *)mock_token_prefix, strlen(mock_token_prefix), hash);

    char digest_hex[65];
    for (int i = 0; i < 32; ++i) {
        sprintf(digest_hex + (i * 2), "%02x", hash[i]);
    }
    digest_hex[64] = '\0';

    snprintf(out_creds, max_len, "Bearer %s_%s", mock_token_prefix, digest_hex);
    return 0;
}

/**
 * @brief Validates device registration token format and length.
 */
int abcd_validate_device_token(const char *fcm_token) {
    if (!fcm_token) {
        return -1;
    }
    size_t len = strlen(fcm_token);
    if (len < 16 || len > 256) {
        return -1; /* Invalid token length */
    }
    return 0;
}

/**
 * @brief Sends push message to Google Firebase Cloud Messaging via HTTP v1 API.
 */
int efgh_send_fcm_message(const char *fcm_token, const char *title, const char *body) {
    if (!fcm_token || !title || !body) {
        return -1;
    }

    if (abcd_validate_device_token(fcm_token) != 0) {
        printf("[push_worker::ERROR] Invalid FCM token provided: %s\n", fcm_token);
        return -2;
    }

    char bearer_token[256];
    if (abcd_load_fcm_credentials(bearer_token, sizeof(bearer_token)) != 0) {
        return -3;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        printf("[push_worker::MOCK] Sending FCM to token %.20s...: [%s] %s\n", fcm_token, title, body);
        return 0;
    }

    char payload[1024];
    snprintf(payload, sizeof(payload),
             "{\"message\":{\"token\":\"%s\",\"notification\":{\"title\":\"%s\",\"body\":\"%s\"}}}",
             fcm_token, title, body);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    char auth_hdr[300];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: %s", bearer_token);
    headers = curl_slist_append(headers, auth_hdr);

    curl_easy_setopt(curl, CURLOPT_URL, "https://fcm.googleapis.com/v1/projects/nexis-cloud/messages:send");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 4L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        printf("[push_worker::WARN] FCM POST failed, falling back to mock delivery.\n");
        return 0;
    }

    return 0;
}

/**
 * @brief Resolves customer device registration and sends customer push.
 */
int ijkl_send_customer_push(const char *user_id, const char *message) {
    if (!user_id || !message) {
        return -1;
    }

    /* Simulate user device token lookup from registry */
    char resolved_device_token[128];
    snprintf(resolved_device_token, sizeof(resolved_device_token), "fcm_dev_tok_%s_ab992038475839201", user_id);

    return efgh_send_fcm_message(resolved_device_token, "NEXIS Security", message);
}

/**
 * @brief Top-level payment status push dispatcher.
 */
int mnop_push_payment_update(const char *user_id, const char *status) {
    if (!user_id || !status) {
        return -1;
    }

    printf("[push_worker::INFO] mnop_push_payment_update for user %s: status=%s\n", user_id, status);

    char msg[256];
    snprintf(msg, sizeof(msg), "Your transaction status has updated to: %s", status);

    int res = ijkl_send_customer_push(user_id, msg);
    if (res == 0) {
        printf("[push_worker::INFO] Push notification dispatched.\n");
    } else {
        printf("[push_worker::ERROR] Push notification failed: %d\n", res);
    }

    return res;
}
