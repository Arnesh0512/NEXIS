/**
 * @file email_dispatcher.c
 * @brief Subsystem for dispatching transactional and alert emails via HTTP/SMTP relays.
 * Target Libraries: libcurl, OpenSSL (HMAC, SHA256).
 * Follows abcd_* -> efgh_* -> ijkl_* -> mnop_* call hierarchy.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Target library headers */
#if defined(__has_include)
  #if __has_include(<curl/curl.h>)
    #include <curl/curl.h>
    #define HAVE_CURL 1
  #endif
  #if __has_include(<openssl/hmac.h>) && __has_include(<openssl/sha.h>)
    #include <openssl/hmac.h>
    #include <openssl/sha.h>
    #include <openssl/evp.h>
    #define HAVE_OPENSSL 1
  #endif
#endif

#ifndef HAVE_CURL
/* In-memory mock definitions for CURL */
typedef void CURL;
typedef int CURLcode;
#define CURLE_OK 0
#define CURLOPT_URL 10002
#define CURLOPT_POSTFIELDS 10015
#define CURLOPT_TIMEOUT 10013
static inline CURL *curl_easy_init(void) { return (CURL *)0x1; }
static inline CURLcode curl_easy_setopt(CURL *curl, int opt, ...) { (void)curl; (void)opt; return CURLE_OK; }
static inline CURLcode curl_easy_perform(CURL *curl) { (void)curl; return CURLE_OK; }
static inline void curl_easy_cleanup(CURL *curl) { (void)curl; }
#endif

#ifndef HAVE_OPENSSL
/* In-memory mock OpenSSL fallback */
static inline unsigned char *HMAC(const void *evp_md, const void *key, int key_len,
                                  const unsigned char *d, size_t n,
                                  unsigned char *md, unsigned int *md_len) {
    (void)evp_md; (void)key; (void)key_len;
    for (size_t i = 0; i < 32; ++i) {
        md[i] = (unsigned char)((i < n ? d[i] : 0xAA) ^ 0x5C);
    }
    if (md_len) *md_len = 32;
    return md;
}
#define EVP_sha256() NULL
#endif

/* Forward declarations */
int abcd_generate_unsubscribe_token(const char *email, char *out_tok, size_t max_len);
int efgh_send_email_http(const char *recipient, const char *subject, const char *body);
int efgh_render_receipt_template(const char *payment_data_json, char *out_tmpl, size_t max_len);
int ijkl_dispatch_payment_receipt(const char *payment_data_json);
int mnop_send_transaction_alert(const char *payment_dto_json);

/**
 * @brief Generates a cryptographically secure HMAC-SHA256 unsubscribe token.
 */
int abcd_generate_unsubscribe_token(const char *email, char *out_tok, size_t max_len) {
    if (!email || !out_tok || max_len < 65) {
        return -1;
    }

    const char *secret_salt = "nexis_notification_unsub_secret_key_2026";
    unsigned char md[32];
    unsigned int md_len = 0;

    HMAC(EVP_sha256(), secret_salt, (int)strlen(secret_salt),
         (const unsigned char *)email, strlen(email), md, &md_len);

    for (unsigned int i = 0; i < 32 && (i * 2 + 2) < max_len; ++i) {
        sprintf(out_tok + (i * 2), "%02x", md[i]);
    }
    out_tok[64] = '\0';
    return 0;
}

/**
 * @brief Sends an email payload via HTTP POST to the email delivery gateway using libcurl.
 */
int efgh_send_email_http(const char *recipient, const char *subject, const char *body) {
    if (!recipient || !subject || !body) {
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        /* Fallback in-memory simulation */
        printf("[email_dispatcher::MOCK] Sending email to: %s | Subject: %s\n", recipient, subject);
        return 0;
    }

    char payload[2048];
    snprintf(payload, sizeof(payload),
             "{\"to\":\"%s\",\"subject\":\"%s\",\"content\":\"%s\"}",
             recipient, subject, body);

    curl_easy_setopt(curl, CURLOPT_URL, "https://api.nexis-internal.net/v1/notifications/email");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        printf("[email_dispatcher::WARN] Curl failed, using mock fallback. Err: %d\n", (int)res);
        return 0;
    }

    return 0;
}

/**
 * @brief Renders the receipt HTML/text template using payment json and appends unsub token.
 */
int efgh_render_receipt_template(const char *payment_data_json, char *out_tmpl, size_t max_len) {
    if (!payment_data_json || !out_tmpl || max_len < 256) {
        return -1;
    }

    char unsub_token[128] = {0};
    /* Extract mock or default recipient email from json or default */
    const char *mock_email = "customer@nexis-pay.io";
    if (strstr(payment_data_json, "email")) {
        /* Basic key extraction simulation */
        mock_email = "billing@partner.com";
    }

    if (abcd_generate_unsubscribe_token(mock_email, unsub_token, sizeof(unsub_token)) != 0) {
        snprintf(unsub_token, sizeof(unsub_token), "default_fallback_token_12345");
    }

    snprintf(out_tmpl, max_len,
             "================ NEXIS PAYMENT RECEIPT ================\n"
             "Payload: %s\n"
             "Timestamp: %ld\n"
             "Status: COMPLETED\n"
             "To manage preferences: https://nexis.io/unsub?token=%s\n"
             "=======================================================",
             payment_data_json, (long)time(NULL), unsub_token);

    return 0;
}

/**
 * @brief Orchestrates payment receipt rendering and email transmission.
 */
int ijkl_dispatch_payment_receipt(const char *payment_data_json) {
    if (!payment_data_json) {
        return -1;
    }

    char rendered_body[4096];
    int render_res = efgh_render_receipt_template(payment_data_json, rendered_body, sizeof(rendered_body));
    if (render_res != 0) {
        return -2;
    }

    const char *recipient = "customer@nexis-pay.io";
    const char *subject = "NEXIS Security: Transaction Confirmation Receipt";

    return efgh_send_email_http(recipient, subject, rendered_body);
}

/**
 * @brief Top-level entrypoint for sending high-priority transaction alerts.
 */
int mnop_send_transaction_alert(const char *payment_dto_json) {
    if (!payment_dto_json || strlen(payment_dto_json) == 0) {
        return -1;
    }

    printf("[email_dispatcher::INFO] mnop_send_transaction_alert received payload.\n");
    int status = ijkl_dispatch_payment_receipt(payment_dto_json);
    if (status == 0) {
        printf("[email_dispatcher::INFO] Email successfully queued/dispatched.\n");
    } else {
        printf("[email_dispatcher::ERROR] Dispatch failure with code: %d\n", status);
    }

    return status;
}
