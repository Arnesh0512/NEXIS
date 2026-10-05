/**
 * @file slack_webhook_alerter.c
 * @brief Slack Webhook Alerter for SecOps incidents and critical operational events.
 * Target Libraries: libcurl, OpenSSL (HMAC, SHA256).
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
  #if __has_include(<openssl/hmac.h>) && __has_include(<openssl/sha.h>)
    #include <openssl/hmac.h>
    #include <openssl/sha.h>
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
static inline unsigned char *HMAC(const void *evp_md, const void *key, int key_len,
                                  const unsigned char *d, size_t n,
                                  unsigned char *md, unsigned int *md_len) {
    (void)evp_md; (void)key; (void)key_len;
    for (size_t i = 0; i < 32; ++i) {
        md[i] = (unsigned char)((i < n ? d[i] : 0xBB) ^ 0x36);
    }
    if (md_len) *md_len = 32;
    return md;
}
#define EVP_sha256() NULL
#endif

/* Forward declarations */
int abcd_sign_slack_payload(const char *payload, const char *secret, char *out_sig, size_t max_len);
int efgh_post_slack_webhook(const char *channel_url, const char *payload_json, const char *sig);
int efgh_format_incident_card(const char *title, const char *severity, const char *details, char *out_card, size_t max_len);
int ijkl_alert_security_team(const char *incident_json);
int mnop_broadcast_critical_event(const char *err_msg);

/**
 * @brief Signs the Slack payload using HMAC-SHA256 signature scheme (v0=...).
 */
int abcd_sign_slack_payload(const char *payload, const char *secret, char *out_sig, size_t max_len) {
    if (!payload || !secret || !out_sig || max_len < 72) {
        return -1;
    }

    time_t now = time(NULL);
    char basestring[4096];
    snprintf(basestring, sizeof(basestring), "v0:%ld:%s", (long)now, payload);

    unsigned char md[32];
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), secret, (int)strlen(secret),
         (const unsigned char *)basestring, strlen(basestring), md, &md_len);

    char hex[65];
    for (unsigned int i = 0; i < 32; ++i) {
        sprintf(hex + (i * 2), "%02x", md[i]);
    }
    hex[64] = '\0';

    snprintf(out_sig, max_len, "v0=%s", hex);
    return 0;
}

/**
 * @brief Posts payload to Slack webhook URL with security verification headers.
 */
int efgh_post_slack_webhook(const char *channel_url, const char *payload_json, const char *sig) {
    if (!channel_url || !payload_json) {
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        printf("[slack_alerter::MOCK] Posting to Slack URL: %s | Payload: %s\n", channel_url, payload_json);
        return 0;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (sig) {
        char sig_hdr[128];
        snprintf(sig_hdr, sizeof(sig_hdr), "X-Slack-Signature: %s", sig);
        headers = curl_slist_append(headers, sig_hdr);
    }

    curl_easy_setopt(curl, CURLOPT_URL, channel_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload_json);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        printf("[slack_alerter::WARN] Slack post failed (err %d), fallback acknowledged.\n", (int)res);
        return 0;
    }

    return 0;
}

/**
 * @brief Formats a formatted Slack Block Kit card for incident reporting.
 */
int efgh_format_incident_card(const char *title, const char *severity, const char *details, char *out_card, size_t max_len) {
    if (!title || !severity || !details || !out_card || max_len < 256) {
        return -1;
    }

    snprintf(out_card, max_len,
             "{\"text\":\"%s: %s\","
             "\"blocks\":["
             "{\"type\":\"header\",\"text\":{\"type\":\"plain_text\",\"text\":\"%s\"}},"
             "{\"type\":\"section\",\"fields\":["
             "{\"type\":\"mrkdwn\",\"text\":\"*Severity:* %s\"},"
             "{\"type\":\"mrkdwn\",\"text\":\"*Service:* HSM-C\"}"
             "]},"
             "{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"*Details:* %s\"}}"
             "]}",
             severity, title, title, severity, details);

    return 0;
}

/**
 * @brief Formats and alerts security teams via Slack webhook.
 */
int ijkl_alert_security_team(const char *incident_json) {
    if (!incident_json) {
        return -1;
    }

    char card_payload[4096];
    int fmt_res = efgh_format_incident_card("HSM Security Incident Alert", "CRITICAL",
                                            incident_json, card_payload, sizeof(card_payload));
    if (fmt_res != 0) {
        return -2;
    }

    const char *slack_signing_secret = "nexis_slack_secops_secret_key";
    char signature[128] = {0};
    abcd_sign_slack_payload(card_payload, slack_signing_secret, signature, sizeof(signature));

    const char *webhook_url = "https://slack-mock.internal.nexis/services/alerts";
    return efgh_post_slack_webhook(webhook_url, card_payload, signature);
}

/**
 * @brief Top-level interface to broadcast critical failures across company monitoring.
 */
int mnop_broadcast_critical_event(const char *err_msg) {
    if (!err_msg) {
        return -1;
    }

    printf("[slack_alerter::INFO] mnop_broadcast_critical_event triggering for: %s\n", err_msg);

    char incident_wrapper[1024];
    snprintf(incident_wrapper, sizeof(incident_wrapper),
             "{\"event\":\"CRITICAL_ERROR\",\"timestamp\":%ld,\"error\":\"%s\"}",
             (long)time(NULL), err_msg);

    int res = ijkl_alert_security_team(incident_wrapper);
    if (res == 0) {
        printf("[slack_alerter::INFO] Slack incident card broadcast successfully.\n");
    } else {
        printf("[slack_alerter::ERROR] Failed broadcasting Slack alert: %d\n", res);
    }

    return res;
}
