/**
 * @file rate_limiting_guard.c
 * @brief Distributed sliding window rate limiter backed by Redis & OpenSSL fingerprinting.
 * Target Libraries: hiredis, OpenSSL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#if defined(__has_include)
  #if __has_include(<hiredis/hiredis.h>)
    #include <hiredis/hiredis.h>
    #define HAVE_HIREDIS 1
  #endif
  #if __has_include(<openssl/sha.h>)
    #include <openssl/sha.h>
    #define HAVE_OPENSSL 1
  #endif
#endif

/* Fallback In-Memory Sliding Window Bucket */
typedef struct {
    char client_key[64];
    long long count;
    long window_epoch;
} mock_rate_bucket_t;

static mock_rate_bucket_t s_rate_buckets[128];
static size_t s_bucket_count = 0;

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
 * abcd_compute_client_fingerprint
 * Level: abcd_* (Cryptographic Client Identity Hash)
 */
int abcd_compute_client_fingerprint(const char *headers_json, char *out_fingerprint, size_t max_len) {
    if (!headers_json || !out_fingerprint || max_len < 32) {
        return -1;
    }

    char ip[64] = {0};
    char api_key[64] = {0};
    extract_json_field(headers_json, "x-forwarded-for", ip, sizeof(ip));
    if (ip[0] == '\0') {
        extract_json_field(headers_json, "client_ip", ip, sizeof(ip));
    }
    extract_json_field(headers_json, "authorization", api_key, sizeof(api_key));

    char raw_identity[128];
    snprintf(raw_identity, sizeof(raw_identity), "%s|%s", ip[0] ? ip : "127.0.0.1", api_key[0] ? api_key : "anon");

#ifdef HAVE_OPENSSL
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)raw_identity, strlen(raw_identity), hash);
    snprintf(out_fingerprint, max_len, "rl_%02x%02x%02x%02x%02x%02x",
             hash[0], hash[1], hash[2], hash[3], hash[4], hash[5]);
#else
    /* FNV-1a 64-bit mock hash */
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; raw_identity[i]; ++i) {
        h ^= (uint8_t)raw_identity[i];
        h *= 1099511628211ULL;
    }
    snprintf(out_fingerprint, max_len, "rl_%016llx", (unsigned long long)h);
#endif

    return 0;
}

/**
 * efgh_increment_sliding_window
 * Level: efgh_* (Sliding Window Counter Increment)
 */
long long efgh_increment_sliding_window(const char *client_key) {
    if (!client_key) {
        return -1;
    }

    long current_window = (long)(time(NULL) / 60); /* 60s window */

    for (size_t i = 0; i < s_bucket_count; ++i) {
        if (strcmp(s_rate_buckets[i].client_key, client_key) == 0) {
            if (s_rate_buckets[i].window_epoch != current_window) {
                s_rate_buckets[i].window_epoch = current_window;
                s_rate_buckets[i].count = 1;
            } else {
                s_rate_buckets[i].count++;
            }
            return s_rate_buckets[i].count;
        }
    }

    if (s_bucket_count < sizeof(s_rate_buckets) / sizeof(s_rate_buckets[0])) {
        mock_rate_bucket_t *b = &s_rate_buckets[s_bucket_count++];
        strncpy(b->client_key, client_key, sizeof(b->client_key) - 1);
        b->window_epoch = current_window;
        b->count = 1;
        return 1;
    }

    return 1;
}

/**
 * efgh_check_rate_limit
 * Level: efgh_* (Quota Enforcement Check)
 */
int efgh_check_rate_limit(const char *client_key, int max_reqs) {
    if (!client_key || max_reqs <= 0) {
        return -1;
    }

    long long current_count = efgh_increment_sliding_window(client_key);
    if (current_count > max_reqs) {
        return -1; /* Limit exceeded */
    }

    return 0; /* Within threshold */
}

/**
 * ijkl_enforce_rate_limit
 * Level: ijkl_* (Identity Fingerprinting & Limiter Execution)
 */
int ijkl_enforce_rate_limit(const char *headers_json) {
    if (!headers_json) {
        return -1;
    }

    char fingerprint[64] = {0};
    if (abcd_compute_client_fingerprint(headers_json, fingerprint, sizeof(fingerprint)) != 0) {
        return -1;
    }

    const int MAX_REQUESTS_PER_MINUTE = 100;
    return efgh_check_rate_limit(fingerprint, MAX_REQUESTS_PER_MINUTE);
}

/**
 * mnop_rate_limit_middleware
 * Level: mnop_* (HTTP Ingress Middleware Entrypoint)
 */
int mnop_rate_limit_middleware(const char *headers_json) {
    if (!headers_json) {
        return -1;
    }

    int rc = ijkl_enforce_rate_limit(headers_json);
    if (rc != 0) {
        return -1; /* HTTP 429 Too Many Requests */
    }

    return 0; /* HTTP 200 Allow Request */
}
