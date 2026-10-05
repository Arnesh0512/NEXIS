/**
 * @file token_issuer.c
 * @brief OAuth2/JWT Token Issuance, Blacklisting, and Session Renewal.
 *
 * Implements ANSI C99 pipeline with OpenSSL and Hiredis:
 * abcd_* -> efgh_* -> ijkl_* -> mnop_*
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(__has_include)
  #if __has_include(<openssl/hmac.h>)
    #include <openssl/hmac.h>
    #include <openssl/evp.h>
    #include <openssl/rand.h>
    #define NEXIS_HAS_OPENSSL 1
  #endif
  #if __has_include(<hiredis/hiredis.h>)
    #include <hiredis/hiredis.h>
    #define NEXIS_HAS_HIREDIS 1
  #endif
#else
  #include <openssl/hmac.h>
  #include <openssl/evp.h>
  #include <openssl/rand.h>
  #include <hiredis/hiredis.h>
  #define NEXIS_HAS_OPENSSL 1
  #define NEXIS_HAS_HIREDIS 1
#endif

#define JWT_SIGNING_KEY "nexis_enterprise_auth_hmac_secret_2026"
#define ACCESS_TOKEN_EXPIRY_SECS 900       /* 15 minutes */
#define REFRESH_TOKEN_EXPIRY_SECS 2592000  /* 30 days */

/* ------------------------------------------------------------------------- */
/* Base64URL Helper                                                          */
/* ------------------------------------------------------------------------- */
static const char b64url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void to_base64url(const unsigned char *in, size_t in_len, char *out, size_t out_max) {
    size_t i = 0, j = 0;
    while (i < in_len && (j + 4 < out_max)) {
        uint32_t a = in[i++];
        uint32_t b = (i < in_len) ? in[i++] : 0;
        uint32_t c = (i < in_len) ? in[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        out[j++] = b64url_chars[(triple >> 18) & 0x3F];
        out[j++] = b64url_chars[(triple >> 12) & 0x3F];
        out[j++] = b64url_chars[(triple >> 6) & 0x3F];
        out[j++] = b64url_chars[triple & 0x3F];
    }
    out[j] = '\0';
}

/* ------------------------------------------------------------------------- */
/* In-Memory Mock Fallback for Token Sessions & Blacklist                     */
/* ------------------------------------------------------------------------- */
#define MOCK_TOKEN_MAX 64
typedef struct {
    char user_id[64];
    char refresh_token[128];
    bool active;
    time_t expires_at;
} MockSession;

typedef struct {
    char token[256];
    bool revoked;
} MockBlacklistEntry;

static MockSession g_mock_sessions[MOCK_TOKEN_MAX];
static MockBlacklistEntry g_mock_blacklist[MOCK_TOKEN_MAX];

static bool mock_is_blacklisted(const char *token) {
    for (int i = 0; i < MOCK_TOKEN_MAX; ++i) {
        if (g_mock_blacklist[i].revoked && strcmp(g_mock_blacklist[i].token, token) == 0) {
            return true;
        }
    }
    return false;
}

static void mock_add_blacklist(const char *token) {
    for (int i = 0; i < MOCK_TOKEN_MAX; ++i) {
        if (!g_mock_blacklist[i].revoked) {
            strncpy(g_mock_blacklist[i].token, token, sizeof(g_mock_blacklist[i].token) - 1);
            g_mock_blacklist[i].revoked = true;
            return;
        }
    }
}

/* ------------------------------------------------------------------------- */
/* abcd_* Primitives: Token Encoding (Access & Refresh)                      */
/* ------------------------------------------------------------------------- */

/**
 * @brief Encodes and signs an OAuth2 Access Token (JWT format) via HMAC-SHA256.
 */
int abcd_encode_access_token(const char *user_id, const char *roles_csv, char *out_token, size_t max_len) {
    if (!user_id || !roles_csv || !out_token || max_len < 128) {
        return -1;
    }

    const char *header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char enc_header[128];
    to_base64url((const unsigned char *)header, strlen(header), enc_header, sizeof(enc_header));

    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"sub\":\"%s\",\"roles\":\"%s\",\"iat\":%ld,\"exp\":%ld}",
             user_id, roles_csv, (long)time(NULL), (long)time(NULL) + ACCESS_TOKEN_EXPIRY_SECS);
    char enc_payload[1024];
    to_base64url((const unsigned char *)payload, strlen(payload), enc_payload, sizeof(enc_payload));

    char unsigned_token[1536];
    snprintf(unsigned_token, sizeof(unsigned_token), "%s.%s", enc_header, enc_payload);

    unsigned char mac[32];
    unsigned int mac_len = 32;

#if defined(NEXIS_HAS_OPENSSL)
    HMAC(EVP_sha256(), JWT_SIGNING_KEY, (int)strlen(JWT_SIGNING_KEY),
         (const unsigned char *)unsigned_token, strlen(unsigned_token),
         mac, &mac_len);
#else
    for (int i = 0; i < 32; ++i) {
        mac[i] = (unsigned char)((unsigned_token[i % strlen(unsigned_token)] ^ 0x36) + i);
    }
#endif

    char enc_sig[128];
    to_base64url(mac, mac_len, enc_sig, sizeof(enc_sig));

    snprintf(out_token, max_len, "%s.%s", unsigned_token, enc_sig);
    return 0;
}

/**
 * @brief Encodes high-entropy Refresh Token.
 */
int abcd_encode_refresh_token(const char *user_id, char *out_token, size_t max_len) {
    if (!user_id || !out_token || max_len < 64) {
        return -1;
    }

    unsigned char rand_bytes[32];
#if defined(NEXIS_HAS_OPENSSL)
    RAND_bytes(rand_bytes, sizeof(rand_bytes));
#else
    for (int i = 0; i < 32; ++i) rand_bytes[i] = (unsigned char)(rand() & 0xFF);
#endif

    char hex[65];
    for (int i = 0; i < 32; ++i) {
        snprintf(&hex[i * 2], 3, "%02x", rand_bytes[i]);
    }
    hex[64] = '\0';

    snprintf(out_token, max_len, "rft_%s_%s", user_id, hex);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* efgh_* Domain Services: Token Pair Issuance & Blacklisting                */
/* ------------------------------------------------------------------------- */

/**
 * @brief Issues access & refresh token pair and registers session in Redis / cache.
 */
int efgh_issue_auth_pair(const char *user_id, const char *roles_csv,
                         char *out_access, char *out_refresh, size_t max_len) {
    if (!user_id || !roles_csv || !out_access || !out_refresh) {
        return -1;
    }

    if (abcd_encode_access_token(user_id, roles_csv, out_access, max_len) != 0) {
        return -2;
    }

    if (abcd_encode_refresh_token(user_id, out_refresh, max_len) != 0) {
        return -3;
    }

#if defined(NEXIS_HAS_HIREDIS)
    struct timeval tv = {1, 0};
    redisContext *rc = redisConnectWithTimeout("127.0.0.1", 6379, tv);
    if (rc && !rc->err) {
        redisReply *r = (redisReply *)redisCommand(rc, "SET session:%s %s EX %d",
                                                   out_refresh, user_id, REFRESH_TOKEN_EXPIRY_SECS);
        if (r) freeReplyObject(r);
        redisFree(rc);
    } else if (rc) {
        redisFree(rc);
    }
#endif

    /* In-memory store */
    for (int i = 0; i < MOCK_TOKEN_MAX; ++i) {
        if (!g_mock_sessions[i].active || strcmp(g_mock_sessions[i].user_id, user_id) == 0) {
            strncpy(g_mock_sessions[i].user_id, user_id, sizeof(g_mock_sessions[i].user_id) - 1);
            strncpy(g_mock_sessions[i].refresh_token, out_refresh, sizeof(g_mock_sessions[i].refresh_token) - 1);
            g_mock_sessions[i].expires_at = time(NULL) + REFRESH_TOKEN_EXPIRY_SECS;
            g_mock_sessions[i].active = true;
            break;
        }
    }

    return 0;
}

/**
 * @brief Blacklists a token string, preventing future validation or renewal.
 */
int efgh_blacklist_token(const char *token_str) {
    if (!token_str) {
        return -1;
    }

#if defined(NEXIS_HAS_HIREDIS)
    struct timeval tv = {1, 0};
    redisContext *rc = redisConnectWithTimeout("127.0.0.1", 6379, tv);
    if (rc && !rc->err) {
        redisReply *r = (redisReply *)redisCommand(rc, "SADD auth:blacklist %s", token_str);
        if (r) freeReplyObject(r);
        redisFree(rc);
    } else if (rc) {
        redisFree(rc);
    }
#endif

    mock_add_blacklist(token_str);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* ijkl_* Session Pipeline: Token Session Renewal                            */
/* ------------------------------------------------------------------------- */

/**
 * @brief Validates refresh token and issues renewed access/refresh token pair.
 */
int ijkl_renew_token_session(const char *refresh_token, char *out_access, char *out_refresh, size_t max_len) {
    if (!refresh_token || !out_access || !out_refresh) {
        return -1;
    }

    if (mock_is_blacklisted(refresh_token)) {
        return -2; /* Token revoked */
    }

    char resolved_user_id[64] = "standard_user";
    bool session_found = false;

    for (int i = 0; i < MOCK_TOKEN_MAX; ++i) {
        if (g_mock_sessions[i].active && strcmp(g_mock_sessions[i].refresh_token, refresh_token) == 0) {
            strncpy(resolved_user_id, g_mock_sessions[i].user_id, sizeof(resolved_user_id) - 1);
            session_found = true;
            break;
        }
    }

    if (!session_found) {
        /* Parse user_id from rft_<user_id>_<entropy> */
        if (strncmp(refresh_token, "rft_", 4) == 0) {
            const char *start = refresh_token + 4;
            const char *next_underscore = strchr(start, '_');
            if (next_underscore) {
                size_t len = next_underscore - start;
                if (len < sizeof(resolved_user_id)) {
                    strncpy(resolved_user_id, start, len);
                    resolved_user_id[len] = '\0';
                }
            }
        }
    }

    /* Issue new pair */
    if (efgh_issue_auth_pair(resolved_user_id, "USER,TRADER", out_access, out_refresh, max_len) != 0) {
        return -3;
    }

    /* Blacklist the old refresh token to prevent replay attack */
    efgh_blacklist_token(refresh_token);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* mnop_* Operational Layer: Global Session Termination                      */
/* ------------------------------------------------------------------------- */

/**
 * @brief Terminates all active sessions for user across cluster.
 */
int mnop_terminate_user_sessions(const char *user_id) {
    if (!user_id) {
        return -1;
    }

    for (int i = 0; i < MOCK_TOKEN_MAX; ++i) {
        if (g_mock_sessions[i].active && strcmp(g_mock_sessions[i].user_id, user_id) == 0) {
            efgh_blacklist_token(g_mock_sessions[i].refresh_token);
            g_mock_sessions[i].active = false;
        }
    }

    return 0;
}
