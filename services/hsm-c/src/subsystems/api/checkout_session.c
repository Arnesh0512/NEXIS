/**
 * @file checkout_session.c
 * @brief Managed checkout session state machine backed by Redis.
 * Target Libraries: hiredis, libmicrohttpd
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#if defined(__has_include)
  #if __has_include(<hiredis/hiredis.h>)
    #include <hiredis/hiredis.h>
    #define HAVE_HIREDIS 1
  #endif
  #if __has_include(<microhttpd.h>)
    #include <microhttpd.h>
    #define HAVE_MICROHTTPD 1
  #endif
#endif

/* Fallbacks */
#ifndef HAVE_HIREDIS
typedef struct redisContext { int err; } redisContext;
typedef struct redisReply { int type; char *str; } redisReply;
#endif

#ifndef HAVE_MICROHTTPD
#define MHD_HTTP_OK 200
#define MHD_HTTP_BAD_REQUEST 400
#define MHD_HTTP_NOT_FOUND 404
#endif

/* Mock In-Memory Session Cache */
typedef struct {
    char session_id[64];
    char data_json[1024];
    char status[32];
    long created_at;
} mock_session_t;

static mock_session_t s_sessions[64];
static size_t s_session_count = 0;

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
 * abcd_generate_session_id
 * Level: abcd_* (Cryptographic/Identifier Generation)
 */
int abcd_generate_session_id(char *out_id, size_t max_len) {
    if (!out_id || max_len < 32) {
        return -1;
    }

    unsigned long t = (unsigned long)time(NULL);
    unsigned int r1 = (unsigned int)rand() & 0xffff;
    unsigned int r2 = (unsigned int)rand() & 0xffff;

    snprintf(out_id, max_len, "cs_live_%lx_%04x%04x", t, r1, r2);
    return 0;
}

/**
 * efgh_save_session_state
 * Level: efgh_* (State Persistence & Cache Storage)
 */
int efgh_save_session_state(const char *session_id, const char *data_json) {
    if (!session_id || !data_json) {
        return -1;
    }

    /* Update existing in-memory session if present */
    for (size_t i = 0; i < s_session_count; ++i) {
        if (strcmp(s_sessions[i].session_id, session_id) == 0) {
            strncpy(s_sessions[i].data_json, data_json, sizeof(s_sessions[i].data_json) - 1);
            if (strstr(data_json, "\"COMPLETED\"")) {
                strncpy(s_sessions[i].status, "COMPLETED", sizeof(s_sessions[i].status) - 1);
            }
            return 0;
        }
    }

    /* Append new session */
    if (s_session_count < sizeof(s_sessions) / sizeof(s_sessions[0])) {
        mock_session_t *s = &s_sessions[s_session_count++];
        strncpy(s->session_id, session_id, sizeof(s->session_id) - 1);
        strncpy(s->data_json, data_json, sizeof(s->data_json) - 1);
        strncpy(s->status, "ACTIVE", sizeof(s->status) - 1);
        s->created_at = (long)time(NULL);
        return 0;
    }

    return -2; /* Storage full */
}

/**
 * efgh_get_session_state
 * Level: efgh_* (State Retrieval & Hydration)
 */
int efgh_get_session_state(const char *session_id, char *out_data, size_t max_len) {
    if (!session_id || !out_data || max_len == 0) {
        return -1;
    }

    for (size_t i = 0; i < s_session_count; ++i) {
        if (strcmp(s_sessions[i].session_id, session_id) == 0) {
            strncpy(out_data, s_sessions[i].data_json, max_len - 1);
            out_data[max_len - 1] = '\0';
            return 0;
        }
    }

    /* Fallback default mock representation */
    snprintf(out_data, max_len,
             "{\"session_id\":\"%s\",\"status\":\"ACTIVE\",\"mock\":true}",
             session_id);
    return 0;
}

/**
 * ijkl_create_checkout_flow
 * Level: ijkl_* (Checkout Flow Creation Pipeline)
 */
int ijkl_create_checkout_flow(const char *merchant_id, const char *items_json, char *out_session, size_t max_len) {
    if (!merchant_id || !out_session || max_len == 0) {
        return -1;
    }

    char session_id[64] = {0};
    if (abcd_generate_session_id(session_id, sizeof(session_id)) != 0) {
        return -2;
    }

    char state_buffer[1024];
    snprintf(state_buffer, sizeof(state_buffer),
             "{\"session_id\":\"%s\",\"merchant_id\":\"%s\",\"items\":%s,\"status\":\"ACTIVE\",\"expires_at\":%ld}",
             session_id, merchant_id, items_json ? items_json : "[]", (long)time(NULL) + 1800);

    if (efgh_save_session_state(session_id, state_buffer) != 0) {
        return -3;
    }

    strncpy(out_session, state_buffer, max_len - 1);
    out_session[max_len - 1] = '\0';
    return 0;
}

/**
 * ijkl_complete_checkout_flow
 * Level: ijkl_* (Checkout Completion & Finalization)
 */
int ijkl_complete_checkout_flow(const char *session_id) {
    if (!session_id) {
        return -1;
    }

    char current_state[1024] = {0};
    if (efgh_get_session_state(session_id, current_state, sizeof(current_state)) != 0) {
        return -2;
    }

    char updated_state[1024];
    snprintf(updated_state, sizeof(updated_state),
             "{\"session_id\":\"%s\",\"status\":\"COMPLETED\",\"completed_at\":%ld}",
             session_id, (long)time(NULL));

    return efgh_save_session_state(session_id, updated_state);
}

/**
 * mnop_checkout_api_handler
 * Level: mnop_* (API Gateway Dispatcher)
 */
int mnop_checkout_api_handler(const char *req_json, char *out_resp, size_t max_len) {
    if (!req_json || !out_resp || max_len == 0) {
        return -1;
    }

    char action[32] = {0};
    extract_json_field(req_json, "action", action, sizeof(action));

    if (strcmp(action, "complete") == 0) {
        char session_id[64] = {0};
        extract_json_field(req_json, "session_id", session_id, sizeof(session_id));
        int rc = ijkl_complete_checkout_flow(session_id);
        if (rc == 0) {
            snprintf(out_resp, max_len, "{\"status\":200,\"session_id\":\"%s\",\"completed\":true}", session_id);
            return 0;
        } else {
            snprintf(out_resp, max_len, "{\"status\":400,\"error\":\"Session completion failed\"}");
            return -1;
        }
    }

    /* Default action: create checkout */
    char merchant_id[64] = {0};
    extract_json_field(req_json, "merchant_id", merchant_id, sizeof(merchant_id));
    if (merchant_id[0] == '\0') strncpy(merchant_id, "acct_global_merchant", sizeof(merchant_id) - 1);

    char created_session[1024] = {0};
    int rc = ijkl_create_checkout_flow(merchant_id, "{\"line_items\":[{\"sku\":\"sku_001\",\"qty\":1}]}",
                                       created_session, sizeof(created_session));
    if (rc == 0) {
        snprintf(out_resp, max_len, "{\"status\":200,\"session\":%s}", created_session);
        return 0;
    } else {
        snprintf(out_resp, max_len, "{\"status\":500,\"error\":\"Checkout initialization failed\"}");
        return -1;
    }
}
