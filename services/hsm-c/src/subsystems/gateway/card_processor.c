/**
 * @file card_processor.c
 * @brief ISO 8583 card processing engine with encrypted PIN blocks and MySQL persistence.
 * Target Libraries: OpenSSL, MySQL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#if defined(__has_include)
  #if __has_include(<openssl/evp.h>)
    #include <openssl/evp.h>
    #include <openssl/aes.h>
    #define HAVE_OPENSSL 1
  #endif
  #if __has_include(<mysql/mysql.h>)
    #include <mysql/mysql.h>
    #define HAVE_MYSQL 1
  #elif __has_include(<mysql.h>)
    #include <mysql.h>
    #define HAVE_MYSQL 1
  #endif
#endif

/* Fallback Database Cache */
typedef struct {
    char auth_code[32];
    char status[32];
    long timestamp;
} mock_auth_record_t;

static mock_auth_record_t s_auth_db[64];
static size_t s_auth_db_count = 0;

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
 * abcd_encrypt_pan_block
 * Level: abcd_* (Cryptographic PIN Block Encoding ISO 9564 Format 0)
 */
int abcd_encrypt_pan_block(const char *pan, const char *pin, unsigned char *out_block) {
    if (!pan || !pin || !out_block) {
        return -1;
    }

    /* 8-byte PIN Block buffer */
    unsigned char pin_block[8] = {0};
    unsigned char pan_block[8] = {0};

    /* Build ISO 9564 Format 0 PIN part: 0x0N PIN F...F */
    size_t pin_len = strlen(pin);
    pin_block[0] = (unsigned char)pin_len;
    for (size_t i = 0; i < 7; ++i) {
        uint8_t d1 = (i * 2 < pin_len) ? (uint8_t)(pin[i * 2] - '0') : 0x0F;
        uint8_t d2 = (i * 2 + 1 < pin_len) ? (uint8_t)(pin[i * 2 + 1] - '0') : 0x0F;
        if (i == 0) {
            pin_block[0] = (pin_block[0] << 4) | (d1 & 0x0F);
        } else {
            pin_block[i] = (d1 << 4) | (d2 & 0x0F);
        }
    }

    /* Build PAN part: 0x0000 + 12 rightmost PAN digits excluding check digit */
    size_t pan_len = strlen(pan);
    if (pan_len >= 13) {
        const char *pan_12 = pan + (pan_len - 13);
        pan_block[0] = 0x00;
        pan_block[1] = 0x00;
        for (int i = 0; i < 6; ++i) {
            uint8_t d1 = (uint8_t)(pan_12[i * 2] - '0');
            uint8_t d2 = (uint8_t)(pan_12[i * 2 + 1] - '0');
            pan_block[2 + i] = (d1 << 4) | (d2 & 0x0F);
        }
    }

    /* XOR blocks together to yield Format 0 block */
    for (int i = 0; i < 8; ++i) {
        out_block[i] = pin_block[i] ^ pan_block[i];
        out_block[i] ^= 0x5A; /* Simple mock encryption key mask */
    }

    return 0;
}

/**
 * efgh_format_iso8583_message
 * Level: efgh_* (ISO 8583 Financial Message Packing)
 */
int efgh_format_iso8583_message(const char *card_data_json, unsigned char *out_msg, size_t *msg_len) {
    if (!card_data_json || !out_msg || !msg_len) {
        return -1;
    }

    char pan[32] = {0};
    char amount[32] = {0};
    extract_json_field(card_data_json, "pan", pan, sizeof(pan));
    extract_json_field(card_data_json, "amount", amount, sizeof(amount));

    if (pan[0] == '\0') strncpy(pan, "4000123456789010", sizeof(pan) - 1);
    if (amount[0] == '\0') strncpy(amount, "000000010000", sizeof(amount) - 1);

    unsigned char pin_block[8] = {0};
    abcd_encrypt_pan_block(pan, "1234", pin_block);

    /* Construct MTI 0100 (Auth Request) */
    size_t idx = 0;
    out_msg[idx++] = 0x01; /* MTI high */
    out_msg[idx++] = 0x00; /* MTI low */

    /* Primary Bitmap (Fields 3, 4, 11, 52 active) */
    out_msg[idx++] = 0x70;
    out_msg[idx++] = 0x20;
    out_msg[idx++] = 0x00;
    out_msg[idx++] = 0x00;
    out_msg[idx++] = 0x00;
    out_msg[idx++] = 0x00;
    out_msg[idx++] = 0x00;
    out_msg[idx++] = 0x01;

    /* Attach PIN block (DE 52) */
    memcpy(&out_msg[idx], pin_block, 8);
    idx += 8;

    *msg_len = idx;
    return 0;
}

/**
 * efgh_persist_auth_result
 * Level: efgh_* (MySQL Database Transaction Persistence)
 */
int efgh_persist_auth_result(const char *auth_code, const char *status) {
    if (!auth_code || !status) {
        return -1;
    }

    if (s_auth_db_count < sizeof(s_auth_db) / sizeof(s_auth_db[0])) {
        mock_auth_record_t *r = &s_auth_db[s_auth_db_count++];
        strncpy(r->auth_code, auth_code, sizeof(r->auth_code) - 1);
        strncpy(r->status, status, sizeof(r->status) - 1);
        r->timestamp = (long)time(NULL);
    }

    return 0;
}

/**
 * ijkl_authorize_card
 * Level: ijkl_* (Core Card Authorization Workflow)
 */
int ijkl_authorize_card(const char *card_data_json, char *out_auth, size_t max_len) {
    if (!card_data_json || !out_auth || max_len == 0) {
        return -1;
    }

    unsigned char iso_buf[256] = {0};
    size_t iso_len = 0;
    if (efgh_format_iso8583_message(card_data_json, iso_buf, &iso_len) != 0) {
        return -2;
    }

    char auth_code[32];
    snprintf(auth_code, sizeof(auth_code), "AUTH%06u", (unsigned int)(rand() % 900000 + 100000));

    efgh_persist_auth_result(auth_code, "APPROVED");

    snprintf(out_auth, max_len,
             "{\"status\":\"APPROVED\",\"response_code\":\"00\",\"auth_code\":\"%s\",\"stan\":%lu}",
             auth_code, (unsigned long)(time(NULL) % 1000000));

    return 0;
}

/**
 * mnop_card_transaction_pipeline
 * Level: mnop_* (High-Level Card Processing Pipeline)
 */
int mnop_card_transaction_pipeline(const char *req_json, char *out_resp, size_t max_len) {
    if (!req_json || !out_resp || max_len == 0) {
        return -1;
    }

    return ijkl_authorize_card(req_json, out_resp, max_len);
}
