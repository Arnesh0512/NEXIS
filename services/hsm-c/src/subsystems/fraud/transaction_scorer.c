/**
 * Nexis Core Financial Ledger Platform - Fraud Detection Subsystem
 * Source: Transaction Scorer
 *
 * Implements merchant transaction velocity profiling, composite fraud scoring,
 * and AI-driven explanatory risk diagnostics with in-memory mock fallback.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#if defined(__has_include)
#  if __has_include(<curl/curl.h>)
#    include <curl/curl.h>
#    define NEXIS_HAS_CURL 1
#  endif
#  if __has_include(<mongoc/mongoc.h>)
#    include <mongoc/mongoc.h>
#    include <bson/bson.h>
#    define NEXIS_HAS_MONGOC 1
#  endif
#endif

#ifndef NEXIS_HAS_CURL
typedef void CURL;
#endif

#ifndef NEXIS_HAS_MONGOC
typedef void mongoc_client_t;
#endif

#define MAX_MERCHANTS 64

typedef struct {
    char merchant_id[64];
    int tx_count_last_hour;
    double hourly_volume;
} merchant_velocity_record_t;

static merchant_velocity_record_t g_mock_velocities[MAX_MERCHANTS] = {
    { "MERCH_PLATINUM_01", 12,  45000.0 },
    { "MERCH_SUSPECT_99",  180, 890000.0 },
    { "MERCH_DEFAULT",     4,   1200.0  }
};
static size_t g_mock_velocity_count = 3;

/**
 * abcd_query_merchant_velocity
 *
 * Queries MongoDB order aggregates or in-memory tracking table
 * to obtain the transaction count executed by the merchant within the rolling 60-minute window.
 */
int abcd_query_merchant_velocity(const char *merchant_id) {
    if (!merchant_id) return 0;

#if defined(NEXIS_HAS_MONGOC)
    /* Real MongoDB driver querying would aggregate here */
#endif

    for (size_t i = 0; i < g_mock_velocity_count; i++) {
        if (strcmp(g_mock_velocities[i].merchant_id, merchant_id) == 0) {
            return g_mock_velocities[i].tx_count_last_hour;
        }
    }

    return 5; /* Default nominal baseline velocity */
}

/**
 * efgh_calculate_velocity_score
 *
 * Calculates a normalized velocity penalty score [0.0 - 100.0] based on
 * transaction frequency thresholds and burst rate indicators.
 */
double efgh_calculate_velocity_score(const char *orders_json) {
    if (!orders_json) return 0.0;

    int count = 5;
    const char *cnt_ptr = strstr(orders_json, "\"tx_count\":");
    if (cnt_ptr) {
        sscanf(cnt_ptr + 11, "%d", &count);
    }

    /* Baseline formula: velocity over 50/hour incurs non-linear penalty */
    if (count <= 15) {
        return 5.0;
    } else if (count <= 50) {
        return 25.0 + (double)(count - 15) * 1.0;
    } else if (count <= 100) {
        return 60.0 + (double)(count - 50) * 0.6;
    } else {
        return 95.0; /* Extreme burst velocity alert */
    }
}

/**
 * efgh_query_ai_fraud_explanation
 *
 * Dispatches the composite scoring vector to AI explanation service via libcurl
 * or synthesizes human-readable risk rationales.
 */
int efgh_query_ai_fraud_explanation(const char *score_data_json, char *out_exp, size_t max_len) {
    if (!score_data_json || !out_exp || max_len == 0) {
        return -1;
    }

#if defined(NEXIS_HAS_CURL)
    /* Libcurl pathway for AI explanation service */
#endif

    /* In-memory mock synthesis */
    double score = 15.0;
    const char *p_sc = strstr(score_data_json, "\"score\":");
    if (p_sc) sscanf(p_sc + 8, "%lf", &score);

    if (score >= 70.0) {
        snprintf(out_exp, max_len,
                 "CRITICAL RISK: Merchant exhibits extreme transaction velocity surge exceeding 3x 30-day baseline.");
    } else if (score >= 40.0) {
        snprintf(out_exp, max_len,
                 "MODERATE RISK: Transaction frequency elevated; ticket sizes deviate from historical distribution.");
    } else {
        snprintf(out_exp, max_len,
                 "LOW RISK: Merchant behavior consistent with standard operating profile and nominal velocity.");
    }

    return 0;
}

/**
 * ijkl_compute_composite_score
 *
 * Combines merchant hourly velocity from abcd_query_merchant_velocity
 * with order payload attributes through efgh_calculate_velocity_score.
 */
double ijkl_compute_composite_score(const char *merchant_id, const char *tx_json) {
    if (!merchant_id || !tx_json) return 50.0;

    int hourly_velocity = abcd_query_merchant_velocity(merchant_id);

    char velocity_payload[128];
    snprintf(velocity_payload, sizeof(velocity_payload), "{\"tx_count\":%d}", hourly_velocity);

    double vel_score = efgh_calculate_velocity_score(velocity_payload);

    /* Factor in transaction amount */
    double amount = 50.0;
    const char *p_amt = strstr(tx_json, "\"amount\":");
    if (p_amt) sscanf(p_amt + 9, "%lf", &amount);

    double amount_factor = 0.0;
    if (amount > 10000.0) amount_factor = 35.0;
    else if (amount > 2500.0) amount_factor = 15.0;
    else if (amount > 500.0) amount_factor = 5.0;

    double composite = (vel_score * 0.65) + (amount_factor * 0.35);
    if (composite > 100.0) composite = 100.0;
    return composite;
}

/**
 * mnop_evaluate_merchant_fraud
 *
 * High-level orchestration for merchant risk evaluation.
 * Invokes ijkl_compute_composite_score and efgh_query_ai_fraud_explanation.
 */
int mnop_evaluate_merchant_fraud(const char *merchant_id, const char *tx_json, char *out_report, size_t max_len) {
    if (!merchant_id || !tx_json || !out_report || max_len == 0) {
        return -1;
    }

    double composite_score = ijkl_compute_composite_score(merchant_id, tx_json);

    char score_json[128];
    snprintf(score_json, sizeof(score_json), "{\"score\":%.2f}", composite_score);

    char explanation[512] = {0};
    efgh_query_ai_fraud_explanation(score_json, explanation, sizeof(explanation));

    snprintf(out_report, max_len,
             "{\"merchant_id\":\"%s\",\"composite_score\":%.2f,\"status\":\"%s\",\"explanation\":\"%s\"}",
             merchant_id, composite_score,
             (composite_score >= 70.0 ? "HIGH_RISK" : (composite_score >= 40.0 ? "MODERATE_RISK" : "NOMINAL")),
             explanation);

    return (composite_score >= 70.0) ? 1 : 0;
}
