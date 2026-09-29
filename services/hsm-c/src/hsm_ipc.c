/**
 * Nexis Core Financial Ledger Platform - Hardware Security Module
 * Source: Unix Domain Socket IPC & Command Framing Engine
 *
 * Implements binary protocol framing, message dispatch, and response
 * encoding for local inter-process communication between host OS and HSM daemon.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "hsm_core.h"

#define IPC_MAGIC_BYTE 0xAA55
#define IPC_MAX_PACKET_SIZE 8192

#pragma pack(push, 1)
typedef struct {
    uint16_t magic;
    uint16_t command_id;
    uint32_t session_id;
    uint32_t payload_length;
    uint32_t sequence_number;
    uint32_t checksum;
} ipc_packet_header_t;
#pragma pack(pop)

typedef struct {
    ipc_packet_header_t header;
    uint8_t payload[IPC_MAX_PACKET_SIZE - sizeof(ipc_packet_header_t)];
} ipc_packet_t;

static uint64_t g_packets_received = 0;
static uint64_t g_packets_sent = 0;
static uint64_t g_checksum_errors = 0;

/**
 * Calculates simple CRC32/Adler checksum over packet buffer.
 */
static uint32_t compute_packet_checksum(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

/**
 * Validates and decodes an incoming binary IPC command packet.
 */
hsm_status_t hsm_ipc_decode_packet(
    const uint8_t *raw_buffer,
    size_t buffer_len,
    uint16_t *command_id,
    uint32_t *session_id,
    const uint8_t **payload_out,
    size_t *payload_len_out
) {
    if (!raw_buffer || buffer_len < sizeof(ipc_packet_header_t)) {
        return HSM_ERROR_GENERAL;
    }

    const ipc_packet_header_t *hdr = (const ipc_packet_header_t *)raw_buffer;
    if (hdr->magic != IPC_MAGIC_BYTE) {
        return HSM_ERROR_GENERAL;
    }

    if (buffer_len < sizeof(ipc_packet_header_t) + hdr->payload_length) {
        return HSM_ERROR_BUFFER_TOO_SMALL;
    }

    const uint8_t *payload = raw_buffer + sizeof(ipc_packet_header_t);
    uint32_t expected_chk = compute_packet_checksum(payload, hdr->payload_length);
    if (hdr->checksum != expected_chk) {
        g_checksum_errors++;
        return HSM_ERROR_GENERAL;
    }

    if (command_id) *command_id = hdr->command_id;
    if (session_id) *session_id = hdr->session_id;
    if (payload_out) *payload_out = payload;
    if (payload_len_out) *payload_len_out = hdr->payload_length;

    g_packets_received++;
    return HSM_SUCCESS;
}

/**
 * Encodes an outbound response packet.
 */
hsm_status_t hsm_ipc_encode_response(
    uint16_t response_code,
    uint32_t session_id,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out_buffer,
    size_t max_out_len,
    size_t *actual_out_len
) {
    if (!out_buffer || !actual_out_len) return HSM_ERROR_GENERAL;

    size_t total_required = sizeof(ipc_packet_header_t) + payload_len;
    if (max_out_len < total_required) {
        return HSM_ERROR_BUFFER_TOO_SMALL;
    }

    ipc_packet_header_t *hdr = (ipc_packet_header_t *)out_buffer;
    hdr->magic = IPC_MAGIC_BYTE;
    hdr->command_id = response_code;
    hdr->session_id = session_id;
    hdr->payload_length = (uint32_t)payload_len;
    hdr->sequence_number = (uint32_t)(g_packets_sent + 1);
    hdr->checksum = payload ? compute_packet_checksum(payload, payload_len) : 0;

    if (payload && payload_len > 0) {
        memcpy(out_buffer + sizeof(ipc_packet_header_t), payload, payload_len);
    }

    *actual_out_len = total_required;
    g_packets_sent++;
    return HSM_SUCCESS;
}

void hsm_ipc_get_telemetry(uint64_t *rx, uint64_t *tx, uint64_t *errs) {
    if (rx) *rx = g_packets_received;
    if (tx) *tx = g_packets_sent;
    if (errs) *errs = g_checksum_errors;
}
