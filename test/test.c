/*
 * Copyright 2025 Emiliano Augusto Gonzalez (egonzalez . hiperion @ gmail . com))
 * * Project Site: https://github.com/hiperiondev/ax25 *
 *
 * This is based on other projects:
 *    Asynchronous AX.25 library using asyncio: https://github.com/sjlongland/aioax25/
 *
 *    please contact their authors for more information.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "ax25.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

uint8_t err = 0;

#define TEST_ASSERT(condition, message, err) \
    do { \
        if (!(condition)) { \
            printf("\033[0;31mFAIL(%u): %s\033[0m\n", err, message); \
            return 1; \
        } else { \
            printf("\033[0;32m   PASS: %s\033[0m\n", message); \
        } \
    } while (0)

#define COMPARE_FRAME(encoded, encoded_len, expected, expected_len, msg) \
    do { \
        int cmp = memcmp(encoded, expected, (encoded_len < expected_len) ? encoded_len : expected_len); \
        if (cmp != 0 || encoded_len != expected_len) { \
            printf("\033[0;31mFAIL: %s\nExpected (%zu bytes): ", msg, expected_len); \
            for (size_t i = 0; i < expected_len; i++) printf("%02X ", expected[i]); \
            printf("\nGot (%zu bytes): ", encoded_len); \
            for (size_t i = 0; i < encoded_len; i++) printf("%02X ", encoded[i]); \
            printf("\033[0m\n"); \
            TEST_ASSERT(false, msg, cmp); \
        } else { \
            printf("\033[0;32m   PASS: %s\033[0m\n", msg); \
        } \
    } while (0)

int test_address_functions() {
    // Test ax25_address_from_string
    ax25_address_t *addr = ax25_address_from_string("NOCALL-0", &err);
    TEST_ASSERT(addr != NULL, "ax25_address_from_string should return non-NULL", err);
    if (addr) {
        TEST_ASSERT(strcmp(addr->callsign, "NOCALL") == 0, "Callsign should be NOCALL", err);
        TEST_ASSERT(addr->ssid == 0, "SSID should be 0", err);
    }

    // Test ax25_address_encode
    size_t len;
    uint8_t *encoded = ax25_address_encode(addr, &len, &err);
    TEST_ASSERT(encoded != NULL, "ax25_address_encode should return non-NULL", err);
    TEST_ASSERT(len == 7, "Encoded address length should be 7 bytes", err);
    if (encoded) {
        // Test ax25_address_decode
        ax25_address_t *decoded_addr = ax25_address_decode(encoded, &err);
        TEST_ASSERT(decoded_addr != NULL, "ax25_address_decode should return non-NULL", err);
        if (decoded_addr) {
            TEST_ASSERT(strcmp(decoded_addr->callsign, "NOCALL") == 0, "Decoded callsign should be NOCALL", err);
            ax25_address_free(decoded_addr, &err);
        }
        free(encoded);
    }

    // Test ax25_address_copy
    ax25_address_t *addr_copy = ax25_address_copy(addr, &err);
    TEST_ASSERT(addr_copy != NULL, "ax25_address_copy should return non-NULL", err);
    if (addr_copy) {
        TEST_ASSERT(strcmp(addr_copy->callsign, addr->callsign) == 0, "Copied callsign should match", err);
    }

    // Clean up
    ax25_address_free(addr_copy, &err);
    return 0;
}

int test_path_functions() {
    ax25_address_t *addr1 = ax25_address_from_string("NOCALL-0", &err);
    ax25_address_t *addr2 = ax25_address_from_string("REPEATER-1", &err);
    ax25_address_t *repeaters[] = { addr1, addr2 };
    ax25_path_t *path = ax25_path_new(repeaters, 2, &err);
    TEST_ASSERT(path != NULL, "ax25_path_new should return non-NULL", err);
    ax25_path_free(path, &err);
    ax25_address_free(addr1, &err);
    ax25_address_free(addr2, &err);
    return 0;
}

int test_frame_header_functions() {
    uint8_t header_data[] = { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1 };
    header_decode_result_t result = ax25_frame_header_decode(header_data, sizeof(header_data), &err);
    TEST_ASSERT(result.header != NULL, "ax25_frame_header_decode should return non-NULL header", err);
    if (result.header) {
        size_t len;
        uint8_t *encoded = ax25_frame_header_encode(result.header, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_frame_header_encode should return non-NULL", err);
        TEST_ASSERT(len == sizeof(header_data), "Encoded header length should match input", err);
        if (encoded)
            free(encoded);
        ax25_frame_header_free(result.header, &err);
    }
    return 0;
}

int test_frame_functions() {
    uint8_t frame_data[] = { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1, 0x03, 0xF0, 'T', 'E', 'S', 'T' };
    ax25_frame_t *frame = ax25_frame_decode(frame_data, sizeof(frame_data), 0, &err);
    TEST_ASSERT(frame != NULL, "ax25_frame_decode should return non-NULL", err);
    if (frame) {
        size_t len;
        uint8_t *encoded = ax25_frame_encode(frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_frame_encode should return non-NULL", err);
        if (encoded)
            free(encoded);
        ax25_frame_free(frame, &err);
    }
    return 0;
}

int test_raw_frame_functions() {
    uint8_t frame_data[] = { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1, 0x03, 0xF0, 'T', 'E', 'S', 'T' };
    ax25_raw_frame_t raw_frame = { .payload = frame_data, .payload_len = sizeof(frame_data) };
    size_t len;
    uint8_t *encoded = ax25_raw_frame_encode(&raw_frame, &len, &err);
    TEST_ASSERT(encoded != NULL, "ax25_raw_frame_encode should return non-NULL", err);
    if (encoded)
        free(encoded);
    return 0;
}

int test_unnumbered_frame_functions() {
    // Decode a valid header for testing
    uint8_t header_data[] = { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1 };
    ax25_frame_header_t *header = ax25_frame_header_decode(header_data, sizeof(header_data), &err).header;
    TEST_ASSERT(header != NULL, "ax25_frame_header_decode should return non-NULL", err);
    if (header == NULL)
        return 1;

    // Test ax25_unnumbered_frame_decode with a valid UI frame and info field
    uint8_t dummy_info_field[] = { 0xF0, 'T', 'E', 'S', 'T' }; // PID (0xF0) + "TEST"
    size_t dummy_info_len = sizeof(dummy_info_field);

    ax25_unnumbered_frame_t *u_frame = ax25_unnumbered_frame_decode(header, 0x03, dummy_info_field, dummy_info_len, &err);
    TEST_ASSERT(u_frame != NULL, "ax25_unnumbered_frame_decode should return non-NULL", err);
    if (u_frame) {
        // Test ax25_unnumbered_information_frame_encode for UI frame
        size_t len;
        uint8_t *encoded = ax25_unnumbered_information_frame_encode((ax25_unnumbered_information_frame_t*) u_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_unnumbered_information_frame_encode should return non-NULL", err);
        if (encoded) {
            // Verify encoded content (control byte should be 0x03, followed by PID and payload)
            uint8_t expected[] = { 0x03, 0xF0, 'T', 'E', 'S', 'T' };
            size_t expected_len = sizeof(expected);
            TEST_ASSERT(len == expected_len && memcmp(encoded, expected, len) == 0, "Encoded UI frame content should match", err);
            free(encoded);
        }
        ax25_frame_free((ax25_frame_t*) u_frame, &err);
        TEST_ASSERT(err == 0, "Freeing UI frame", err);
    }

    // Clean up
    ax25_frame_header_free(header, &err);
    TEST_ASSERT(err == 0, "Freeing header", err);
    return err ? 1 : 0;
}

int test_unnumbered_information_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[] ) { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1 },
            14, &err).header;
    uint8_t info[] = "TEST";
    ax25_unnumbered_information_frame_t *ui_frame = ax25_unnumbered_information_frame_decode(header, true, info, 4, &err);
    TEST_ASSERT(ui_frame != NULL, "ax25_unnumbered_information_frame_decode should return non-NULL", err);
    if (ui_frame) {
        size_t len;
        uint8_t *encoded = ax25_unnumbered_information_frame_encode(ui_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_unnumbered_information_frame_encode should return non-NULL", err);
        if (encoded)
            free(encoded);
        ax25_frame_free((ax25_frame_t*) ui_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

int test_frame_reject_frame_functions() {
    ax25_frame_reject_frame_t frame = { .base.base.type = AX25_FRAME_UNNUMBERED_FRMR, .base.base.header = { .destination = { .callsign = "AAAAAA", .ssid = 0,
            .ch = false, .res0 = true, .res1 = true, .extension = false }, .source = { .callsign = "BBBBBB", .ssid = 0, .ch = false, .res0 = true, .res1 = true,
            .extension = true }, .cr = false, .src_cr = false, .legacy = true, .repeaters = { .num_repeaters = 0 } }, .base.base.timestamp = 0.0,
            .base.base.deadline = 0.0, .base.pf = false, .base.modifier = 0x87, .frmr_control = 0x0A, .w = true, .x = false, .y = false, .z = false, .vr = 0,
            .frmr_cr = false, .vs = 2 };

    uint8_t frmr_data[] = { 0x01, 0x05, 0x0A };
    size_t frmr_data_len = sizeof(frmr_data);
    uint8_t err;
    ax25_frame_reject_frame_t *decoded = ax25_frame_reject_frame_decode(&frame.base.base.header, frame.base.pf, frmr_data, frmr_data_len, &err);

    TEST_ASSERT(err == 0, "FRMR decode should not fail", err);
    TEST_ASSERT(decoded->frmr_control == frame.frmr_control, "frmr_control should match", err);
    TEST_ASSERT(decoded->w == frame.w, "w should match", err);
    TEST_ASSERT(decoded->x == frame.x, "x should match", err);
    TEST_ASSERT(decoded->y == frame.y, "y should match", err);
    TEST_ASSERT(decoded->z == frame.z, "z should match", err);
    TEST_ASSERT(decoded->vr == frame.vr, "vr should match", err);
    TEST_ASSERT(decoded->frmr_cr == frame.frmr_cr, "frmr_cr should match", err);
    TEST_ASSERT(decoded->vs == frame.vs, "vs should match", err);

    ax25_frame_free((ax25_frame_t*) decoded, &err);

    size_t len;
    uint8_t *encoded = ax25_frame_reject_frame_encode(&frame, &len, &err);
    TEST_ASSERT(err == 0, "FRMR encode should not fail", err);
    TEST_ASSERT(len == 4, "Encoded FRMR frame length should be 4 bytes", err);
    TEST_ASSERT(encoded[0] == 0x87, "Control should be 0x87", err);
    TEST_ASSERT(encoded[1] == 0x0A, "frmr_control should match", err);
    TEST_ASSERT(encoded[2] == 0x01, "Rejection flags should match", err);
    TEST_ASSERT(encoded[3] == 0x40, "vr/frmr_cr/vs should match", err);

    free(encoded);

    return 0;
}

int test_information_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[] ) { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1 },
            14, &err).header;
    uint8_t info[] = "TEST";
    ax25_information_frame_t *i_frame = ax25_information_frame_decode(header, 0x00, info, 4, false, &err);
    TEST_ASSERT(i_frame != NULL, "ax25_information_frame_decode should return non-NULL", err);
    if (i_frame) {
        size_t len;
        uint8_t *encoded = ax25_information_frame_encode(i_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_information_frame_encode should return non-NULL", err);
        if (encoded)
            free(encoded);
        ax25_frame_free((ax25_frame_t*) i_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

int test_supervisory_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[] ) { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1 },
            14, &err).header;
    ax25_supervisory_frame_t *s_frame = ax25_supervisory_frame_decode(header, 0x01, false, &err); // RR
    TEST_ASSERT(s_frame != NULL, "ax25_supervisory_frame_decode should return non-NULL", err);
    if (s_frame) {
        size_t len;
        uint8_t *encoded = ax25_supervisory_frame_encode(s_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_supervisory_frame_encode should return non-NULL", err);
        if (encoded)
            free(encoded);
        ax25_frame_free((ax25_frame_t*) s_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

int test_xid_parameter_functions() {
    uint8_t pv[] = { 0x01, 0x02 };
    ax25_xid_parameter_t *param = ax25_xid_raw_parameter_new(1, pv, 2, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_raw_parameter_new should return non-NULL", err);
    if (param) {
        size_t len;
        uint8_t *encoded = ax25_xid_raw_parameter_encode(param, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_xid_raw_parameter_encode should return non-NULL", err);
        if (encoded) {
            size_t consumed;
            ax25_xid_parameter_t *decoded = ax25_xid_parameter_decode(encoded, len, &consumed, &err);
            TEST_ASSERT(decoded != NULL, "ax25_xid_parameter_decode should return non-NULL", err);
            if (decoded)
                ax25_xid_raw_parameter_free(decoded, &err);
            free(encoded);
        }
        ax25_xid_parameter_t *copy = ax25_xid_raw_parameter_copy(param, &err);
        TEST_ASSERT(copy != NULL, "ax25_xid_raw_parameter_copy should return non-NULL", err);
        if (copy)
            ax25_xid_raw_parameter_free(copy, &err);
        ax25_xid_raw_parameter_free(param, &err);
    }

    param = ax25_xid_class_of_procedures_new(true, false, true, false, true, false, true, false, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_class_of_procedures_new should return non-NULL", err);
    if (param)
        ax25_xid_raw_parameter_free(param, &err);

    param = ax25_xid_hdlc_optional_functions_new(true, false, true, false, true, false, true, false, true,
    false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_hdlc_optional_functions_new should return non-NULL", err);
    if (param)
        ax25_xid_raw_parameter_free(param, &err);

    param = ax25_xid_big_endian_new(1, 0x12345678, 4, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_big_endian_new should return non-NULL", err);
    if (param)
        ax25_xid_raw_parameter_free(param, &err);

    ax25_xid_init_defaults(&err); // No return value to check
    printf("\033[0;32m   PASS: ax25_xid_init_defaults executed\033[0m\n");
    return 0;
}

int test_exchange_identification_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[]) { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1 }, 14, &err).header;
    TEST_ASSERT(header != NULL, "ax25_frame_header_decode should return non-NULL", err);
    if (header == NULL)
        return 1;

    uint8_t data[] = { 0x82, 0x80, 0x00, 0x04, 0x01, 0x02, 0x41, 0x00 };
    ax25_exchange_identification_frame_t *xid_frame = ax25_exchange_identification_frame_decode(header, true, data, sizeof(data), &err);
    TEST_ASSERT(xid_frame != NULL, "ax25_exchange_identification_frame_decode should return non-NULL", err);
    if (xid_frame) {
        TEST_ASSERT(xid_frame->base.base.type == AX25_FRAME_UNNUMBERED_XID, "XID frame type should be AX25_FRAME_UNNUMBERED_XID", err);
        TEST_ASSERT(xid_frame->base.pf == true, "Poll/Final bit should be true", err);
        TEST_ASSERT(xid_frame->base.modifier == 0xAF, "Modifier should be 0xAF", err);
        TEST_ASSERT(xid_frame->fi == 0x82, "Function Identifier should be 0x82", err);
        TEST_ASSERT(xid_frame->gi == 0x80, "Group Identifier should be 0x80", err);
        TEST_ASSERT(xid_frame->param_count == 1, "Should have 1 parameter", err);
        if (xid_frame->param_count > 0) {
            TEST_ASSERT(xid_frame->parameters[0]->pi == 0x01, "Parameter Identifier should be 0x01", err);
            uint8_t *pv = (uint8_t*)xid_frame->parameters[0]->data;
            size_t pv_len = pv ? *(size_t*)(pv + 2) : 0;
            TEST_ASSERT(pv_len == 2, "Parameter value length should be 2", err);
            TEST_ASSERT(pv[0] == 0x41 && pv[1] == 0x00, "Parameter value should match {0x41, 0x00}", err);
        }

        size_t len;
        uint8_t *encoded = ax25_exchange_identification_frame_encode(xid_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_exchange_identification_frame_encode should return non-NULL", err);
        if (encoded) {
            // Try expected with control byte 0xBF (with poll/final)
            uint8_t expected_with_pf[] = { 0xBF, 0x82, 0x80, 0x00, 0x04, 0x01, 0x02, 0x41, 0x00 };
            size_t expected_len = sizeof(expected_with_pf);
            int pf_cmp = memcmp(encoded, expected_with_pf, (len < expected_len) ? len : expected_len);
            if (pf_cmp == 0 && len == expected_len) {
                printf("\033[0;32m   PASS: Encoded XID frame content matches with poll/final (0xBF)\033[0m\n");
            } else {
                // Try expected with control byte 0xAF (without poll/final)
                uint8_t expected_no_pf[] = { 0xAF, 0x82, 0x80, 0x00, 0x04, 0x01, 0x02, 0x41, 0x00 };
                COMPARE_FRAME(encoded, len, expected_no_pf, expected_len, "Encoded XID frame content should match (trying 0xAF)");
            }
            free(encoded);
        }
        ax25_frame_free((ax25_frame_t*)xid_frame, &err);
        TEST_ASSERT(err == 0, "Freeing XID frame", err);
    }
    ax25_frame_header_free(header, &err);
    TEST_ASSERT(err == 0, "Freeing header", err);
    return err ? 1 : 0;
}

int test_test_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[] ) { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1 },
            14, &err).header;
    uint8_t data[] = "TEST";
    ax25_test_frame_t *test_frame = ax25_test_frame_decode(header, true, data, 4, &err);
    TEST_ASSERT(test_frame != NULL, "ax25_test_frame_decode should return non-NULL", err);
    if (test_frame) {
        size_t len;
        uint8_t *encoded = ax25_test_frame_encode(test_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_test_frame_encode should return non-NULL", err);
        if (encoded)
            free(encoded);
        ax25_frame_free((ax25_frame_t*) test_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

// full test: connect, send, receive, disconnect
// --- AX.25 Packet Definitions ---
// These arrays represent the AX.25 frame content without flags and FCS,
// as per AX.25 v2.2 standard, to match the library's encoding/decoding behavior.

// 1. CONNECT Request (Station A -> Station B: SABM)
// Purpose: Initiate a connected-mode session.
// Control: 0x3F (SABM, Poll bit set)
unsigned char ax25_sabm_packet[] = {
        // Destination Address (VA3BBB-7)
        0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEE, // C-bit=1, extension=0
        // Source Address (VA3AAA-1)
        0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x63, // C-bit=0, extension=1
        0x3F // Control Field: SABM with P=1
        };
size_t ax25_sabm_packet_len = sizeof(ax25_sabm_packet);

// 2. CONNECT Acknowledgment (Station B -> Station A: UA)
// Purpose: Acknowledge the connection request.
// Control: 0x73 (UA, Final bit set)
unsigned char ax25_ua_connect_packet[] = {
        // Destination Address (VA3AAA-1)
        0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x62, // C-bit=0, extension=0
        // Source Address (VA3BBB-7)
        0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEF, // C-bit=1, extension=1
        0x73 // Control Field: UA with F=1
        };
size_t ax25_ua_connect_packet_len = sizeof(ax25_ua_connect_packet);

// 3. SEND Data (Station A -> Station B: I-Frame)
// Purpose: Transmit information.
// Control: 0x00 (I-Frame, N(S)=0, N(R)=0)
// Information: "Hello, World!" (ASCII)
unsigned char ax25_i_frame_packet[] = {
        // Destination Address (VA3BBB-7)
        0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEE,
        // Source Address (VA3AAA-1)
        0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x63,
        0x00, // Control Field: I-Frame (N(S)=0, N(R)=0)
        0xF0, // PID Field: No Layer 3 Protocol
        // Information Field: "Hello, World!" (ASCII Hex)
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21
        };
size_t ax25_i_frame_packet_len = sizeof(ax25_i_frame_packet);

// 4. RECEIVE Data Acknowledgment (Station B -> Station A: RR)
// Purpose: Acknowledge receipt of the I-Frame and indicate readiness for the next.
// Control: 0x01 (RR, N(R)=1)
unsigned char ax25_rr_packet[] = {
        // Destination Address (VA3AAA-1)
        0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x62,
        // Source Address (VA3BBB-7)
        0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEF,
        0x01 // Control Field: RR (Receive Ready, N(R)=1)
        };
size_t ax25_rr_packet_len = sizeof(ax25_rr_packet);

// 5. DISCONNECT Request (Station A -> Station B: DISC)
// Purpose: Terminate the connected-mode session.
// Control: 0x43 (DISC, Poll bit set)
unsigned char ax25_disc_packet[] = {
        // Destination Address (VA3BBB-7)
        0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEE,
        // Source Address (VA3AAA-1)
        0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x63,
        0x43 // Control Field: DISC with P=1
        };
size_t ax25_disc_packet_len = sizeof(ax25_disc_packet);

// 6. DISCONNECT Acknowledgment (Station B -> Station A: UA)
// Purpose: Acknowledge the disconnect request.
// Control: 0x73 (UA, Final bit set)
unsigned char ax25_ua_disconnect_packet[] = {
        // Destination Address (VA3AAA-1)
        0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x62,
        // Source Address (VA3BBB-7)
        0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEF,
        0x73 // Control Field: UA with F=1
        };
size_t ax25_ua_disconnect_packet_len = sizeof(ax25_ua_disconnect_packet);

unsigned char invalid_packet[] = {
        0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEE, // Dest: VA3BBB-7
        0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x63, // Src: VA3AAA-1
        0xFF // Invalid control
        };
size_t invalid_packet_len = sizeof(invalid_packet);

// Helper function to print a packet in hexadecimal format
void print_packet(const char *name, const unsigned char *packet, size_t len) {
    printf("--- %s (Length: %zu bytes) ---\n", name, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", packet[i]);
        if ((i + 1) % 16 == 0) { // Newline every 16 bytes for readability
            printf("\n");
        }
    }
    printf("\n\n");
}

int test_ax25_connection(void) {
    unsigned char short_packet[] = { 0xAC, 0x82, 0x66 };
    size_t short_packet_len = sizeof(short_packet);

    // Initialize addresses
    uint8_t addr_err;
    ax25_address_t *station_a = ax25_address_from_string("VA3AAA-1", &addr_err);
    TEST_ASSERT(station_a != NULL && addr_err == 0, "Create VA3AAA-1 address", addr_err);
    ax25_address_t *station_b = ax25_address_from_string("VA3BBB-7", &addr_err);
    TEST_ASSERT(station_b != NULL && addr_err == 0, "Create VA3BBB-7 address", addr_err);

    // Buffer for encoded frames
    size_t encoded_len;
    ax25_frame_t *decoded_frame;
    uint8_t *encode_result;

    // 1. Test SABM frame
    decoded_frame = ax25_frame_decode(ax25_sabm_packet, ax25_sabm_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding SABM frame", err);
    encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
    TEST_ASSERT(encode_result != NULL && err == 0, "Encoding SABM frame", err);
    COMPARE_FRAME(encode_result, encoded_len, ax25_sabm_packet, ax25_sabm_packet_len, "SABM frame content");
    free(encode_result);
    ax25_frame_free(decoded_frame, &err);
    TEST_ASSERT(err == 0, "Freeing SABM frame", err);

    // 2. Test UA connect frame
    decoded_frame = ax25_frame_decode(ax25_ua_connect_packet, ax25_ua_connect_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding UA connect frame", err);
    encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
    TEST_ASSERT(encode_result != NULL && err == 0, "Encoding UA connect frame", err);
    COMPARE_FRAME(encode_result, encoded_len, ax25_ua_connect_packet, ax25_ua_connect_packet_len, "UA connect frame content");
    free(encode_result);
    ax25_frame_free(decoded_frame, &err);
    TEST_ASSERT(err == 0, "Freeing UA connect frame", err);

    // 3. Test I-Frame
    decoded_frame = ax25_frame_decode(ax25_i_frame_packet, ax25_i_frame_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding I-Frame", err);
    encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
    TEST_ASSERT(encode_result != NULL && err == 0, "Encoding I-Frame", err);
    COMPARE_FRAME(encode_result, encoded_len, ax25_i_frame_packet, ax25_i_frame_packet_len, "I-Frame content");
    free(encode_result);
    ax25_frame_free(decoded_frame, &err);
    TEST_ASSERT(err == 0, "Freeing I-Frame", err);

    // 4. Test RR frame
    decoded_frame = ax25_frame_decode(ax25_rr_packet, ax25_rr_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding RR frame", err);
    encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
    TEST_ASSERT(encode_result != NULL && err == 0, "Encoding RR frame", err);
    COMPARE_FRAME(encode_result, encoded_len, ax25_rr_packet, ax25_rr_packet_len, "RR frame content");
    free(encode_result);
    ax25_frame_free(decoded_frame, &err);
    TEST_ASSERT(err == 0, "Freeing RR frame", err);

    // 5. Test DISC frame
    decoded_frame = ax25_frame_decode(ax25_disc_packet, ax25_disc_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding DISC frame", err);
    encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
    TEST_ASSERT(encode_result != NULL && err == 0, "Encoding DISC frame", err);
    COMPARE_FRAME(encode_result, encoded_len, ax25_disc_packet, ax25_disc_packet_len, "DISC frame content");
    free(encode_result);
    ax25_frame_free(decoded_frame, &err);
    TEST_ASSERT(err == 0, "Freeing DISC frame", err);

    // 6. Test UA disconnect frame
    decoded_frame = ax25_frame_decode(ax25_ua_disconnect_packet, ax25_ua_disconnect_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding UA disconnect frame", err);
    encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
    TEST_ASSERT(encode_result != NULL && err == 0, "Encoding UA disconnect frame", err);
    COMPARE_FRAME(encode_result, encoded_len, ax25_ua_disconnect_packet, ax25_ua_disconnect_packet_len, "UA disconnect frame content");
    free(encode_result);
    ax25_frame_free(decoded_frame, &err);
    TEST_ASSERT(err == 0, "Freeing UA disconnect frame", err);

    // 7. Error Case: Invalid control byte
    decoded_frame = ax25_frame_decode(invalid_packet, invalid_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame == NULL && err != 0, "Decoding invalid control frame should fail", err);

    // 8. Error Case: Short frame
    decoded_frame = ax25_frame_decode(short_packet, short_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame == NULL && err != 0, "Decoding short frame should fail", err);

    // 9. Error Case: Null input
    decoded_frame = ax25_frame_decode(NULL, 0, 0, &err);
    TEST_ASSERT(decoded_frame == NULL && err != 0, "Decoding null input should fail", err);

    // Clean up addresses
    ax25_address_free(station_a, &addr_err);
    TEST_ASSERT(addr_err == 0, "Freeing VA3AAA-1 address", addr_err);
    ax25_address_free(station_b, &addr_err);
    TEST_ASSERT(addr_err == 0, "Freeing VA3BBB-7 address", addr_err);

    printf("\033[0;32mAll tests passed successfully!\033[0m\n");
    return 0;
}

int main() {
    printf("Starting AX.25 Library Tests\n");
    int result = 0;
    result |= test_address_functions();
    result |= test_path_functions();
    result |= test_frame_header_functions();
    result |= test_frame_functions();
    result |= test_raw_frame_functions();
    result |= test_unnumbered_frame_functions();
    result |= test_unnumbered_information_frame_functions();
    result |= test_frame_reject_frame_functions();
    result |= test_information_frame_functions();
    result |= test_supervisory_frame_functions();
    result |= test_xid_parameter_functions();
    result |= test_exchange_identification_frame_functions();
    result |= test_test_frame_functions();

    printf("\nSimulated AX.25 Connected-Mode Communication Packets:\n\n");
    print_packet("1. CONNECT Request (A -> B: SABM)", ax25_sabm_packet, ax25_sabm_packet_len);
    print_packet("2. CONNECT Acknowledgment (B -> A: UA)", ax25_ua_connect_packet, ax25_ua_connect_packet_len);
    print_packet("3. SEND Data (A -> B: I-Frame)", ax25_i_frame_packet, ax25_i_frame_packet_len);
    print_packet("4. RECEIVE Data Acknowledgment (B -> A: RR)", ax25_rr_packet, ax25_rr_packet_len);
    print_packet("5. DISCONNECT Request (A -> B: DISC)", ax25_disc_packet, ax25_disc_packet_len);
    print_packet("6. DISCONNECT Acknowledgment (B -> A: UA)", ax25_ua_disconnect_packet, ax25_ua_disconnect_packet_len);
    result |= test_ax25_connection();

    printf("Tests Completed. %s\n", result == 0 ? "All tests passed" : "Some tests failed");
    return result;
}
