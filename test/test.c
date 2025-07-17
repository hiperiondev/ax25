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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ax25.h"
#include "hdlc.h"
#include "utils.h"

uint32_t assert_count = 0;

#define TEST_ASSERT(condition, message, err) \
    do { \
        if (!(condition)) { \
            printf("\033[0;31m[%04d] FAIL(%u): %s\033[0m\n", ++assert_count, err, message); \
            return 1; \
        } else { \
            printf("\033[0;32m[%04d]    PASS: %s\033[0m\n", ++assert_count, message); \
        } \
    } while (0)

#define COMPARE_FRAME(encoded, encoded_len, expected, expected_len, msg) \
    do { \
        int cmp = memcmp(encoded, expected, (encoded_len < expected_len) ? encoded_len : expected_len); \
        if (cmp != 0 || encoded_len != expected_len) { \
            printf("\033[0;31m[%04d] FAIL: %s\nExpected (%zu bytes): ", ++assert_count, msg, expected_len); \
            for (size_t i = 0; i < expected_len; i++) printf("%02X ", expected[i]); \
            printf("\nGot (%zu bytes): ", encoded_len); \
            for (size_t i = 0; i < encoded_len; i++) printf("%02X ", encoded[i]); \
            printf("\033[0m\n"); \
            TEST_ASSERT(false, msg, cmp); \
        } else { \
            printf("\033[0;32m[%04d]    PASS: %s\033[0m\n", ++assert_count, msg); \
        } \
    } while (0)

#define PRINT_PACKET(packet, len)   \
    printf("         -- packet: "); \
    for (uint32_t n=0;n<len;n++)    \
        printf("%02x ", packet[n]); \
    printf("\n")

int test_address_functions() {
    uint8_t err = 0;

    // Test ax25_address_from_string with "NOCALL-7*"
    ax25_address_t *addr = ax25_address_from_string("NOCALL-7*", &err);
    TEST_ASSERT(addr != NULL, "  ax25_address_from_string should return non-NULL", err);
    if (addr) {
        TEST_ASSERT(strcmp(addr->callsign, "NOCALL") == 0, "Callsign should be NOCALL", err);
        TEST_ASSERT(addr->ssid == 7, "SSID should be 7", err);
        TEST_ASSERT(addr->ch == true, "ch should be true due to '*'", err);
        TEST_ASSERT(addr->res0 == true, "res0 should be true", err);
        TEST_ASSERT(addr->res1 == true, "res1 should be true", err);
        TEST_ASSERT(addr->extension == false, "extension should be false", err);

        // Test ax25_address_encode
        size_t len;
        uint8_t *encoded = ax25_address_encode(addr, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_address_encode should return non-NULL", err);
        TEST_ASSERT(len == 7, "Encoded address length should be 7 bytes", err);
        if (encoded) {
            uint8_t expected[] = { 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xEE };
            TEST_ASSERT(memcmp(encoded, expected, 7) == 0, "Encoded address should match expected bytes", err);

            // Test ax25_address_decode
            ax25_address_t *decoded_addr = ax25_address_decode(encoded, &err);
            TEST_ASSERT(decoded_addr != NULL, "ax25_address_decode should return non-NULL", err);
            if (decoded_addr) {
                TEST_ASSERT(strcmp(decoded_addr->callsign, "NOCALL") == 0, "Decoded callsign should be NOCALL", err);
                TEST_ASSERT(decoded_addr->ssid == 7, "Decoded SSID should be 7", err);
                TEST_ASSERT(decoded_addr->ch == true, "Decoded ch should be true", err);
                TEST_ASSERT(decoded_addr->res0 == true, "Decoded res0 should be true", err);
                TEST_ASSERT(decoded_addr->res1 == true, "Decoded res1 should be true", err);
                TEST_ASSERT(decoded_addr->extension == false, "Decoded extension should be false", err);
                ax25_address_free(decoded_addr, &err);
            }
            free(encoded);
        }

        // Test ax25_address_copy
        ax25_address_t *addr_copy = ax25_address_copy(addr, &err);
        TEST_ASSERT(addr_copy != NULL, "ax25_address_copy should return non-NULL", err);
        if (addr_copy) {
            TEST_ASSERT(strcmp(addr_copy->callsign, addr->callsign) == 0, "Copied callsign should match", err);
            TEST_ASSERT(addr_copy->ssid == addr->ssid, "Copied SSID should match", err);
            TEST_ASSERT(addr_copy->ch == addr->ch, "Copied ch should match", err);
            TEST_ASSERT(addr_copy->res0 == addr->res0, "Copied res0 should match", err);
            TEST_ASSERT(addr_copy->res1 == addr->res1, "Copied res1 should match", err);
            TEST_ASSERT(addr_copy->extension == addr->extension, "Copied extension should match", err);
            ax25_address_free(addr_copy, &err);
        }
        ax25_address_free(addr, &err);
    }

    // Test modulo-128 source address with res1 = false
    ax25_address_t *addr_mod128 = ax25_address_from_string("SOURCE-0", &err);
    TEST_ASSERT(addr_mod128 != NULL, "ax25_address_from_string should return non-NULL for modulo-128 source", err);
    if (addr_mod128) {
        addr_mod128->res1 = false; // Set res1 to false for modulo-128 source address
        TEST_ASSERT(addr_mod128->res0 == true, "res0 should be true for modulo-128 source", err);
        TEST_ASSERT(addr_mod128->res1 == false, "res1 should be false for modulo-128 source", err);

        size_t len;
        uint8_t *encoded = ax25_address_encode(addr_mod128, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_address_encode should return non-NULL for modulo-128 source", err);
        TEST_ASSERT(len == 7, "Encoded length should be 7 for modulo-128 source", err);
        if (encoded) {
            // Expected SSID byte: SSID=0 (0<<1)=0x00, extension=0 (0x00), res0=1 (0x20), res1=0 (0x00), ch=0 (0x00) = 0x20
            uint8_t expected[] = { 'S' << 1, 'O' << 1, 'U' << 1, 'R' << 1, 'C' << 1, 'E' << 1, 0x20 }; // 0xA2, 0x9E, 0xB4, 0xA0, 0x86, 0x8A, 0x20
            TEST_ASSERT(memcmp(encoded, expected, 7) == 0, "Encoded modulo-128 source address should match expected bytes", err);
            TEST_ASSERT((encoded[6] & 0x40) == 0, "Bit 6 (res1) should be 0 for modulo-128 source address", err);
            free(encoded);
        }
        ax25_address_free(addr_mod128, &err);
    }

    return 0;
}

int test_path_functions() {
    uint8_t err = 0;

    // Create addresses for path
    ax25_address_t *addr1 = ax25_address_from_string("NOCALL-0", &err);
    ax25_address_t *addr2 = ax25_address_from_string("REPEATER-1*", &err);
    ax25_address_t *repeaters[] = { addr1, addr2 };
    ax25_path_t *path = ax25_path_new(repeaters, 2, &err);
    TEST_ASSERT(path != NULL, "ax25_path_new should return non-NULL", err);
    if (path) {
        TEST_ASSERT(path->num_repeaters == 2, "Path should have 2 repeaters", err);
        TEST_ASSERT(strcmp(path->repeaters[0].callsign, "NOCALL") == 0, "Repeater 0 callsign should be NOCALL", err);
        TEST_ASSERT(path->repeaters[0].ssid == 0, "Repeater 0 SSID should be 0", err);
        TEST_ASSERT(path->repeaters[0].ch == false, "Repeater 0 ch should be false", err);
        TEST_ASSERT(strcmp(path->repeaters[1].callsign, "REPEAT") == 0, "Repeater 1 callsign should be REPEAT", err);
        TEST_ASSERT(path->repeaters[1].ssid == 1, "Repeater 1 SSID should be 1", err);
        TEST_ASSERT(path->repeaters[1].ch == true, "Repeater 1 ch should be true", err);
        ax25_path_free(path, &err);
    }
    ax25_address_free(addr1, &err);
    ax25_address_free(addr2, &err);
    return 0;
}

int test_modulo128_source_address() {
    uint8_t err = 0;

    // Create addresses
    ax25_address_t dest = { .callsign = "NOCALL", .ssid = 0, .ch = true, .res0 = true, .res1 = true, .extension = false };
    ax25_address_t src = { .callsign = "REPEAT", .ssid = 1, .ch = false, .res0 = true, .res1 = true, .extension = true };
    // Set callsign properly
    memset(dest.callsign, ' ', 6);
    memcpy(dest.callsign, "NOCALL", 6);
    memset(src.callsign, ' ', 6);
    memcpy(src.callsign, "REPEAT", 6);

    // Create a modulo-128 I-frame
    ax25_information_frame_t i_frame;
    i_frame.base.type = AX25_FRAME_INFORMATION_16BIT;
    i_frame.base.header.destination = dest;
    i_frame.base.header.source = src;
    i_frame.base.header.cr = true;
    i_frame.base.header.src_cr = false;
    i_frame.base.header.repeaters.num_repeaters = 0;
    i_frame.nr = 3;
    i_frame.pf = true;
    i_frame.ns = 5;
    i_frame.pid = 0xF0;
    i_frame.payload_len = 4;
    i_frame.payload = (uint8_t*) "TEST";

    // Encode the frame
    size_t len;
    uint8_t *encoded = ax25_frame_encode((ax25_frame_t*) &i_frame, &len, &err);
    TEST_ASSERT(encoded != NULL, "Frame encoding should succeed", err);
    if (encoded) {
        // Source address is bytes 7 to 13
        uint8_t source_ssid_byte = encoded[13];
        TEST_ASSERT((source_ssid_byte & 0x40) == 0, "Source SSID bit 6 should be 0 for modulo-128", err);
        // Expected SSID byte: 0x23
        TEST_ASSERT(source_ssid_byte == 0x23, "Source SSID byte should be 0x23", err);
        free(encoded);
    }
    return 0;
}

int test_modulo8_source_address() {
    uint8_t err = 0;

    // Create addresses
    ax25_address_t dest = { .callsign = "NOCALL", .ssid = 0, .ch = true, .res0 = true, .res1 = true, .extension = false };
    ax25_address_t src = { .callsign = "REPEAT", .ssid = 1, .ch = false, .res0 = true, .res1 = true, .extension = true };
    memset(dest.callsign, ' ', 6);
    memcpy(dest.callsign, "NOCALL", 6);
    memset(src.callsign, ' ', 6);
    memcpy(src.callsign, "REPEAT", 6);

    // Create a modulo-8 I-frame
    ax25_information_frame_t i_frame;
    i_frame.base.type = AX25_FRAME_INFORMATION_8BIT;
    i_frame.base.header.destination = dest;
    i_frame.base.header.source = src;
    i_frame.base.header.cr = true;
    i_frame.base.header.src_cr = false;
    i_frame.base.header.repeaters.num_repeaters = 0;
    i_frame.nr = 3;
    i_frame.pf = true;
    i_frame.ns = 5;
    i_frame.pid = 0xF0;
    i_frame.payload_len = 4;
    i_frame.payload = (uint8_t*) "TEST";

    // Encode the frame
    size_t len;
    uint8_t *encoded = ax25_frame_encode((ax25_frame_t*) &i_frame, &len, &err);
    TEST_ASSERT(encoded != NULL, "Frame encoding should succeed", err);
    if (encoded) {
        // Source address is bytes 7 to 13
        uint8_t source_ssid_byte = encoded[13];
        TEST_ASSERT((source_ssid_byte & 0x40) == 0x40, "Source SSID bit 6 should be 1 for modulo-8", err);
        // Expected SSID byte: 0x63
        TEST_ASSERT(source_ssid_byte == 0x63, "Source SSID byte should be 0x63", err);
        free(encoded);
    }
    return 0;
}

int test_frame_header_functions() {
    uint8_t err = 0;

    // Test data: Header with destination "ABCDEF-7" and source "GHIJKL-1*"
    // Dest: 'A'<<1=0x82, 'B'<<1=0x84, 'C'<<1=0x86, 'D'<<1=0x88, 'E'<<1=0x8A, 'F'<<1=0x8C, SSID=7, ch=1, res0=1, res1=1, ext=0: 0xEE
    // Src:  'G'<<1=0x8E, 'H'<<1=0x90, 'I'<<1=0x92, 'J'<<1=0x94, 'K'<<1=0x96, 'L'<<1=0x98, SSID=1, ch=0, res0=1, res1=1, ext=1: 0x63
    uint8_t header_data[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63 };
    header_decode_result_t result = ax25_frame_header_decode(header_data, sizeof(header_data), &err);
    TEST_ASSERT(result.header != NULL, "ax25_frame_header_decode should return non-NULL header", err);
    if (result.header) {
        // Verify all fields
        TEST_ASSERT(strcmp(result.header->destination.callsign, "ABCDEF") == 0, "Destination callsign should be ABCDEF", err);
        TEST_ASSERT(result.header->destination.ssid == 7, "Destination SSID should be 7", err);
        TEST_ASSERT(result.header->destination.ch == true, "Destination ch should be true", err);
        TEST_ASSERT(result.header->destination.res0 == true, "Destination res0 should be true", err);
        TEST_ASSERT(result.header->destination.res1 == true, "Destination res1 should be true", err);
        TEST_ASSERT(result.header->destination.extension == false, "Destination extension should be false", err);

        TEST_ASSERT(strcmp(result.header->source.callsign, "GHIJKL") == 0, "Source callsign should be GHIJKL", err);
        TEST_ASSERT(result.header->source.ssid == 1, "Source SSID should be 1", err);
        TEST_ASSERT(result.header->source.ch == false, "Source ch should be false", err);
        TEST_ASSERT(result.header->source.res0 == true, "Source res0 should be true", err);
        TEST_ASSERT(result.header->source.res1 == true, "Source res1 should be true", err);
        TEST_ASSERT(result.header->source.extension == true, "Source extension should be true", err);

        TEST_ASSERT(result.header->cr == true, "cr should be true (dest ch=1, src ch=0)", err);
        TEST_ASSERT(result.header->src_cr == false, "src_cr should be false", err);
        TEST_ASSERT(result.header->repeaters.num_repeaters == 0, "No repeaters expected", err);

        size_t len;
        uint8_t *encoded = ax25_frame_header_encode(result.header, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_frame_header_encode should return non-NULL", err);
        TEST_ASSERT(len == sizeof(header_data), "Encoded header length should match input", err);
        COMPARE_FRAME(encoded, len, header_data, sizeof(header_data), "Header re-encoding should match");
        free(encoded);
        ax25_frame_header_free(result.header, &err);
    }
    return 0;
}

int test_frame_functions() {
    uint8_t err = 0;

    // Test data: UI frame with dest "ABCDEF-7", src "GHIJKL-1*", control=0x03, PID=0xF0, payload="TEST"
    uint8_t frame_data[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63, 0x03, 0xF0, 'T', 'E', 'S', 'T' };
    ax25_frame_t *frame = ax25_frame_decode(frame_data, sizeof(frame_data), 0, &err);
    TEST_ASSERT(frame != NULL, "ax25_frame_decode should return non-NULL", err);
    if (frame) {
        TEST_ASSERT(frame->type == AX25_FRAME_UNNUMBERED_INFORMATION, "Frame type should be UI", err);
        ax25_unnumbered_information_frame_t *ui_frame = (ax25_unnumbered_information_frame_t*) frame;
        TEST_ASSERT(strcmp(ui_frame->base.base.header.destination.callsign, "ABCDEF") == 0, "Destination callsign should be ABCDEF", err);
        TEST_ASSERT(ui_frame->base.base.header.destination.ssid == 7, "Destination SSID should be 7", err);
        TEST_ASSERT(ui_frame->base.base.header.source.ssid == 1, "Source SSID should be 1", err);
        TEST_ASSERT(ui_frame->base.pf == false, "Poll/Final should be false", err);
        TEST_ASSERT(ui_frame->base.modifier == 0x03, "Modifier should be 0x03", err);
        TEST_ASSERT(ui_frame->pid == 0xF0, "PID should be 0xF0", err);
        TEST_ASSERT(ui_frame->payload_len == 4, "Payload length should be 4", err);
        TEST_ASSERT(memcmp(ui_frame->payload, "TEST", 4) == 0, "Payload should be 'TEST'", err);

        size_t len;
        uint8_t *encoded = ax25_frame_encode(frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_frame_encode should return non-NULL", err);
        COMPARE_FRAME(encoded, len, frame_data, sizeof(frame_data), "Frame re-encoding should match");
        free(encoded);
        ax25_frame_free(frame, &err);
    }
    return 0;
}

int test_raw_frame_functions() {
    uint8_t err = 0;

    // Test data: Raw frame with header and payload, control byte set to 0x00 (I-frame)
    uint8_t frame_data[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63, 0x00, 0xF0, 'T', 'E', 'S', 'T' };
    ax25_frame_t *frame = ax25_frame_decode(frame_data, sizeof(frame_data), MODULO128_NONE, &err);
    TEST_ASSERT(frame != NULL, "ax25_frame_decode should return non-NULL", err);
    if (frame) {
        TEST_ASSERT(frame->type == AX25_FRAME_RAW, "Frame type should be RAW", err);
        ax25_raw_frame_t *raw_frame = (ax25_raw_frame_t*) frame;
        TEST_ASSERT(raw_frame->control == 0x00, "Control should be 0x00", err);
        TEST_ASSERT(raw_frame->payload_len == 5, "Payload length should be 5", err);
        TEST_ASSERT(memcmp(raw_frame->payload, "\xF0TEST", 5) == 0, "Payload should be 0xF0 followed by 'TEST'", err);

        size_t len;
        uint8_t *encoded = ax25_raw_frame_encode(raw_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_raw_frame_encode should return non-NULL", err);
        TEST_ASSERT(len == 6, "Encoded length should be 6 (control + payload)", err);
        TEST_ASSERT(memcmp(encoded, "\x00\xF0TEST", 6) == 0, "Encoded raw frame should match control + payload", err);
        free(encoded);
        ax25_frame_free(frame, &err);
    }
    return 0;
}

int test_unnumbered_frame_functions() {
    uint8_t err = 0;

    // Test data: Header for "ABCDEF-7" -> "GHIJKL-1*"
    uint8_t header_data[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63 };
    ax25_frame_header_t *header = ax25_frame_header_decode(header_data, sizeof(header_data), &err).header;
    TEST_ASSERT(header != NULL, "ax25_frame_header_decode should return non-NULL", err);
    if (header) {
        // Test UI frame with PID=0xF0, payload="TEST"
        uint8_t dummy_info_field[] = { 0xF0, 'T', 'E', 'S', 'T' };
        ax25_unnumbered_frame_t *u_frame = ax25_unnumbered_frame_decode(header, 0x13, dummy_info_field, sizeof(dummy_info_field), &err); // 0x13 = UI with P/F=1
        TEST_ASSERT(u_frame != NULL, "ax25_unnumbered_frame_decode should return non-NULL", err);
        if (u_frame) {
            TEST_ASSERT(u_frame->base.type == AX25_FRAME_UNNUMBERED_INFORMATION, "Frame type should be UI", err);
            ax25_unnumbered_information_frame_t *ui_frame = (ax25_unnumbered_information_frame_t*) u_frame;
            TEST_ASSERT(ui_frame->base.pf == true, "Poll/Final should be true", err);
            TEST_ASSERT(ui_frame->base.modifier == 0x03, "Modifier should be 0x03", err);
            TEST_ASSERT(ui_frame->pid == 0xF0, "PID should be 0xF0", err);
            TEST_ASSERT(ui_frame->payload_len == 4, "Payload length should be 4", err);
            TEST_ASSERT(memcmp(ui_frame->payload, "TEST", 4) == 0, "Payload should be 'TEST'", err);

            size_t len;
            uint8_t *encoded = ax25_unnumbered_information_frame_encode(ui_frame, &len, &err);
            TEST_ASSERT(encoded != NULL, "ax25_unnumbered_information_frame_encode should return non-NULL", err);
            uint8_t expected[] = { 0x13, 0xF0, 'T', 'E', 'S', 'T' };
            COMPARE_FRAME(encoded, len, expected, sizeof(expected), "Encoded UI frame should match");
            free(encoded);
            ax25_frame_free((ax25_frame_t*) u_frame, &err);
        }
        ax25_frame_header_free(header, &err);
    }
    return 0;
}

int test_unnumbered_information_frame_functions() {
    uint8_t err = 0;

    // Test data: Header for "ABCDEF-7" -> "GHIJKL-1*"
    uint8_t header_data[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63 };
    ax25_frame_header_t *header = ax25_frame_header_decode(header_data, sizeof(header_data), &err).header;
    TEST_ASSERT(header != NULL, "ax25_frame_header_decode should return non-NULL", err);
    if (header) {
        uint8_t info[] = { 0xF0, 'T', 'E', 'S', 'T' };
        ax25_unnumbered_information_frame_t *ui_frame = ax25_unnumbered_information_frame_decode(header, true, info, sizeof(info), &err);
        TEST_ASSERT(ui_frame != NULL, "ax25_unnumbered_information_frame_decode should return non-NULL", err);
        if (ui_frame) {
            TEST_ASSERT(ui_frame->base.pf == true, "Poll/Final should be true", err);
            TEST_ASSERT(ui_frame->base.modifier == 0x03, "Modifier should be 0x03", err);
            TEST_ASSERT(ui_frame->pid == 0xF0, "PID should be 0xF0", err);
            TEST_ASSERT(ui_frame->payload_len == 4, "Payload length should be 4", err);
            TEST_ASSERT(memcmp(ui_frame->payload, "TEST", 4) == 0, "Payload should be 'TEST'", err);

            size_t len;
            uint8_t *encoded = ax25_unnumbered_information_frame_encode(ui_frame, &len, &err);
            TEST_ASSERT(encoded != NULL, "ax25_unnumbered_information_frame_encode should return non-NULL", err);
            uint8_t expected[] = { 0x13, 0xF0, 'T', 'E', 'S', 'T' };
            COMPARE_FRAME(encoded, len, expected, sizeof(expected), "Encoded UI frame should match");
            free(encoded);
            ax25_frame_free((ax25_frame_t*) ui_frame, &err);
        }
        ax25_frame_header_free(header, &err);
    }
    return 0;
}

int test_frame_reject_frame_functions() {
    uint8_t err = 0;

    // Test data: Header for "AAAAAA-0" -> "BBBBBB-0"
    uint8_t header_data[] = { 0x82, 0x82, 0x82, 0x82, 0x82, 0x82, 0x60, 0x84, 0x84, 0x84, 0x84, 0x84, 0x84, 0x61 };
    ax25_frame_header_t *header = ax25_frame_header_decode(header_data, sizeof(header_data), &err).header;
    TEST_ASSERT(header != NULL, "ax25_frame_header_decode should return non-NULL", err);
    if (header) {
        // FRMR data: w=1, x=0, y=0, z=0, vr=0, frmr_cr=0, vs=2, frmr_control=0x0A
        uint8_t frmr_data[] = { 0x0A, 0x04, 0x01 };
        ax25_frame_reject_frame_t *frmr_frame = ax25_frame_reject_frame_decode(header, false, frmr_data, sizeof(frmr_data), &err);
        TEST_ASSERT(frmr_frame != NULL, "ax25_frame_reject_frame_decode should return non-NULL", err);
        if (frmr_frame) {
            TEST_ASSERT(frmr_frame->base.pf == false, "Poll/Final should be false", err);
            TEST_ASSERT(frmr_frame->base.modifier == 0x87, "Modifier should be 0x87", err);
            TEST_ASSERT(frmr_frame->w == true, "w should be true", err);
            TEST_ASSERT(frmr_frame->x == false, "x should be false", err);
            TEST_ASSERT(frmr_frame->y == false, "y should be false", err);
            TEST_ASSERT(frmr_frame->z == false, "z should be false", err);
            TEST_ASSERT(frmr_frame->vr == 0, "vr should be 0", err);
            TEST_ASSERT(frmr_frame->frmr_cr == false, "frmr_cr should be false", err);
            TEST_ASSERT(frmr_frame->vs == 2, "vs should be 2", err);
            TEST_ASSERT(frmr_frame->frmr_control == 0x0A, "frmr_control should be 0x0A", err);

            size_t len;
            uint8_t *encoded = ax25_frame_reject_frame_encode(frmr_frame, &len, &err);
            TEST_ASSERT(encoded != NULL, "ax25_frame_reject_frame_encode should return non-NULL", err);
            uint8_t expected[] = { 0x87, 0x0A, 0x04, 0x01 };
            COMPARE_FRAME(encoded, len, expected, sizeof(expected), "Encoded FRMR frame should match");
            free(encoded);
            ax25_frame_free((ax25_frame_t*) frmr_frame, &err);
        }
        ax25_frame_header_free(header, &err);
    }
    return 0;
}

int test_information_frame_functions() {
    uint8_t err = 0;

    // Test data: Header for "ABCDEF-7" -> "GHIJKL-1*"
    uint8_t header_data[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63 };
    ax25_frame_header_t *header = ax25_frame_header_decode(header_data, sizeof(header_data), &err).header;
    TEST_ASSERT(header != NULL, "ax25_frame_header_decode should return non-NULL", err);
    if (header) {
        // I-frame data: control=0x10 (nr=0, pf=1, ns=0), PID=0xF0, payload="TEST"
        uint8_t info[] = { 0xF0, 'T', 'E', 'S', 'T' };
        ax25_information_frame_t *i_frame = ax25_information_frame_decode(header, 0x10, info, sizeof(info), false, &err);
        TEST_ASSERT(i_frame != NULL, "ax25_information_frame_decode should return non-NULL", err);
        if (i_frame) {
            TEST_ASSERT(i_frame->base.type == AX25_FRAME_INFORMATION_8BIT, "Frame type should be 8-bit I-frame", err);
            TEST_ASSERT(i_frame->nr == 0, "nr should be 0", err);
            TEST_ASSERT(i_frame->pf == true, "Poll/Final should be true", err);
            TEST_ASSERT(i_frame->ns == 0, "ns should be 0", err);
            TEST_ASSERT(i_frame->pid == 0xF0, "PID should be 0xF0", err);
            TEST_ASSERT(i_frame->payload_len == 4, "Payload length should be 4", err);
            TEST_ASSERT(memcmp(i_frame->payload, "TEST", 4) == 0, "Payload should be 'TEST'", err);

            size_t len;
            uint8_t *encoded = ax25_information_frame_encode(i_frame, &len, &err);
            TEST_ASSERT(encoded != NULL, "ax25_information_frame_encode should return non-NULL", err);
            uint8_t expected[] = { 0x10, 0xF0, 'T', 'E', 'S', 'T' };
            COMPARE_FRAME(encoded, len, expected, sizeof(expected), "Encoded I-frame should match");
            free(encoded);
            ax25_frame_free((ax25_frame_t*) i_frame, &err);
        }
        ax25_frame_header_free(header, &err);
    }
    return 0;
}

int test_supervisory_frame_functions() {
    uint8_t err = 0;

    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[] ) { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1 },
            14, &err).header;
    TEST_ASSERT(header != NULL, "ax25_frame_header_decode should return non-NULL", err);
    if (header == NULL)
        return 1;

    ax25_supervisory_frame_t *s_frame = ax25_supervisory_frame_decode(header, 0x21, false, &err); // RR with nr=1
    TEST_ASSERT(s_frame != NULL, "ax25_supervisory_frame_decode should return non-NULL", err);
    if (s_frame) {
        TEST_ASSERT(s_frame->nr == 1, "nr should be 1", err); // Explicitly test nr
        TEST_ASSERT(s_frame->code == 0x00, "Supervisory code should be 0x00 (RR)", err);
        TEST_ASSERT(s_frame->pf == false, "Poll/Final bit should be false", err);
        TEST_ASSERT(s_frame->base.type == AX25_FRAME_SUPERVISORY_RR_8BIT, "Frame type should be RR_8BIT", err);

        size_t len;
        uint8_t *encoded = ax25_supervisory_frame_encode(s_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_supervisory_frame_encode should return non-NULL", err);
        TEST_ASSERT(len == 1, "Encoded length should be 1 byte", err);
        TEST_ASSERT(encoded[0] == 0x21, "Encoded control byte should be 0x21", err);
        if (encoded)
            free(encoded);
        ax25_frame_free((ax25_frame_t*) s_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    TEST_ASSERT(err == 0, "Freeing header", err);
    return err ? 1 : 0;
}

int test_xid_parameter_functions() {
    uint8_t err = 0;

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

    param = ax25_xid_class_of_procedures_new(true, false, true, false, false, true, false, 0, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_class_of_procedures_new should return non-NULL", err);
    if (param) {
        size_t len;
        uint8_t *encoded = ax25_xid_raw_parameter_encode(param, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_xid_raw_parameter_encode should return non-NULL", err);
        if (encoded) {
            uint8_t expected[] = { 0x01, 0x02, 0x25, 0x00 }; // PI=1, PL=2, PV=0x25,0x00
            size_t expected_len = sizeof(expected);
            COMPARE_FRAME(encoded, len, expected, expected_len, "Class of Procedures parameter encoding");
            free(encoded);
        }
        ax25_xid_raw_parameter_free(param, &err);
    }

    param = ax25_xid_hdlc_optional_functions_new(true, false, true, false, true, false, true, false, true,
    false, false, false, false, false, false, false, false,
    false, false, false, false, 0, false, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_hdlc_optional_functions_new should return non-NULL", err);
    if (param)
        ax25_xid_raw_parameter_free(param, &err);

    param = ax25_xid_big_endian_new(1, 0x12345678, 4, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_big_endian_new should return non-NULL", err);
    if (param)
        ax25_xid_raw_parameter_free(param, &err);

    ax25_xid_init_defaults(&err); // No return value to check
    ax25_xid_deinit_defaults(&err);
    printf("\033[0;32m[%04d]    PASS: ax25_xid_init_defaults executed\033[0m\n", ++assert_count);
    return 0;
}

int test_exchange_identification_frame_functions() {
    uint8_t err = 0;

    // Test data: Header for "ABCDEF-7" -> "GHIJKL-1*"
    uint8_t header_data[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63 };
    ax25_frame_header_t *header = ax25_frame_header_decode(header_data, sizeof(header_data), &err).header;
    TEST_ASSERT(header != NULL, "ax25_frame_header_decode should return non-NULL", err);
    if (header) {
        // XID data: FI=0x82, GI=0x80, GL=0x0004, param PI=0x01, PL=0x02, PV={0x41, 0x00}
        uint8_t data[] = { 0x82, 0x80, 0x00, 0x04, 0x01, 0x02, 0x41, 0x00 };
        ax25_exchange_identification_frame_t *xid_frame = ax25_exchange_identification_frame_decode(header, true, data, sizeof(data), &err);
        TEST_ASSERT(xid_frame != NULL, "ax25_exchange_identification_frame_decode should return non-NULL", err);
        if (xid_frame) {
            TEST_ASSERT(xid_frame->base.pf == true, "Poll/Final should be true", err);
            TEST_ASSERT(xid_frame->base.modifier == 0xAF, "Modifier should be 0xAF", err);
            TEST_ASSERT(xid_frame->fi == 0x82, "FI should be 0x82", err);
            TEST_ASSERT(xid_frame->gi == 0x80, "GI should be 0x80", err);
            TEST_ASSERT(xid_frame->param_count == 1, "Should have 1 parameter", err);
            if (xid_frame->param_count > 0) {
                TEST_ASSERT(xid_frame->parameters[0]->pi == 0x01, "Parameter PI should be 0x01", err);
                ax25_raw_param_data_t *param_data = (ax25_raw_param_data_t*) xid_frame->parameters[0]->data;
                TEST_ASSERT(param_data->pv_len == 2, "Parameter PV length should be 2", err);
                TEST_ASSERT(memcmp(param_data->pv, "\x41\x00", 2) == 0, "Parameter PV should be {0x41, 0x00}", err);
            }

            size_t len;
            uint8_t *encoded = ax25_exchange_identification_frame_encode(xid_frame, &len, &err);
            TEST_ASSERT(encoded != NULL, "ax25_exchange_identification_frame_encode should return non-NULL", err);
            uint8_t expected[] = { 0xBF, 0x82, 0x80, 0x00, 0x04, 0x01, 0x02, 0x41, 0x00 };
            COMPARE_FRAME(encoded, len, expected, sizeof(expected), "Encoded XID frame should match");
            free(encoded);
            ax25_frame_free((ax25_frame_t*) xid_frame, &err);
        }
        ax25_frame_header_free(header, &err);
    }
    return 0;
}

int test_test_frame_functions() {
    uint8_t err = 0;

    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[] ) { 0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0, 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1 },
            14, &err).header;
    TEST_ASSERT(header != NULL, "ax25_frame_header_decode should return non-NULL", err);
    if (header == NULL)
        return 1;

    uint8_t data[] = "TEST";
    ax25_test_frame_t *test_frame = ax25_test_frame_decode(header, true, data, 4, &err);
    TEST_ASSERT(test_frame != NULL, "ax25_test_frame_decode should return non-NULL", err);
    if (test_frame) {
        TEST_ASSERT(test_frame->payload_len == 4, "Payload length should be 4", err);
        TEST_ASSERT(memcmp(test_frame->payload, data, 4) == 0, "Payload should match 'TEST'", err);
        size_t len;
        uint8_t *encoded = ax25_test_frame_encode(test_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_test_frame_encode should return non-NULL", err);
        if (encoded) {
            uint8_t expected[] = { 0xF3, 'T', 'E', 'S', 'T' }; // Control byte (0xE3 | POLL_FINAL_8BIT) + "TEST"
            size_t expected_len = sizeof(expected);
            COMPARE_FRAME(encoded, len, expected, expected_len, "Encoded TEST frame content should match");
            free(encoded);
        }
        ax25_frame_free((ax25_frame_t*) test_frame, &err);
        TEST_ASSERT(err == 0, "Freeing TEST frame", err);
    }
    ax25_frame_header_free(header, &err);
    TEST_ASSERT(err == 0, "Freeing header", err);
    return err ? 1 : 0;
}

int test_ax25_modulo128(void) {
    uint8_t err = 0;
    ax25_frame_t *frame;

    // Modulo-128 RR frame: N(R)=4, P/F=0
    uint8_t ax25_rr_frame_mod128[] = { 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE0, // Dest: NOCALL-0, ch=1
            0xA6, 0x8A, 0xA0, 0x8A, 0x82, 0xA2, 0x63, // Src: REPEAT-1, ch=0, extension=1
            0x01, 0x08  // Control: First byte 0x01 (S=00, 01), Second byte 0x08 (N(R)=4, P/F=0)
            };
    size_t ax25_rr_frame_mod128_len = sizeof(ax25_rr_frame_mod128);

    frame = ax25_frame_decode(ax25_rr_frame_mod128, ax25_rr_frame_mod128_len, 1, &err);
    TEST_ASSERT(frame != NULL, "Decoding modulo-128 RR frame", err);

    if (frame) {
        TEST_ASSERT(frame->type == AX25_FRAME_SUPERVISORY_RR_16BIT, "Frame type should be RR 16-bit", err);
        ax25_supervisory_frame_t *s_frame = (ax25_supervisory_frame_t*) frame;
        TEST_ASSERT(s_frame->nr == 4, "nr should be 4", err);
        TEST_ASSERT(s_frame->pf == false, "Poll/Final should be false", err);
        TEST_ASSERT(s_frame->code == 0x00, "Code should be 0x00 (RR)", err);
        ax25_frame_free(frame, &err);
    }

    return 0;
}

int test_ax25_modulo128_encode() {
    uint8_t err = 0;

    // Create addresses
    ax25_address_t *dest = ax25_address_from_string("NOCALL-0", &err);
    TEST_ASSERT(dest != NULL, "Destination address creation should succeed", err);
    ax25_address_t *src = ax25_address_from_string("REPEAT-1", &err);
    TEST_ASSERT(src != NULL, "Source address creation should succeed", err);
    if (!dest || !src)
        return 1;

    // Adjust source address for modulo-128: res1 = false
    src->res1 = false;

    // Create modulo-128 I-frame: N(S)=5, N(R)=3, P/F=1, PID=0xF0, Payload="TEST"
    ax25_information_frame_t *i_frame = malloc(sizeof(ax25_information_frame_t));
    TEST_ASSERT(i_frame != NULL, "I-frame allocation should succeed", err);
    if (!i_frame) {
        ax25_address_free(dest, &err);
        ax25_address_free(src, &err);
        return 1;
    }

    i_frame->base.type = AX25_FRAME_INFORMATION_16BIT;
    i_frame->base.header.destination = *dest;
    i_frame->base.header.source = *src;
    i_frame->base.header.cr = true; // Command frame
    i_frame->base.header.src_cr = false;
    i_frame->base.header.repeaters.num_repeaters = 0;
    i_frame->nr = 3;
    i_frame->pf = true;
    i_frame->ns = 5;
    i_frame->pid = 0xF0;
    i_frame->payload_len = 4;
    i_frame->payload = malloc(4);
    TEST_ASSERT(i_frame->payload != NULL, "Payload allocation should succeed", err);
    if (!i_frame->payload) {
        free(i_frame);
        ax25_address_free(dest, &err);
        ax25_address_free(src, &err);
        return 1;
    }
    memcpy(i_frame->payload, "TEST", 4);

    // Encode the frame
    size_t len;
    uint8_t *encoded = ax25_frame_encode((ax25_frame_t*) i_frame, &len, &err);
    TEST_ASSERT(encoded != NULL, "Frame encoding should succeed", err);
    if (encoded) {
        // Expected frame:
        // Dest: NOCALL-0, ch=1, res0=1, res1=1, ext=0: 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE0
        // Src:  REPEAT-1, ch=0, res0=1, res1=0, ext=1: 0xA6, 0x8A, 0xA0, 0x8A, 0x82, 0xA2, 0x23
        // Control: 0x0A (N(S)=5, I=0), 0x07 (N(R)=3, P/F=1)
        // PID: 0xF0, Payload: "TEST"
        uint8_t expected[] = { 0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE0, 0xA6, 0x8A, 0xA0, 0x8A, 0x82, 0xA2, 0x23, 0x0A, 0x07, 0xF0, 'T', 'E', 'S', 'T' };
        size_t expected_len = sizeof(expected);
        COMPARE_FRAME(encoded, len, expected, expected_len, "Modulo-128 I-frame encoding should match expected bytes");
        TEST_ASSERT((encoded[13] & 0x40) == 0, "Source SSID bit 6 (res1) should be 0 for modulo-128", err);
        free(encoded);
    }

    // Clean up
    free(i_frame->payload);
    free(i_frame);
    ax25_address_free(dest, &err);
    ax25_address_free(src, &err);
    return 0;
}

int test_ax25_connection(void) {
    uint8_t err = 0;

    // AX.25 Connection Test Packets
    // 1. CONNECT Request (Station A -> Station B: SABM)
    // Dest: VA3BBB-7 (C=1, ext=0), Src: VA3AAA-1 (C=0, ext=1), Control: 0x3F (SABM, P=1)
    unsigned char ax25_sabm_packet[] = { 0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEE, 0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x63, 0x3F };
    size_t ax25_sabm_packet_len = sizeof(ax25_sabm_packet);

    // 2. CONNECT Acknowledgment (Station B -> Station A: UA)
    // Dest: VA3AAA-1 (C=0, ext=0), Src: VA3BBB-7 (C=1, ext=1), Control: 0x73 (UA, F=1)
    unsigned char ax25_ua_connect_packet[] = { 0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x62, 0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEF, 0x73 };
    size_t ax25_ua_connect_packet_len = sizeof(ax25_ua_connect_packet);

    // 3. SEND Data (Station A -> Station B: I-Frame)
    // Dest: VA3BBB-7, Src: VA3AAA-1, Control: 0x00 (I, N(S)=0, N(R)=0), PID: 0xF0, Payload: "Hello, World!"
    unsigned char ax25_i_frame_packet[] = { 0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEE, 0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x63, 0x00, 0xF0, 0x48, 0x65, 0x6C,
            0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21 };
    size_t ax25_i_frame_packet_len = sizeof(ax25_i_frame_packet);

    // 4. RECEIVE Data Acknowledgment (Station B -> Station A: RR)
    // Dest: VA3AAA-1, Src: VA3BBB-7, Control: 0x31 (RR, N(R)=1, P/F=1)
    unsigned char ax25_rr_packet[] = { 0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x62, 0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEF, 0x31 };
    size_t ax25_rr_packet_len = sizeof(ax25_rr_packet);

    // 5. DISCONNECT Request (Station A -> Station B: DISC)
    // Dest: VA3BBB-7, Src: VA3AAA-1, Control: 0x43 (DISC, P=0)
    unsigned char ax25_disc_packet[] = { //
            0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEE, 0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x63, 0x43 };
    size_t ax25_disc_packet_len = sizeof(ax25_disc_packet);

    // 6. DISCONNECT Acknowledgment (Station B -> Station A: UA)
    // Dest: VA3AAA-1, Src: VA3BBB-7, Control: 0x73 (UA, F=1)
    unsigned char ax25_ua_disconnect_packet[] = { 0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x62, 0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEF, 0x73 };
    size_t ax25_ua_disconnect_packet_len = sizeof(ax25_ua_disconnect_packet);

    // Invalid packet for error testing
    unsigned char invalid_packet[] = { 0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEE, 0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x63, 0xFF };
    size_t invalid_packet_len = sizeof(invalid_packet);

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
    if (decoded_frame) {
        TEST_ASSERT(decoded_frame->type == AX25_FRAME_UNNUMBERED_SABM, "Frame type should be SABM", err);
        ax25_unnumbered_frame_t *u_frame = (ax25_unnumbered_frame_t*) decoded_frame;
        TEST_ASSERT(u_frame->pf == true, "Poll/Final should be true", err);
        TEST_ASSERT(u_frame->modifier == 0x2F, "Modifier should be 0x2F", err);
        encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
        TEST_ASSERT(encode_result != NULL && err == 0, "Encoding SABM frame", err);
        COMPARE_FRAME(encode_result, encoded_len, ax25_sabm_packet, ax25_sabm_packet_len, "SABM frame content");
        //PRINT_PACKET(encode_result, encoded_len);
        free(encode_result);
        ax25_frame_free(decoded_frame, &err);
    }

    // 2. Test UA connect frame
    decoded_frame = ax25_frame_decode(ax25_ua_connect_packet, ax25_ua_connect_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding UA connect frame", err);
    if (decoded_frame) {
        TEST_ASSERT(decoded_frame->type == AX25_FRAME_UNNUMBERED_UA, "Frame type should be UA", err);
        ax25_unnumbered_frame_t *u_frame = (ax25_unnumbered_frame_t*) decoded_frame;
        TEST_ASSERT(u_frame->pf == true, "Poll/Final should be true", err);
        TEST_ASSERT(u_frame->modifier == 0x63, "Modifier should be 0x63", err);
        encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
        TEST_ASSERT(encode_result != NULL && err == 0, "Encoding UA connect frame", err);
        COMPARE_FRAME(encode_result, encoded_len, ax25_ua_connect_packet, ax25_ua_connect_packet_len, "UA connect frame content");
        //PRINT_PACKET(encode_result, encoded_len);
        free(encode_result);
        ax25_frame_free(decoded_frame, &err);
    }

    // 3. Test I-Frame
    decoded_frame = ax25_frame_decode(ax25_i_frame_packet, ax25_i_frame_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding I-Frame", err);
    if (decoded_frame) {
        TEST_ASSERT(decoded_frame->type == AX25_FRAME_INFORMATION_8BIT, "Frame type should be I-frame 8-bit", err);
        ax25_information_frame_t *i_frame = (ax25_information_frame_t*) decoded_frame;
        TEST_ASSERT(i_frame->nr == 0, "nr should be 0", err);
        TEST_ASSERT(i_frame->ns == 0, "ns should be 0", err);
        TEST_ASSERT(i_frame->pf == false, "Poll/Final should be false", err);
        TEST_ASSERT(i_frame->pid == 0xF0, "PID should be 0xF0", err);
        TEST_ASSERT(i_frame->payload_len == 13, "Payload length should be 13", err);
        TEST_ASSERT(memcmp(i_frame->payload, "Hello, World!", 13) == 0, "Payload should be 'Hello, World!'", err);
        encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
        TEST_ASSERT(encode_result != NULL && err == 0, "Encoding I-Frame", err);
        COMPARE_FRAME(encode_result, encoded_len, ax25_i_frame_packet, ax25_i_frame_packet_len, "I-Frame content");
        //PRINT_PACKET(encode_result, encoded_len);
        free(encode_result);
        ax25_frame_free(decoded_frame, &err);
    }

    // 4. Test RR frame
    decoded_frame = ax25_frame_decode(ax25_rr_packet, ax25_rr_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding RR frame", err);
    if (decoded_frame) {
        TEST_ASSERT(decoded_frame->type == AX25_FRAME_SUPERVISORY_RR_8BIT, "Frame type should be RR 8-bit", err);
        ax25_supervisory_frame_t *s_frame = (ax25_supervisory_frame_t*) decoded_frame;
        TEST_ASSERT(s_frame->nr == 1, "nr should be 1", err);
        TEST_ASSERT(s_frame->pf == true, "Poll/Final should be true", err); // Changed from false to true
        TEST_ASSERT(s_frame->code == 0x00, "Code should be 0x00 (RR)", err);
        encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
        TEST_ASSERT(encode_result != NULL && err == 0, "Encoding RR frame", err);
        COMPARE_FRAME(encode_result, encoded_len, ax25_rr_packet, ax25_rr_packet_len, "RR frame content");
        //PRINT_PACKET(encode_result, encoded_len);
        free(encode_result);
        ax25_frame_free(decoded_frame, &err);
    }

    // 5. Test DISC frame
    decoded_frame = ax25_frame_decode(ax25_disc_packet, ax25_disc_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding DISC frame", err);
    if (decoded_frame) {
        TEST_ASSERT(decoded_frame->type == AX25_FRAME_UNNUMBERED_DISC, "Frame type should be DISC", err);
        ax25_unnumbered_frame_t *u_frame = (ax25_unnumbered_frame_t*) decoded_frame;
        TEST_ASSERT(u_frame->pf == false, "Poll/Final should be false", err);
        TEST_ASSERT(u_frame->modifier == 0x43, "Modifier should be 0x43", err);
        encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
        TEST_ASSERT(encode_result != NULL && err == 0, "Encoding DISC frame", err);
        COMPARE_FRAME(encode_result, encoded_len, ax25_disc_packet, ax25_disc_packet_len, "DISC frame content");
        //PRINT_PACKET(encode_result, encoded_len);
        free(encode_result);
        ax25_frame_free(decoded_frame, &err);
    }

    // 6. Test UA disconnect frame
    decoded_frame = ax25_frame_decode(ax25_ua_disconnect_packet, ax25_ua_disconnect_packet_len, 0, &err);
    TEST_ASSERT(decoded_frame != NULL && err == 0, "Decoding UA disconnect frame", err);
    if (decoded_frame) {
        TEST_ASSERT(decoded_frame->type == AX25_FRAME_UNNUMBERED_UA, "Frame type should be UA", err);
        ax25_unnumbered_frame_t *u_frame = (ax25_unnumbered_frame_t*) decoded_frame;
        TEST_ASSERT(u_frame->pf == true, "Poll/Final should be true", err);
        TEST_ASSERT(u_frame->modifier == 0x63, "Modifier should be 0x63", err);
        encode_result = ax25_frame_encode(decoded_frame, &encoded_len, &err);
        TEST_ASSERT(encode_result != NULL && err == 0, "Encoding UA disconnect frame", err);
        COMPARE_FRAME(encode_result, encoded_len, ax25_ua_disconnect_packet, ax25_ua_disconnect_packet_len, "UA disconnect frame content");
        //PRINT_PACKET(encode_result, encoded_len);
        free(encode_result);
        ax25_frame_free(decoded_frame, &err);
    }

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
    ax25_address_free(station_b, &addr_err);
    return 0;
}

int test_frmr_frame_functions() {
    uint8_t err = 0;

    // Define the modulo-8 FRMR frame components
    uint8_t header_mod8[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, // Dest: ABCDEF-7
            0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63 }; // Src: GHIJKL-1, res1=1
    uint8_t control_byte = 0x87; // FRMR control byte
    uint8_t frmr_data_mod8[] = { 0x10, 0x24, 0x01 }; // FRMR data

    // Calculate lengths
    size_t header_len = sizeof(header_mod8);       // 14 bytes
    size_t frmr_data_len = sizeof(frmr_data_mod8); // 3 bytes
    size_t total_len = header_len + 1 + frmr_data_len; // Header + control + data

    // Construct the frame
    uint8_t *frame_mod8 = malloc(total_len);
    memcpy(frame_mod8, header_mod8, header_len);
    frame_mod8[header_len] = control_byte;
    memcpy(frame_mod8 + header_len + 1, frmr_data_mod8, frmr_data_len);

    // Decode the frame
    ax25_frame_t *frame = ax25_frame_decode(frame_mod8, total_len, 0, &err);
    if (!frame) {
        printf("Decoding failed with error %d\n", err);
        free(frame_mod8);
        return 1;
    }

    // Verify the decoded FRMR frame
    ax25_frame_reject_frame_t *frmr = (ax25_frame_reject_frame_t*) frame;

    // Assertions
    if (frmr->base.base.type != AX25_FRAME_UNNUMBERED_FRMR || frmr->is_modulo128 || frmr->frmr_control != 0x10 || frmr->vr != 1 || frmr->vs != 2
            || frmr->frmr_cr || !frmr->w || frmr->x || frmr->y || frmr->z) {
        printf("Test failed: Expected control=0x10, vr=1, vs=2, cr=0, w=1, x=0, y=0, z=0\n");
        ax25_frame_free(frame, &err);
        free(frame_mod8);
        return 1;
    }

    // Clean up
    ax25_frame_free(frame, &err);
    free(frame_mod8);

    return 0; // Success
}

int test_auto_modulo_detection() {
    uint8_t err = 0;

    // Test modulo-8 I-frame
    uint8_t frame_mod8[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE,  // dest: ABCDEF-7, ch=1
            0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63,  // src: GHIJKL-1, ch=0, res1=1 (0x63)
            0x00,  // control: I-frame, nr=0, ns=0, pf=0
            0xF0, 'T', 'E', 'S', 'T'  // PID and payload
            };
    ax25_frame_t *frame = ax25_frame_decode(frame_mod8, sizeof(frame_mod8), MODULO128_AUTO, &err);
    TEST_ASSERT(frame != NULL, "Decoding modulo-8 I-frame with auto detection", err);
    if (frame) {
        TEST_ASSERT(frame->type == AX25_FRAME_INFORMATION_8BIT, "Should decode as 8-bit I-frame", err);
        ax25_information_frame_t *i_frame = (ax25_information_frame_t*) frame;
        TEST_ASSERT(i_frame->nr == 0, "nr should be 0", err);
        TEST_ASSERT(i_frame->ns == 0, "ns should be 0", err);
        TEST_ASSERT(i_frame->pf == false, "pf should be false", err);
        ax25_frame_free(frame, &err);
    }

    // Test modulo-128 I-frame
    uint8_t frame_mod128[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE,  // dest: ABCDEF-7, ch=1
            0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x23,  // src: GHIJKL-1, ch=0, res1=0 (0x23)
            0x00, 0x00,  // control: 16-bit, nr=0, ns=0, pf=0
            0xF0, 'T', 'E', 'S', 'T'  // PID and payload
            };
    frame = ax25_frame_decode(frame_mod128, sizeof(frame_mod128), MODULO128_AUTO, &err);
    TEST_ASSERT(frame != NULL, "Decoding modulo-128 I-frame with auto detection", err);
    if (frame) {
        TEST_ASSERT(frame->type == AX25_FRAME_INFORMATION_16BIT, "Should decode as 16-bit I-frame", err);
        ax25_information_frame_t *i_frame = (ax25_information_frame_t*) frame;
        TEST_ASSERT(i_frame->nr == 0, "nr should be 0", err);
        TEST_ASSERT(i_frame->ns == 0, "ns should be 0", err);
        TEST_ASSERT(i_frame->pf == false, "pf should be false", err);
        ax25_frame_free(frame, &err);
    }

    return 0;
}

int test_hdlc() {
    uint8_t err = 0;

    // Test Case 1: Valid UI frame
    {
        uint8_t ax25_ui_frame[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63, 0x03, 0xF0, 'T', 'E', 'S', 'T' };
        size_t ax25_ui_frame_len = sizeof(ax25_ui_frame);
        unsigned char ax25_with_fcs[sizeof(ax25_ui_frame) + 2];
        memcpy(ax25_with_fcs, ax25_ui_frame, ax25_ui_frame_len);
        unsigned char encodedFrame[1024];
        int encodedLen;
        hdlc_frame_encode(ax25_with_fcs, ax25_ui_frame_len, encodedFrame, &encodedLen);
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(encodedFrame, encodedLen, decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result == 0, "hdlc_frame_decode should succeed for UI frame", err);
        TEST_ASSERT(decodedLen == ax25_ui_frame_len, "Decoded length should match original UI frame", err);
        COMPARE_FRAME(decodedFrame, (size_t )decodedLen, ax25_ui_frame, ax25_ui_frame_len, "Decoded UI frame should match original");
        ax25_frame_t *frame = ax25_frame_decode(decodedFrame, decodedLen, 0, &err);
        TEST_ASSERT(frame != NULL, "ax25_frame_decode should succeed for UI frame", err);
        if (frame) {
            TEST_ASSERT(frame->type == AX25_FRAME_UNNUMBERED_INFORMATION, "Frame type should be UI", err);
            ax25_unnumbered_information_frame_t *ui_frame = (ax25_unnumbered_information_frame_t*) frame;
            TEST_ASSERT(ui_frame->pid == 0xF0, "PID should be 0xF0", err);
            TEST_ASSERT(ui_frame->payload_len == 4, "Payload length should be 4", err);
            TEST_ASSERT(memcmp(ui_frame->payload, "TEST", 4) == 0, "Payload should be 'TEST'", err);
            ax25_frame_free(frame, &err);
        }
    }

    // Test Case 2: Valid I-frame
    {
        unsigned char ax25_i_frame[] =
                { 0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEE, 0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x63, 0x00, 0xF0, 'H', 'e', 'l', 'l', 'o' };
        size_t ax25_i_frame_len = sizeof(ax25_i_frame);
        unsigned char ax25_with_fcs[sizeof(ax25_i_frame) + 2];
        memcpy(ax25_with_fcs, ax25_i_frame, ax25_i_frame_len);
        unsigned char encodedFrame[1024];
        int encodedLen;
        hdlc_frame_encode(ax25_with_fcs, ax25_i_frame_len, encodedFrame, &encodedLen);
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(encodedFrame, encodedLen, decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result == 0, "hdlc_frame_decode should succeed for I-frame", err);
        TEST_ASSERT(decodedLen == ax25_i_frame_len, "Decoded length should match original I-frame", err);
        COMPARE_FRAME(decodedFrame, (size_t )decodedLen, ax25_i_frame, ax25_i_frame_len, "Decoded I-frame should match original");
        ax25_frame_t *frame = ax25_frame_decode(decodedFrame, decodedLen, 0, &err);
        TEST_ASSERT(frame != NULL, "ax25_frame_decode should succeed for I-frame", err);
        if (frame) {
            TEST_ASSERT(frame->type == AX25_FRAME_INFORMATION_8BIT, "Frame type should be I-frame 8-bit", err);
            ax25_information_frame_t *i_frame = (ax25_information_frame_t*) frame;
            TEST_ASSERT(i_frame->nr == 0, "nr should be 0", err);
            TEST_ASSERT(i_frame->ns == 0, "ns should be 0", err);
            TEST_ASSERT(i_frame->pf == false, "Poll/Final should be false", err);
            TEST_ASSERT(i_frame->pid == 0xF0, "PID should be 0xF0", err);
            TEST_ASSERT(i_frame->payload_len == 5, "Payload length should be 5", err);
            TEST_ASSERT(memcmp(i_frame->payload, "Hello", 5) == 0, "Payload should be 'Hello'", err);
            ax25_frame_free(frame, &err);
        }
    }

    // Test Case 3: Bit-stuffing
    {
        uint8_t ax25_bitstuff_frame[] =
                { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63, 0x03, 0xF0, 0x1F, 0x1F, 0x1F, 0x1F };
        size_t ax25_bitstuff_frame_len = sizeof(ax25_bitstuff_frame);
        unsigned char ax25_with_fcs[sizeof(ax25_bitstuff_frame) + 2];
        memcpy(ax25_with_fcs, ax25_bitstuff_frame, ax25_bitstuff_frame_len);
        unsigned char encodedFrame[1024];
        int encodedLen;
        hdlc_frame_encode(ax25_with_fcs, ax25_bitstuff_frame_len, encodedFrame, &encodedLen);
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(encodedFrame, encodedLen, decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result == 0, "hdlc_frame_decode should succeed for bitstuff frame", err);
        TEST_ASSERT(decodedLen == ax25_bitstuff_frame_len, "Decoded length should match original bitstuff frame", err);
        COMPARE_FRAME(decodedFrame, (size_t )decodedLen, ax25_bitstuff_frame, ax25_bitstuff_frame_len, "Decoded bitstuff frame should match original");
    }

    // Test Case 4: Invalid FCS
    {
        uint8_t ax25_ui_frame[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63, 0x03, 0xF0, 'T', 'E', 'S', 'T' };
        size_t ax25_ui_frame_len = sizeof(ax25_ui_frame);
        unsigned char ax25_with_fcs[sizeof(ax25_ui_frame) + 2];
        memcpy(ax25_with_fcs, ax25_ui_frame, ax25_ui_frame_len);
        unsigned char encodedFrame[1024];
        int encodedLen;
        hdlc_frame_encode(ax25_with_fcs, ax25_ui_frame_len, encodedFrame, &encodedLen);
        encodedFrame[encodedLen - 2] ^= 0x01; // Corrupt FCS
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(encodedFrame, encodedLen, decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result != 0, "hdlc_frame_decode should fail for invalid FCS", err);
    }

    // Test Case 5: Short frame
    {
        uint8_t short_frame[] = { 0x7E, 0x7E };
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(short_frame, sizeof(short_frame), decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result != 0, "hdlc_frame_decode should fail for short frame", err);
    }

    // Test Case 6: No flags
    {
        uint8_t no_flags_frame[] = { 0x00, 0x01, 0x02, 0x03 };
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(no_flags_frame, sizeof(no_flags_frame), decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result != 0, "hdlc_frame_decode should fail for frame with no flags", err);
    }

    // Test Case 7: Supervisory frame (RR) with no payload
    {
        unsigned char ax25_rr_frame[] = { 0xAC, 0x82, 0x66, 0x82, 0x82, 0x82, 0x62, 0xAC, 0x82, 0x66, 0x84, 0x84, 0x84, 0xEF, 0x31 };
        size_t ax25_rr_frame_len = sizeof(ax25_rr_frame);
        unsigned char ax25_with_fcs[sizeof(ax25_rr_frame) + 2];
        memcpy(ax25_with_fcs, ax25_rr_frame, ax25_rr_frame_len);
        unsigned char encodedFrame[1024];
        int encodedLen;
        hdlc_frame_encode(ax25_with_fcs, ax25_rr_frame_len, encodedFrame, &encodedLen);
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(encodedFrame, encodedLen, decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result == 0, "hdlc_frame_decode should succeed for RR frame", err);
        TEST_ASSERT(decodedLen == ax25_rr_frame_len, "Decoded length should match original RR frame", err);
        COMPARE_FRAME(decodedFrame, (size_t )decodedLen, ax25_rr_frame, ax25_rr_frame_len, "Decoded RR frame should match original");
        ax25_frame_t *frame = ax25_frame_decode(decodedFrame, decodedLen, 0, &err);
        TEST_ASSERT(frame != NULL, "ax25_frame_decode should succeed for RR frame", err);
        if (frame) {
            TEST_ASSERT(frame->type == AX25_FRAME_SUPERVISORY_RR_8BIT, "Frame type should be RR 8-bit", err);
            ax25_supervisory_frame_t *s_frame = (ax25_supervisory_frame_t*) frame;
            TEST_ASSERT(s_frame->nr == 1, "nr should be 1", err);
            TEST_ASSERT(s_frame->pf == true, "Poll/Final should be true", err);
            TEST_ASSERT(s_frame->code == 0x00, "Code should be 0x00 (RR)", err);
            ax25_frame_free(frame, &err);
        }
    }

    // Test Case 8: Multiple flags
    {
        uint8_t ax25_ui_frame[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63, 0x03, 0xF0, 'T', 'E', 'S', 'T' };
        size_t ax25_ui_frame_len = sizeof(ax25_ui_frame);
        unsigned char ax25_with_fcs[sizeof(ax25_ui_frame) + 2];
        memcpy(ax25_with_fcs, ax25_ui_frame, ax25_ui_frame_len);
        unsigned char encodedFrame[1024];
        int encodedLen;
        hdlc_frame_encode(ax25_with_fcs, ax25_ui_frame_len, encodedFrame, &encodedLen);
        unsigned char multi_flag_frame[encodedLen + 2];
        memcpy(multi_flag_frame, encodedFrame, encodedLen);
        multi_flag_frame[encodedLen] = 0x7E;
        multi_flag_frame[encodedLen + 1] = 0x7E;
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(multi_flag_frame, encodedLen + 2, decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result == 0, "hdlc_frame_decode should succeed with multiple flags", err);
        TEST_ASSERT(decodedLen == ax25_ui_frame_len, "Decoded length should match original with multiple flags", err);
        COMPARE_FRAME(decodedFrame, (size_t )decodedLen, ax25_ui_frame, ax25_ui_frame_len, "Decoded frame with multiple flags should match original");
    }

    // Test Case 9: Maximum size frame (256 bytes payload)
    {
        uint8_t ax25_max_frame[14 + 1 + 1 + 256]; // Header + Control + PID + Payload
        uint8_t header[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63 };
        memcpy(ax25_max_frame, header, 14);
        ax25_max_frame[14] = 0x03; // Control (UI)
        ax25_max_frame[15] = 0xF0; // PID
        for (int i = 0; i < 256; i++) {
            ax25_max_frame[16 + i] = (uint8_t) (i & 0xFF);
        }
        size_t ax25_max_frame_len = sizeof(ax25_max_frame);
        unsigned char ax25_with_fcs[sizeof(ax25_max_frame) + 2];
        memcpy(ax25_with_fcs, ax25_max_frame, ax25_max_frame_len);
        unsigned char encodedFrame[1024];
        int encodedLen;
        hdlc_frame_encode(ax25_with_fcs, ax25_max_frame_len, encodedFrame, &encodedLen);
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(encodedFrame, encodedLen, decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result == 0, "hdlc_frame_decode should succeed for max size frame", err);
        TEST_ASSERT(decodedLen == ax25_max_frame_len, "Decoded length should match original max size frame", err);
        COMPARE_FRAME(decodedFrame, (size_t )decodedLen, ax25_max_frame, ax25_max_frame_len, "Decoded max size frame should match original");
    }

    // Test Case 10: Frame with flags in middle (invalid HDLC)
    {
        uint8_t ax25_ui_frame[] = { 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0xEE, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x63, 0x03, 0xF0, 'T', 'E', 'S', 'T' };
        size_t ax25_ui_frame_len = sizeof(ax25_ui_frame);
        unsigned char ax25_with_fcs[sizeof(ax25_ui_frame) + 2];
        memcpy(ax25_with_fcs, ax25_ui_frame, ax25_ui_frame_len);
        unsigned char encodedFrame[1024];
        int encodedLen;
        hdlc_frame_encode(ax25_with_fcs, ax25_ui_frame_len, encodedFrame, &encodedLen);
        int mid_point = encodedLen / 2;
        memmove(encodedFrame + mid_point + 1, encodedFrame + mid_point, encodedLen - mid_point);
        encodedFrame[mid_point] = 0x7E; // Insert flag in middle
        encodedLen++;
        unsigned char decodedFrame[1024];
        int decodedLen;
        int decode_result = hdlc_frame_decode(encodedFrame, encodedLen, decodedFrame, &decodedLen);
        TEST_ASSERT(decode_result != 0, "hdlc_frame_decode should fail with flag in middle", err);
    }

    return 0;
}

int test_segmentation_reassembly() {
    uint8_t err = 0;
    int result = 0; // Track test result

    // Create a large payload (10000 bytes)
    size_t payload_len = 10000;
    uint8_t *payload = malloc(payload_len);
    if (!payload) {
        printf("\033[0;31m[%04d] FAIL(%u): Payload allocation should succeed\033[0m\n", ++assert_count, err);
        return 1;
    }
    for (size_t i = 0; i < payload_len; i++) {
        payload[i] = (uint8_t) (i % 256); // Fill with 0x00, 0x01, ..., 0xFF, 0x00, ...
    }

    // Segment the payload with N1=256
    size_t n1 = 256;
    size_t num_segments;
    ax25_segmented_info_t *segments = ax25_segment_info_fields(payload, payload_len, n1, &err, &num_segments);
    if (!segments || err != 0) {
        result = 1;
        goto cleanup_payload;
    }

    // Check segment count
    if (num_segments != 40) {
        result = 1;
        goto cleanup_segments;
    }

    // Verify first segment
    if (segments[0].info_field_len != 256 || segments[0].info_field[0] != 0x08 || segments[0].info_field[1] != 0x80 || segments[0].info_field[2] != 0x27
            || segments[0].info_field[3] != 0x10 || memcmp(segments[0].info_field + 4, payload, 252) != 0) {
        result = 1;
        goto cleanup_segments;
    }

    // Verify second segment
    if (segments[1].info_field_len != 256 || segments[1].info_field[0] != 0x08 || segments[1].info_field[1] != 0x01
            || memcmp(segments[1].info_field + 2, payload + 252, 254) != 0) {
        result = 1;
        goto cleanup_segments;
    }

    // Verify last segment
    size_t last_seg = num_segments - 1;
    size_t last_data_len = payload_len - 252 - (num_segments - 2) * 254; // 96 bytes
    size_t last_info_len = 2 + last_data_len; // 98 bytes
    size_t offset = 252 + (last_seg - 1) * 254;
    if (segments[last_seg].info_field_len != last_info_len || segments[last_seg].info_field[0] != 0x08 || segments[last_seg].info_field[1] != 0x67
            || memcmp(segments[last_seg].info_field + 2, payload + offset, last_data_len) != 0) {
        result = 1;
        goto cleanup_segments;
    }

    // Calculate overhead
    size_t total_segment_bytes = 0;
    for (size_t i = 0; i < num_segments; i++) {
        total_segment_bytes += segments[i].info_field_len;
    }
    double overhead = (double) (total_segment_bytes - payload_len) / payload_len * 100;
    if (overhead >= 1.0) {
        result = 1;
        goto cleanup_segments;
    }

    // Reassemble segments
    size_t reassembled_len;
    uint8_t *reassembled = ax25_reassemble_info_fields(segments, num_segments, &reassembled_len, &err);
    if (!reassembled || err != 0 || reassembled_len != payload_len || memcmp(reassembled, payload, payload_len) != 0) {
        result = 1;
        free(reassembled);
        goto cleanup_segments;
    }

    free(reassembled);  // Free the reassembled buffer after use

    // Print final result only
    printf("\033[0;32m[%04d]    PASS: test_segmentation_reassembly completed successfully\033[0m\n", ++assert_count);

    cleanup_segments:
    ax25_free_segmented_info(segments, num_segments);
    cleanup_payload:
    free(payload);
    if (result != 0) {
        printf("\033[0;31m[%04d] FAIL(%u): test_segmentation_reassembly failed\033[0m\n", ++assert_count, err);
    }
    return result;
}

int main() {
    int result = 0;
    printf("\n----------------------------------------------------------------------------------\n");
    printf("Starting AX.25 Library Tests\n");
    printf("----------------------------------------------------------------------------------\n\n");
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
    result |= test_ax25_connection();
    result |= test_hdlc();
    result |= test_ax25_modulo128();
    result |= test_frmr_frame_functions();
    result |= test_auto_modulo_detection();
    result |= test_segmentation_reassembly();

    printf("\nTests Completed. %s\n", result == 0 ? "All tests passed" : "Some tests failed");
    printf("----------------------------------------------------------------------------------\n\n");
    return result;
}
