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
#include <string.h>
#include <stdlib.h>

// Sample AX.25 packet data (without flags)
static uint8_t frame_data[] = {
    0x82, 0xa0, 0xa4, 0xa6, 0x40, 0x40, 0xe0, // Destination: APRS
    0x9c, 0x9e, 0x86, 0x82, 0x98, 0x98, 0xe2, // Source: NOCALL-1
    0xae, 0x92, 0x88, 0x8a, 0x62, 0x40, 0xe3, // Digipeater: WIDE1-1
    0x03, // Control: UI frame
    0xf0, // PID: No Layer 3
    // Payload: APRS position data
    0x40, 0x30, 0x39, 0x32, 0x33, 0x34, 0x35, 0x7a,
    0x2f, 0x3a, 0x2a, 0x45, 0x22, 0x3b, 0x71, 0x5a,
    0x3d, 0x4f, 0x4d, 0x52, 0x43, 0x2f, 0x41, 0x3d,
    0x30, 0x38, 0x38, 0x31, 0x33, 0x32, 0x48, 0x65,
    0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
    0x64, 0x21,
    0xa2, 0x48 // FCS
};
static size_t frame_len = sizeof(frame_data);

static uint8_t expected_payload[] = {
    0x40, 0x30, 0x39, 0x32, 0x33, 0x34, 0x35, 0x7a,
    0x2f, 0x3a, 0x2a, 0x45, 0x22, 0x3b, 0x71, 0x5a,
    0x3d, 0x4f, 0x4d, 0x52, 0x43, 0x2f, 0x41, 0x3d,
    0x30, 0x38, 0x38, 0x31, 0x33, 0x32, 0x48, 0x65,
    0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
    0x64, 0x21
};

// Test address decoding
void test_address_decode() {
    printf("--test_address_decode\n");
    uint8_t data[7] = {0x82, 0xa0, 0xa4, 0xa6, 0x40, 0x40, 0xe0}; // APRS
    ax25_address_t *addr = ax25_address_decode(data);
    if (addr == NULL) {
        printf("1- test_address_decode: Failed to decode address\n");
        return;
    }
    char expected_callsign[7] = "APRS  ";
    if (memcmp(addr->callsign, expected_callsign, 6) != 0) {
        printf("2 -test_address_decode: Callsign mismatch: %.*s\n", 6, addr->callsign);
    }
    if (addr->ssid != 0) {
        printf("3 -test_address_decode: SSID mismatch: %d\n", addr->ssid);
    }
    ax25_address_free(addr);
    printf("- test_address_decode: Passed\n");
}

// Test address encoding
void test_address_encode() {
    printf("--test_address_encode\n");
    ax25_address_t addr;
    memset(&addr, 0, sizeof(addr));
    memcpy(addr.callsign, "APRS  ", 6);
    addr.ssid = 0;
    uint8_t expected[7] = {0x82, 0xa0, 0xa4, 0xa6, 0x40, 0x40, 0xe0};
    size_t len;
    uint8_t *encoded = ax25_address_encode(&addr, &len);
    if (encoded == NULL || len != 7) {
        printf("1- test_address_encode: Encoding failed\n");
        free(encoded);
        return;
    }
    if (memcmp(encoded, expected, 7) != 0) {
        printf("2 -test_address_encode: Encoded data mismatch\n");
    }
    free(encoded);
    printf("- test_address_encode: Passed\n");
}

// Test address from string
void test_address_from_string() {
    printf("--test_address_from_string\n");
    ax25_address_t *addr = ax25_address_from_string("APRS");
    if (addr == NULL) {
        printf("1- test_address_from_string: Failed to create address\n");
        return;
    }
    char expected_callsign[7] = "APRS  ";
    if (memcmp(addr->callsign, expected_callsign, 6) != 0) {
        printf("2- test_address_from_string: Callsign mismatch: %.*s\n", 6, addr->callsign);
    }
    if (addr->ssid != 0) {
        printf("3- test_address_from_string: SSID mismatch: %d\n", addr->ssid);
    }
    ax25_address_free(addr);
    printf("- test_address_from_string: Passed\n");
}

// Test address copy
void test_address_copy() {
    printf("--test_address_copy\n");
    ax25_address_t *addr1 = ax25_address_from_string("APRS");
    if (addr1 == NULL) {
        printf("1- test_address_copy: Failed to create address\n");
        return;
    }
    ax25_address_t *addr2 = ax25_address_copy(addr1);
    if (addr2 == NULL) {
        printf("2- test_address_copy: Copy failed\n");
        ax25_address_free(addr1);
        return;
    }
    if (memcmp(addr1->callsign, addr2->callsign, 6) != 0 || addr1->ssid != addr2->ssid) {
        printf("3- test_address_copy: Copied address mismatch\n");
    }
    ax25_address_free(addr1);
    ax25_address_free(addr2);
    printf("- test_address_copy: Passed\n");
}

// Test frame header decoding
void test_frame_header_decode() {
    printf("--test_frame_header_decode\n");
    header_decode_result_t result = ax25_frame_header_decode(frame_data, frame_len);
    if (result.header == NULL) {
        printf("1- test_frame_header_decode: Failed to decode header\n");
        return;
    }
    if (memcmp(result.header->destination.callsign, "APRS  ", 6) != 0 || result.header->destination.ssid != 0) {
        printf("2- test_frame_header_decode: Destination mismatch\n");
    }
    if (memcmp(result.header->source.callsign, "NOCALL", 6) != 0 || result.header->source.ssid != 1) {
        printf("3- test_frame_header_decode: Source mismatch\n");
    }
    if (result.header->repeaters.num_repeaters != 1 ||
        memcmp(result.header->repeaters.repeaters[0].callsign, "WIDE1 ", 6) != 0 ||
        result.header->repeaters.repeaters[0].ssid != 1) {
        printf("4 -test_frame_header_decode: Digipeater mismatch\n");
    }
    if (result.remaining_len < 1 || result.remaining[0] != 0x03) {
        printf("5 -test_frame_header_decode: Remaining data mismatch\n");
    }
    ax25_frame_header_free(result.header);
    printf("- test_frame_header_decode: Passed\n");
}

// Test frame decoding
void test_frame_decode() {
    printf("--test_frame_decode\n");
    ax25_frame_t *frame = ax25_frame_decode(frame_data, frame_len, MODULO128_FALSE);
    if (frame == NULL) {
        printf("1- test_frame_decode: Failed to decode frame\n");
        return;
    }
    if (frame->type != AX25_FRAME_UNNUMBERED_INFORMATION) {
        printf("2- test_frame_decode: Frame type mismatch: %d\n", frame->type);
    } else {
        ax25_unnumbered_information_frame_t *ui_frame = (ax25_unnumbered_information_frame_t *)frame;
        if (ui_frame->pid != 0xf0) {
            printf("3- test_frame_decode: PID mismatch: %02x\n", ui_frame->pid);
        }
        if (ui_frame->payload_len != sizeof(expected_payload) ||
            memcmp(ui_frame->payload, expected_payload, ui_frame->payload_len) != 0) {
            printf("4- test_frame_decode: Payload mismatch\n");
        }
    }
    ax25_frame_free(frame);
    printf("- test_frame_decode: Passed\n");
}

// Test frame encoding
void test_frame_encode() {
    printf("--test_frame_encode\n");
    ax25_address_t *dest = ax25_address_from_string("APRS");
    ax25_address_t *src = ax25_address_from_string("NOCALL-1");
    ax25_address_t *digi = ax25_address_from_string("WIDE1-1");
    if (!dest || !src || !digi) {
        printf("1- test_frame_encode: Failed to create addresses\n");
        ax25_address_free(dest);
        ax25_address_free(src);
        ax25_address_free(digi);
        return;
    }
    ax25_path_t path = {{*digi}, 1};
    ax25_frame_header_t *header = malloc(sizeof(ax25_frame_header_t));
    if (!header) {
        printf("2- test_frame_encode: Failed to allocate header\n");
        ax25_address_free(dest);
        ax25_address_free(src);
        ax25_address_free(digi);
        return;
    }
    header->destination = *dest;
    header->source = *src;
    header->repeaters = path;
    header->cr = 1;
    header->src_cr = 1;
    header->legacy = 0;
    ax25_unnumbered_information_frame_t *ui_frame = malloc(sizeof(ax25_unnumbered_information_frame_t));
    if (!ui_frame) {
        printf("3- test_frame_encode: Failed to allocate frame\n");
        free(header);
        ax25_address_free(dest);
        ax25_address_free(src);
        ax25_address_free(digi);
        return;
    }
    ui_frame->base.base.type = AX25_FRAME_UNNUMBERED_INFORMATION;
    memcpy(&(ui_frame->base.base.header), header, sizeof(ax25_frame_header_t));
    ui_frame->pid = 0xf0;
    ui_frame->payload = expected_payload;
    ui_frame->payload_len = sizeof(expected_payload);
    size_t encoded_len;
    uint8_t *encoded = ax25_frame_encode((ax25_frame_t *)ui_frame, &encoded_len);
    if (encoded == NULL || encoded_len != frame_len) {
        printf("4- test_frame_encode: Encoding failed or length mismatch: %zu vs %zu\n", encoded_len, frame_len);
    } else if (memcmp(encoded, frame_data, frame_len) != 0) {
        printf("5- test_frame_encode: Encoded data mismatch\n");
    } else {
        printf("- test_frame_encode: Passed\n");
    }
    free(encoded);
    ax25_frame_free((ax25_frame_t *)ui_frame);
    ax25_address_free(dest);
    ax25_address_free(src);
    ax25_address_free(digi);
}

// Test encode and decode in series
void test_encode_decode_series() {
    printf("--test_encode_decode_series\n");
    ax25_address_t *dest = ax25_address_from_string("APRS");
    ax25_address_t *src = ax25_address_from_string("NOCALL-1");
    ax25_address_t *digi = ax25_address_from_string("WIDE1-1");
    if (!dest || !src || !digi) {
        printf("1- test_encode_decode_series: Failed to create addresses\n");
        ax25_address_free(dest);
        ax25_address_free(src);
        ax25_address_free(digi);
        return;
    }
    ax25_path_t path = {{*digi}, 1};
    ax25_frame_header_t *header = malloc(sizeof(ax25_frame_header_t));
    if (!header) {
        printf("2- test_encode_decode_series: Failed to allocate header\n");
        ax25_address_free(dest);
        ax25_address_free(src);
        ax25_address_free(digi);
        return;
    }
    header->destination = *dest;
    header->source = *src;
    header->repeaters = path;
    header->cr = 1;
    header->src_cr = 1;
    header->legacy = 0;
    ax25_unnumbered_information_frame_t *ui_frame = malloc(sizeof(ax25_unnumbered_information_frame_t));
    if (!ui_frame) {
        printf("3- test_encode_decode_series: Failed to allocate frame\n");
        free(header);
        ax25_address_free(dest);
        ax25_address_free(src);
        ax25_address_free(digi);
        return;
    }
    ui_frame->base.base.type = AX25_FRAME_UNNUMBERED_INFORMATION;
    memcpy(&(ui_frame->base.base.header), header, sizeof(ax25_frame_header_t));
    ui_frame->pid = 0xf0;
    ui_frame->payload = expected_payload;
    ui_frame->payload_len = sizeof(expected_payload);
    size_t encoded_len;
    uint8_t *encoded = ax25_frame_encode((ax25_frame_t *)ui_frame, &encoded_len);
    if (encoded == NULL) {
        printf("4- test_encode_decode_series: Encoding failed\n");
        ax25_frame_free((ax25_frame_t *)ui_frame);
        ax25_address_free(dest);
        ax25_address_free(src);
        ax25_address_free(digi);
        return;
    }
    ax25_frame_t *decoded_frame = ax25_frame_decode(encoded, encoded_len, MODULO128_FALSE);
    if (decoded_frame == NULL) {
        printf("test_encode_decode_series: Decoding failed\n");
        free(encoded);
        ax25_frame_free((ax25_frame_t *)ui_frame);
        ax25_address_free(dest);
        ax25_address_free(src);
        ax25_address_free(digi);
        return;
    }
    if (decoded_frame->type != AX25_FRAME_UNNUMBERED_INFORMATION) {
        printf("5- test_encode_decode_series: Frame type mismatch: %d\n", decoded_frame->type);
    } else {
        ax25_unnumbered_information_frame_t *decoded_ui = (ax25_unnumbered_information_frame_t *)decoded_frame;
        if (decoded_ui->pid != ui_frame->pid) {
            printf("6- test_encode_decode_series: PID mismatch: %02x vs %02x\n", decoded_ui->pid, ui_frame->pid);
        }
        if (decoded_ui->payload_len != ui_frame->payload_len ||
            memcmp(decoded_ui->payload, ui_frame->payload, ui_frame->payload_len) != 0) {
            printf("7- test_encode_decode_series: Payload mismatch\n");
        }
        if (memcmp(decoded_ui->base.base.header.destination.callsign, ui_frame->base.base.header.destination.callsign, 6) != 0 ||
            decoded_ui->base.base.header.destination.ssid != ui_frame->base.base.header.destination.ssid) {
            printf("8- test_encode_decode_series: Destination mismatch\n");
        }
    }
    free(encoded);
    ax25_frame_free(decoded_frame);
    ax25_frame_free((ax25_frame_t *)ui_frame);
    ax25_address_free(dest);
    ax25_address_free(src);
    ax25_address_free(digi);
    printf("- test_encode_decode_series: Passed\n");
}

int main() {
    printf("Starting AX.25 library tests...\n");
    test_address_decode();
    test_address_encode();
    test_address_from_string();
    test_address_copy();
    test_frame_header_decode();
    test_frame_decode();
    test_frame_encode();
    test_encode_decode_series();
    printf("All tests completed.\n");
    return 0;
}
