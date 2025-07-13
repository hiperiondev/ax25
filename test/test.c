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
    ax25_address_t *repeaters[] = {addr1, addr2};
    ax25_path_t *path = ax25_path_new(repeaters, 2, &err);
    TEST_ASSERT(path != NULL, "ax25_path_new should return non-NULL", err);
    ax25_path_free(path, &err);
    ax25_address_free(addr1, &err);
    ax25_address_free(addr2, &err);
    return 0;
}

int test_frame_header_functions() {
    uint8_t header_data[] = {0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                             0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1};
    header_decode_result_t result = ax25_frame_header_decode(header_data, sizeof(header_data), &err);
    TEST_ASSERT(result.header != NULL, "ax25_frame_header_decode should return non-NULL header", err);
    if (result.header) {
        size_t len;
        uint8_t *encoded = ax25_frame_header_encode(result.header, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_frame_header_encode should return non-NULL", err);
        TEST_ASSERT(len == sizeof(header_data), "Encoded header length should match input", err);
        if (encoded) free(encoded);
        ax25_frame_header_free(result.header, &err);
    }
    return 0;
}

int test_frame_functions() {
    uint8_t frame_data[] = {0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                            0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1,
                            0x03, 0xF0, 'T', 'E', 'S', 'T'};
    ax25_frame_t *frame = ax25_frame_decode(frame_data, sizeof(frame_data), 0, &err);
    TEST_ASSERT(frame != NULL, "ax25_frame_decode should return non-NULL", err);
    if (frame) {
        size_t len;
        uint8_t *encoded = ax25_frame_encode(frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_frame_encode should return non-NULL", err);
        if (encoded) free(encoded);
        ax25_frame_free(frame, &err);
    }
    return 0;
}

int test_raw_frame_functions() {
    uint8_t frame_data[] = {0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                            0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1,
                            0x03, 0xF0, 'T', 'E', 'S', 'T'};
    ax25_raw_frame_t raw_frame = {
        .payload = frame_data,
        .payload_len = sizeof(frame_data)
    };
    size_t len;
    uint8_t *encoded = ax25_raw_frame_encode(&raw_frame, &len, &err);
    TEST_ASSERT(encoded != NULL, "ax25_raw_frame_encode should return non-NULL", err);
    if (encoded) free(encoded);
    return 0;
}

int test_unnumbered_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[]){0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                                                                       0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1}, 14, &err).header;
    ax25_unnumbered_frame_t *u_frame = ax25_unnumbered_frame_decode(header, 0x03, NULL, 0, &err);
    TEST_ASSERT(u_frame != NULL, "ax25_unnumbered_frame_decode should return non-NULL", err);
    if (u_frame) {
        size_t len;
        uint8_t *encoded = ax25_unnumbered_frame_encode(u_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_unnumbered_frame_encode should return non-NULL", err);
        if (encoded) free(encoded);
        ax25_frame_free((ax25_frame_t *)u_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

int test_unnumbered_information_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[]){0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                                                                       0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1}, 14, &err).header;
    uint8_t info[] = "TEST";
    ax25_unnumbered_information_frame_t *ui_frame = ax25_unnumbered_information_frame_decode(header, true, info, 4, &err);
    TEST_ASSERT(ui_frame != NULL, "ax25_unnumbered_information_frame_decode should return non-NULL", err);
    if (ui_frame) {
        size_t len;
        uint8_t *encoded = ax25_unnumbered_information_frame_encode(ui_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_unnumbered_information_frame_encode should return non-NULL", err);
        if (encoded) free(encoded);
        ax25_frame_free((ax25_frame_t *)ui_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

int test_frame_reject_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[]){0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                                                                       0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1}, 14, &err).header;
    ax25_frame_reject_frame_t *frmr_frame = ax25_frame_reject_frame_decode(header, true, NULL, 0, &err);
    TEST_ASSERT(frmr_frame != NULL, "ax25_frame_reject_frame_decode should return non-NULL", err);
    if (frmr_frame) {
        size_t len;
        uint8_t *encoded = ax25_frame_reject_frame_encode(frmr_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_frame_reject_frame_encode should return non-NULL", err);
        if (encoded) free(encoded);
        ax25_frame_free((ax25_frame_t *)frmr_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

int test_information_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[]){0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                                                                       0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1}, 14, &err).header;
    uint8_t info[] = "TEST";
    ax25_information_frame_t *i_frame = ax25_information_frame_decode(header, 0x00, info, 4, false, &err);
    TEST_ASSERT(i_frame != NULL, "ax25_information_frame_decode should return non-NULL", err);
    if (i_frame) {
        size_t len;
        uint8_t *encoded = ax25_information_frame_encode(i_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_information_frame_encode should return non-NULL", err);
        if (encoded) free(encoded);
        ax25_frame_free((ax25_frame_t *)i_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

int test_supervisory_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[]){0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                                                                       0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1}, 14, &err).header;
    ax25_supervisory_frame_t *s_frame = ax25_supervisory_frame_decode(header, 0x01, false, &err); // RR
    TEST_ASSERT(s_frame != NULL, "ax25_supervisory_frame_decode should return non-NULL", err);
    if (s_frame) {
        size_t len;
        uint8_t *encoded = ax25_supervisory_frame_encode(s_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_supervisory_frame_encode should return non-NULL", err);
        if (encoded) free(encoded);
        ax25_frame_free((ax25_frame_t *)s_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

int test_xid_parameter_functions() {
    uint8_t pv[] = {0x01, 0x02};
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
            if (decoded) ax25_xid_raw_parameter_free(decoded, &err);
            free(encoded);
        }
        ax25_xid_parameter_t *copy = ax25_xid_raw_parameter_copy(param, &err);
        TEST_ASSERT(copy != NULL, "ax25_xid_raw_parameter_copy should return non-NULL", err);
        if (copy) ax25_xid_raw_parameter_free(copy, &err);
        ax25_xid_raw_parameter_free(param, &err);
    }

    param = ax25_xid_class_of_procedures_new(true, false, true, false, true, false, true, false, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_class_of_procedures_new should return non-NULL", err);
    if (param) ax25_xid_raw_parameter_free(param, &err);

    param = ax25_xid_hdlc_optional_functions_new(true, false, true, false, true, false, true, false, true,
                                                false, false, false, false, false, false, false, false,
                                                false, false, false, false, false, false, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_hdlc_optional_functions_new should return non-NULL", err);
    if (param) ax25_xid_raw_parameter_free(param, &err);

    param = ax25_xid_big_endian_new(1, 0x12345678, 4, &err);
    TEST_ASSERT(param != NULL, "ax25_xid_big_endian_new should return non-NULL", err);
    if (param) ax25_xid_raw_parameter_free(param, &err);

    ax25_xid_init_defaults(&err); // No return value to check
    printf("\033[0;32m   PASS: ax25_xid_init_defaults executed\033[0m\n");
    return 0;
}

int test_exchange_identification_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[]){0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                                                                       0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1}, 14, &err).header;
    uint8_t data[] = {0x01, 0x02};
    ax25_exchange_identification_frame_t *xid_frame = ax25_exchange_identification_frame_decode(header, true, data, 2, &err);
    TEST_ASSERT(xid_frame != NULL, "ax25_exchange_identification_frame_decode should return non-NULL", err);
    if (xid_frame) {
        size_t len;
        uint8_t *encoded = ax25_exchange_identification_frame_encode(xid_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_exchange_identification_frame_encode should return non-NULL", err);
        if (encoded) free(encoded);
        ax25_frame_free((ax25_frame_t *)xid_frame, &err);
    }
    ax25_frame_header_free(header, &err);
    return 0;
}

int test_test_frame_functions() {
    ax25_frame_header_t *header = ax25_frame_header_decode((uint8_t[]){0x82, 0xA0, 0xA4, 0xA6, 0x40, 0x40, 0xE0,
                                                                       0x9C, 0x9E, 0x86, 0x82, 0x98, 0x98, 0xE1}, 14, &err).header;
    uint8_t data[] = "TEST";
    ax25_test_frame_t *test_frame = ax25_test_frame_decode(header, true, data, 4, &err);
    TEST_ASSERT(test_frame != NULL, "ax25_test_frame_decode should return non-NULL", err);
    if (test_frame) {
        size_t len;
        uint8_t *encoded = ax25_test_frame_encode(test_frame, &len, &err);
        TEST_ASSERT(encoded != NULL, "ax25_test_frame_encode should return non-NULL", err);
        if (encoded) free(encoded);
        ax25_frame_free((ax25_frame_t *)test_frame, &err);
    }
    ax25_frame_header_free(header, &err);
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
    printf("\nTests Completed. %s\n", result == 0 ? "All tests passed" : "Some tests failed");
    return result;
}
