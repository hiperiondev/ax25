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

#include "test_common.h"
#include "ax25.h"
#include "hdlc.h"

static uint32_t assert_count = 0;

int test_hdlc() {
    printf("test_hdlc\n");
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

int test_hdlc_main() {
    int result = 0;
    printf("\n----------------------------------------------------------------------------------\n");
    printf("Starting HDLC Tests\n");
    printf("----------------------------------------------------------------------------------\n\n");
    result |= test_hdlc();
    printf("\n----------------------------------------------------------------------------------\n");
    printf("Tests HDLC Completed. %s\n", result == 0 ? "All tests passed" : "Some tests failed");
    printf("----------------------------------------------------------------------------------\n\n");
    return result;
}


