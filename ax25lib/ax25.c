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
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "ax25.h"

// Default XID Parameters
ax25_xid_parameter_t *AX25_20_DEFAULT_XID_COP = NULL;
ax25_xid_parameter_t *AX25_22_DEFAULT_XID_COP = NULL;
ax25_xid_parameter_t *AX25_20_DEFAULT_XID_HDLCOPTFUNC = NULL;
ax25_xid_parameter_t *AX25_22_DEFAULT_XID_HDLCOPTFUNC = NULL;
ax25_xid_parameter_t *AX25_20_DEFAULT_XID_IFIELDRX = NULL;
ax25_xid_parameter_t *AX25_22_DEFAULT_XID_IFIELDRX = NULL;
ax25_xid_parameter_t *AX25_20_DEFAULT_XID_WINDOWSZRX = NULL;
ax25_xid_parameter_t *AX25_22_DEFAULT_XID_WINDOWSZRX = NULL;
ax25_xid_parameter_t *AX25_20_DEFAULT_XID_ACKTIMER = NULL;
ax25_xid_parameter_t *AX25_22_DEFAULT_XID_ACKTIMER = NULL;
ax25_xid_parameter_t *AX25_20_DEFAULT_XID_RETRIES = NULL;
ax25_xid_parameter_t *AX25_22_DEFAULT_XID_RETRIES = NULL;

static double current_time() {
    return (double) time(NULL);
}

static uint8_t* uint_encode(uint32_t value, bool big_endian, size_t length, size_t *out_len, uint8_t *err) {
    *err = 0;

    uint8_t *bytes = malloc(length);
    if (!bytes){
        *err = 1;
        return NULL;
    }

    for (size_t i = 0; i < length; i++) {
        bytes[big_endian ? length - 1 - i : i] = (value >> (i * 8)) & 0xFF;
    }

    *out_len = length;
    return bytes;
}

static uint32_t uint_decode(const uint8_t *data, size_t len, bool big_endian, uint8_t *err) {
    *err = 0;
    uint32_t value = 0;

    for (size_t i = 0; i < len; i++) {
        value |= (data[big_endian ? len - 1 - i : i]) << (i * 8);
    }

    return value;
}

ax25_address_t* ax25_address_decode(const uint8_t *data, uint8_t *err) {
    *err = 0;
    ax25_address_t *addr = malloc(sizeof(ax25_address_t));

    if (!addr) {
        *err = 1;
        return NULL;
    }

    for (int i = 0; i < 6; i++) {
        addr->callsign[i] = (data[i] >> 1) & 0x7F;
    }

    addr->callsign[6] = '\0';
    addr->ssid = (data[6] & 0x1E) >> 1;
    addr->ch = (data[6] & 0x80) != 0;
    addr->res0 = (data[6] & 0x40) != 0;
    addr->res1 = (data[6] & 0x20) != 0;
    addr->extension = (data[6] & 0x01) != 0;

    return addr;
}

ax25_address_t* ax25_address_from_string(const char *str, uint8_t *err) {
    *err = 0;
    ax25_address_t *addr = malloc(sizeof(ax25_address_t));

    if (!addr){
        *err = 1;
        return NULL;
    }

    char callsign[CALLSIGN_MAX];
    int ssid = 0;
    bool ch = false;

    sscanf(str, "%6[^-]%d%*[*]", callsign, &ssid);
    if (strchr(str, '*'))
        ch = true;

    strncpy(addr->callsign, callsign, CALLSIGN_MAX - 1);
    addr->callsign[CALLSIGN_MAX - 1] = '\0';
    addr->ssid = ssid & 0x0F;
    addr->ch = ch;
    addr->res0 = true;
    addr->res1 = true;
    addr->extension = false;

    return addr;
}

uint8_t* ax25_address_encode(const ax25_address_t *addr, size_t *len, uint8_t *err) {
    *err = 0;
    uint8_t *bytes = malloc(7);

    if (!bytes){
        *err = 1;
        return NULL;
    }

    for (int i = 0; i < 6; i++) {
        bytes[i] = (addr->callsign[i] ? addr->callsign[i] : ' ') << 1;
    }

    bytes[6] = (addr->ssid << 1) & 0x1E;
    if (addr->extension)
        bytes[6] |= 0x01;
    if (addr->res0)
        bytes[6] |= 0x20;
    if (addr->res1)
        bytes[6] |= 0x40;
    if (addr->ch)
        bytes[6] |= 0x80;
    *len = 7;

    return bytes;
}

ax25_address_t* ax25_address_copy(const ax25_address_t *addr, uint8_t *err) {
    *err = 0;
    ax25_address_t *copy = malloc(sizeof(ax25_address_t));

    if (!copy){
        *err = 1;
        return NULL;
    }
    memcpy(copy, addr, sizeof(ax25_address_t));

    return copy;
}

void ax25_address_free(ax25_address_t *addr, uint8_t *err) {
    *err = 0;
    free(addr);
}

ax25_path_t* ax25_path_new(ax25_address_t **repeaters, int num, uint8_t *err) {
    *err = 0;
    ax25_path_t *path = malloc(sizeof(ax25_path_t));

    if (!path){
        *err = 1;
        return NULL;
    }

    path->num_repeaters = num > MAX_REPEATERS ? MAX_REPEATERS : num;
    for (int i = 0; i < path->num_repeaters; i++) {
        path->repeaters[i] = *repeaters[i];
    }

    return path;
}

void ax25_path_free(ax25_path_t *path, uint8_t *err) {
    *err = 0;
    free(path);
}

header_decode_result_t ax25_frame_header_decode(const uint8_t *data, size_t len, uint8_t *err) {
    *err = 0;
    header_decode_result_t result = { NULL, data, len };
    ax25_address_t *addresses[2 + MAX_REPEATERS];
    int addr_count = 0;
    size_t pos = 0;

    while (pos + 7 <= len && addr_count < 2 + MAX_REPEATERS) {
        addresses[addr_count] = ax25_address_decode(data + pos, err);
        pos += 7;
        addr_count++;
        if (addr_count > 0 && addresses[addr_count - 1]->extension)
            break;
    }

    if (addr_count < 2) {
        for (int i = 0; i < addr_count; i++)
            ax25_address_free(addresses[i], err);
        return result;
    }

    ax25_frame_header_t *header = malloc(sizeof(ax25_frame_header_t));
    if (!header) {
        for (int i = 0; i < addr_count; i++)
            ax25_address_free(addresses[i], err);
        return result;
    }

    header->destination = *addresses[0];
    header->source = *addresses[1];
    header->cr = header->destination.ch;
    header->src_cr = header->source.ch;
    header->legacy = (header->destination.ch == header->source.ch);
    header->repeaters.num_repeaters = addr_count - 2;
    for (int i = 0; i < header->repeaters.num_repeaters; i++) {
        header->repeaters.repeaters[i] = *addresses[i + 2];
    }

    for (int i = 0; i < addr_count; i++)
        ax25_address_free(addresses[i], err);

    result.header = header;
    result.remaining = data + pos;
    result.remaining_len = len - pos;

    return result;
}

uint8_t* ax25_frame_header_encode(const ax25_frame_header_t *header, size_t *len, uint8_t *err) {
    *err = 0;
    size_t total_len = 7 * (2 + header->repeaters.num_repeaters);
    uint8_t *bytes = malloc(total_len);

    if (!bytes){
        *err = 1;
        return NULL;
    }

    size_t offset = 0;
    ax25_address_t dest = header->destination;
    dest.extension = false;
    dest.ch = header->cr;
    size_t dest_len;
    uint8_t *dest_bytes = ax25_address_encode(&dest, &dest_len, err);
    memcpy(bytes + offset, dest_bytes, dest_len);
    offset += dest_len;
    free(dest_bytes);

    ax25_address_t src = header->source;
    src.extension = (header->repeaters.num_repeaters == 0);
    src.ch = header->src_cr;
    size_t src_len;
    uint8_t *src_bytes = ax25_address_encode(&src, &src_len, err);
    memcpy(bytes + offset, src_bytes, src_len);
    offset += src_len;
    free(src_bytes);

    for (int i = 0; i < header->repeaters.num_repeaters; i++) {
        ax25_address_t rpt = header->repeaters.repeaters[i];
        rpt.extension = (i == header->repeaters.num_repeaters - 1);
        size_t rpt_len;
        uint8_t *rpt_bytes = ax25_address_encode(&rpt, &rpt_len, err);
        memcpy(bytes + offset, rpt_bytes, rpt_len);
        offset += rpt_len;
        free(rpt_bytes);
    }

    *len = total_len;
    return bytes;
}

void ax25_frame_header_free(ax25_frame_header_t *header, uint8_t *err) {
    *err = 0;
    free(header);
}

ax25_frame_t* ax25_frame_decode(const uint8_t *data, size_t len, int modulo128, uint8_t *err) {
    *err = 0;

    if (len < 14) {
        *err = 1;
        return NULL; // Minimum header size
    }
    header_decode_result_t hdr_result = ax25_frame_header_decode(data, len, err);
    if (!hdr_result.header) {
        *err = 2;
        return NULL;
    }

    if (hdr_result.remaining_len == 0) {
        *err = 3;
        ax25_frame_header_free(hdr_result.header, err);
        return NULL;
    }

    uint8_t control = hdr_result.remaining[0];
    ax25_frame_t *frame = NULL;

    if ((control & CONTROL_US_MASK) == CONTROL_U_VAL) {
        frame = (ax25_frame_t*) ax25_unnumbered_frame_decode(hdr_result.header, control, hdr_result.remaining + 1, hdr_result.remaining_len - 1, err);
    } else {
        if (modulo128 == MODULO128_NONE) {
            ax25_raw_frame_t *raw = malloc(sizeof(ax25_raw_frame_t));
            if (!raw) {
                *err = 4;
                ax25_frame_header_free(hdr_result.header, err);
                return NULL;
            }
            raw->base.type = AX25_FRAME_RAW;
            raw->base.header = *hdr_result.header;
            raw->base.timestamp = current_time();
            raw->base.deadline = 0.0;
            raw->payload_len = hdr_result.remaining_len;
            raw->payload = malloc(raw->payload_len);
            if (!raw->payload) {
                *err = 5;
                free(raw);
                ax25_frame_header_free(hdr_result.header, err);
                return NULL;
            }
            memcpy(raw->payload, hdr_result.remaining, raw->payload_len);
            frame = (ax25_frame_t*) raw;
        } else {
            bool is_16bit = (modulo128 == MODULO128_TRUE);
            size_t control_size = is_16bit ? 2 : 1;
            if (hdr_result.remaining_len < control_size) {
                *err = 6;
                ax25_frame_header_free(hdr_result.header, err);
                return NULL;
            }
            uint16_t full_control = control;
            if (is_16bit)
                full_control |= (hdr_result.remaining[1] << 8);

            const uint8_t *data_start = hdr_result.remaining + control_size;
            size_t data_len = hdr_result.remaining_len - control_size;

            if ((full_control & CONTROL_I_MASK) == CONTROL_I_VAL) {
                frame = (ax25_frame_t*) ax25_information_frame_decode(hdr_result.header, full_control, data_start, data_len, is_16bit, err);
            } else if ((full_control & CONTROL_US_MASK) == CONTROL_S_VAL) {
                frame = (ax25_frame_t*) ax25_supervisory_frame_decode(hdr_result.header, full_control, is_16bit, err);
            }
        }
    }

    ax25_frame_header_free(hdr_result.header, err);

    return frame;
}

uint8_t* ax25_frame_encode(const ax25_frame_t *frame, size_t *len, uint8_t *err) {
    *err = 0;
    size_t header_len, payload_len;
    uint8_t *header_bytes = ax25_frame_header_encode(&frame->header, &header_len, err);

    if (!header_bytes){
        *err = 1;
        return NULL;
    }

    uint8_t *payload_bytes = NULL;
    switch (frame->type) {
        case AX25_FRAME_RAW:
            payload_bytes = ax25_raw_frame_encode((ax25_raw_frame_t*) frame, &payload_len, err);
        break;
        case AX25_FRAME_UNNUMBERED_INFORMATION:
            payload_bytes = ax25_unnumbered_information_frame_encode((ax25_unnumbered_information_frame_t*) frame, &payload_len, err);
        break;
        case AX25_FRAME_UNNUMBERED_SABM:
        case AX25_FRAME_UNNUMBERED_SABME:
        case AX25_FRAME_UNNUMBERED_DISC:
        case AX25_FRAME_UNNUMBERED_DM:
        case AX25_FRAME_UNNUMBERED_UA:
            payload_bytes = ax25_unnumbered_frame_encode((ax25_unnumbered_frame_t*) frame, &payload_len, err);
        break;
        case AX25_FRAME_UNNUMBERED_FRMR:
            payload_bytes = ax25_frame_reject_frame_encode((ax25_frame_reject_frame_t*) frame, &payload_len, err);
        break;
        case AX25_FRAME_UNNUMBERED_XID:
            payload_bytes = ax25_exchange_identification_frame_encode((ax25_exchange_identification_frame_t*) frame, &payload_len, err);
        break;
        case AX25_FRAME_UNNUMBERED_TEST:
            payload_bytes = ax25_test_frame_encode((ax25_test_frame_t*) frame, &payload_len, err);
        break;
        case AX25_FRAME_INFORMATION_8BIT:
        case AX25_FRAME_INFORMATION_16BIT:
            payload_bytes = ax25_information_frame_encode((ax25_information_frame_t*) frame, &payload_len, err);
        break;
        case AX25_FRAME_SUPERVISORY_RR_8BIT:
        case AX25_FRAME_SUPERVISORY_RNR_8BIT:
        case AX25_FRAME_SUPERVISORY_REJ_8BIT:
        case AX25_FRAME_SUPERVISORY_SREJ_8BIT:
        case AX25_FRAME_SUPERVISORY_RR_16BIT:
        case AX25_FRAME_SUPERVISORY_RNR_16BIT:
        case AX25_FRAME_SUPERVISORY_REJ_16BIT:
        case AX25_FRAME_SUPERVISORY_SREJ_16BIT:
            payload_bytes = ax25_supervisory_frame_encode((ax25_supervisory_frame_t*) frame, &payload_len, err);
        break;
        default:
            *err = 2;
            free(header_bytes);
            return NULL;
    }

    if (!payload_bytes) {
        *err = 3;
        free(header_bytes);
        return NULL;
    }

    *len = header_len + payload_len;
    uint8_t *result = malloc(*len);
    if (!result) {
        *err = 4;
        free(header_bytes);
        free(payload_bytes);
        return NULL;
    }

    memcpy(result, header_bytes, header_len);
    memcpy(result + header_len, payload_bytes, payload_len);
    free(header_bytes);
    free(payload_bytes);

    return result;
}

void ax25_frame_free(ax25_frame_t *frame, uint8_t *err) {
    *err = 0;

    if (!frame){
        *err = 1;
        return;
    }

    switch (frame->type) {
        case AX25_FRAME_RAW:
            free(((ax25_raw_frame_t*) frame)->payload);
        break;
        case AX25_FRAME_UNNUMBERED_INFORMATION:
            free(((ax25_unnumbered_information_frame_t*) frame)->payload);
        break;
        case AX25_FRAME_UNNUMBERED_XID: {
            ax25_exchange_identification_frame_t *xid = (ax25_exchange_identification_frame_t*) frame;
            for (size_t i = 0; i < xid->param_count; i++) {
                xid->parameters[i]->free(xid->parameters[i], err);
            }
            free(xid->parameters);
            break;
        }
        case AX25_FRAME_UNNUMBERED_TEST:
            free(((ax25_test_frame_t*) frame)->payload);
        break;
        case AX25_FRAME_INFORMATION_8BIT:
        case AX25_FRAME_INFORMATION_16BIT:
            free(((ax25_information_frame_t*) frame)->payload);
        break;
        default:
        break;
    }

    free(frame);
}

uint8_t* ax25_raw_frame_encode(const ax25_raw_frame_t *frame, size_t *len, uint8_t *err) {
    *err = 0;
    *len = frame->payload_len;
    uint8_t *bytes = malloc(*len);

    if (!bytes){
        *err = 1;
        return NULL;
    }
    memcpy(bytes, frame->payload, *len);

    return bytes;
}

ax25_unnumbered_frame_t* ax25_unnumbered_frame_decode(ax25_frame_header_t *header, uint8_t control, const uint8_t *data, size_t len, uint8_t *err) {
    uint8_t modifier = control & 0xEF;
    bool pf = (control & POLL_FINAL_8BIT) != 0;

    switch (modifier) {
        case 0x03: // UI
            return (ax25_unnumbered_frame_t*) ax25_unnumbered_information_frame_decode(header, pf, data, len, err);
        case 0x87: // FRMR
            return (ax25_unnumbered_frame_t*) ax25_frame_reject_frame_decode(header, pf, data, len, err);
        case 0xAF: // XID
            return (ax25_unnumbered_frame_t*) ax25_exchange_identification_frame_decode(header, pf, data, len, err);
        case 0xE3: // TEST
            return (ax25_unnumbered_frame_t*) ax25_test_frame_decode(header, pf, data, len, err);
        case 0x2F: // SABM
        case 0x6F: // SABME
        case 0x43: // DISC
        case 0x0F: // DM
        case 0x63: // UA
        break;
        default:
            *err = 1;
            return NULL;
    }

    ax25_unnumbered_frame_t *frame = malloc(sizeof(ax25_unnumbered_frame_t));

    if (!frame){
        *err = 2;
        return NULL;
    }
    frame->base.type = (modifier == 0x2F) ? AX25_FRAME_UNNUMBERED_SABM : (modifier == 0x6F) ? AX25_FRAME_UNNUMBERED_SABME :
                       (modifier == 0x43) ? AX25_FRAME_UNNUMBERED_DISC : (modifier == 0x0F) ? AX25_FRAME_UNNUMBERED_DM : AX25_FRAME_UNNUMBERED_UA;
    frame->base.header = *header;
    frame->base.timestamp = current_time();
    frame->base.deadline = 0.0;
    frame->pf = pf;
    frame->modifier = modifier;

    return frame;
}

uint8_t* ax25_unnumbered_frame_encode(const ax25_unnumbered_frame_t *frame, size_t *len, uint8_t *err) {
    *err = 0;
    uint8_t control = frame->modifier | (frame->pf ? POLL_FINAL_8BIT : 0);
    *len = 1;
    uint8_t *bytes = malloc(1);

    if (!bytes){
        *err = 1;
        return NULL;
    }

    bytes[0] = control;

    return bytes;
}

ax25_unnumbered_information_frame_t* ax25_unnumbered_information_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len, uint8_t *err) {
    *err = 0;

    if (len < 1){
        *err = 1;
        return NULL;
    }

    ax25_unnumbered_information_frame_t *frame = malloc(sizeof(ax25_unnumbered_information_frame_t));

    if (!frame){
        *err = 2;
        return NULL;
    }

    frame->base.base.type = AX25_FRAME_UNNUMBERED_INFORMATION;
    frame->base.base.header = *header;
    frame->base.base.timestamp = current_time();
    frame->base.base.deadline = 0.0;
    frame->base.pf = pf;
    frame->base.modifier = 0x03;
    frame->pid = data[0];
    frame->payload_len = len - 1;
    frame->payload = malloc(frame->payload_len);

    if (!frame->payload) {
        *err = 3;
        free(frame);
        return NULL;
    }

    memcpy(frame->payload, data + 1, frame->payload_len);

    return frame;
}

uint8_t* ax25_unnumbered_information_frame_encode(const ax25_unnumbered_information_frame_t *frame, size_t *len, uint8_t *err) {
    *err = 0;
    *len = 1 + 1 + frame->payload_len;
    uint8_t *bytes = malloc(*len);

    if (!bytes){
        *err = 1;
        return NULL;
    }

    bytes[0] = frame->base.modifier | (frame->base.pf ? POLL_FINAL_8BIT : 0);
    bytes[1] = frame->pid;
    memcpy(bytes + 2, frame->payload, frame->payload_len);

    return bytes;
}

ax25_frame_reject_frame_t* ax25_frame_reject_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len, uint8_t *err) {
    *err = 0;

    if (len != 3){
        *err = 1;
        return NULL;
    }

    ax25_frame_reject_frame_t *frame = malloc(sizeof(ax25_frame_reject_frame_t));

    if (!frame){
        *err = 2;
        return NULL;
    }

    frame->base.base.type = AX25_FRAME_UNNUMBERED_FRMR;
    frame->base.base.header = *header;
    frame->base.base.timestamp = current_time();
    frame->base.base.deadline = 0.0;
    frame->base.pf = pf;
    frame->base.modifier = 0x87;
    frame->w = (data[0] & 0x01) != 0;
    frame->x = (data[0] & 0x02) != 0;
    frame->y = (data[0] & 0x04) != 0;
    frame->z = (data[0] & 0x08) != 0;
    frame->vr = (data[1] & 0xE0) >> 5;
    frame->frmr_cr = (data[1] & 0x10) != 0;
    frame->vs = (data[1] & 0x0E) >> 1;
    frame->frmr_control = data[2];

    return frame;
}

uint8_t* ax25_frame_reject_frame_encode(const ax25_frame_reject_frame_t *frame, size_t *len, uint8_t *err) {
    *err = 0;
    *len = 4;
    uint8_t *bytes = malloc(*len);

    if (!bytes){
        *err = 1;
        return NULL;
    }

    bytes[0] = frame->base.modifier | (frame->base.pf ? POLL_FINAL_8BIT : 0);
    bytes[1] = (frame->w ? 0x01 : 0) | (frame->x ? 0x02 : 0) | (frame->y ? 0x04 : 0) | (frame->z ? 0x08 : 0);
    bytes[2] = ((frame->vr << 5) & 0xE0) | (frame->frmr_cr ? 0x10 : 0) | ((frame->vs << 1) & 0x0E);
    bytes[3] = frame->frmr_control;

    return bytes;
}

ax25_information_frame_t* ax25_information_frame_decode(ax25_frame_header_t *header, uint16_t control, const uint8_t *data, size_t len, bool is_16bit, uint8_t *err) {
    *err = 0;

    if (len < 1){
        *err = 1;
        return NULL;
    }

    ax25_information_frame_t *frame = malloc(sizeof(ax25_information_frame_t));

    if (!frame){
        *err = 2;
        return NULL;
    }

    frame->base.type = is_16bit ? AX25_FRAME_INFORMATION_16BIT : AX25_FRAME_INFORMATION_8BIT;
    frame->base.header = *header;
    frame->base.timestamp = current_time();
    frame->base.deadline = 0.0;
    frame->nr = is_16bit ? ((control & 0xFE00) >> 9) : ((control & 0xE0) >> 5);
    frame->pf = (control & (is_16bit ? POLL_FINAL_16BIT : POLL_FINAL_8BIT)) != 0;
    frame->ns = is_16bit ? ((control & 0x01FE) >> 1) : ((control & 0x0E) >> 1);
    frame->pid = data[0];
    frame->payload_len = len - 1;
    frame->payload = malloc(frame->payload_len);

    if (!frame->payload) {
        *err = 3;
        free(frame);
        return NULL;
    }

    memcpy(frame->payload, data + 1, frame->payload_len);
    return frame;
}

uint8_t* ax25_information_frame_encode(const ax25_information_frame_t *frame, size_t *len, uint8_t *err) {
    *err = 0;
    bool is_16bit = (frame->base.type == AX25_FRAME_INFORMATION_16BIT);
    *len = (is_16bit ? 2 : 1) + 1 + frame->payload_len;
    uint8_t *bytes = malloc(*len);

    if (!bytes){
        *err = 1;
        return NULL;
    }

    if (is_16bit) {
        uint16_t control = ((frame->nr << 9) & 0xFE00) | (frame->pf ? POLL_FINAL_16BIT : 0) | ((frame->ns << 1) & 0x01FE) | CONTROL_I_VAL;
        bytes[0] = control & 0xFF;
        bytes[1] = (control >> 8) & 0xFF;
        bytes[2] = frame->pid;
        memcpy(bytes + 3, frame->payload, frame->payload_len);
    } else {
        bytes[0] = ((frame->nr << 5) & 0xE0) | (frame->pf ? POLL_FINAL_8BIT : 0) | ((frame->ns << 1) & 0x0E) | CONTROL_I_VAL;
        bytes[1] = frame->pid;
        memcpy(bytes + 2, frame->payload, frame->payload_len);
    }

    return bytes;
}

ax25_supervisory_frame_t* ax25_supervisory_frame_decode(ax25_frame_header_t *header, uint16_t control, bool is_16bit, uint8_t *err) {
    *err = 0;
    uint8_t code = (control & 0x0C);
    ax25_frame_type_t type;

    if (is_16bit) {
        switch (code) {
            case 0x00:
                type = AX25_FRAME_SUPERVISORY_RR_16BIT;
            break;
            case 0x04:
                type = AX25_FRAME_SUPERVISORY_RNR_16BIT;
            break;
            case 0x08:
                type = AX25_FRAME_SUPERVISORY_REJ_16BIT;
            break;
            case 0x0C:
                type = AX25_FRAME_SUPERVISORY_SREJ_16BIT;
            break;
            default:
                return NULL;
        }
    } else {
        switch (code) {
            case 0x00:
                type = AX25_FRAME_SUPERVISORY_RR_8BIT;
            break;
            case 0x04:
                type = AX25_FRAME_SUPERVISORY_RNR_8BIT;
            break;
            case 0x08:
                type = AX25_FRAME_SUPERVISORY_REJ_8BIT;
            break;
            case 0x0C:
                type = AX25_FRAME_SUPERVISORY_SREJ_8BIT;
            break;
            default:
                *err = 1;
                return NULL;
        }
    }

    ax25_supervisory_frame_t *frame = malloc(sizeof(ax25_supervisory_frame_t));
    if (!frame){
        *err = 2;
        return NULL;
    }
    frame->base.type = type;
    frame->base.header = *header;
    frame->base.timestamp = current_time();
    frame->base.deadline = 0.0;
    frame->nr = is_16bit ? ((control & 0xFE00) >> 9) : ((control & 0xE0) >> 5);
    frame->pf = (control & (is_16bit ? POLL_FINAL_16BIT : POLL_FINAL_8BIT)) != 0;
    frame->code = code;

    return frame;
}

uint8_t* ax25_supervisory_frame_encode(const ax25_supervisory_frame_t *frame, size_t *len, uint8_t *err) {
    *err = 0;
    bool is_16bit = (frame->base.type >= AX25_FRAME_SUPERVISORY_RR_16BIT);
    *len = is_16bit ? 2 : 1;
    uint8_t *bytes = malloc(*len);

    if (!bytes){
        *err = 1;
        return NULL;
    }

    if (is_16bit) {
        uint16_t control = ((frame->nr << 9) & 0xFE00) | (frame->pf ? POLL_FINAL_16BIT : 0) | (frame->code & 0x0C) | CONTROL_S_VAL;
        bytes[0] = control & 0xFF;
        bytes[1] = (control >> 8) & 0xFF;
    } else {
        bytes[0] = ((frame->nr << 5) & 0xE0) | (frame->pf ? POLL_FINAL_8BIT : 0) | (frame->code & 0x0C) | CONTROL_S_VAL;
    }

    return bytes;
}

ax25_xid_parameter_t* ax25_xid_raw_parameter_new(int pi, const uint8_t *pv, size_t pv_len, uint8_t *err) {
    *err = 0;
    ax25_xid_parameter_t *param = malloc(sizeof(ax25_xid_parameter_t));

    if (!param){
        *err = 1;
        return NULL;
    }

    uint8_t *pv_copy = pv ? malloc(pv_len + sizeof(size_t)) : NULL;
    if (pv && !pv_copy) {
        *err = 2;
        free(param);
        return NULL;
    }

    if (pv) {
        memcpy(pv_copy, pv, pv_len);
        *(size_t*) (pv_copy + pv_len) = pv_len;
    }

    param->pi = pi;
    param->encode = ax25_xid_raw_parameter_encode;
    param->copy = ax25_xid_raw_parameter_copy;
    param->free = ax25_xid_raw_parameter_free;
    param->data = pv_copy;

    return param;
}

uint8_t* ax25_xid_raw_parameter_encode(const ax25_xid_parameter_t *param, size_t *len, uint8_t *err) {
    *err = 0;
    uint8_t *pv = (uint8_t*) param->data;
    size_t pv_len = pv ? *(size_t*) (pv + pv_len) : 0;
    *len = 2 + pv_len;
    uint8_t *bytes = malloc(*len);

    if (!bytes){
        *err = 1;
        return NULL;
    }

    bytes[0] = param->pi;
    bytes[1] = pv_len;
    if (pv_len)
        memcpy(bytes + 2, pv, pv_len);

    return bytes;
}

ax25_xid_parameter_t* ax25_xid_raw_parameter_copy(const ax25_xid_parameter_t *param, uint8_t *err) {
    *err = 0;
    uint8_t *pv = (uint8_t*) param->data;
    size_t pv_len = pv ? *(size_t*) (pv + pv_len) : 0;

    return ax25_xid_raw_parameter_new(param->pi, pv, pv_len, err);
}

void ax25_xid_raw_parameter_free(ax25_xid_parameter_t *param, uint8_t *err) {
    *err = 0;

    if (!param){
        *err = 1;
        return;
    }

    free(param->data);
    free(param);
}

ax25_xid_parameter_t* ax25_xid_parameter_decode(const uint8_t *data, size_t len, size_t *consumed, uint8_t *err) {
    *err = 0;

    if (len < 2){
        *err = 1;
        return NULL;
    }

    int pi = data[0];
    size_t pv_len = data[1];
    if (len < 2 + pv_len){
        *err = 2;
        return NULL;
    }

    ax25_xid_parameter_t *param = ax25_xid_raw_parameter_new(pi, data + 2, pv_len, err);
    if (!param){
        *err = 3;
        return NULL;
    }

    *consumed = 2 + pv_len;

    return param;
}

ax25_exchange_identification_frame_t* ax25_exchange_identification_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len, uint8_t *err) {
    *err = 0;

    if (len < 4){
        *err = 1;
        return NULL;
    }

    uint8_t fi = data[0];
    uint8_t gi = data[1];
    uint16_t gl = uint_decode(data + 2, 2, true, err);

    if (len - 4 != gl){
        *err = 2;
        return NULL;
    }

    ax25_xid_parameter_t **params = NULL;
    size_t param_count = 0;
    const uint8_t *param_data = data + 4;
    size_t remaining = gl;

    while (remaining > 0) {
        size_t consumed;
        ax25_xid_parameter_t *param = ax25_xid_parameter_decode(param_data, remaining, &consumed, err);
        if (!param) {
            *err = 3;
            for (size_t i = 0; i < param_count; i++)
                params[i]->free(params[i], err);
            free(params);
            return NULL;
        }

        ax25_xid_parameter_t **new_params = realloc(params, (param_count + 1) * sizeof(ax25_xid_parameter_t*));
        if (!new_params) {
            *err = 4;
            param->free(param, err);
            for (size_t i = 0; i < param_count; i++)
                params[i]->free(params[i], err);
            free(params);
            return NULL;
        }

        params = new_params;
        params[param_count++] = param;
        param_data += consumed;
        remaining -= consumed;
    }

    ax25_exchange_identification_frame_t *frame = malloc(sizeof(ax25_exchange_identification_frame_t));
    if (!frame) {
        *err = 5;
        for (size_t i = 0; i < param_count; i++)
            params[i]->free(params[i], err);
        free(params);
        return NULL;
    }

    frame->base.base.type = AX25_FRAME_UNNUMBERED_XID;
    frame->base.base.header = *header;
    frame->base.base.timestamp = current_time();
    frame->base.base.deadline = 0.0;
    frame->base.pf = pf;
    frame->base.modifier = 0xAF;
    frame->fi = fi;
    frame->gi = gi;
    frame->parameters = params;
    frame->param_count = param_count;

    return frame;
}

uint8_t* ax25_exchange_identification_frame_encode(const ax25_exchange_identification_frame_t *frame, size_t *len, uint8_t *err) {
    *err = 0;
    size_t params_len = 0;
    uint8_t **param_bytes = malloc(frame->param_count * sizeof(uint8_t*));
    size_t *param_lens = malloc(frame->param_count * sizeof(size_t));

    if (!param_bytes || !param_lens) {
        *err = 1;
        free(param_bytes);
        free(param_lens);
        return NULL;
    }

    for (size_t i = 0; i < frame->param_count; i++) {
        param_bytes[i] = frame->parameters[i]->encode(frame->parameters[i], &param_lens[i], err);
        if (!param_bytes[i]) {
            *err = 2;
            for (size_t j = 0; j < i; j++)
                free(param_bytes[j]);
            free(param_bytes);
            free(param_lens);
            return NULL;
        }
        params_len += param_lens[i];
    }

    *len = 1 + 4 + params_len;
    uint8_t *bytes = malloc(*len);
    if (!bytes) {
        *err = 3;
        for (size_t i = 0; i < frame->param_count; i++)
            free(param_bytes[i]);
        free(param_bytes);
        free(param_lens);
        return NULL;
    }

    bytes[0] = frame->base.modifier | (frame->base.pf ? POLL_FINAL_8BIT : 0);
    bytes[1] = frame->fi;
    bytes[2] = frame->gi;
    uint8_t *gl_bytes = uint_encode(params_len, true, 2, &params_len, err);
    memcpy(bytes + 3, gl_bytes, 2);
    free(gl_bytes);

    size_t offset = 5;
    for (size_t i = 0; i < frame->param_count; i++) {
        memcpy(bytes + offset, param_bytes[i], param_lens[i]);
        offset += param_lens[i];
        free(param_bytes[i]);
    }
    free(param_bytes);
    free(param_lens);

    return bytes;
}

ax25_test_frame_t* ax25_test_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len, uint8_t *err) {
    *err = 0;

    ax25_test_frame_t *frame = malloc(sizeof(ax25_test_frame_t));
    if (!frame){
        *err = 1;
        return NULL;
    }

    frame->base.base.type = AX25_FRAME_UNNUMBERED_TEST;
    frame->base.base.header = *header;
    frame->base.base.timestamp = current_time();
    frame->base.base.deadline = 0.0;
    frame->base.pf = pf;
    frame->base.modifier = 0xE3;
    frame->payload_len = len;
    frame->payload = malloc(len);

    if (!frame->payload) {
        *err = 2;
        free(frame);
        return NULL;
    }
    memcpy(frame->payload, data, len);

    return frame;
}

uint8_t* ax25_test_frame_encode(const ax25_test_frame_t *frame, size_t *len, uint8_t *err) {
    *err = 0;
    *len = 1 + frame->payload_len;
    uint8_t *bytes = malloc(*len);

    if (!bytes){
        *err = 1;
        return NULL;
    }

    bytes[0] = frame->base.modifier | (frame->base.pf ? POLL_FINAL_8BIT : 0);
    memcpy(bytes + 1, frame->payload, frame->payload_len);

    return bytes;
}

ax25_xid_parameter_t* ax25_xid_class_of_procedures_new(
bool a_flag, bool b_flag, bool c_flag, bool d_flag,
bool e_flag, bool f_flag, bool g_flag, uint8_t reserved, uint8_t *err) {
    *err = 0;
    uint8_t pv[2];
    pv[0] = (a_flag ? 0x01 : 0) | (b_flag ? 0x02 : 0) | (c_flag ? 0x04 : 0) | (d_flag ? 0x08 : 0) | (e_flag ? 0x10 : 0) | (f_flag ? 0x20 : 0)
            | (g_flag ? 0x40 : 0);
    pv[1] = reserved;

    return ax25_xid_raw_parameter_new(1, pv, 2, err);
}

ax25_xid_parameter_t* ax25_xid_hdlc_optional_functions_new(
bool rnr, bool rej, bool srej, bool sabm, bool sabme, bool dm, bool disc,
bool ua, bool frmr, bool ui, bool xid, bool test, bool modulo8, bool modulo128,
bool res1, bool res2, bool res3, bool res4, bool res5, bool res6, bool res7, uint8_t reserved, bool ext, uint8_t *err) {
    *err = 0;
    uint8_t pv[4];
    pv[0] = (rnr ? 0x01 : 0) | (rej ? 0x02 : 0) | (srej ? 0x04 : 0) | (sabm ? 0x08 : 0) | (sabme ? 0x10 : 0) | (dm ? 0x20 : 0) | (disc ? 0x40 : 0)
            | (ua ? 0x80 : 0);
    pv[1] = (frmr ? 0x01 : 0) | (ui ? 0x02 : 0) | (xid ? 0x04 : 0) | (test ? 0x08 : 0) | (modulo8 ? 0x10 : 0) | (modulo128 ? 0x20 : 0) | (res1 ? 0x40 : 0)
            | (res2 ? 0x80 : 0);
    pv[2] = (res3 ? 0x01 : 0) | (res4 ? 0x02 : 0) | (res5 ? 0x04 : 0) | (res6 ? 0x06 : 0) | (res7 ? 0x08 : 0);
    pv[3] = reserved | (ext ? 0x80 : 0);
    return ax25_xid_raw_parameter_new(2, pv, 4, err);
}

ax25_xid_parameter_t* ax25_xid_big_endian_new(int pi, uint32_t value, size_t length, uint8_t *err) {
    *err = 0;
    size_t len;
    uint8_t *pv = uint_encode(value, true, length, &len, err);
    if (!pv){
        *err = 1;
        return NULL;
    }

    ax25_xid_parameter_t *param = ax25_xid_raw_parameter_new(pi, pv, len, err);
    free(pv);

    return param;
}

void ax25_xid_init_defaults(uint8_t *err) {
    *err = 0;
    AX25_20_DEFAULT_XID_COP = ax25_xid_class_of_procedures_new(true, false, false, false, false, false, true, 0, err);
    AX25_22_DEFAULT_XID_COP = ax25_xid_class_of_procedures_new(true, false, false, false, false, false, true, 0, err);
    AX25_20_DEFAULT_XID_HDLCOPTFUNC = ax25_xid_hdlc_optional_functions_new(
    false, true, false, true, false, false, false, false, true, false, true, false, true, false,
    false, false, true, false, false, false, false, 0, false, err);
    AX25_22_DEFAULT_XID_HDLCOPTFUNC = ax25_xid_hdlc_optional_functions_new(
    false, true, true, false, false, false, false, false, true, false, true, false, true, false,
    false, false, true, false, false, false, false, 0, false, err);
    AX25_20_DEFAULT_XID_IFIELDRX = ax25_xid_big_endian_new(6, 2048, 2, err);
    AX25_22_DEFAULT_XID_IFIELDRX = ax25_xid_big_endian_new(6, 2048, 2, err);
    AX25_20_DEFAULT_XID_WINDOWSZRX = ax25_xid_big_endian_new(8, 7, 1, err);
    AX25_22_DEFAULT_XID_WINDOWSZRX = ax25_xid_big_endian_new(8, 7, 1, err);
    AX25_20_DEFAULT_XID_ACKTIMER = ax25_xid_big_endian_new(9, 3000, 2, err);
    AX25_22_DEFAULT_XID_ACKTIMER = ax25_xid_big_endian_new(9, 3000, 2, err);
    AX25_20_DEFAULT_XID_RETRIES = ax25_xid_big_endian_new(10, 10, 2, err);
    AX25_22_DEFAULT_XID_RETRIES = ax25_xid_big_endian_new(10, 10, 2, err);
}
