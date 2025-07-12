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

// Utility Functions

/**
 * @brief Retrieves the current time in seconds since the Unix epoch.
 *
 * This function provides a timestamp by converting the result of time(NULL)
 * to a double-precision floating-point number. It is used primarily for
 * timestamping AX.25 frames to record when they were created or processed.
 *
 * @return double The current time in seconds since January 1, 1970 (Unix epoch).
 */
static double current_time() {
    return (double) time(NULL);
}

/**
 * @brief Encodes a 32-bit unsigned integer into a byte array.
 *
 * This utility function converts an unsigned integer into a byte array with
 * a specified length and byte order (big-endian or little-endian). It is used
 * in various encoding operations where numeric values need to be serialized
 * into binary format, such as in XID parameters or frame fields.
 *
 * @param value The 32-bit unsigned integer to encode.
 * @param big_endian Boolean flag; true for big-endian (MSB first), false for little-endian (LSB first).
 * @param length The number of bytes to use for the encoded result (typically 1, 2, or 4).
 * @param out_len Pointer to a size_t where the length of the encoded byte array will be stored.
 * @return uint8_t* Pointer to the dynamically allocated byte array containing the encoded integer,
 *                  or NULL if memory allocation fails.
 */
static uint8_t* uint_encode(uint32_t value, bool big_endian, size_t length, size_t *out_len) {
    uint8_t *bytes = malloc(length);
    if (!bytes)
        return NULL;
    for (size_t i = 0; i < length; i++) {
        bytes[big_endian ? length - 1 - i : i] = (value >> (i * 8)) & 0xFF;
    }
    *out_len = length;
    return bytes;
}

/**
 * @brief Decodes a 32-bit unsigned integer from a byte array.
 *
 * This function reverses the process of uint_encode, reconstructing a 32-bit
 * unsigned integer from a byte array based on the specified byte order. It is
 * useful for parsing numeric values from received AX.25 frame data.
 *
 * @param data Pointer to the byte array containing the encoded integer.
 * @param len The length of the byte array (number of bytes to decode).
 * @param big_endian Boolean flag; true for big-endian (MSB first), false for little-endian (LSB first).
 * @return uint32_t The decoded 32-bit unsigned integer value.
 */
static uint32_t uint_decode(const uint8_t *data, size_t len, bool big_endian) {
    uint32_t value = 0;
    for (size_t i = 0; i < len; i++) {
        value |= (data[big_endian ? len - 1 - i : i]) << (i * 8);
    }
    return value;
}

// AX25Address Functions

/**
 * @brief Decodes an AX.25 address from a 7-byte binary data segment.
 *
 * This function extracts an AX.25 address from binary data, interpreting the
 * 7-byte format specified by the AX.25 protocol. The address includes a callsign
 * (6 bytes, shifted right by 1) and a seventh byte containing SSID and control bits.
 *
 * @param data Pointer to the 7-byte binary data containing the encoded address.
 * @return AX25Address* Pointer to a newly allocated AX25Address structure containing
 *                      the decoded address, or NULL if memory allocation fails.
 */
ax25_address_t* ax25_address_decode(const uint8_t *data) {
    ax25_address_t *addr = malloc(sizeof(ax25_address_t));
    if (!addr)
        return NULL;
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

/**
 * @brief Creates an AX25Address structure from a string representation.
 *
 * This function parses a string in the format "CALLSIGN-SSID*" (e.g., "N0CALL-7*")
 * to create an AX25Address structure. The asterisk (*) indicates the 'ch' bit,
 * typically used to mark a repeated address.
 *
 * @param str Pointer to a null-terminated string containing the address in textual form.
 * @return AX25Address* Pointer to a newly allocated AX25Address structure, or NULL if
 *                      memory allocation fails or the string is malformed.
 */
ax25_address_t* ax25_address_from_string(const char *str) {
    ax25_address_t *addr = malloc(sizeof(ax25_address_t));
    if (!addr)
        return NULL;
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

/**
 * @brief Encodes an AX25Address structure into a 7-byte binary array.
 *
 * This function serializes an AX25Address into the AX.25 protocol's 7-byte address
 * format, shifting the callsign characters left by 1 and packing SSID and control
 * bits into the seventh byte.
 *
 * @param addr Pointer to the AX25Address structure to encode.
 * @param len Pointer to a size_t where the length of the encoded data (always 7) will be stored.
 * @return uint8_t* Pointer to a dynamically allocated 7-byte array containing the encoded address,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_address_encode(const ax25_address_t *addr, size_t *len) {
    uint8_t *bytes = malloc(7);
    if (!bytes)
        return NULL;
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

/**
 * @brief Creates a deep copy of an AX25Address structure.
 *
 * This function duplicates an AX25Address, allocating new memory and copying all fields,
 * ensuring that the original and copy are independent.
 *
 * @param addr Pointer to the AX25Address structure to copy.
 * @return AX25Address* Pointer to the newly allocated copy of the address, or NULL if
 *                      memory allocation fails.
 */
ax25_address_t* ax25_address_copy(const ax25_address_t *addr) {
    ax25_address_t *copy = malloc(sizeof(ax25_address_t));
    if (!copy)
        return NULL;
    memcpy(copy, addr, sizeof(ax25_address_t));
    return copy;
}

/**
 * @brief Frees the memory allocated for an AX25Address structure.
 *
 * This function deallocates the memory used by an AX25Address, preventing memory leaks.
 * It should be called when the address is no longer needed.
 *
 * @param addr Pointer to the AX25Address structure to free. If NULL, the function does nothing.
 */
void ax25_address_free(ax25_address_t *addr) {
    free(addr);
}

// AX25Path Functions

/**
 * @brief Creates a new AX25Path structure containing a list of repeater addresses.
 *
 * This function allocates and initializes an AX25Path structure with up to MAX_REPEATERS
 * repeater addresses, copying the provided addresses into the structure.
 *
 * @param repeaters Array of pointers to AX25Address structures representing the repeaters.
 * @param num Number of repeaters in the array; capped at MAX_REPEATERS if exceeded.
 * @return AX25Path* Pointer to the newly allocated AX25Path structure, or NULL if memory
 *                   allocation fails.
 */
ax25_path_t* ax25_path_new(ax25_address_t **repeaters, int num) {
    ax25_path_t *path = malloc(sizeof(ax25_path_t));
    if (!path)
        return NULL;
    path->num_repeaters = num > MAX_REPEATERS ? MAX_REPEATERS : num;
    for (int i = 0; i < path->num_repeaters; i++) {
        path->repeaters[i] = *repeaters[i];
    }
    return path;
}

/**
 * @brief Frees the memory allocated for an AX25Path structure.
 *
 * This function deallocates an AX25Path structure. Note that it does not free the individual
 * AX25Address structures within the repeaters array, as they are assumed to be managed elsewhere.
 *
 * @param path Pointer to the AX25Path structure to free. If NULL, the function does nothing.
 */
void ax25_path_free(ax25_path_t *path) {
    free(path);
}

// AX25FrameHeader Functions

/**
 * @brief Decodes an AX.25 frame header from binary data.
 *
 * This function parses the address field of an AX.25 frame, extracting the destination,
 * source, and optional repeater addresses. It handles the extension bit to determine
 * the end of the address field and returns both the decoded header and any remaining data.
 *
 * @param data Pointer to the binary data containing the frame header.
 * @param len Length of the input data in bytes.
 * @return HeaderDecodeResult Structure containing the decoded header (or NULL on failure),
 *                            a pointer to the remaining data, and its length.
 */
header_decode_result_t ax25_frame_header_decode(const uint8_t *data, size_t len) {
    header_decode_result_t result = { NULL, data, len };
    ax25_address_t *addresses[2 + MAX_REPEATERS];
    int addr_count = 0;
    size_t pos = 0;

    while (pos + 7 <= len && addr_count < 2 + MAX_REPEATERS) {
        addresses[addr_count] = ax25_address_decode(data + pos);
        pos += 7;
        addr_count++;
        if (addr_count > 0 && addresses[addr_count - 1]->extension)
            break;
    }

    if (addr_count < 2) {
        for (int i = 0; i < addr_count; i++)
            ax25_address_free(addresses[i]);
        return result;
    }

    ax25_frame_header_t *header = malloc(sizeof(ax25_frame_header_t));
    if (!header) {
        for (int i = 0; i < addr_count; i++)
            ax25_address_free(addresses[i]);
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
        ax25_address_free(addresses[i]);

    result.header = header;
    result.remaining = data + pos;
    result.remaining_len = len - pos;
    return result;
}

/**
 * @brief Encodes an AX25FrameHeader into a binary array.
 *
 * This function serializes an AX25FrameHeader into a binary format, including destination,
 * source, and repeater addresses, setting the extension bit appropriately to indicate
 * the end of the address field.
 *
 * @param header Pointer to the AX25FrameHeader structure to encode.
 * @param len Pointer to a size_t where the total length of the encoded data will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the encoded header,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_frame_header_encode(const ax25_frame_header_t *header, size_t *len) {
    size_t total_len = 7 * (2 + header->repeaters.num_repeaters);
    uint8_t *bytes = malloc(total_len);
    if (!bytes)
        return NULL;
    size_t offset = 0;

    ax25_address_t dest = header->destination;
    dest.extension = false;
    dest.ch = header->cr;
    size_t dest_len;
    uint8_t *dest_bytes = ax25_address_encode(&dest, &dest_len);
    memcpy(bytes + offset, dest_bytes, dest_len);
    offset += dest_len;
    free(dest_bytes);

    ax25_address_t src = header->source;
    src.extension = (header->repeaters.num_repeaters == 0);
    src.ch = header->src_cr;
    size_t src_len;
    uint8_t *src_bytes = ax25_address_encode(&src, &src_len);
    memcpy(bytes + offset, src_bytes, src_len);
    offset += src_len;
    free(src_bytes);

    for (int i = 0; i < header->repeaters.num_repeaters; i++) {
        ax25_address_t rpt = header->repeaters.repeaters[i];
        rpt.extension = (i == header->repeaters.num_repeaters - 1);
        size_t rpt_len;
        uint8_t *rpt_bytes = ax25_address_encode(&rpt, &rpt_len);
        memcpy(bytes + offset, rpt_bytes, rpt_len);
        offset += rpt_len;
        free(rpt_bytes);
    }

    *len = total_len;
    return bytes;
}

/**
 * @brief Frees the memory allocated for an AX25FrameHeader structure.
 *
 * This function deallocates an AX25FrameHeader, but does not free the nested AX25Address
 * structures, as they are copied by value and managed within the header itself.
 *
 * @param header Pointer to the AX25FrameHeader structure to free. If NULL, the function does nothing.
 */
void ax25_frame_header_free(ax25_frame_header_t *header) {
    free(header);
}

// AX25Frame Functions

/**
 * @brief Decodes an AX.25 frame from binary data based on the specified modulo setting.
 *
 * This function interprets the binary data as an AX.25 frame, determining its type (raw,
 * unnumbered, information, or supervisory) based on the control field and the modulo128
 * parameter, which dictates whether to use 8-bit or 16-bit sequence numbers.
 *
 * @param data Pointer to the binary data containing the frame.
 * @param len Length of the input data in bytes.
 * @param modulo128 Integer flag controlling frame decoding:
 *                  - MODULO128_NONE (-1): Returns a raw frame with unparsed payload.
 *                  - MODULO128_FALSE (0): Decodes using 8-bit control field.
 *                  - MODULO128_TRUE (1): Decodes using 16-bit control field.
 * @return AX25Frame* Pointer to a newly allocated AX25Frame structure of the appropriate subtype,
 *                    or NULL if decoding fails or memory allocation fails.
 */
ax25_frame_t* ax25_frame_decode(const uint8_t *data, size_t len, int modulo128) {
    if (len < 14)
        return NULL; // Minimum header size
    header_decode_result_t hdr_result = ax25_frame_header_decode(data, len);
    if (!hdr_result.header)
        return NULL;

    if (hdr_result.remaining_len == 0) {
        ax25_frame_header_free(hdr_result.header);
        return NULL;
    }

    uint8_t control = hdr_result.remaining[0];
    ax25_frame_t *frame = NULL;

    if ((control & CONTROL_US_MASK) == CONTROL_U_VAL) {
        frame = (ax25_frame_t*) ax25_unnumbered_frame_decode(hdr_result.header, control, hdr_result.remaining + 1, hdr_result.remaining_len - 1);
    } else {
        if (modulo128 == MODULO128_NONE) {
            ax25_raw_frame_t *raw = malloc(sizeof(ax25_raw_frame_t));
            if (!raw) {
                ax25_frame_header_free(hdr_result.header);
                return NULL;
            }
            raw->base.type = AX25_FRAME_RAW;
            raw->base.header = *hdr_result.header;
            raw->base.timestamp = current_time();
            raw->base.deadline = 0.0;
            raw->payload_len = hdr_result.remaining_len;
            raw->payload = malloc(raw->payload_len);
            if (!raw->payload) {
                free(raw);
                ax25_frame_header_free(hdr_result.header);
                return NULL;
            }
            memcpy(raw->payload, hdr_result.remaining, raw->payload_len);
            frame = (ax25_frame_t*) raw;
        } else {
            bool is_16bit = (modulo128 == MODULO128_TRUE);
            size_t control_size = is_16bit ? 2 : 1;
            if (hdr_result.remaining_len < control_size) {
                ax25_frame_header_free(hdr_result.header);
                return NULL;
            }
            uint16_t full_control = control;
            if (is_16bit)
                full_control |= (hdr_result.remaining[1] << 8);

            const uint8_t *data_start = hdr_result.remaining + control_size;
            size_t data_len = hdr_result.remaining_len - control_size;

            if ((full_control & CONTROL_I_MASK) == CONTROL_I_VAL) {
                frame = (ax25_frame_t*) ax25_information_frame_decode(hdr_result.header, full_control, data_start, data_len, is_16bit);
            } else if ((full_control & CONTROL_US_MASK) == CONTROL_S_VAL) {
                frame = (ax25_frame_t*) ax25_supervisory_frame_decode(hdr_result.header, full_control, is_16bit);
            }
        }
    }

    ax25_frame_header_free(hdr_result.header);
    return frame;
}

/**
 * @brief Encodes an AX25Frame into a binary array.
 *
 * This function serializes an AX25Frame into its binary representation, combining the
 * encoded header with the frame-specific payload (control field, PID, data, etc.),
 * depending on the frame type.
 *
 * @param frame Pointer to the AX25Frame structure to encode.
 * @param len Pointer to a size_t where the total length of the encoded data will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the encoded frame,
 *                  or NULL if encoding or memory allocation fails.
 */
uint8_t* ax25_frame_encode(const ax25_frame_t *frame, size_t *len) {
    size_t header_len, payload_len;
    uint8_t *header_bytes = ax25_frame_header_encode(&frame->header, &header_len);
    if (!header_bytes)
        return NULL;

    uint8_t *payload_bytes = NULL;
    switch (frame->type) {
        case AX25_FRAME_RAW:
            payload_bytes = ax25_raw_frame_encode((ax25_raw_frame_t*) frame, &payload_len);
        break;
        case AX25_FRAME_UNNUMBERED_INFORMATION:
            payload_bytes = ax25_unnumbered_information_frame_encode((ax25_unnumbered_information_frame_t*) frame, &payload_len);
        break;
        case AX25_FRAME_UNNUMBERED_SABM:
        case AX25_FRAME_UNNUMBERED_SABME:
        case AX25_FRAME_UNNUMBERED_DISC:
        case AX25_FRAME_UNNUMBERED_DM:
        case AX25_FRAME_UNNUMBERED_UA:
            payload_bytes = ax25_unnumbered_frame_encode((ax25_unnumbered_frame_t*) frame, &payload_len);
        break;
        case AX25_FRAME_UNNUMBERED_FRMR:
            payload_bytes = ax25_frame_reject_frame_encode((ax25_frame_reject_frame_t*) frame, &payload_len);
        break;
        case AX25_FRAME_UNNUMBERED_XID:
            payload_bytes = ax25_exchange_identification_frame_encode((ax25_exchange_identification_frame_t*) frame, &payload_len);
        break;
        case AX25_FRAME_UNNUMBERED_TEST:
            payload_bytes = ax25_test_frame_encode((ax25_test_frame_t*) frame, &payload_len);
        break;
        case AX25_FRAME_INFORMATION_8BIT:
        case AX25_FRAME_INFORMATION_16BIT:
            payload_bytes = ax25_information_frame_encode((ax25_information_frame_t*) frame, &payload_len);
        break;
        case AX25_FRAME_SUPERVISORY_RR_8BIT:
        case AX25_FRAME_SUPERVISORY_RNR_8BIT:
        case AX25_FRAME_SUPERVISORY_REJ_8BIT:
        case AX25_FRAME_SUPERVISORY_SREJ_8BIT:
        case AX25_FRAME_SUPERVISORY_RR_16BIT:
        case AX25_FRAME_SUPERVISORY_RNR_16BIT:
        case AX25_FRAME_SUPERVISORY_REJ_16BIT:
        case AX25_FRAME_SUPERVISORY_SREJ_16BIT:
            payload_bytes = ax25_supervisory_frame_encode((ax25_supervisory_frame_t*) frame, &payload_len);
        break;
        default:
            free(header_bytes);
            return NULL;
    }

    if (!payload_bytes) {
        free(header_bytes);
        return NULL;
    }

    *len = header_len + payload_len;
    uint8_t *result = malloc(*len);
    if (!result) {
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

/**
 * @brief Frees the memory allocated for an AX25Frame structure and its associated data.
 *
 * This function deallocates an AX25Frame and any dynamically allocated fields (e.g., payload)
 * specific to its subtype, ensuring no memory leaks occur.
 *
 * @param frame Pointer to the AX25Frame structure to free. If NULL, the function does nothing.
 */
void ax25_frame_free(ax25_frame_t *frame) {
    if (!frame)
        return;
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
                xid->parameters[i]->free(xid->parameters[i]);
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

// AX25RawFrame Functions

/**
 * @brief Encodes the payload of an AX25RawFrame into a binary array.
 *
 * This function creates a copy of the raw frame's payload, which includes the control
 * field and any subsequent data, as-is, without further interpretation.
 *
 * @param frame Pointer to the AX25RawFrame structure to encode.
 * @param len Pointer to a size_t where the length of the payload will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the payload,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_raw_frame_encode(const ax25_raw_frame_t *frame, size_t *len) {
    *len = frame->payload_len;
    uint8_t *bytes = malloc(*len);
    if (!bytes)
        return NULL;
    memcpy(bytes, frame->payload, *len);
    return bytes;
}

// AX25UnnumberedFrame Functions

/**
 * @brief Decodes an unnumbered AX.25 frame from binary data.
 *
 * This function interprets an unnumbered frame based on its control byte modifier,
 * creating the appropriate subtype (e.g., UI, SABM, FRMR) and populating its fields
 * with the provided header and data.
 *
 * @param header Pointer to the AX25FrameHeader structure for the frame.
 * @param control The control byte from the frame data.
 * @param data Pointer to the remaining data after the control byte.
 * @param len Length of the remaining data in bytes.
 * @return AX25UnnumberedFrame* Pointer to a newly allocated unnumbered frame structure,
 *                              or NULL if decoding fails or memory allocation fails.
 */
ax25_unnumbered_frame_t* ax25_unnumbered_frame_decode(ax25_frame_header_t *header, uint8_t control, const uint8_t *data, size_t len) {
    uint8_t modifier = control & 0xEF;
    bool pf = (control & POLL_FINAL_8BIT) != 0;

    switch (modifier) {
        case 0x03: // UI
            return (ax25_unnumbered_frame_t*) ax25_unnumbered_information_frame_decode(header, pf, data, len);
        case 0x87: // FRMR
            return (ax25_unnumbered_frame_t*) ax25_frame_reject_frame_decode(header, pf, data, len);
        case 0xAF: // XID
            return (ax25_unnumbered_frame_t*) ax25_exchange_identification_frame_decode(header, pf, data, len);
        case 0xE3: // TEST
            return (ax25_unnumbered_frame_t*) ax25_test_frame_decode(header, pf, data, len);
        case 0x2F: // SABM
        case 0x6F: // SABME
        case 0x43: // DISC
        case 0x0F: // DM
        case 0x63: // UA
        break;
        default:
            return NULL;
    }

    ax25_unnumbered_frame_t *frame = malloc(sizeof(ax25_unnumbered_frame_t));
    if (!frame)
        return NULL;
    frame->base.type = (modifier == 0x2F) ? AX25_FRAME_UNNUMBERED_SABM : (modifier == 0x6F) ? AX25_FRAME_UNNUMBERED_SABME :
                       (modifier == 0x43) ? AX25_FRAME_UNNUMBERED_DISC : (modifier == 0x0F) ? AX25_FRAME_UNNUMBERED_DM : AX25_FRAME_UNNUMBERED_UA;
    frame->base.header = *header;
    frame->base.timestamp = current_time();
    frame->base.deadline = 0.0;
    frame->pf = pf;
    frame->modifier = modifier;
    return frame;
}

/**
 * @brief Encodes an AX25UnnumberedFrame into a binary array.
 *
 * This function serializes the control byte of an unnumbered frame, combining the
 * modifier with the poll/final (pf) bit.
 *
 * @param frame Pointer to the AX25UnnumberedFrame structure to encode.
 * @param len Pointer to a size_t where the length of the encoded data (always 1) will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the control byte,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_unnumbered_frame_encode(const ax25_unnumbered_frame_t *frame, size_t *len) {
    uint8_t control = frame->modifier | (frame->pf ? POLL_FINAL_8BIT : 0);
    *len = 1;
    uint8_t *bytes = malloc(1);
    if (!bytes)
        return NULL;
    bytes[0] = control;
    return bytes;
}

// AX25UnnumberedInformationFrame Functions

/**
 * @brief Decodes an Unnumbered Information (UI) frame from binary data.
 *
 * This function creates an AX25UnnumberedInformationFrame from the provided data,
 * extracting the PID and payload following the control byte.
 *
 * @param header Pointer to the AX25FrameHeader structure for the frame.
 * @param pf Boolean indicating the poll/final bit from the control byte.
 * @param data Pointer to the data containing the PID and payload.
 * @param len Length of the data in bytes (must be at least 1 for PID).
 * @return AX25UnnumberedInformationFrame* Pointer to the decoded UI frame, or NULL if
 *                                         decoding fails or memory allocation fails.
 */
ax25_unnumbered_information_frame_t* ax25_unnumbered_information_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len) {
    if (len < 1)
        return NULL;
    ax25_unnumbered_information_frame_t *frame = malloc(sizeof(ax25_unnumbered_information_frame_t));
    if (!frame)
        return NULL;
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
        free(frame);
        return NULL;
    }
    memcpy(frame->payload, data + 1, frame->payload_len);
    return frame;
}

/**
 * @brief Encodes an AX25UnnumberedInformationFrame into a binary array.
 *
 * This function serializes a UI frame, including the control byte (with pf bit),
 * PID, and payload, into a contiguous binary array.
 *
 * @param frame Pointer to the AX25UnnumberedInformationFrame structure to encode.
 * @param len Pointer to a size_t where the total length of the encoded data will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the encoded frame,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_unnumbered_information_frame_encode(const ax25_unnumbered_information_frame_t *frame, size_t *len) {
    *len = 1 + 1 + frame->payload_len;
    uint8_t *bytes = malloc(*len);
    if (!bytes)
        return NULL;
    bytes[0] = frame->base.modifier | (frame->base.pf ? POLL_FINAL_8BIT : 0);
    bytes[1] = frame->pid;
    memcpy(bytes + 2, frame->payload, frame->payload_len);
    return bytes;
}

// AX25FrameRejectFrame Functions

/**
 * @brief Decodes a Frame Reject (FRMR) frame from binary data.
 *
 * This function interprets a 3-byte FRMR payload, extracting rejection flags (w, x, y, z),
 * sequence numbers (vr, vs), and control fields, as per the AX.25 protocol.
 *
 * @param header Pointer to the AX25FrameHeader structure for the frame.
 * @param pf Boolean indicating the poll/final bit from the control byte.
 * @param data Pointer to the 3-byte data containing FRMR fields.
 * @param len Length of the data (must be exactly 3 bytes).
 * @return AX25FrameRejectFrame* Pointer to the decoded FRMR frame, or NULL if decoding fails
 *                               or memory allocation fails.
 */
ax25_frame_reject_frame_t* ax25_frame_reject_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len) {
    if (len != 3)
        return NULL;
    ax25_frame_reject_frame_t *frame = malloc(sizeof(ax25_frame_reject_frame_t));
    if (!frame)
        return NULL;
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

/**
 * @brief Encodes an AX25FrameRejectFrame into a binary array.
 *
 * This function serializes an FRMR frame, including the control byte and the 3-byte
 * rejection payload, into a binary format as specified by AX.25.
 *
 * @param frame Pointer to the AX25FrameRejectFrame structure to encode.
 * @param len Pointer to a size_t where the length of the encoded data (always 4) will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the encoded frame,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_frame_reject_frame_encode(const ax25_frame_reject_frame_t *frame, size_t *len) {
    *len = 4;
    uint8_t *bytes = malloc(*len);
    if (!bytes)
        return NULL;
    bytes[0] = frame->base.modifier | (frame->base.pf ? POLL_FINAL_8BIT : 0);
    bytes[1] = (frame->w ? 0x01 : 0) | (frame->x ? 0x02 : 0) | (frame->y ? 0x04 : 0) | (frame->z ? 0x08 : 0);
    bytes[2] = ((frame->vr << 5) & 0xE0) | (frame->frmr_cr ? 0x10 : 0) | ((frame->vs << 1) & 0x0E);
    bytes[3] = frame->frmr_control;
    return bytes;
}

// AX25InformationFrame Functions

/**
 * @brief Decodes an Information (I) frame from binary data.
 *
 * This function interprets an I frame, supporting both 8-bit and 16-bit control fields,
 * extracting sequence numbers (nr, ns), PID, and payload as per the AX.25 protocol.
 *
 * @param header Pointer to the AX25FrameHeader structure for the frame.
 * @param control The control field (up to 16 bits) from the frame data.
 * @param data Pointer to the data containing PID and payload.
 * @param len Length of the data in bytes (must be at least 1 for PID).
 * @param is_16bit Boolean flag indicating whether the control field is 16-bit (true) or 8-bit (false).
 * @return AX25InformationFrame* Pointer to the decoded I frame, or NULL if decoding fails
 *                               or memory allocation fails.
 */
ax25_information_frame_t* ax25_information_frame_decode(ax25_frame_header_t *header, uint16_t control, const uint8_t *data, size_t len, bool is_16bit) {
    if (len < 1)
        return NULL;
    ax25_information_frame_t *frame = malloc(sizeof(ax25_information_frame_t));
    if (!frame)
        return NULL;
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
        free(frame);
        return NULL;
    }
    memcpy(frame->payload, data + 1, frame->payload_len);
    return frame;
}

/**
 * @brief Encodes an AX25InformationFrame into a binary array.
 *
 * This function serializes an I frame, including the control field (8-bit or 16-bit),
 * PID, and payload, into a binary format as specified by AX.25.
 *
 * @param frame Pointer to the AX25InformationFrame structure to encode.
 * @param len Pointer to a size_t where the total length of the encoded data will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the encoded frame,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_information_frame_encode(const ax25_information_frame_t *frame, size_t *len) {
    bool is_16bit = (frame->base.type == AX25_FRAME_INFORMATION_16BIT);
    *len = (is_16bit ? 2 : 1) + 1 + frame->payload_len;
    uint8_t *bytes = malloc(*len);
    if (!bytes)
        return NULL;
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

// AX25SupervisoryFrame Functions

/**
 * @brief Decodes a Supervisory (S) frame from binary data.
 *
 * This function interprets an S frame (RR, RNR, REJ, SREJ), supporting both 8-bit and
 * 16-bit control fields, extracting the receive sequence number (nr) and frame type.
 *
 * @param header Pointer to the AX25FrameHeader structure for the frame.
 * @param control The control field (up to 16 bits) from the frame data.
 * @param is_16bit Boolean flag indicating whether the control field is 16-bit (true) or 8-bit (false).
 * @return AX25SupervisoryFrame* Pointer to the decoded S frame, or NULL if decoding fails
 *                               or memory allocation fails.
 */
ax25_supervisory_frame_t* ax25_supervisory_frame_decode(ax25_frame_header_t *header, uint16_t control, bool is_16bit) {
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
                return NULL;
        }
    }

    ax25_supervisory_frame_t *frame = malloc(sizeof(ax25_supervisory_frame_t));
    if (!frame)
        return NULL;
    frame->base.type = type;
    frame->base.header = *header;
    frame->base.timestamp = current_time();
    frame->base.deadline = 0.0;
    frame->nr = is_16bit ? ((control & 0xFE00) >> 9) : ((control & 0xE0) >> 5);
    frame->pf = (control & (is_16bit ? POLL_FINAL_16BIT : POLL_FINAL_8BIT)) != 0;
    frame->code = code;
    return frame;
}

/**
 * @brief Encodes an AX25SupervisoryFrame into a binary array.
 *
 * This function serializes an S frame, including the control field (8-bit or 16-bit),
 * into a binary format as specified by AX.25.
 *
 * @param frame Pointer to the AX25SupervisoryFrame structure to encode.
 * @param len Pointer to a size_t where the length of the encoded data (1 or 2) will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the encoded frame,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_supervisory_frame_encode(const ax25_supervisory_frame_t *frame, size_t *len) {
    bool is_16bit = (frame->base.type >= AX25_FRAME_SUPERVISORY_RR_16BIT);
    *len = is_16bit ? 2 : 1;
    uint8_t *bytes = malloc(*len);
    if (!bytes)
        return NULL;
    if (is_16bit) {
        uint16_t control = ((frame->nr << 9) & 0xFE00) | (frame->pf ? POLL_FINAL_16BIT : 0) | (frame->code & 0x0C) | CONTROL_S_VAL;
        bytes[0] = control & 0xFF;
        bytes[1] = (control >> 8) & 0xFF;
    } else {
        bytes[0] = ((frame->nr << 5) & 0xE0) | (frame->pf ? POLL_FINAL_8BIT : 0) | (frame->code & 0x0C) | CONTROL_S_VAL;
    }
    return bytes;
}

// AX25XIDParameter Functions

/**
 * @brief Creates a new raw XID parameter with specified identifier and value.
 *
 * This function allocates a generic XID parameter structure with a parameter identifier (PI)
 * and an arbitrary byte array as the parameter value (PV), used in XID frames.
 *
 * @param pi The parameter identifier (PI) as an integer.
 * @param pv Pointer to the parameter value bytes, or NULL if no value.
 * @param pv_len Length of the parameter value in bytes.
 * @return AX25XIDParameter* Pointer to the newly allocated XID parameter, or NULL if memory
 *                           allocation fails.
 */
ax25_xid_parameter_t* ax25_xid_raw_parameter_new(int pi, const uint8_t *pv, size_t pv_len) {
    ax25_xid_parameter_t *param = malloc(sizeof(ax25_xid_parameter_t));
    if (!param)
        return NULL;
    uint8_t *pv_copy = pv ? malloc(pv_len + sizeof(size_t)) : NULL;
    if (pv && !pv_copy) {
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

/**
 * @brief Encodes a raw XID parameter into a binary array.
 *
 * This function serializes an XID parameter into the format [PI, PL, PV], where PI is
 * the parameter identifier (1 byte), PL is the parameter length (1 byte), and PV is
 * the parameter value (variable length).
 *
 * @param param Pointer to the AX25XIDParameter structure to encode.
 * @param len Pointer to a size_t where the total length of the encoded data will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the encoded parameter,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_xid_raw_parameter_encode(const ax25_xid_parameter_t *param, size_t *len) {
    uint8_t *pv = (uint8_t*) param->data;
    size_t pv_len = pv ? *(size_t*) (pv + pv_len) : 0;
    *len = 2 + pv_len;
    uint8_t *bytes = malloc(*len);
    if (!bytes)
        return NULL;
    bytes[0] = param->pi;
    bytes[1] = pv_len;
    if (pv_len)
        memcpy(bytes + 2, pv, pv_len);
    return bytes;
}

/**
 * @brief Creates a deep copy of a raw XID parameter.
 *
 * This function duplicates an XID parameter, including its parameter value, ensuring
 * the copy is independent of the original.
 *
 * @param param Pointer to the AX25XIDParameter structure to copy.
 * @return AX25XIDParameter* Pointer to the newly allocated copy, or NULL if memory
 *                           allocation fails.
 */
ax25_xid_parameter_t* ax25_xid_raw_parameter_copy(const ax25_xid_parameter_t *param) {
    uint8_t *pv = (uint8_t*) param->data;
    size_t pv_len = pv ? *(size_t*) (pv + pv_len) : 0;
    return ax25_xid_raw_parameter_new(param->pi, pv, pv_len);
}

/**
 * @brief Frees the memory allocated for a raw XID parameter.
 *
 * This function deallocates an XID parameter and its associated parameter value data,
 * preventing memory leaks.
 *
 * @param param Pointer to the AX25XIDParameter structure to free. If NULL, the function does nothing.
 */
void ax25_xid_raw_parameter_free(ax25_xid_parameter_t *param) {
    if (!param)
        return;
    free(param->data);
    free(param);
}

/**
 * @brief Decodes an XID parameter from binary data.
 *
 * This function interprets a segment of XID frame data as a parameter, extracting
 * the PI, PL, and PV fields, and returning a raw XID parameter structure.
 *
 * @param data Pointer to the binary data containing the parameter.
 * @param len Length of the available data in bytes.
 * @param consumed Pointer to a size_t where the number of bytes consumed will be stored.
 * @return AX25XIDParameter* Pointer to the decoded XID parameter, or NULL if decoding fails
 *                           or memory allocation fails.
 */
ax25_xid_parameter_t* ax25_xid_parameter_decode(const uint8_t *data, size_t len, size_t *consumed) {
    if (len < 2)
        return NULL;
    int pi = data[0];
    size_t pv_len = data[1];
    if (len < 2 + pv_len)
        return NULL;
    ax25_xid_parameter_t *param = ax25_xid_raw_parameter_new(pi, data + 2, pv_len);
    if (!param)
        return NULL;
    *consumed = 2 + pv_len;
    return param;
}

// AX25ExchangeIdentificationFrame Functions

/**
 * @brief Decodes an Exchange Identification (XID) frame from binary data.
 *
 * This function interprets an XID frame, extracting the function identifier (FI),
 * group identifier (GI), group length (GL), and a list of XID parameters.
 *
 * @param header Pointer to the AX25FrameHeader structure for the frame.
 * @param pf Boolean indicating the poll/final bit from the control byte.
 * @param data Pointer to the data containing XID fields and parameters.
 * @param len Length of the data in bytes (must be at least 4).
 * @return AX25ExchangeIdentificationFrame* Pointer to the decoded XID frame, or NULL if
 *                                          decoding fails or memory allocation fails.
 */
ax25_exchange_identification_frame_t* ax25_exchange_identification_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len) {
    if (len < 4)
        return NULL;
    uint8_t fi = data[0];
    uint8_t gi = data[1];
    uint16_t gl = uint_decode(data + 2, 2, true);
    if (len - 4 != gl)
        return NULL;

    ax25_xid_parameter_t **params = NULL;
    size_t param_count = 0;
    const uint8_t *param_data = data + 4;
    size_t remaining = gl;

    while (remaining > 0) {
        size_t consumed;
        ax25_xid_parameter_t *param = ax25_xid_parameter_decode(param_data, remaining, &consumed);
        if (!param) {
            for (size_t i = 0; i < param_count; i++)
                params[i]->free(params[i]);
            free(params);
            return NULL;
        }
        ax25_xid_parameter_t **new_params = realloc(params, (param_count + 1) * sizeof(ax25_xid_parameter_t*));
        if (!new_params) {
            param->free(param);
            for (size_t i = 0; i < param_count; i++)
                params[i]->free(params[i]);
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
        for (size_t i = 0; i < param_count; i++)
            params[i]->free(params[i]);
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

/**
 * @brief Encodes an AX25ExchangeIdentificationFrame into a binary array.
 *
 * This function serializes an XID frame, including the control byte, FI, GI, GL,
 * and all parameters, into a binary format as specified by AX.25.
 *
 * @param frame Pointer to the AX25ExchangeIdentificationFrame structure to encode.
 * @param len Pointer to a size_t where the total length of the encoded data will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the encoded frame,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_exchange_identification_frame_encode(const ax25_exchange_identification_frame_t *frame, size_t *len) {
    size_t params_len = 0;
    uint8_t **param_bytes = malloc(frame->param_count * sizeof(uint8_t*));
    size_t *param_lens = malloc(frame->param_count * sizeof(size_t));
    if (!param_bytes || !param_lens) {
        free(param_bytes);
        free(param_lens);
        return NULL;
    }

    for (size_t i = 0; i < frame->param_count; i++) {
        param_bytes[i] = frame->parameters[i]->encode(frame->parameters[i], &param_lens[i]);
        if (!param_bytes[i]) {
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
        for (size_t i = 0; i < frame->param_count; i++)
            free(param_bytes[i]);
        free(param_bytes);
        free(param_lens);
        return NULL;
    }

    bytes[0] = frame->base.modifier | (frame->base.pf ? POLL_FINAL_8BIT : 0);
    bytes[1] = frame->fi;
    bytes[2] = frame->gi;
    uint8_t *gl_bytes = uint_encode(params_len, true, 2, &params_len);
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

// AX25TestFrame Functions

/**
 * @brief Decodes a Test (TEST) frame from binary data.
 *
 * This function interprets a TEST frame, extracting the payload following the control byte,
 * which is used for testing link connectivity in AX.25.
 *
 * @param header Pointer to the AX25FrameHeader structure for the frame.
 * @param pf Boolean indicating the poll/final bit from the control byte.
 * @param data Pointer to the test payload data.
 * @param len Length of the payload data in bytes.
 * @return AX25TestFrame* Pointer to the decoded TEST frame, or NULL if memory allocation fails.
 */
ax25_test_frame_t* ax25_test_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len) {
    ax25_test_frame_t *frame = malloc(sizeof(ax25_test_frame_t));
    if (!frame)
        return NULL;
    frame->base.base.type = AX25_FRAME_UNNUMBERED_TEST;
    frame->base.base.header = *header;
    frame->base.base.timestamp = current_time();
    frame->base.base.deadline = 0.0;
    frame->base.pf = pf;
    frame->base.modifier = 0xE3;
    frame->payload_len = len;
    frame->payload = malloc(len);
    if (!frame->payload) {
        free(frame);
        return NULL;
    }
    memcpy(frame->payload, data, len);
    return frame;
}

/**
 * @brief Encodes an AX25TestFrame into a binary array.
 *
 * This function serializes a TEST frame, including the control byte and test payload,
 * into a binary format as specified by AX.25.
 *
 * @param frame Pointer to the AX25TestFrame structure to encode.
 * @param len Pointer to a size_t where the total length of the encoded data will be stored.
 * @return uint8_t* Pointer to a dynamically allocated byte array containing the encoded frame,
 *                  or NULL if memory allocation fails.
 */
uint8_t* ax25_test_frame_encode(const ax25_test_frame_t *frame, size_t *len) {
    *len = 1 + frame->payload_len;
    uint8_t *bytes = malloc(*len);
    if (!bytes)
        return NULL;
    bytes[0] = frame->base.modifier | (frame->base.pf ? POLL_FINAL_8BIT : 0);
    memcpy(bytes + 1, frame->payload, frame->payload_len);
    return bytes;
}

/**
 * @brief Creates an XID parameter for Class of Procedures (COP).
 *
 * This function constructs an XID parameter representing the Class of Procedures
 * as defined in AX.25, with various procedure flags and a reserved field.
 *
 * @param a_flag Boolean flag for procedure A.
 * @param b_flag Boolean flag for procedure B.
 * @param c_flag Boolean flag for procedure C.
 * @param d_flag Boolean flag for procedure D.
 * @param e_flag Boolean flag for procedure E.
 * @param f_flag Boolean flag for procedure F.
 * @param g_flag Boolean flag for procedure G.
 * @param reserved Reserved field value (8 bits).
 * @return AX25XIDParameter* Pointer to the new XID parameter, or NULL if memory allocation fails.
 */
ax25_xid_parameter_t* ax25_xid_class_of_procedures_new(
bool a_flag, bool b_flag, bool c_flag, bool d_flag,
bool e_flag, bool f_flag, bool g_flag, uint8_t reserved) {
    uint8_t pv[2];
    pv[0] = (a_flag ? 0x01 : 0) | (b_flag ? 0x02 : 0) | (c_flag ? 0x04 : 0) | (d_flag ? 0x08 : 0) | (e_flag ? 0x10 : 0) | (f_flag ? 0x20 : 0)
            | (g_flag ? 0x40 : 0);
    pv[1] = reserved;
    return ax25_xid_raw_parameter_new(1, pv, 2);
}

/**
 * @brief Creates an XID parameter for HDLC Optional Functions.
 *
 * This function constructs an XID parameter representing HDLC optional functions,
 * with numerous flags and reserved fields as per AX.25 specifications.
 *
 * @param rnr Boolean flag for Receiver Not Ready.
 * @param rej Boolean flag for Reject.
 * @param srej Boolean flag for Selective Reject.
 * @param sabm Boolean flag for Set Asynchronous Balanced Mode.
 * @param sabme Boolean flag for SABM Extended.
 * @param dm Boolean flag for Disconnect Mode.
 * @param disc Boolean flag for Disconnect.
 * @param ua Boolean flag for Unnumbered Acknowledge.
 * @param frmr Boolean flag for Frame Reject.
 * @param ui Boolean flag for Unnumbered Information.
 * @param xid Boolean flag for Exchange Identification.
 * @param test Boolean flag for Test.
 * @param modulo8 Boolean flag for modulo 8 operation.
 * @param modulo128 Boolean flag for modulo 128 operation.
 * @param res1 Boolean reserved flag 1.
 * @param res2 Boolean reserved flag 2.
 * @param res3 Boolean reserved flag 3.
 * @param res4 Boolean reserved flag 4.
 * @param res5 Boolean reserved flag 5.
 * @param res6 Boolean reserved flag 6.
 * @param res7 Boolean reserved flag 7.
 * @param reserved Reserved field value (8 bits).
 * @param ext Boolean flag for extension bit.
 * @return AX25XIDParameter* Pointer to the new XID parameter, or NULL if memory allocation fails.
 */
ax25_xid_parameter_t* ax25_xid_hdlc_optional_functions_new(
bool rnr, bool rej, bool srej, bool sabm, bool sabme, bool dm, bool disc,
bool ua, bool frmr, bool ui, bool xid, bool test, bool modulo8, bool modulo128,
bool res1, bool res2, bool res3, bool res4, bool res5, bool res6, bool res7, uint8_t reserved, bool ext) {
    uint8_t pv[4];
    pv[0] = (rnr ? 0x01 : 0) | (rej ? 0x02 : 0) | (srej ? 0x04 : 0) | (sabm ? 0x08 : 0) | (sabme ? 0x10 : 0) | (dm ? 0x20 : 0) | (disc ? 0x40 : 0)
            | (ua ? 0x80 : 0);
    pv[1] = (frmr ? 0x01 : 0) | (ui ? 0x02 : 0) | (xid ? 0x04 : 0) | (test ? 0x08 : 0) | (modulo8 ? 0x10 : 0) | (modulo128 ? 0x20 : 0) | (res1 ? 0x40 : 0)
            | (res2 ? 0x80 : 0);
    pv[2] = (res3 ? 0x01 : 0) | (res4 ? 0x02 : 0) | (res5 ? 0x04 : 0) | (res6 ? 0x06 : 0) | (res7 ? 0x08 : 0);
    pv[3] = reserved | (ext ? 0x80 : 0);
    return ax25_xid_raw_parameter_new(2, pv, 4);
}

/**
 * @brief Creates an XID parameter with a big-endian integer value.
 *
 * This function constructs an XID parameter with a specified PI and a big-endian
 * encoded integer value, used for parameters like I-field length or window size.
 *
 * @param pi The parameter identifier (PI).
 * @param value The integer value to encode.
 * @param length The number of bytes to use for the value (1, 2, or 4).
 * @return AX25XIDParameter* Pointer to the new XID parameter, or NULL if memory allocation fails.
 */
ax25_xid_parameter_t* ax25_xid_big_endian_new(int pi, uint32_t value, size_t length) {
    size_t len;
    uint8_t *pv = uint_encode(value, true, length, &len);
    if (!pv)
        return NULL;
    ax25_xid_parameter_t *param = ax25_xid_raw_parameter_new(pi, pv, len);
    free(pv);
    return param;
}

/**
 * @brief Initializes default XID parameters for AX.25 versions 2.0 and 2.2.
 *
 * This function sets up global default XID parameters as specified in AX.25 2.0 and 2.2,
 * including Class of Procedures, HDLC Optional Functions, and various numeric parameters.
 * It should be called once during program initialization.
 */
void ax25_xid_init_defaults() {
    AX25_20_DEFAULT_XID_COP = ax25_xid_class_of_procedures_new(true, false, false, false, false, false, true, 0);
    AX25_22_DEFAULT_XID_COP = ax25_xid_class_of_procedures_new(true, false, false, false, false, false, true, 0);
    AX25_20_DEFAULT_XID_HDLCOPTFUNC = ax25_xid_hdlc_optional_functions_new(
    false, true, false, true, false, false, false, false, true, false, true, false, true, false,
    false, false, true, false, false, false, false, 0, false);
    AX25_22_DEFAULT_XID_HDLCOPTFUNC = ax25_xid_hdlc_optional_functions_new(
    false, true, true, false, false, false, false, false, true, false, true, false, true, false,
    false, false, true, false, false, false, false, 0, false);
    AX25_20_DEFAULT_XID_IFIELDRX = ax25_xid_big_endian_new(6, 2048, 2);
    AX25_22_DEFAULT_XID_IFIELDRX = ax25_xid_big_endian_new(6, 2048, 2);
    AX25_20_DEFAULT_XID_WINDOWSZRX = ax25_xid_big_endian_new(8, 7, 1);
    AX25_22_DEFAULT_XID_WINDOWSZRX = ax25_xid_big_endian_new(8, 7, 1);
    AX25_20_DEFAULT_XID_ACKTIMER = ax25_xid_big_endian_new(9, 3000, 2);
    AX25_22_DEFAULT_XID_ACKTIMER = ax25_xid_big_endian_new(9, 3000, 2);
    AX25_20_DEFAULT_XID_RETRIES = ax25_xid_big_endian_new(10, 10, 2);
    AX25_22_DEFAULT_XID_RETRIES = ax25_xid_big_endian_new(10, 10, 2);
}
