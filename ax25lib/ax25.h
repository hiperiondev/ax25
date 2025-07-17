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

/*
 * https://www.tapr.org/pub_ax25.html
 * https://www.tapr.org/pdf/AX25.2.2.pdf
 *
 *
 * +----------+----------------+---------+--------+----------+---------+----------+
 * | Flag     | Address        | Control | (PID)  | (Data)   |  FCS    | Flag     |
 * +----------+----------------+---------+--------+----------+---------+----------+
 * | 01111110 | 112 - 560 bits | 8 bits  | 8 bits | n*8 bits | 16 bits | 01111110 |
 * +----------+----------------+---------+--------+----------+---------+----------+
 *                    |          |         |
 *                    |          |         |  +------+------------------+
 *                    |          |         |  | PID  | Layer 3 protocol |
 *                    |          |         |  +------+------------------+-------------------------------------------------------+
 *                    |          |         \- | 0x01 | ISO 8208/CCITT X.25 PLP                                                  |
 *                    |          |            | 0x06 | Compressed TCP/IP packet. Van Jacobson (RFC 1144)                        |
 *                    |          |            | 0x07 | Uncompressed TCP/IP packet. Van Jacobson (RFC 1144)                      |
 *                    |          |            | 0x08 | Segmentation fragment                                                    |
 *                    |          |            | **** | AX.25 layer 3 implemented (xx01xxxx)                                     |
 *                    |          |            | **** | AX.25 layer 3 implemented (xx10xxxx)                                     |
 *                    |          |            | 0xC3 | TEXNET datagram protocol                                                 |
 *                    |          |            | 0xC4 | Link Quality Protocol                                                    |
 *                    |          |            | 0xCA | Appletalk                                                                |
 *                    |          |            | 0xCB | Appletalk ARP                                                            |
 *                    |          |            | 0xCC | ARPA Internet Protocol                                                   |
 *                    |          |            | 0xCD | ARPA Address resolution                                                  |
 *                    |          |            | 0xCE | FlexNet                                                                  |
 *                    |          |            | 0xCF | NET/ROM                                                                  |
 *                    |          |            | 0xF0 | No layer 3 protocol implemented                                          |
 *                    |          |            | 0xFF | Escape character. Next octet contains more Level 3 protocol information. |
 *                    |          |            +------+--------------------------------------------------------------------------+
 *                    |          |
 *                    |          |       ==========================================================================================
 *                    |          |
 *                    |          |         /-
 *                    |          \--------|
 *                    |                   |  +---------------+--------------------+
 *                    |                   |  | Frame type    | Bit number (7 MSB) |
 *                    |                   |  |               +---+---+---+---+---++--+---+---+
 *                    |                   |  |               | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
 *                    |                   |  +---------------+---+---+---+---+---+---+---+---+
 *                    |                   |  | I(nformation) |    RSN    | P |    SSN    | 0 |
 *                    |                   |  +---------------+---+---+---+---+---+---+---+---+
 *                    |                   |  | S(upervisory) |    RSN    | G |   S   | 0 | 1 |
 *                    |                   |  +---------------+---+---+---+---+---+---+---+---+
 *                    |                   |  | U(nnumbered)  | M | M | M | G | M | M | 1 | 1 |
 *                    |                   |  +---------------+---+---+---+---+---+---+---+---+
 *                    |                   |
 *                    |                   |  P: Poll bit (command)
 *                    |                   |  F: Final bit (command response)
 *                    |                   |  G: Either poll or final
 *                    |                   |  RSN: Receive sequence number
 *                    |                   |  SSN: Send sequence number
 *                    |                   |
 *                    |                   |  S: +-------------------+----+
 *                    |                   |     | Receive ready     | 00 |
 *                    |                   |     | Receive not ready | 01 |
 *                    |                   |     | Reject            | 10 |
 *                    |                   |     +-------------------+----+
 *                    |                   |
 *                    |                   |  M: +--------------------------------+--------+
 *                    |                   |     | Set asynchronous balanced mode | 001P11 |
 *                    |                   |     | Disconnect                     | 010P00 |
 *                    |                   |     | Disconnected mode              | 000F11 |
 *                    |                   |     | Unnumbered acknowledge         | 011F00 |
 *                    |                   |     | Frame reject                   | 100F01 |
 *                    |                   |     | Unnumbered information         | 000G00 |
 *                    |                   |     +--------------------------------+--------+
 *                    |                   |
 *                    |                    \-
 *                    |
 *                    |           ==================================================================================================
 *                    |
 *                    |          /-
 *                    \---------|
 *                              |  +-----------------------------------------+-----------------------------------------+----------...
 *                              |  | Destination address                     | Source address                          | Repeaters...
 *                              |  +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----------...
 *                              |  | A1  | A2  | A3  | A4  | A5  | A6  | A7  | A8  | A9  | A10 | A11 | A12 | A13 | A14 |...
 *                              |  +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+----------...
 *                              |
 *                              |  Up to a total of 10 address fields, of which 8 are special optional repeater addresses
 *                              |
 *                              |  +-----------------+--------------------+
 *                              |  | Address byte    | Bit number (7 MSB) |
 *                              |  |                 +---+---+---+---+---++--+---+---+
 *                              |  |        An       | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
 *                              |  +-----------------+---+---+---+---+---+---+---+---+
 *                              |  | A7 & A14 (SSID) | C | R | R |     SSID      | H |
 *                              |  +-----------------+---+---+---+---+---+---+---+---+
 *                              |  | Other (Data)    |             D             | H |
 *                              |  +-----------------+---+---+---+---+---+---+---+---+
 *                              |
 *                              |
 *                              |  C: A7/A14:
 *                              |                +----------------+-----------------+
 *                              |                | Dest. SSID bit | Source SSID bit |
 *                              |     +----------+----------------+-----------------+
 *                              |     | Command  |        1       |        0        |
 *                              |     | Response |        0       |        1        |
 *                              |     +----------+----------------+-----------------+
 *                              |
 *                              |    other ssids:
 *                                    has-been-repeated bit, set when sent through repeater
 *                              |
 *                              |  R: Reserved bit, should be 1
 *                              |  H: HDLC extension bit. When 0, next byte is another address bytes, when 1 end
 *                              |     of address field
 *                              |  D: Data. For call signs, ASCII left-shifted by one
 *                              |
 *                              \-
 */

#ifndef AX25_H_
#define AX25_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Constants
#define CONTROL_I_MASK  0x01
#define CONTROL_I_VAL   0x00
#define CONTROL_US_MASK 0x03
#define CONTROL_S_VAL   0x01
#define CONTROL_U_VAL   0x03

#define POLL_FINAL_8BIT  0x10
#define POLL_FINAL_16BIT 0x0100

#define MODULO128_NONE  -1
#define MODULO128_FALSE 0
#define MODULO128_TRUE  1
#define MODULO128_AUTO 2

#define MAX_REPEATERS 8
#define CALLSIGN_MAX 7

// PID Codes
#define PID_ISO8208_CCITT   0x01
#define PID_VJ_IP4_COMPRESS 0x06
#define PID_VJ_IP4          0x07
#define PID_SEGMENTATION    0x08
#define PID_TEXNET          0xC3
#define PID_LINKQUALITY     0xC4
#define PID_APPLETALK       0xCA
#define PID_APPLETALK_ARP   0xCB
#define PID_ARPA_IP4        0xCC
#define PID_APRA_ARP        0xCD
#define PID_FLEXNET         0xCE
#define PID_NETROM          0xCF
#define PID_NO_L3           0xF0
#define PID_ESCAPE          0xFF

// Frame Types
typedef enum {
    AX25_FRAME_RAW,
    AX25_FRAME_UNNUMBERED_INFORMATION,
    AX25_FRAME_UNNUMBERED_SABM,
    AX25_FRAME_UNNUMBERED_SABME,
    AX25_FRAME_UNNUMBERED_DISC,
    AX25_FRAME_UNNUMBERED_DM,
    AX25_FRAME_UNNUMBERED_UA,
    AX25_FRAME_UNNUMBERED_FRMR,
    AX25_FRAME_UNNUMBERED_XID,
    AX25_FRAME_UNNUMBERED_TEST,
    AX25_FRAME_INFORMATION_8BIT,
    AX25_FRAME_INFORMATION_16BIT,
    AX25_FRAME_SUPERVISORY_RR_8BIT,
    AX25_FRAME_SUPERVISORY_RNR_8BIT,
    AX25_FRAME_SUPERVISORY_REJ_8BIT,
    AX25_FRAME_SUPERVISORY_SREJ_8BIT,
    AX25_FRAME_SUPERVISORY_RR_16BIT,
    AX25_FRAME_SUPERVISORY_RNR_16BIT,
    AX25_FRAME_SUPERVISORY_REJ_16BIT,
    AX25_FRAME_SUPERVISORY_SREJ_16BIT
} ax25_frame_type_t;

typedef struct {
    char callsign[CALLSIGN_MAX];
    int ssid;
    bool ch;
    bool res0;
    bool res1;
    bool extension;
} ax25_address_t;

typedef struct {
    ax25_address_t repeaters[MAX_REPEATERS];
    int num_repeaters;
} ax25_path_t;

typedef struct {
    ax25_address_t destination;
    ax25_address_t source;
    ax25_path_t repeaters;
    bool cr;
    bool src_cr;
} ax25_frame_header_t;

typedef struct {
    ax25_frame_type_t type;
    ax25_frame_header_t header;
} ax25_frame_t;

typedef struct {
    ax25_frame_t base;
    uint8_t control;
    uint8_t *payload;
    size_t payload_len;
} ax25_raw_frame_t;

typedef struct {
    ax25_frame_t base;
    bool pf;
    uint8_t modifier;
} ax25_unnumbered_frame_t;

typedef struct {
    ax25_unnumbered_frame_t base;
    uint8_t pid;
    uint8_t *payload;
    size_t payload_len;
} ax25_unnumbered_information_frame_t;

typedef struct {
    ax25_unnumbered_frame_t base;    // Base unnumbered frame structure
    bool is_modulo128;               // True for modulo-128, false for modulo-8
    uint16_t frmr_control;           // Control field: 8 bits (modulo-8) or 16 bits (modulo-128)
    int vs;                          // Send sequence number: 3 bits (modulo-8) or 7 bits (modulo-128)
    int vr;                          // Receive sequence number: 3 bits (modulo-8) or 7 bits (modulo-128)
    bool frmr_cr;                    // Command/Response flag
    bool w, x, y, z;                 // Rejection cause flags
} ax25_frame_reject_frame_t;

typedef struct {
    ax25_frame_t base;
    int nr;
    bool pf;
    int ns;
    uint8_t pid;
    uint8_t *payload;
    size_t payload_len;
} ax25_information_frame_t;

typedef struct {
    ax25_frame_t base;
    int nr;
    bool pf;
    uint8_t code;
} ax25_supervisory_frame_t;

typedef struct AX25XIDParameter ax25_xid_parameter_t;
typedef struct AX25XIDParameter {
    int pi;
    uint8_t* (*encode)(const ax25_xid_parameter_t*, size_t*, uint8_t *err);
    ax25_xid_parameter_t* (*copy)(const ax25_xid_parameter_t*, uint8_t *err);
    void (*free)(ax25_xid_parameter_t*, uint8_t *err);
    void *data;
} ax25_xid_parameter_t;

typedef struct {
    ax25_unnumbered_frame_t base;
    uint8_t fi, gi;
    ax25_xid_parameter_t **parameters;
    size_t param_count;
} ax25_exchange_identification_frame_t;

typedef struct {
    ax25_unnumbered_frame_t base;
    uint8_t *payload;
    size_t payload_len;
} ax25_test_frame_t;

typedef struct {
    size_t pv_len;
    uint8_t pv[];
} ax25_raw_param_data_t;

/**
 * @brief Structure to hold the result of decoding an AX.25 frame header.
 *
 * This structure encapsulates the decoded header and the remaining data after decoding,
 * facilitating further processing of the frame.
 */
typedef struct {
    ax25_frame_header_t *header;  ///< Pointer to the decoded header, or NULL on failure.
    const uint8_t *remaining; ///< Pointer to the data following the header.
    size_t remaining_len;     ///< Length of the remaining data in bytes.
} header_decode_result_t;

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
ax25_address_t* ax25_address_decode(const uint8_t *data, uint8_t *err);

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
ax25_address_t* ax25_address_from_string(const char *str, uint8_t *err);

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
uint8_t* ax25_address_encode(const ax25_address_t *addr, size_t *len, uint8_t *err);

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
ax25_address_t* ax25_address_copy(const ax25_address_t *addr, uint8_t *err);

/**
 * @brief Frees the memory allocated for an AX25Address structure.
 *
 * This function deallocates the memory used by an AX25Address, preventing memory leaks.
 * It should be called when the address is no longer needed.
 *
 * @param addr Pointer to the AX25Address structure to free. If NULL, the function does nothing.
 */
void ax25_address_free(ax25_address_t *addr, uint8_t *err);

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
ax25_path_t* ax25_path_new(ax25_address_t **repeaters, int num, uint8_t *err);

/**
 * @brief Frees the memory allocated for an AX25Path structure.
 *
 * This function deallocates an AX25Path structure. Note that it does not free the individual
 * AX25Address structures within the repeaters array, as they are assumed to be managed elsewhere.
 *
 * @param path Pointer to the AX25Path structure to free. If NULL, the function does nothing.
 */
void ax25_path_free(ax25_path_t *path, uint8_t *err);

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
header_decode_result_t ax25_frame_header_decode(const uint8_t *data, size_t len, uint8_t *err);

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
uint8_t* ax25_frame_header_encode(const ax25_frame_header_t *header, size_t *len, uint8_t *err);

/**
 * @brief Frees the memory allocated for an AX25FrameHeader structure.
 *
 * This function deallocates an AX25FrameHeader, but does not free the nested AX25Address
 * structures, as they are copied by value and managed within the header itself.
 *
 * @param header Pointer to the AX25FrameHeader structure to free. If NULL, the function does nothing.
 */
void ax25_frame_header_free(ax25_frame_header_t *header, uint8_t *err);

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
ax25_frame_t* ax25_frame_decode(const uint8_t *data, size_t len, int modulo128, uint8_t *err);

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
uint8_t* ax25_frame_encode(const ax25_frame_t *frame, size_t *len, uint8_t *err);

/**
 * @brief Frees the memory allocated for an AX25Frame structure and its associated data.
 *
 * This function deallocates an AX25Frame and any dynamically allocated fields (e.g., payload)
 * specific to its subtype, ensuring no memory leaks occur.
 *
 * @param frame Pointer to the AX25Frame structure to free. If NULL, the function does nothing.
 */
void ax25_frame_free(ax25_frame_t *frame, uint8_t *err);

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
uint8_t* ax25_raw_frame_encode(const ax25_raw_frame_t *frame, size_t *len, uint8_t *err);

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
ax25_unnumbered_frame_t* ax25_unnumbered_frame_decode(ax25_frame_header_t *header, uint8_t control, const uint8_t *data, size_t len, uint8_t *err);

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
uint8_t* ax25_unnumbered_frame_encode(const ax25_unnumbered_frame_t *frame, size_t *len, uint8_t *err);

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
ax25_unnumbered_information_frame_t* ax25_unnumbered_information_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len,
        uint8_t *err);

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
uint8_t* ax25_unnumbered_information_frame_encode(const ax25_unnumbered_information_frame_t *frame, size_t *len, uint8_t *err);

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
ax25_frame_reject_frame_t* ax25_frame_reject_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len, uint8_t *err);

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
uint8_t* ax25_frame_reject_frame_encode(const ax25_frame_reject_frame_t *frame, size_t *len, uint8_t *err);

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
 * @return ax25_information_frame_t* Pointer to the decoded I frame, or NULL if decoding fails
 *                               or memory allocation fails.
 */
ax25_information_frame_t* ax25_information_frame_decode(ax25_frame_header_t *header, uint16_t control, const uint8_t *data, size_t len, bool is_16bit,
        uint8_t *err);

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
uint8_t* ax25_information_frame_encode(const ax25_information_frame_t *frame, size_t *len, uint8_t *err);

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
 * @return ax25_supervisory_frame_t* Pointer to the decoded S frame, or NULL if decoding fails
 *                               or memory allocation fails.
 */
ax25_supervisory_frame_t* ax25_supervisory_frame_decode(ax25_frame_header_t *header, uint16_t control, bool is_16bit, uint8_t *err);

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
uint8_t* ax25_supervisory_frame_encode(const ax25_supervisory_frame_t *frame, size_t *len, uint8_t *err);

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
ax25_xid_parameter_t* ax25_xid_raw_parameter_new(int pi, const uint8_t *pv, size_t pv_len, uint8_t *err);

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
uint8_t* ax25_xid_raw_parameter_encode(const ax25_xid_parameter_t *param, size_t *len, uint8_t *err);

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
ax25_xid_parameter_t* ax25_xid_raw_parameter_copy(const ax25_xid_parameter_t *param, uint8_t *err);

/**
 * @brief Frees the memory allocated for a raw XID parameter.
 *
 * This function deallocates an XID parameter and its associated parameter value data,
 * preventing memory leaks.
 *
 * @param param Pointer to the AX25XIDParameter structure to free. If NULL, the function does nothing.
 */
void ax25_xid_raw_parameter_free(ax25_xid_parameter_t *param, uint8_t *err);

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
ax25_xid_parameter_t* ax25_xid_parameter_decode(const uint8_t *data, size_t len, size_t *consumed, uint8_t *err);

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
ax25_exchange_identification_frame_t* ax25_exchange_identification_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len,
        uint8_t *err);

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
uint8_t* ax25_exchange_identification_frame_encode(const ax25_exchange_identification_frame_t *frame, size_t *len, uint8_t *err);

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
ax25_test_frame_t* ax25_test_frame_decode(ax25_frame_header_t *header, bool pf, const uint8_t *data, size_t len, uint8_t *err);

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
uint8_t* ax25_test_frame_encode(const ax25_test_frame_t *frame, size_t *len, uint8_t *err);

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
ax25_xid_parameter_t* ax25_xid_class_of_procedures_new(bool a_flag, bool b_flag, bool c_flag, bool d_flag, bool e_flag, bool f_flag, bool g_flag,
        uint8_t reserved, uint8_t *err);

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
ax25_xid_parameter_t* ax25_xid_hdlc_optional_functions_new( bool rnr, bool rej, bool srej, bool sabm, bool sabme, bool dm, bool disc, bool ua, bool frmr,
bool ui,
bool xid, bool test, bool modulo8, bool modulo128, bool res1, bool res2, bool res3, bool res4, bool res5, bool res6, bool res7, uint8_t reserved,
bool ext, uint8_t *err);

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
ax25_xid_parameter_t* ax25_xid_big_endian_new(int pi, uint32_t value, size_t length, uint8_t *err);

/**
 * @brief Initializes default XID parameters for AX.25 versions 2.0 and 2.2.
 *
 * This function sets up global default XID parameters as specified in AX.25 2.0 and 2.2,
 * including Class of Procedures, HDLC Optional Functions, and various numeric parameters.
 * It should be called once during program initialization.
 */
void ax25_xid_init_defaults(uint8_t *err);

void ax25_xid_deinit_defaults(uint8_t *err);

#endif /* AX25_H_ */
