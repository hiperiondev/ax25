#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

uint16_t CRCCalculation(unsigned char *frame, int len) {
    const uint16_t crcTable[256] = { 0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE,
            0xF1EF, 0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE, 0x2462,
            0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485, 0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D, 0x3653, 0x2672, 0x1611,
            0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC, 0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840,
            0x1861, 0x2802, 0x3823, 0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B, 0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33,
            0x2A12, 0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A, 0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE,
            0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49, 0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70, 0xFF9F, 0xEFBE, 0xDFDD,
            0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78, 0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004,
            0x4025, 0x7046, 0x6067, 0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277,
            0x7256, 0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405, 0xA7DB,
            0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634, 0xD94C, 0xC96D, 0xF90E,
            0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3, 0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9,
            0x9BD8, 0xABBB, 0xBB9A, 0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92, 0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8,
            0x8DC9, 0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1, 0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17,
            0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0 };

    uint16_t crc = 0xFFFF;

    for (int i = 0; i < len; i++) {
        uint8_t j = (frame[i] ^ (crc >> 8)) & 0xFF;
        crc = crcTable[j] ^ (crc << 8);
    }

    crc = (crc ^ 0xFFFF) & 0xFFFF;
    return crc;
}

unsigned char ReverseBits(unsigned char byte) {
    byte = ((byte >> 1) & 0x55) | ((byte & 0x55) << 1);
    byte = ((byte >> 2) & 0x33) | ((byte & 0x33) << 2);
    byte = ((byte >> 4) & 0x0F) | ((byte & 0x0F) << 4);
    return byte;
}

void hdlc_frame_encode(unsigned char *frame, int frameLen, unsigned char *encodedFrame, int *encodedLen) {
    for (int i = 0; i < frameLen; i++) {
        frame[i] = ReverseBits(frame[i]);
    }

    uint16_t crc = CRCCalculation(frame, frameLen);
    frame[frameLen++] = (crc >> 8) & 0xFF;
    frame[frameLen++] = crc & 0xFF;

    int cnt = 0;
    int bitIndex = 7;
    unsigned char byte = 0;
    int encodedIndex = 0;

    encodedFrame[encodedIndex++] = 0x7E;

    for (int i = 0; i < frameLen; i++) {
        for (int mask = 128; mask > 0; mask >>= 1) {
            if (frame[i] & mask) {
                byte |= (1 << bitIndex);
                bitIndex--;
                if (bitIndex < 0) {
                    encodedFrame[encodedIndex++] = byte;
                    byte = 0;
                    bitIndex = 7;
                }
                cnt++;
                if (cnt == 5) {
                    bitIndex--;
                    if (bitIndex < 0) {
                        encodedFrame[encodedIndex++] = byte;
                        byte = 0;
                        bitIndex = 7;
                    }
                    cnt = 0;
                }
            } else {
                bitIndex--;
                if (bitIndex < 0) {
                    encodedFrame[encodedIndex++] = byte;
                    byte = 0;
                    bitIndex = 7;
                }
                cnt = 0;
            }
        }
    }

    bitIndex--;
    if (bitIndex < 0) {
        encodedFrame[encodedIndex++] = byte;
        byte = 0;
        bitIndex = 7;
    }
    for (int i = 0; i < 6; i++) {
        byte |= (1 << bitIndex);
        bitIndex--;
        if (bitIndex < 0) {
            encodedFrame[encodedIndex++] = byte;
            byte = 0;
            bitIndex = 7;
        }
    }
    bitIndex--;
    if (bitIndex >= 0) {
        encodedFrame[encodedIndex++] = byte;
    } else {
        encodedFrame[encodedIndex++] = byte;
    }

    *encodedLen = encodedIndex;
}

int hdlc_frame_decode(unsigned char *encodedFrame, int encodedLen, unsigned char *decodedFrame, int *decodedLen) {
    int startFlagFound = 0;
    int endFlagFound = 0;
    int cnt = 0;
    int bitIndex = 0;
    unsigned char byte = 0;
    unsigned char shiftRegister = 0;
    int decodedIndex = 0;

    for (int i = 0; i < encodedLen; i++) {
        for (int k = 7; k >= 0; k--) {
            unsigned char bit = (encodedFrame[i] >> k) & 0x01;
            shiftRegister = ((shiftRegister << 1) | bit) & 0xFF;

            if (!startFlagFound && shiftRegister == 0x7E) {
                startFlagFound = 1;
                cnt = 0;
                bitIndex = 0;
                byte = 0;
                continue;
            }

            if (startFlagFound) {
                if (shiftRegister == 0x7E) {
                    endFlagFound = 1;
                    break;
                } else {
                    if (bit == 1) {
                        cnt++;
                        if (cnt > 6) {
                            return -1;
                        }
                        byte = (byte << 1) | bit;
                        bitIndex++;
                    } else if (cnt == 5) {
                        cnt = 0;
                    } else {
                        cnt = 0;
                        byte = (byte << 1) | bit;
                        bitIndex++;
                    }

                    if (bitIndex == 8) {
                        decodedFrame[decodedIndex++] = byte;
                        byte = 0;
                        bitIndex = 0;
                    }
                }
            }
        }
        if (endFlagFound)
            break;
    }

    if (!endFlagFound)
        return -1;

    if (decodedIndex < 2)
        return -1;
    uint16_t frameCRC = (decodedFrame[decodedIndex - 2] << 8) | decodedFrame[decodedIndex - 1];
    decodedIndex -= 2;

    uint16_t crc = CRCCalculation(decodedFrame, decodedIndex);
    if (crc != frameCRC)
        return -1;

    for (int i = 0; i < decodedIndex; i++) {
        decodedFrame[i] = ReverseBits(decodedFrame[i]);
    }

    *decodedLen = decodedIndex;
    return 0;
}
