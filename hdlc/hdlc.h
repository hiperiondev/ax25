/*
 * hdlc.h
 *
 *  Created on: 16 jul 2025
 *      Author: egonzalez
 */

#ifndef HDLC_H_
#define HDLC_H_

void hdlc_frame_encode(unsigned char *frame, int frameLen, unsigned char *encodedFrame, int *encodedLen);
int hdlc_frame_decode(unsigned char *encodedFrame, int encodedLen, unsigned char *decodedFrame, int *decodedLen);

uint16_t CRCCalculation(unsigned char *frame, int len);
unsigned char ReverseBits(unsigned char byte);

#endif /* HDLC_H_ */
