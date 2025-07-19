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

int test_aprs() {
    printf("test_aprs\n");
    uint8_t err = 0;

    return 0;
}

int test_aprs_main() {
    int result = 0;
    printf("\n----------------------------------------------------------------------------------\n");
    printf("Starting APRS Tests\n");
    printf("----------------------------------------------------------------------------------\n\n");
    result |= test_aprs();
    printf("\n----------------------------------------------------------------------------------\n");
    printf("Tests APRS Completed. %s\n", result == 0 ? "All tests passed" : "Some tests failed");
    printf("----------------------------------------------------------------------------------\n\n");
    return result;
}


