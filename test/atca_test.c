/**
 * \file
 * \brief  Cryptoauthlib Testing: Common Resources & Functions
 *
 * \copyright Copyright (c) 2017 Microchip Technology Inc. and its subsidiaries (Microchip). All rights reserved.
 *
 * \page License
 *
 * You are permitted to use this software and its derivatives with Microchip
 * products. Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Microchip may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with a
 *    Microchip integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL MICROCHIP BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include "atca_test.h"

// gCfg must point to one of the cfg_ structures for any unit test to work.  this allows
// the command console to switch device types at runtime.
ATCAIfaceCfg g_iface_config = {
    .iface_type        = ATCA_I2C_IFACE,
    .devtype           = ATECC508A,
    .atcai2c           = {
        .slave_address = 0xC0,
        .bus           = 2,
        .baud          = 400000,
    },
    .wake_delay        = 1500,
    .rx_retries        = 20
};

ATCAIfaceCfg *gCfg = &g_iface_config;

const uint8_t g_slot4_key[32] = {
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5, 0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00, 0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
};


#if defined(_WIN32) || defined(__linux__)
#include <stdio.h>
#include <stdlib.h>
#include "cmd-processor.h"
int main(int argc, char* argv[])
{

    char buffer[1024];
    size_t bufsize = sizeof(buffer);

    if (!buffer)
    {
        fprintf(stderr, "Failed to allocated a buffer");
        return 1;
    }

    while (true)
    {
        printf("$ ");
        if (fgets(buffer, bufsize, stdin))
            parseCmd(buffer);
    }

    return 0;
}
#endif
