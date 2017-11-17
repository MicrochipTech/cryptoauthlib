/** \file
 * \brief simple command processor for test console
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
// Undefine the Unity FAIL macro so it doesn't conflict with the ASF definition
#undef FAIL

#if !defined(_WIN32) && !defined(__linux__) && !defined(__XC32__)
#ifdef ATMEL_START
#include "atmel_start.h"
#else
#include <asf.h>
#endif
#endif

#include <string.h>
#ifndef _WIN32
#include "cbuf.h"
#endif
#include "cryptoauthlib.h"
#include "atca_unit_tests.h"
#include "atca_basic_tests.h"
#include "atca_crypto_sw_tests.h"
#include "cmd-processor.h"

#define TEST_CD
#define TEST_CIO
#define TEST_SW_CRYPTO

#if XMEGA_A3BU
#undef TEST_CD
#undef TEST_CIO
#endif

#if SAMB11G
#undef TEST_CD
#undef TEST_CIO
#endif

#ifdef __AVR_AT90USB1287__
#undef TEST_CD
#undef TEST_CIO
#undef TEST_SW_CRYPTO
#endif

#ifdef TEST_CD
void RunAllCertDataTests(void);

int certdata_unit_tests(void)
{
    const char* argv[] = { "manual", "-v" };

    UnityMain(sizeof(argv) / sizeof(char*), argv, RunAllCertDataTests);

    return ATCA_SUCCESS;
}
#endif

#ifdef TEST_CIO
void RunAllCertIOTests(void);

int certio_unit_tests(void)
{
    const char* argv[] = { "manual", "-v" };

    UnityMain(sizeof(argv) / sizeof(char*), argv, RunAllCertIOTests);

    return ATCA_SUCCESS;
}
#endif

static ATCA_STATUS set_test_config(ATCADeviceType deviceType)
{
    bool is_set = true;

    switch (deviceType)
    {
    case ATSHA204A:
#if defined(ATCA_HAL_I2C)
        *gCfg = cfg_atsha204a_i2c_default;
#elif defined(ATCA_HAL_SWI)
        *gCfg = cfg_atsha204a_swi_default;
#elif defined(ATCA_HAL_KIT_HID)
        *gCfg = cfg_atsha204a_kithid_default;
#elif defined(ATCA_HAL_KIT_CDC)
        *gCfg = cfg_atsha204a_kitcdc_default;
#else
        is_set = false;
#endif
        break;

    case ATECC108A:
#if defined(ATCA_HAL_I2C)
        *gCfg = cfg_ateccx08a_i2c_default;
#elif defined(ATCA_HAL_SWI)
        *gCfg = cfg_ateccx08a_swi_default;
#elif defined(ATCA_HAL_KIT_HID)
        *gCfg = cfg_atecc508a_kithid_default;
#elif defined(ATCA_HAL_KIT_CDC)
        *gCfg = cfg_atecc508a_kitcdc_default;
#else
        is_set = false;
#endif
        break;

    case ATECC508A:
#if defined(ATCA_HAL_I2C)
        *gCfg = cfg_ateccx08a_i2c_default;
#elif defined(ATCA_HAL_SWI)
        *gCfg = cfg_ateccx08a_swi_default;
#elif defined(ATCA_HAL_KIT_HID)
        *gCfg = cfg_atecc508a_kithid_default;
#elif defined(ATCA_HAL_KIT_CDC)
        *gCfg = cfg_atecc508a_kitcdc_default;
#elif defined(ATCA_HAL_SIM)
        memset(gCfg, 0, sizeof(*gCfg));
        gCfg->iface_type = ATCA_SIM_IFACE;
#else
        is_set = false;
#endif
        break;

    default:
        is_set = false;
        break;
    }

    if (!is_set)
        return ATCA_GEN_FAIL;

    gCfg->devtype = deviceType;

#ifdef ATCA_RASPBERRY_PI_3
    gCfg->atcai2c.bus = 1;
#endif

    return ATCA_SUCCESS;
}

static int atca_unit_tests(ATCADeviceType deviceType)
{
    const char* argv[] = { "manual", "-v" };

    if (set_test_config(deviceType))
    {
        printf("Unable to set configuration");
        return ATCA_GEN_FAIL;
    }

    UnityMain(sizeof(argv) / sizeof(char*), argv, RunAllFeatureTests);

    return ATCA_SUCCESS;
}

static void atca_basic_tests(ATCADeviceType deviceType)
{
    const char* argv[] = { "manual", "-v" };

    if (set_test_config(deviceType))
    {
        printf("Unable to set configuration");
        return;
    }

    UnityMain(sizeof(argv) / sizeof(char*), argv, RunAllBasicTests);
}

static void atca_basic_otpzero_test(void)
{
    const char* argv[] = { "manual", "-v" };

    UnityMain(sizeof(argv) / sizeof(char*), argv, RunBasicOtpZero);
}

static void atca_helper_tests(void)
{
    const char* argv[] = { "manual", "-v" };

    UnityMain(sizeof(argv) / sizeof(char*), argv, RunAllHelperTests);
}

int help(void)
{
    printf("Usage:\r\n");
    printf("508  - set target device to ATECC508A\r\n");
    printf("108  - set target device to ATECC108A\r\n");
    printf("204  - set target device to ATSHA204A\r\n");
    printf("u508 - run unit tests for ECC508A\r\n");
    printf("b508 - run basic tests on ECC508A\r\n");
    printf("u108 - run unit tests for ECC108A\r\n");
    printf("b108 - run basic tests on ECC108A\r\n");
    printf("u204 - run unit tests for SHA204A\r\n");
    printf("b204 - run basic tests for SHA204A\r\n");
    printf("util - run helper function tests\r\n");
    printf("readcfg - read the config zone\r\n");
    printf("lockstat - zone lock status\r\n");
    printf("lockcfg  - lock config zone\r\n");
    printf("lockdata - lock data and OTP zones\r\n");
#ifdef TEST_CD
    printf("cd  - run unit tests on cert data\r\n");
#endif
#ifdef TEST_CIO
    printf("cio - run unit tests on cert i/o\r\n");
#endif
    printf("otpzero - Zero out OTP zone\r\n");
    printf("info - get the chip revision\r\n");
    printf("sernum - get the chip serial number\r\n");
#ifdef TEST_SW_CRYPTO
    printf("crypto - run unit tests for software crypto functions\r\n");
#endif
    printf("rand - generate some random numbers\r\n");
    printf("discover - buses and devices\r\n");


    printf("\r\n");
    return ATCA_SUCCESS;
}

uint8_t cmdbytes[128];


ATCA_STATUS isDeviceLocked(uint8_t zone, bool *isLocked)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
        return status;

    status = atcab_is_locked(zone, isLocked);
    atcab_release();

    return status;
}

ATCA_STATUS lockstatus(void)
{
    ATCA_STATUS status;
    bool is_locked = false;

    if ( (status = isDeviceLocked(LOCK_ZONE_CONFIG, &is_locked)) != ATCA_SUCCESS)
    {
        printf("isDeviceLocked() failed with ret=0x%08d\r\n", status);
        return status;
    }
    printf("Config Zone: %s\r\n", is_locked ? "LOCKED" : "unlocked");

    if ( (status = isDeviceLocked(LOCK_ZONE_DATA, &is_locked)) != ATCA_SUCCESS)
    {
        printf("isDeviceLocked() failed with ret=0x%08d\r\n", status);
        return status;
    }
    printf("Data Zone  : %s\r\n", is_locked ? "LOCKED" : "unlocked");

    return status;
}

ATCA_STATUS lock_config_zone(void)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08d\r\n", status);
        return status;
    }

    status = atcab_lock_config_zone();
    atcab_release();
    if (status != ATCA_SUCCESS)
        printf("atcab_lock_config_zone() failed with ret=0x%08d\r\n", status);

    return status;
}

ATCA_STATUS lock_data_zone(void)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08d\r\n", status);
        return status;
    }

    status = atcab_lock_data_zone();
    atcab_release();
    if (status != ATCA_SUCCESS)
        printf("atcab_lock_data_zone() failed with ret=0x%08d\r\n", status);

    return status;
}

ATCA_STATUS getinfo(uint8_t *revision)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08d\r\n", status);
        return status;
    }

    status = atcab_info(revision);
    atcab_release();
    if (status != ATCA_SUCCESS)
        printf("atcab_info() failed with ret=0x%08d\r\n", status);

    return status;
}

ATCA_STATUS getsernum(uint8_t *sernum)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08d\r\n", status);
        return status;
    }

    status = atcab_read_serial_number(sernum);
    atcab_release();
    if (status != ATCA_SUCCESS)
        printf("atcab_read_serial_number() failed with ret=0x%08d\r\n", status);

    return status;
}

ATCA_STATUS doRandoms(void)
{
    ATCA_STATUS status;
    uint8_t randout[RANDOM_RSP_SIZE];
    char displayStr[ RANDOM_RSP_SIZE * 3];
    int displen = sizeof(displayStr);
    int i;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("error: %02x\r\n", status);
        return status;
    }

    for (i = 0; i < 5; i++)
    {
        if ( (status = atcab_random(randout)) != ATCA_SUCCESS)
            break;

        atcab_bin2hex(randout, 32, displayStr, &displen);
        printf("%s\r\n", displayStr);
    }

    if (status != ATCA_SUCCESS)
        printf("error: %02x\r\n", status);

    atcab_release();

    return status;
}

static void read_config(void)
{
    ATCA_STATUS status;
    uint8_t config[ATCA_ECC_CONFIG_SIZE];
    size_t config_size = 0;
    size_t i = 0;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed: %02x\r\n", status);
        return;
    }

    do
    {
        status = atcab_get_zone_size(ATCA_ZONE_CONFIG, 0, &config_size);
        if (status != ATCA_SUCCESS)
        {
            printf("atcab_get_zone_size() failed: %02x\r\n", status);
            break;
        }

        status = atcab_read_config_zone(config);
        if (status != ATCA_SUCCESS)
        {
            printf("atcab_read_config_zone() failed: %02x\r\n", status);
            break;
        }

        for (i = 0; i < config_size; i++)
        {
            if (i % 16 == 0)
                printf("\r\n");
            else if (i % 8 == 0)
                printf("  ");
            else
                printf(" ");
            printf("%02X", (int)config[i]);
        }
        printf("\r\n");
    }
    while (0);

    atcab_release();
}

int parseCmd(const char *command)
{
    char *cmds = NULL;
    ATCA_STATUS status;
    ATCAIfaceCfg ifaceCfgs[10];
    const char *devname[] = { "ATSHA204A", "ATECC108A", "ATECC508A" };  // indexed by ATCADeviceType
    int i;

    printf("\r\n");
    if ( (cmds = strstr(command, "help")) )
    {
        help();
    }
    else if ( (cmds = strstr(command, "u508")) )
    {
        atca_unit_tests(ATECC508A);
    }
    else if ( (cmds = strstr(command, "b508")) )
    {
        atca_basic_tests(ATECC508A);
    }
    else if ( (cmds = strstr(command, "u108")) )
    {
        atca_unit_tests(ATECC108A);
    }
    else if ( (cmds = strstr(command, "b108")) )
    {
        atca_basic_tests(ATECC108A);
    }
    else if ( (cmds = strstr(command, "u204")) )
    {
        atca_unit_tests(ATSHA204A);
    }
    else if ( (cmds = strstr(command, "b204")) )
    {
        atca_basic_tests(ATSHA204A);
    }
    else if ( (cmds = strstr(command, "util")) )
    {
        atca_helper_tests();
    }
#ifdef TEST_CD
    else if ( (cmds = strstr(command, "cd")) )
    {
        certdata_unit_tests();
    }
#endif
#ifdef TEST_CIO
    else if ( (cmds = strstr(command, "cio")) )
    {
        certio_unit_tests();
    }
#endif
    else if ( (cmds = strstr(command, "otpzero")) )
    {
        atca_basic_otpzero_test();
    }
    else if ( (cmds = strstr(command, "readcfg")) )
    {
        read_config();
    }
    else if ( (cmds = strstr(command, "lockstat")) )
    {
        lockstatus();
    }
    else if ( (cmds = strstr(command, "lockcfg")) )
    {
        if (lock_config_zone() != ATCA_SUCCESS)
            printf("Could not lock config zone\r\n");
        lockstatus();
    }
    else if ( (cmds = strstr(command, "lockdata")) )
    {
        if (lock_data_zone() != ATCA_SUCCESS)
            printf("Could not lock data zone\r\n");
        lockstatus();
    }
    else if ((cmds = strstr(command, "508")))
    {
        status = set_test_config(ATECC508A);
        if (status == ATCA_SUCCESS)
            printf("Current device: ATECC508A\r\n");
        else
            printf("ATECC508A test support not implemented.\r\n");
    }
    else if ((cmds = strstr(command, "204")))
    {
        status = set_test_config(ATSHA204A);
        if (status == ATCA_SUCCESS)
            printf("Current device: ATSHA204A\r\n");
        else
            printf("ATSHA204A test support not implemented.\r\n");
    }
    else if ((cmds = strstr(command, "108")))
    {
        status = set_test_config(ATECC108A);
        if (status == ATCA_SUCCESS)
            printf("Current device: ATECC108A\r\n");
        else
            printf("ATECC108A test support not implemented.\r\n");
    }
    else if ( (cmds = strstr(command, "info")) )
    {
        uint8_t revision[4];
        char displaystr[15];
        int displaylen = sizeof(displaystr);

        status = getinfo(revision);
        if (status == ATCA_SUCCESS)
        {
            // dump revision
            atcab_bin2hex(revision, 4, displaystr, &displaylen);
            printf("revision:\r\n%s\r\n", displaystr);
        }

    }
    else if ( (cmds = strstr(command, "sernum")) )
    {
        uint8_t serialnum[ATCA_SERIAL_NUM_SIZE];
        char displaystr[30];
        int displaylen = sizeof(displaystr);

        status = getsernum(serialnum);
        if (status == ATCA_SUCCESS)
        {
            // dump serial num
            atcab_bin2hex(serialnum, ATCA_SERIAL_NUM_SIZE, displaystr, &displaylen);
            printf("serial number:\r\n%s\r\n", displaystr);
        }
#ifdef TEST_SW_CRYPTO
    }
    else if ( (cmds = strstr(command, "crypto")) )
    {
        atca_crypto_sw_tests();
#endif
    }
    else if ( (cmds = strstr(command, "rand")) )
    {
        doRandoms();
    }
    else if ( (cmds = strstr(command, "discover")) )
    {
        for (i = 0; i < (int)(sizeof( ifaceCfgs ) / sizeof(ATCAIfaceCfg)); i++)
        {
            ifaceCfgs[i].devtype = ATCA_DEV_UNKNOWN;
            ifaceCfgs[i].iface_type = ATCA_UNKNOWN_IFACE;
        }

        printf("...looking\r\n");
        atcab_cfg_discover(ifaceCfgs, sizeof(ifaceCfgs) / sizeof(ATCAIfaceCfg) );
#ifdef ATCA_HAL_I2C
        for (i = 0; i < (int)(sizeof( ifaceCfgs) / sizeof(ATCAIfaceCfg)); i++)
            if (ifaceCfgs[i].devtype != ATCA_DEV_UNKNOWN && ifaceCfgs[i].iface_type == ATCA_I2C_IFACE)
                printf("Found %s @ bus %d addr %02x\r\n", devname[ifaceCfgs[i].devtype], ifaceCfgs[i].atcai2c.bus, ifaceCfgs[i].atcai2c.slave_address);

#endif
#ifdef ATCA_HAL_SWI
        for (i = 0; i < (int)(sizeof( ifaceCfgs) / sizeof(ATCAIfaceCfg)); i++)
            if (ifaceCfgs[i].devtype != ATCA_DEV_UNKNOWN && ifaceCfgs[i].iface_type == ATCA_SWI_IFACE)
                printf("Found %s @ bus %d\r\n", devname[ifaceCfgs[i].devtype], ifaceCfgs[i].atcaswi.bus);

#endif
    }

    else if (strlen(command) )
    {
        printf("syntax error in command: %s\r\n", command);
    }
    return ATCA_SUCCESS;
}

#ifndef _WIN32
int processCmd(void)
{
    static char cmd[cmdQ_SIZE + 1];
    uint16_t i = 0;

    while (!CBUF_IsEmpty(cmdQ) && i < sizeof(cmd))
        cmd[i++] = CBUF_Pop(cmdQ);
    cmd[i] = '\0';
    //printf("\r\n%s\r\n", command );
    parseCmd(cmd);
    printf("$ ");

    return ATCA_SUCCESS;
}
#endif
