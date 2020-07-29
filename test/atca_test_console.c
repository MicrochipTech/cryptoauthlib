/**
 * \file
 * \brief  Cryptoauthlib Testing: Configuration Management
 *
 * \copyright (c) 2015-2020 Microchip Technology Inc. and its subsidiaries.
 *
 * \page License
 *
 * Subject to your compliance with these terms, you may use Microchip software
 * and any derivatives exclusively with Microchip products. It is your
 * responsibility to comply with third party license terms applicable to your
 * use of third party software (including open source software) that may
 * accompany Microchip software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
 * SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
 * OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
 * MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
 * FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
 * LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
 * THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
 * THIS SOFTWARE.
 */

#include "cryptoauthlib.h"
#include "atca_test.h"
#include "cmd-processor.h"
#include "atca_crypto_sw_tests.h"

#ifndef ATCA_SERIAL_NUM_SIZE
#define ATCA_SERIAL_NUM_SIZE        (9)
#endif

#ifndef RANDOM_RSP_SIZE
#define RANDOM_RSP_SIZE             (32)
#endif

int run_basic_tests(int argc, char* argv[])
{
#ifdef ATCA_ATECC608_SUPPORT
    if (ATECC608 == (gCfg->devtype))
    {
        check_clock_divider(argc, argv);
    }
#endif
    return run_test(argc, argv, RunAllBasicTests);
}

int run_unit_tests(int argc, char* argv[])
{
#ifdef ATCA_ATECC608_SUPPORT
    if (ATECC608 == (gCfg->devtype))
    {
        check_clock_divider(argc, argv);
    }
#endif
    return run_test(argc, argv, RunAllFeatureTests);
}

int run_otpzero_tests(int argc, char* argv[])
{
    return run_test(argc, argv, RunBasicOtpZero);
}

int run_helper_tests(int argc, char* argv[])
{
    return run_test(argc, argv, RunAllHelperTests);
}

int read_config(int argc, char* argv[])
{
    ATCA_STATUS status;
    uint8_t config[200];
    size_t config_size = 0;
    size_t i = 0;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed: %02x\r\n", status);
        return 0;
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
            {
                printf("\r\n");
            }
            else if (i % 8 == 0)
            {
                printf("  ");
            }
            else
            {
                printf(" ");
            }
            printf("%02X", (int)config[i]);
        }
        printf("\r\n");
    }
    while (0);

    atcab_release();

    return 0;
}

int lock_status(int argc, char* argv[])
{
    ATCA_STATUS status;
    bool is_locked = false;

    if ((status = is_config_locked(&is_locked)) != ATCA_SUCCESS)
    {
        printf("is_device_locked() failed with ret=0x%08X\r\n", status);
        return status;
    }
    printf("Config Zone: %s\r\n", is_locked ? "LOCKED" : "unlocked");

    if ((status = is_data_locked(&is_locked)) != ATCA_SUCCESS)
    {
        printf("is_device_locked() failed with ret=0x%08X\r\n", status);
        return status;
    }
    printf("Data Zone  : %s\r\n", is_locked ? "LOCKED" : "unlocked");

    return (int)status;
}

int lock_config(int argc, char* argv[])
{
    int ret = lock_config_zone(argc, argv);

    lock_status(argc, argv);
    return ret;
}

int lock_data(int argc, char* argv[])
{
    int ret = lock_data_zone(argc, argv);

    lock_status(argc, argv);
    return ret;
}

int do_randoms(int argc, char* argv[])
{
    ATCA_STATUS status;
    uint8_t randout[RANDOM_RSP_SIZE];
    char displayStr[100];
    size_t displen = sizeof(displayStr);
    int i;

    if (gCfg->devtype == ATSHA206A)
    {
        printf("ATSHA206A doesn't support random command\r\n");
        return ATCA_GEN_FAIL;
    }

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return status;
    }

    printf("Random Numbers:\r\n");
    for (i = 0; i < 5; i++)
    {
        if ((status = atcab_random(randout)) != ATCA_SUCCESS)
        {
            break;
        }
        displen = sizeof(displayStr);
        atcab_bin2hex(randout, 32, displayStr, &displen);
        printf("%s\r\n", displayStr);
    }

    if (status != ATCA_SUCCESS)
    {
        printf("atcab_random() failed with ret=0x%08X\r\n", status);
    }

    atcab_release();

    return status;
}

#if ATCA_CA_SUPPORT
int discover(int argc, char* argv[])
{
    ATCAIfaceCfg ifaceCfgs[10];
    int i;
    const char* devname[] = { "ATSHA204A", "ATECC108A", "ATECC508A", "ATECC608", "ATSHA206A" };  // indexed by ATCADeviceType

    for (i = 0; i < (int)(sizeof(ifaceCfgs) / sizeof(ATCAIfaceCfg)); i++)
    {
        ifaceCfgs[i].devtype = ATCA_DEV_UNKNOWN;
        ifaceCfgs[i].iface_type = ATCA_UNKNOWN_IFACE;
    }

    printf("Searching...\r\n");
    atcab_cfg_discover(ifaceCfgs, sizeof(ifaceCfgs) / sizeof(ATCAIfaceCfg));
    for (i = 0; i < (int)(sizeof(ifaceCfgs) / sizeof(ATCAIfaceCfg)); i++)
    {
        if (ifaceCfgs[i].devtype != ATCA_DEV_UNKNOWN)
        {
            printf("Found %s ", devname[ifaceCfgs[i].devtype]);
            if (ifaceCfgs[i].iface_type == ATCA_I2C_IFACE)
            {
                printf("@ bus %d addr %02x", ifaceCfgs[i].atcai2c.bus, ifaceCfgs[i].atcai2c.slave_address);
            }
            if (ifaceCfgs[i].iface_type == ATCA_SWI_IFACE)
            {
                printf("@ bus %d", ifaceCfgs[i].atcaswi.bus);
            }
            printf("\r\n");
        }
    }

    return 0;
}
#endif

int info(int argc, char* argv[])
{
    ATCA_STATUS status;
    uint8_t revision[4];
    char displaystr[15];
    size_t displaylen = sizeof(displaystr);

    status = get_info(revision);
    if (status == ATCA_SUCCESS)
    {
        // dump revision
        atcab_bin2hex(revision, 4, displaystr, &displaylen);
        printf("revision:\r\n%s\r\n", displaystr);
    }
    return status;
}

int read_sernum(int argc, char* argv[])
{
    ATCA_STATUS status;
    uint8_t serialnum[ATCA_SERIAL_NUM_SIZE];
    char displaystr[30];
    size_t displaylen = sizeof(displaystr);

    status = get_serial_no(serialnum);
    if (status == ATCA_SUCCESS)
    {
        // dump serial num
        atcab_bin2hex(serialnum, ATCA_SERIAL_NUM_SIZE, displaystr, &displaylen);
        printf("serial number:\r\n%s\r\n", displaystr);
    }
    return status;
}

#if defined(ATCA_ECC_SUPPORT) && !defined(DO_NOT_TEST_CERT)
void RunAllCertDataTests(void);
int certdata_unit_tests(int argc, char* argv[])
{
    UnityMain(argc, (const char**)argv, RunAllCertDataTests);
    return ATCA_SUCCESS;
}

void RunAllCertIOTests(void);
int certio_unit_tests(int argc, char* argv[])
{
    UnityMain(argc, (const char**)argv, RunAllCertIOTests);
    return ATCA_SUCCESS;
}
#endif

ATCA_STATUS is_config_locked(bool* isLocked)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        return status;
    }

    status = atcab_is_config_locked(isLocked);
    atcab_release();

    return status;
}

ATCA_STATUS is_data_locked(bool* isLocked)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        return status;
    }

    status = atcab_is_data_locked(isLocked);
    atcab_release();

    return status;
}

int lock_config_zone(int argc, char* argv[])
{
    ATCA_STATUS status;
    uint8_t ch = 0;

    if (gCfg->devtype == ATSHA206A)
    {
        printf("ATSHA206A doesn't support lock command\r\n");
        return ATCA_GEN_FAIL;
    }

    if (!g_atca_test_quiet_mode)
    {
        int ret;
        printf("Locking with test configuration, which is suitable only for unit tests... \r\nConfirm by typing Y\r\n");
        do
        {
            ret = scanf("%c", &ch);
        }
        while (ch == '\n' || ch == '\r');

        if (!((ch == 'Y') || (ch == 'y') || (ret < 0)))
        {
            printf("Skipping Config Lock on request.\r\n");
            return ATCA_GEN_FAIL;
        }
    }

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return status;
    }

    status = atcab_lock_config_zone();
    atcab_release();
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_lock_config_zone() failed with ret=0x%08X\r\n", status);
    }

    return (int)status;
}

int lock_data_zone(int argc, char* argv[])
{
    ATCA_STATUS status;
    uint8_t ch = 0;

    if (!g_atca_test_quiet_mode)
    {
        int ret;
        printf("Locking Data zone... \r\nConfirm by typing Y\r\n");
        do
        {
            ret = scanf("%c", &ch);
        }
        while (ch == '\n' || ch == '\r');

        if (!((ch == 'Y') || (ch == 'y') || (ret < 0)))
        {
            printf("Skipping Data Zone Lock on request.\r\n");
            return ATCA_GEN_FAIL;
        }
    }

    if (gCfg->devtype == ATSHA206A)
    {
        printf("ATSHA206A doesn't support lock command\r\n");
        return ATCA_GEN_FAIL;
    }

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return status;
    }

    status = atcab_lock_data_zone();
    atcab_release();
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_lock_data_zone() failed with ret=0x%08X\r\n", status);
    }

    return (int)status;
}

ATCA_STATUS get_info(uint8_t* revision)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return status;
    }

    status = atcab_info(revision);
    atcab_release();
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_info() failed with ret=0x%08X\r\n", status);
    }

    return status;
}

ATCA_STATUS get_serial_no(uint8_t* sernum)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return status;
    }

    status = atcab_read_serial_number(sernum);
    atcab_release();
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_read_serial_number() failed with ret=0x%08X\r\n", status);
    }

    return status;
}

int run_test(int argc, char* argv[], void* fptest)
{
    if (CMD_PROCESSOR_MAX_ARGS > argc)
    {
        argv[argc++] = "-v";
    }

    if (gCfg->devtype < ATCA_DEV_UNKNOWN)
    {
        return UnityMain(argc, (const char**)argv, fptest);
    }
    else
    {
        printf("Device is NOT Selected... Select device before running tests!!!");
        return -1;
    }
}

int run_all_tests(int argc, char* argv[])
{
    ATCA_STATUS status;
    bool config_locked = false;
    bool data_locked = false;
    int fails = 0;

#ifdef ATCA_ATECC608_SUPPORT
    if (ATECC608 == (gCfg->devtype))
    {
        check_clock_divider(argc, argv);
    }
#endif

    info(argc, argv);
    (void)read_sernum(argc, argv);
    do_randoms(argc, argv);

    status = is_config_locked(&config_locked);
    if (status != ATCA_SUCCESS)
    {
        printf("is_config_locked() failed with ret=0x%08X\r\n", status);
        return status;
    }
    status = is_data_locked(&data_locked);
    if (status != ATCA_SUCCESS)
    {
        printf("is_data_locked() failed with ret=0x%08X\r\n", status);
        return status;
    }

    status = lock_status(argc, argv);
    if (status != ATCA_SUCCESS)
    {
        printf("lock_status() failed with ret=0x%08X\r\n", status);
        return status;
    }

#ifdef ATCA_TA100_SUPPORT
    if (TA100 == gCfg->devtype)
    {
        (void)talib_configure_device(0, NULL);
    }
#endif

#ifndef DO_NOT_TEST_BASIC_UNIT
    if (!config_locked)
    {
        fails += run_test(argc, argv, RunAllFeatureTests);
        if (fails > 0)
        {
            printf("unit tests with config zone unlocked failed.\r\n");
            return status;
        }

        fails += run_test(argc, argv, RunAllBasicTests);
        if (fails > 0)
        {
            printf("basic tests with config zone unlocked failed.\r\n");
            return status;
        }

        status = lock_config_zone(argc, argv);
        if (status != ATCA_SUCCESS)
        {
            printf("lock_config_zone() failed with ret=0x%08X\r\n", status);
            return status;
        }
        status = lock_status(argc, argv);
        if (status != ATCA_SUCCESS)
        {
            printf("lock_status() failed with ret=0x%08X\r\n", status);
            return status;
        }
    }

    if (!data_locked)
    {
        fails += run_test(argc, argv, RunAllFeatureTests);
        if (fails > 0)
        {
            printf("unit tests with data zone unlocked failed.\r\n");
            return status;
        }

        fails += run_test(argc, argv, RunAllBasicTests);
        if (fails > 0)
        {
            printf("basic tests with data zone unlocked failed.\r\n");
            return status;
        }

        status = lock_data_zone(argc, argv);
        if (status != ATCA_SUCCESS)
        {
            printf("lock_data_zone() failed with ret=0x%08X\r\n", status);
            return status;
        }
        status = lock_status(argc, argv);
        if (status != ATCA_SUCCESS)
        {
            printf("lock_status() failed with ret=0x%08X\r\n", status);
            return status;
        }
    }

    fails += run_test(argc, argv, RunAllFeatureTests);
    if (fails > 0)
    {
        printf("unit tests with data zone locked failed.\r\n");
        return status;
    }

    fails += run_test(argc, argv, RunAllBasicTests);
    if (fails > 0)
    {
        printf("basic tests with data zone locked failed.\r\n");
        return status;
    }

    fails = run_test(argc, argv, RunAllHelperTests);
    if (fails > 0)
    {
        printf("util tests failed.\r\n");
        return status;
    }
#endif

#ifndef DO_NOT_TEST_SW_CRYPTO
    fails += atca_crypto_sw_tests(argc, argv);
    if (fails > 0)
    {
        printf("crypto tests failed.\r\n");
        return status;
    }
#endif

#if !defined(DO_NOT_TEST_CERT) && defined(ATCA_ECC_SUPPORT)
    if (atIsECCFamily(gCfg->devtype))
    {
        fails += run_test(argc, argv, RunAllCertIOTests);
        if (fails > 0)
        {
            printf("cio tests failed.\r\n");
            return 0;
        }
    }
    else
    {
        printf("cio tests don't apply to non-ECC devices.\r\n");
    }

    fails += run_test(argc, argv, RunAllCertDataTests);
    if (fails > 0)
    {
        printf("cd tests failed.\r\n");
        return 0;
    }
#endif

    printf("All unit tests passed.\r\n");
    return 0;
}

int run_tng_tests(int argc, char* argv[])
{
    ATCA_STATUS status;

    gCfg->atcahid.dev_interface = ATCA_KIT_I2C_IFACE;
    gCfg->atcahid.dev_identity = 0x6C;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return status;
    }

    run_test(argc, argv, RunTNGTests);

    atcab_release();
    return 0;
}
