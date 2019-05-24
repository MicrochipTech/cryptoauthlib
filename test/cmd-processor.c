/** \file
 * \brief simple command processor for test console
 *
 * \copyright (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
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

#include "atca_test.h"
// Undefine the Unity FAIL macro so it doesn't conflict with the ASF definition
#undef FAIL

#if !defined(_WIN32) && !defined(__linux__) && !defined(__XC32__) && !defined(__APPLE__) && !defined(ESP32)
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
#include "atca_test.h"
#include "atca_crypto_sw_tests.h"
#include "cmd-processor.h"
#include "atca_cfgs.h"

static ATCA_STATUS set_test_config(ATCADeviceType deviceType);
static int certdata_unit_tests(void);
static int certio_unit_tests(void);
static ATCA_STATUS is_device_locked(uint8_t zone, bool *isLocked);
static ATCA_STATUS lock_status(void);
static ATCA_STATUS lock_config_zone(void);
static ATCA_STATUS lock_data_zone(void);
static ATCA_STATUS get_info(uint8_t *revision);
static ATCA_STATUS get_serial_no(uint8_t *sernum);
static ATCA_STATUS do_randoms(void);
static void read_config(void);
static void lock_config(void);
static void lock_data(void);
static void info(void);
static void sernum(void);
static void discover(void);
static void select_device(ATCADeviceType device_type);
static int run_test(void* fptest);
static void select_204(void);
static void select_108(void);
static void select_508(void);
static void select_608(void);
static void run_basic_tests(void);
static void run_unit_tests(void);
static void run_otpzero_tests(void);
static void run_helper_tests(void);
static void help(void);
static int parse_cmd(const char *command);
static void run_all_tests(void);
static ATCA_STATUS set_chip_mode(uint8_t i2c_user_extra_add, uint8_t ttl_enable, uint8_t watchdog, uint8_t clock_divider);
static void set_clock_divider_m0(void);
static void set_clock_divider_m1(void);
static void set_clock_divider_m2(void);
static void tng22_tests(void);
static void tngtn_tests(void);

static const char* argv[] = { "manual", "-v" };
// *INDENT-OFF*  - Preserve formatting
static t_menu_info mas_menu_info[] =
{
    { "help",     "Display Menu",                                   help                                 },
    { "discover", "Discover Buses and Devices",                     discover                             },
    { "204",      "Set Target Device to ATSHA204A",                 select_204                           },
    { "108",      "Set Target Device to ATECC108A",                 select_108                           },
    { "508",      "Set Target Device to ATECC508A",                 select_508                           },
    { "608",      "Set Target Device to ATECC608A",                 select_608                           },
    { "info",     "Get the Chip Revision",                          info                                 },
    { "sernum",   "Get the Chip Serial Number",                     sernum                               },
    { "rand",     "Generate Some Random Numbers",                   (fp_menu_handler)do_randoms          },
    { "readcfg",  "Read the Config Zone",                           read_config                          },
    { "lockstat", "Zone Lock Status",                               (fp_menu_handler)lock_status         },
    { "lockcfg",  "Lock the Config Zone",                           lock_config                          },
    { "lockdata", "Lock Data and OTP Zones",                        lock_data                            },
    { "all",      "Run all unit tests, locking as needed.",         run_all_tests                        },
    { "tng22",    "Run unit tests on TNG 22 type part.",            tng22_tests                          },
    { "tngtn",    "Run unit tests on TNG TN type part.",            tngtn_tests                          },
    #ifndef DO_NOT_TEST_BASIC_UNIT
    { "basic",    "Run Basic Test on Selected Device",              run_basic_tests                      },
    { "unit",     "Run Unit Test on Selected Device",               run_unit_tests                       },
    { "otpzero",  "Zero Out OTP Zone",                              run_otpzero_tests                    },
    { "util",     "Run Helper Function Tests",                      run_helper_tests                     },
    { "clkdivm0", "Set ATECC608A to ClockDivider M0(0x00)",         set_clock_divider_m0                 },
    { "clkdivm1", "Set ATECC608A to ClockDivider M1(0x05)",         set_clock_divider_m1                 },
    { "clkdivm2", "Set ATECC608A to ClockDivider M2(0x0D)",         set_clock_divider_m2                 },
    #endif
    #ifndef DO_NOT_TEST_CERT
    { "cd",       "Run Unit Tests on Cert Data",                    (fp_menu_handler)certdata_unit_tests },
    { "cio",      "Run Unit Test on Cert I/O",                      (fp_menu_handler)certio_unit_tests   },
    #endif
    #ifndef DO_NOT_TEST_SW_CRYPTO
    { "crypto",   "Run Unit Tests for Software Crypto Functions",   (fp_menu_handler)atca_crypto_sw_tests},
    #endif
    { NULL,       NULL,                                             NULL                                 },
};
// *INDENT-ON*

#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
#include <stdio.h>
#include <stdlib.h>
#include "cmd-processor.h"
int main(int argc, char* argv[])
{
    char buffer[1024];

    while (true)
    {
        printf("$ ");
        if (fgets(buffer, sizeof(buffer), stdin))
        {
            parse_cmd(buffer);
        }
    }

    return 0;
}
#else
int processCmd(void)
{
    static char cmd[cmdQ_SIZE + 1];
    uint16_t i = 0;

    while (!CBUF_IsEmpty(cmdQ) && i < sizeof(cmd))
    {
        cmd[i++] = CBUF_Pop(cmdQ);
    }
    cmd[i] = '\0';
    //printf("\r\n%s\r\n", command );
    parse_cmd(cmd);
    printf("$ ");

    return ATCA_SUCCESS;
}
#endif

static int parse_cmd(const char *command)
{
    uint8_t index = 0;

    printf("\r\n");
    if (command[0] == '\0' || command[0] == '\n')
    {
        return ATCA_SUCCESS;
    }
    while (mas_menu_info[index].menu_cmd != NULL)
    {
        if (strstr(command, mas_menu_info[index].menu_cmd))
        {
            if (mas_menu_info[index].fp_handler)
            {
                mas_menu_info[index].fp_handler();
            }
            break;
        }
        index++;
    }

    if (mas_menu_info[index].menu_cmd == NULL)
    {
        printf("syntax error in command: %s", command);
    }
    printf("\r\n");
    return ATCA_SUCCESS;
}

static void help(void)
{
    uint8_t index = 0;

    printf("Usage:\r\n");
    while (mas_menu_info[index].menu_cmd != NULL)
    {
        printf("%s - %s\r\n", mas_menu_info[index].menu_cmd, mas_menu_info[index].menu_cmd_description);
        index++;
    }
}

static void select_204(void)
{
    select_device(ATSHA204A);
}
static void select_108(void)
{
    select_device(ATECC108A);
}
static void select_508(void)
{
    select_device(ATECC508A);
}
static void select_608(void)
{
    select_device(ATECC608A);
}

static void update_chip_mode(uint8_t* chip_mode, uint8_t i2c_user_extra_add, uint8_t ttl_enable, uint8_t watchdog, uint8_t clock_divider)
{
    if (i2c_user_extra_add != 0xFF)
    {
        *chip_mode &= ~ATCA_CHIPMODE_I2C_ADDRESS_FLAG;
        *chip_mode |= i2c_user_extra_add & ATCA_CHIPMODE_I2C_ADDRESS_FLAG;
    }
    if (ttl_enable != 0xFF)
    {
        *chip_mode &= ~ATCA_CHIPMODE_TTL_ENABLE_FLAG;
        *chip_mode |= ttl_enable & ATCA_CHIPMODE_TTL_ENABLE_FLAG;
    }
    if (watchdog != 0xFF)
    {
        *chip_mode &= ~ATCA_CHIPMODE_WATCHDOG_MASK;
        *chip_mode |= watchdog & ATCA_CHIPMODE_WATCHDOG_MASK;
    }
    if (clock_divider != 0xFF)
    {
        *chip_mode &= ~ATCA_CHIPMODE_CLOCK_DIV_MASK;
        *chip_mode |= clock_divider & ATCA_CHIPMODE_CLOCK_DIV_MASK;
    }
}

static ATCA_STATUS check_clock_divider(void)
{
    ATCA_STATUS status;
    uint8_t chip_mode = 0;

    if (gCfg->devtype != ATECC608A)
    {
        printf("Current device doesn't support clock divider settings (only ATECC608A)\r\n");
        return ATCA_GEN_FAIL;
    }

    // Update the actual ATECC608A chip mode so it takes effect immediately
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return status;
    }

    do
    {
        // Read current config values
        status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, ATCA_CHIPMODE_OFFSET, &chip_mode, 1);
        if (status != ATCA_SUCCESS)
        {
            printf("atcab_read_bytes_zone() failed with ret=0x%08X\r\n", status);
            break;
        }

        // Update the ATECC608A test config data so all the unit tests will run with the new chip mode
        update_chip_mode(&test_ecc608_configdata[ATCA_CHIPMODE_OFFSET], 0xFF, 0xFF, chip_mode & ATCA_CHIPMODE_WATCHDOG_MASK, chip_mode & ATCA_CHIPMODE_CLOCK_DIV_MASK);

    }
    while (0);

    atcab_release();
    return status;
}

static void run_basic_tests(void)
{
    if (gCfg->devtype == ATECC608A)
    {
        check_clock_divider();
    }
    run_test(RunAllBasicTests);
}

static void run_unit_tests(void)
{
    if (gCfg->devtype == ATECC608A)
    {
        check_clock_divider();
    }
    run_test(RunAllFeatureTests);
}
static void run_otpzero_tests(void)
{
    run_test(RunBasicOtpZero);
}
static void run_helper_tests(void)
{
    run_test(RunAllHelperTests);
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
}

static ATCA_STATUS lock_status(void)
{
    ATCA_STATUS status;
    bool is_locked = false;

    if ((status = is_device_locked(LOCK_ZONE_CONFIG, &is_locked)) != ATCA_SUCCESS)
    {
        printf("is_device_locked() failed with ret=0x%08X\r\n", status);
        return status;
    }
    printf("Config Zone: %s\r\n", is_locked ? "LOCKED" : "unlocked");

    if ((status = is_device_locked(LOCK_ZONE_DATA, &is_locked)) != ATCA_SUCCESS)
    {
        printf("is_device_locked() failed with ret=0x%08X\r\n", status);
        return status;
    }
    printf("Data Zone  : %s\r\n", is_locked ? "LOCKED" : "unlocked");

    return status;
}

static void lock_config(void)
{
    lock_config_zone();
    lock_status();
}

static void lock_data(void)
{
    lock_data_zone();
    lock_status();
}

static ATCA_STATUS do_randoms(void)
{
    ATCA_STATUS status;
    uint8_t randout[RANDOM_RSP_SIZE];
    char displayStr[RANDOM_RSP_SIZE * 3];
    size_t displen = sizeof(displayStr);
    int i;

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

static void discover(void)
{
    ATCAIfaceCfg ifaceCfgs[10];
    int i;
    const char *devname[] = { "ATSHA204A", "ATECC108A", "ATECC508A", "ATECC608A" };  // indexed by ATCADeviceType

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
}
static void info(void)
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
}

static void sernum(void)
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
}

void RunAllCertDataTests(void);
static int certdata_unit_tests(void)
{
    UnityMain(sizeof(argv) / sizeof(char*), argv, RunAllCertDataTests);
    return ATCA_SUCCESS;
}

void RunAllCertIOTests(void);
static int certio_unit_tests(void)
{
    UnityMain(sizeof(argv) / sizeof(char*), argv, RunAllCertIOTests);
    return ATCA_SUCCESS;
}

static ATCA_STATUS is_device_locked(uint8_t zone, bool *isLocked)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        return status;
    }

    status = atcab_is_locked(zone, isLocked);
    atcab_release();

    return status;
}

static ATCA_STATUS lock_config_zone(void)
{
    ATCA_STATUS status;

    uint8_t ch = 0;

    printf("Locking with test configuration, which is suitable only for unit tests... \r\nConfirm by typing Y\r\n");
    do
    {
        scanf("%c", &ch);
    }
    while (ch == '\n' || ch == '\r');

    if (!((ch == 'Y') || (ch == 'y')))
    {
        printf("Skipping Config Lock on request.\r\n");
        return ATCA_GEN_FAIL;
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

    return status;
}

static ATCA_STATUS lock_data_zone(void)
{
    ATCA_STATUS status;
    uint8_t ch = 0;

    printf("Locking Data zone... \r\nConfirm by typing Y\r\n");
    do
    {
        scanf("%c", &ch);
    }
    while (ch == '\n' || ch == '\r');

    if (!((ch == 'Y') || (ch == 'y')))
    {
        printf("Skipping Data Zone Lock on request.\r\n");
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

    return status;
}

static ATCA_STATUS get_info(uint8_t *revision)
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

static ATCA_STATUS get_serial_no(uint8_t *sernum)
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

static void select_device(ATCADeviceType device_type)
{
    ATCA_STATUS status;

    status = set_test_config(device_type);

    if (status == ATCA_SUCCESS)
    {
        printf("Device Selected.\r\n");
    }
    else
    {
        printf("IFace Cfg are NOT available\r\n");
    }
}

static int run_test(void* fptest)
{
    if (gCfg->devtype < ATCA_DEV_UNKNOWN)
    {
        return UnityMain(sizeof(argv) / sizeof(char*), argv, fptest);
    }
    else
    {
        printf("Device is NOT Selected... Select device before running tests!!!");
        return -1;
    }
}

static void run_all_tests(void)
{
    ATCA_STATUS status;
    bool is_config_locked = false;
    bool is_data_locked = false;
    int fails = 0;

    if (gCfg->devtype == ATECC608A)
    {
        check_clock_divider();
    }

    info();
    sernum();
    do_randoms();

    status = is_device_locked(LOCK_ZONE_CONFIG, &is_config_locked);
    if (status != ATCA_SUCCESS)
    {
        printf("is_device_locked() failed with ret=0x%08X\r\n", status);
        return;
    }
    status = is_device_locked(LOCK_ZONE_DATA, &is_data_locked);
    if (status != ATCA_SUCCESS)
    {
        printf("is_device_locked() failed with ret=0x%08X\r\n", status);
        return;
    }

    status = lock_status();
    if (status != ATCA_SUCCESS)
    {
        printf("lock_status() failed with ret=0x%08X\r\n", status);
        return;
    }

#ifndef DO_NOT_TEST_BASIC_UNIT
    if (!is_config_locked)
    {
        fails += run_test(RunAllFeatureTests);
        if (fails > 0)
        {
            printf("unit tests with config zone unlocked failed.\r\n");
            return;
        }

        fails += run_test(RunAllBasicTests);
        if (fails > 0)
        {
            printf("basic tests with config zone unlocked failed.\r\n");
            return;
        }

        status = lock_config_zone();
        if (status != ATCA_SUCCESS)
        {
            printf("lock_config_zone() failed with ret=0x%08X\r\n", status);
            return;
        }
        status = lock_status();
        if (status != ATCA_SUCCESS)
        {
            printf("lock_status() failed with ret=0x%08X\r\n", status);
            return;
        }
    }

    if (!is_data_locked)
    {
        fails += run_test(RunAllFeatureTests);
        if (fails > 0)
        {
            printf("unit tests with data zone unlocked failed.\r\n");
            return;
        }

        fails += run_test(RunAllBasicTests);
        if (fails > 0)
        {
            printf("basic tests with data zone unlocked failed.\r\n");
            return;
        }

        status = lock_data_zone();
        if (status != ATCA_SUCCESS)
        {
            printf("lock_data_zone() failed with ret=0x%08X\r\n", status);
            return;
        }
        status = lock_status();
        if (status != ATCA_SUCCESS)
        {
            printf("lock_status() failed with ret=0x%08X\r\n", status);
            return;
        }
    }

    fails += run_test(RunAllFeatureTests);
    if (fails > 0)
    {
        printf("unit tests with data zone locked failed.\r\n");
        return;
    }

    fails += run_test(RunAllBasicTests);
    if (fails > 0)
    {
        printf("basic tests with data zone locked failed.\r\n");
        return;
    }

    fails = run_test(RunAllHelperTests);
    if (fails > 0)
    {
        printf("util tests failed.\r\n");
        return;
    }
#endif

#ifndef DO_NOT_TEST_SW_CRYPTO
    fails += atca_crypto_sw_tests();
    if (fails > 0)
    {
        printf("crypto tests failed.\r\n");
        return;
    }
#endif

#ifndef DO_NOT_TEST_CERT
    if (atIsECCFamily(gCfg->devtype))
    {
        fails += run_test(RunAllCertIOTests);
        if (fails > 0)
        {
            printf("cio tests failed.\r\n");
            return;
        }
    }
    else
    {
        printf("cio tests don't apply to non-ECC devices.\r\n");
    }

    fails += run_test(RunAllCertDataTests);
    if (fails > 0)
    {
        printf("cd tests failed.\r\n");
        return;
    }
#endif

    printf("All unit tests passed.\r\n");
}

static ATCA_STATUS set_test_config(ATCADeviceType deviceType)
{
    gCfg->devtype = ATCA_DEV_UNKNOWN;
    gCfg->iface_type = ATCA_UNKNOWN_IFACE;

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
#elif defined(ATCA_HAL_CUSTOM)
        *gCfg = g_cfg_atsha204a_custom;
#else
#error "HAL interface is not selected";
#endif
        break;

    case ATECC108A:
#if defined(ATCA_HAL_I2C)
        *gCfg = cfg_ateccx08a_i2c_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_SWI)
        *gCfg = cfg_ateccx08a_swi_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_KIT_HID)
        *gCfg = cfg_ateccx08a_kithid_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_KIT_CDC)
        *gCfg = cfg_ateccx08a_kitcdc_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_CUSTOM)
        *gCfg = g_cfg_atecc108a_custom;
#else
#error "HAL interface is not selected";
#endif
        break;

    case ATECC508A:
#if defined(ATCA_HAL_I2C)
        *gCfg = cfg_ateccx08a_i2c_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_SWI)
        *gCfg = cfg_ateccx08a_swi_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_KIT_HID)
        *gCfg = cfg_ateccx08a_kithid_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_KIT_CDC)
        *gCfg = cfg_ateccx08a_kitcdc_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_CUSTOM)
        *gCfg = g_cfg_atecc508a_custom;
#else
#error "HAL interface is not selected";
#endif
        break;

    case ATECC608A:
#if defined(ATCA_HAL_I2C)
        *gCfg = cfg_ateccx08a_i2c_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_SWI)
        *gCfg = cfg_ateccx08a_swi_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_KIT_HID)
        *gCfg = cfg_ateccx08a_kithid_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_KIT_CDC)
        *gCfg = cfg_ateccx08a_kitcdc_default;
        gCfg->devtype = deviceType;
#elif defined(ATCA_HAL_CUSTOM)
        *gCfg = g_cfg_atecc608a_custom;
#else
#error "HAL interface is not selected";
#endif
        break;

    default:
        //device type wasn't found, return with error
        return ATCA_GEN_FAIL;
    }

    #ifdef ATCA_RASPBERRY_PI_3
    gCfg->atcai2c.bus = 1;
    #endif

    return ATCA_SUCCESS;
}

static ATCA_STATUS set_chip_mode(uint8_t i2c_user_extra_add, uint8_t ttl_enable, uint8_t watchdog, uint8_t clock_divider)
{
    ATCA_STATUS status;
    uint8_t config_word[ATCA_WORD_SIZE];
    bool is_config_locked = false;

    if (gCfg->devtype != ATECC608A)
    {
        printf("Current device doesn't support clock divider settings (only ATECC608A)\r\n");
        return ATCA_GEN_FAIL;
    }

    status = is_device_locked(LOCK_ZONE_CONFIG, &is_config_locked);
    if (status != ATCA_SUCCESS)
    {
        printf("is_device_locked() failed with ret=0x%08X\r\n", status);
        return status;
    }

    if (is_config_locked)
    {
        printf("Current device is config locked. Can't change clock divider. ");
    }

    // Update the actual ATECC608A chip mode so it takes effect immediately
    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return status;
    }

    do
    {
        // Read current config values
        status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, config_word, 4);
        if (status != ATCA_SUCCESS)
        {
            printf("atcab_read_bytes_zone() failed with ret=0x%08X\r\n", status);
            break;
        }

        if (is_config_locked)
        {
            printf("Currently set to 0x%02X.\r\n", (int)(config_word[3] >> 3));
            status = ATCA_GEN_FAIL;
            break;
        }

        // Update ChipMode
        update_chip_mode(&config_word[3], i2c_user_extra_add, ttl_enable, watchdog, clock_divider);

        // Write config values back to chip
        status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, config_word, 4);
        if (status != ATCA_SUCCESS)
        {
            printf("atcab_write_bytes_zone() failed with ret=0x%08X\r\n", status);
            break;
        }

        // Put to sleep so new values take effect
        status = atcab_wakeup();
        if (status != ATCA_SUCCESS)
        {
            printf("atcab_wakeup() failed with ret=0x%08X\r\n", status);
            break;
        }
        status = atcab_sleep();
        if (status != ATCA_SUCCESS)
        {
            printf("atcab_sleep() failed with ret=0x%08X\r\n", status);
            break;
        }

        // Update the ATECC608A test config data so all the unit tests will run with the new chip mode
        update_chip_mode(&test_ecc608_configdata[ATCA_CHIPMODE_OFFSET], i2c_user_extra_add, ttl_enable, watchdog, clock_divider);

    }
    while (0);

    atcab_release();
    return status;
}

static void set_clock_divider_m0(void)
{
    ATCA_STATUS status = set_chip_mode(0xFF, 0xFF, ATCA_CHIPMODE_WATCHDOG_SHORT, ATCA_CHIPMODE_CLOCK_DIV_M0);

    if (status == ATCA_SUCCESS)
    {
        printf("Set device to clock divider M0 (0x%02X) and watchdog to 1.3s nominal.\r\n", ATCA_CHIPMODE_CLOCK_DIV_M0 >> 3);
    }
}

static void set_clock_divider_m1(void)
{
    ATCA_STATUS status = set_chip_mode(0xFF, 0xFF, ATCA_CHIPMODE_WATCHDOG_SHORT, ATCA_CHIPMODE_CLOCK_DIV_M1);

    if (status == ATCA_SUCCESS)
    {
        printf("Set device to clock divider M1 (0x%02X) and watchdog to 1.3s nominal.\r\n", ATCA_CHIPMODE_CLOCK_DIV_M1 >> 3);
    }
}

static void set_clock_divider_m2(void)
{
    // Additionally set watchdog to long settings (~13s) as some commands
    // can't complete in time on the faster watchdog setting.
    ATCA_STATUS status = set_chip_mode(0xFF, 0xFF, ATCA_CHIPMODE_WATCHDOG_LONG, ATCA_CHIPMODE_CLOCK_DIV_M2);

    if (status == ATCA_SUCCESS)
    {
        printf("Set device to clock divider M2 (0x%02X) and watchdog to 13s nominal.\r\n", ATCA_CHIPMODE_CLOCK_DIV_M2 >> 3);
    }
}

static void tng22_tests(void)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return;
    }

    run_test(RunTNG22Tests);

    atcab_release();
}

static void tngtn_tests(void)
{
    ATCA_STATUS status;

    status = atcab_init(gCfg);
    if (status != ATCA_SUCCESS)
    {
        printf("atcab_init() failed with ret=0x%08X\r\n", status);
        return;
    }

    run_test(RunTNGTNTests);

    atcab_release();
}
