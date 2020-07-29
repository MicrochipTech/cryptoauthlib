/**
 * \file
 * \brief  Cryptoauthlib Testing: Device Specific Utilities for ATECC608
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

#include "atca_test.h"

#ifdef ATCA_ATECC608_SUPPORT

void update_chip_mode(uint8_t* chip_mode, uint8_t i2c_user_extra_add, uint8_t ttl_enable, uint8_t watchdog, uint8_t clock_divider)
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

ATCA_STATUS check_clock_divider(int argc, char* argv[])
{
    ATCA_STATUS status;
    uint8_t chip_mode = 0;

    if (!(ATECC608 == gCfg->devtype))
    {
        printf("Current device doesn't support clock divider settings (only ATECC608)\r\n");
        return ATCA_GEN_FAIL;
    }

    // Update the actual ATECC608 chip mode so it takes effect immediately
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

        // Update the ATECC608 test config data so all the unit tests will run with the new chip mode
        update_chip_mode(&test_ecc608_configdata[ATCA_CHIPMODE_OFFSET], 0xFF, 0xFF, chip_mode & ATCA_CHIPMODE_WATCHDOG_MASK, chip_mode & ATCA_CHIPMODE_CLOCK_DIV_MASK);

    }
    while (0);

    atcab_release();
    return status;
}


ATCA_STATUS set_chip_mode(uint8_t i2c_user_extra_add, uint8_t ttl_enable, uint8_t watchdog, uint8_t clock_divider)
{
    ATCA_STATUS status;
    uint8_t config_word[ATCA_WORD_SIZE];
    bool config_locked = false;

    if (!(ATECC608 == gCfg->devtype))
    {
        printf("Current device doesn't support clock divider settings (only ATECC608)\r\n");
        return ATCA_GEN_FAIL;
    }

    status = is_config_locked(&config_locked);
    if (status != ATCA_SUCCESS)
    {
        printf("is_device_locked() failed with ret=0x%08X\r\n", status);
        return status;
    }

    if (config_locked)
    {
        printf("Current device is config locked. Can't change clock divider. ");
    }

    // Update the actual ATECC608 chip mode so it takes effect immediately
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

        if (config_locked)
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

        // Update the ATECC608 test config data so all the unit tests will run with the new chip mode
        update_chip_mode(&test_ecc608_configdata[ATCA_CHIPMODE_OFFSET], i2c_user_extra_add, ttl_enable, watchdog, clock_divider);

    }
    while (0);

    atcab_release();
    return status;
}

int set_clock_divider_m0(int argc, char* argv[])
{
    ATCA_STATUS status = set_chip_mode(0xFF, 0xFF, ATCA_CHIPMODE_WATCHDOG_SHORT, ATCA_CHIPMODE_CLOCK_DIV_M0);

    if (status == ATCA_SUCCESS)
    {
        printf("Set device to clock divider M0 (0x%02X) and watchdog to 1.3s nominal.\r\n", ATCA_CHIPMODE_CLOCK_DIV_M0 >> 3);
    }
    return status;
}

int set_clock_divider_m1(int argc, char* argv[])
{
    ATCA_STATUS status = set_chip_mode(0xFF, 0xFF, ATCA_CHIPMODE_WATCHDOG_SHORT, ATCA_CHIPMODE_CLOCK_DIV_M1);

    if (status == ATCA_SUCCESS)
    {
        printf("Set device to clock divider M1 (0x%02X) and watchdog to 1.3s nominal.\r\n", ATCA_CHIPMODE_CLOCK_DIV_M1 >> 3);
    }
    return status;
}

int set_clock_divider_m2(int argc, char* argv[])
{
    // Additionally set watchdog to long settings (~13s) as some commands
    // can't complete in time on the faster watchdog setting.
    ATCA_STATUS status = set_chip_mode(0xFF, 0xFF, ATCA_CHIPMODE_WATCHDOG_LONG, ATCA_CHIPMODE_CLOCK_DIV_M2);

    if (status == ATCA_SUCCESS)
    {
        printf("Set device to clock divider M2 (0x%02X) and watchdog to 13s nominal.\r\n", ATCA_CHIPMODE_CLOCK_DIV_M2 >> 3);
    }
    return status;
}

#endif
