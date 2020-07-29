/**
 * \file
 * \brief Unity tests for the cryptoauthlib Verify Command
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
#include <stdlib.h>
#include "atca_test.h"

#if ATCA_CA_SUPPORT
TEST(atca_cmd_basic_test, read_zone)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t data[32];
    uint8_t serial_prefix[] = { 0x01, 0x23 };
    uint16_t slot;
    uint8_t block, offset;
    bool locked = false;

    block = 0;
    offset = 0;

    status = atca_test_config_get_id(TEST_TYPE_DATA, &slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // initialize it with recognizable data
    memset(data, 0x77, sizeof(data));

    // read config zone tests
    status = atcab_read_zone(ATCA_ZONE_CONFIG, slot, block, offset, data, sizeof(data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(serial_prefix, data, 2);

    // read data zone tests
    // data zone cannot be read unless the data zone is locked
    status = atcab_is_data_locked(&locked);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_read_zone(ATCA_ZONE_DATA, slot, block, offset, data, sizeof(data));
    TEST_ASSERT_EQUAL(locked ? ATCA_SUCCESS : ATCA_EXECUTION_ERROR, status);
}
#endif

#ifndef ATCA_ECC_CONFIG_SIZE
#define ATCA_ECC_CONFIG_SIZE    128
#endif

TEST(atca_cmd_basic_test, read_config_zone)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t config_data[ATCA_ECC_CONFIG_SIZE];

    if (TA100 == gCfg->devtype)
    {
        test_assert_data_is_locked();
    }

    status = atcab_read_config_zone(config_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    switch (gCfg->devtype)
    {
#ifdef ATCA_ATSHA204A_SUPPORT
    case ATSHA204A:
        // Compare I2C_Address through LastKeyUse
        TEST_ASSERT_EQUAL_MEMORY(&sha204_default_config[16], &config_data[16], 52 - 16);
        break;
#endif

#if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
    case ATECC108A:
    case ATECC508A:
        // Compare I2C_Address through SlotConfig
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc_configdata[16], &config_data[16], 52 - 16);

        // Skip Counter[0], Counter[1], LastKeyUse, UserExtra, Selector, LockValue, LockConfig, and SlotLocked
        // which can change during operation

        // Compare RFU through KeyConfig
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc_configdata[90], &config_data[90], 38);
        break;
#endif

#ifdef ATCA_ATECC608_SUPPORT
    case ATECC608:
        // Compare I2C_Address through SlotConfig
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc608_configdata[16], &config_data[16], 52 - 16);

        // Skip Counter[0], Counter[1], which can change during operation

        // Compare UseLock through Reserved (75-->83)
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc608_configdata[68], &config_data[68], 84 - 68);

        // UserExtra, UserExtraAdd, LockValue, LockConfig, and SlotLockedwhich can change during operation

        // Compare ChipOptions through KeyConfig
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc608_configdata[90], &config_data[90], 38);
        break;
#endif
    default:
        break;
    }
}

#if ATCA_CA_SUPPORT
TEST(atca_cmd_basic_test, read_otp_zone)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t read_data[ATCA_BLOCK_SIZE * 2];

    test_assert_data_is_locked();

    status = atcab_read_bytes_zone(ATCA_ZONE_OTP, 0, 0x00, read_data, sizeof(read_data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
#endif

#ifndef ATCA_BLOCK_SIZE
#define ATCA_BLOCK_SIZE     (32)
#endif

TEST(atca_cmd_basic_test, read_data_zone)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t read_data[ATCA_BLOCK_SIZE];
    uint16_t slot;

    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_DATA, &slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, 0, read_data, sizeof(read_data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info read_basic_test_info[] =
{
#if ATCA_CA_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_zone),        DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC },
#endif
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_config_zone), DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC | DEVICE_MASK(TA100) },
#if ATCA_CA_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_otp_zone),    DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC },
#endif
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_data_zone),   DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC | DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },      /* Array Termination element*/
};
// *INDENT-ON*

