/**
 * \file
 * \brief Unity tests for the cryptoauthlib Verify Command
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
#include <stdlib.h>
#include "atca_test.h"
#include "basic/atca_basic.h"
#include "host/atca_host.h"
#include "test/atca_tests.h"
#include "atca_execution.h"

TEST(atca_cmd_unit_test, read)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build read command
    packet.param1 = ATCA_ZONE_CONFIG;
    packet.param2 = 0x0000;

    status = atRead(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x07, packet.data[ATCA_COUNT_IDX]);
}

TEST(atca_cmd_basic_test, read_zone)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t data[32];
    uint8_t serial_prefix[] = { 0x01, 0x23 };
    uint8_t slot, block, offset;
    bool locked = false;

    slot = 0;
    block = 0;
    offset = 0;

    // initialize it with recognizable data
    memset(data, 0x77, sizeof(data));

    // read config zone tests
    status = atcab_read_zone(ATCA_ZONE_CONFIG, slot, block, offset, data, sizeof(data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(serial_prefix, data, 2);

    // read data zone tests
    // data zone cannot be read unless the data zone is locked
    status = atcab_is_locked(LOCK_ZONE_DATA, &locked);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_read_zone(LOCK_ZONE_DATA, slot, block, offset, data, sizeof(data));
    TEST_ASSERT_EQUAL(locked ? ATCA_SUCCESS : ATCA_EXECUTION_ERROR, status);
}


TEST(atca_cmd_basic_test, read_config_zone)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t config_data[ATCA_ECC_CONFIG_SIZE];

    status = atcab_read_config_zone(config_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    switch (gCfg->devtype)
    {
    case ATSHA204A:
        // Compare I2C_Address through LastKeyUse
        TEST_ASSERT_EQUAL_MEMORY(&sha204_default_config[16], &config_data[16], 52 - 16);
        break;

    case ATECC108A:
    case ATECC508A:
        // Compare I2C_Address through SlotConfig
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc_configdata[16], &config_data[16], 52 - 16);

        // Skip Counter[0], Counter[1], LastKeyUse, UserExtra, Selector, LockValue, LockConfig, and SlotLocked
        // which can change during operation

        // Compare RFU through KeyConfig
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc_configdata[90], &config_data[90], 38);
        break;

    case ATECC608A:
        // Compare I2C_Address through SlotConfig
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc608_configdata[16], &config_data[16], 52 - 16);

        // Skip Counter[0], Counter[1], which can change during operation

        // Compare UseLock through Reserved (75-->83)
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc608_configdata[68], &config_data[68], 84 - 68);

        // UserExtra, UserExtraAdd, LockValue, LockConfig, and SlotLockedwhich can change during operation

        // Compare ChipOptions through KeyConfig
        TEST_ASSERT_EQUAL_MEMORY(&test_ecc608_configdata[90], &config_data[90], 38);
        break;

    default:
        break;
    }
}

TEST(atca_cmd_basic_test, read_otp_zone)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t read_data[ATCA_BLOCK_SIZE * 2];

    test_assert_data_is_locked();

    status = atcab_read_bytes_zone(ATCA_ZONE_OTP, 0, 0x00, read_data, sizeof(read_data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}


TEST(atca_cmd_basic_test, read_data_zone)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t read_data[ATCA_BLOCK_SIZE];

    test_assert_data_is_locked();

    status = atcab_read_bytes_zone(ATCA_ZONE_DATA, 11, 0, read_data, sizeof(read_data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info read_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_zone),        DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_config_zone), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_otp_zone),    DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_data_zone),   DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },      /* Array Termination element*/
};

t_test_case_info read_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, read), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

