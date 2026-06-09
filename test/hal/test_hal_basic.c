/**
 * \file
 * \brief Hal functionality Tests for ECC and TrustAnchor Devices
 *
 * \copyright (c) 2015-2026 Microchip Technology Inc. and its subsidiaries.
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
#include "test_hal.h"

#ifndef TEST_HAL_RANDOM_EN
#define TEST_HAL_RANDOM_EN            CALIB_RANDOM_EN || TALIB_RANDOM_EN
#endif

TEST_SETUP(hal_basic_tests)
{
    /* Common Setup */
    TEST_hal_SETUP();
}

TEST_TEAR_DOWN(hal_basic_tests)
{
    /* Common Cleanup */
    TEST_hal_TEAR_DOWN();
}

TEST_CONDITION(hal, hal_test_condn)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (atcab_is_ca_device(dev_type)
           || atcab_is_ca2_device(dev_type)
           || atcab_is_ta_device(dev_type));
}

/** \brief This test case gets revision number from the device
 */
TEST(hal, read_info)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t revision[4];

    status = atcab_info(revision);
    TEST_ASSERT_SUCCESS(status);
}

/** \brief This test case gets serial number from the device
 */
TEST(hal, read_serial_number)
{
    ATCA_STATUS status;
    uint8_t serialnum[9];

    status = atcab_read_serial_number(serialnum);
    TEST_ASSERT_SUCCESS(status);
}

#if TEST_HAL_RANDOM_EN
TEST_CONDITION(hal, random)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (atcab_is_ca_device(dev_type) && (ATSHA206A != dev_type))
           || atcab_is_ta_device(dev_type)
    ;
}

/** \brief This test case generates random number from the device
 */
TEST(hal, random)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t randomnum[32];

    status = atcab_random(randomnum);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
#endif


/** \brief This test case checks whether data written is same when read for CA or TA devices
 */
TEST(hal, single_part_write_read)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t write_data[64];
    uint8_t read_data[sizeof(write_data)];
    uint16_t slot;

    /* Note - This test assumes ECC slot sizes */
    if (atcab_is_ca2_device(gCfg->devtype))
    {
        /* This test for the ECC204 needs to be run when the device data is unlocked
           Config Subzone 0 and 1 should be locked */
        test_assert_config_is_locked();
        test_assert_data_is_unlocked();
    }
    else
    {
        /* For all other devices it has to be run when data zone is locked */
        test_assert_data_is_locked();
    }

    status = atca_test_config_get_id(TEST_TYPE_DATA, &slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (!atcab_is_ca2_device(gCfg->devtype))
    {
#if CALIB_RANDOM_EN
        // Generate random data to be written
        status = atcab_random(&write_data[0]);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcab_random(&write_data[ATCA_BLOCK_SIZE]);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
    }
    else
    {
        memset(write_data, 0x5A, sizeof(write_data));
    }

    // Test cross-block writes
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, 4, write_data, sizeof(write_data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (!atcab_is_ca2_device(gCfg->devtype))
    {
        status = atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, 4, read_data, sizeof(read_data));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    }
    else
    {
        status = atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, 128, read_data, sizeof(read_data));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    }

    TEST_ASSERT_EQUAL_MEMORY(write_data, read_data, sizeof(write_data));
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info hal_basic_tests[] =
{
    { REGISTER_TEST_CASE(hal, read_info),                            REGISTER_TEST_CONDITION(hal, hal_test_condn) },
    { REGISTER_TEST_CASE(hal, read_serial_number),                   REGISTER_TEST_CONDITION(hal, hal_test_condn) },
#if TEST_HAL_RANDOM_EN
    { REGISTER_TEST_CASE(hal, random),                               REGISTER_TEST_CONDITION(hal, random) },
#endif
    { REGISTER_TEST_CASE(hal, single_part_write_read),               REGISTER_TEST_CONDITION(hal, hal_test_condn) },
    /* Array Termination element*/
    { (fp_test_case)NULL, NULL },
};
// *INDENT-OFF*

