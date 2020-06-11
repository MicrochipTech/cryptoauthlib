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

TEST(atca_cmd_basic_test, lock_config_zone)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    bool is_locked = false;

    test_assert_config_is_unlocked();

    status = atcab_lock_config_zone();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_is_config_locked(&is_locked);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_locked);
}

TEST(atca_cmd_basic_test, lock_data_zone)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    bool is_locked = false;

    test_assert_config_is_locked();
    test_assert_data_is_unlocked();

    status = atcab_lock_data_zone();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_is_data_locked(&is_locked);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_locked);
}

TEST(atca_cmd_basic_test, lock_data_slot)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    bool is_locked = false;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    // Check the lock status of the slot
    status = atcab_is_slot_locked(13, &is_locked);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    if (is_locked)
    {
        TEST_IGNORE_MESSAGE("Slot locked already.");
    }

    // try to lock slot
    status = atcab_lock_data_slot(13);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Make sure it's now locked
    status = atcab_is_slot_locked(13, &is_locked);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_locked);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info lock_basic_test_info[] =
{
    //{ REGISTER_TEST_CASE(atca_cmd_basic_test, lock_config_zone),	DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    //{ REGISTER_TEST_CASE(atca_cmd_basic_test, lock_data_zone),	DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, lock_data_slot), DEVICE_MASK_ECC },
    { (fp_test_case)NULL,                     (uint8_t)0 },    /* Array Termination element*/
};
// *INDENT-ON*

