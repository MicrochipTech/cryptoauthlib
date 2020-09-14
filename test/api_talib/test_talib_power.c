/**
 * \file
 * \brief Basic test for Power command api - TA100
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
#include "test_talib.h"

#if ATCA_TA_SUPPORT

/** \brief The function put the device in sleep mode
 */
TEST(atca_cmd_basic_test, power_sleep)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

    status = talib_power_sleep(atcab_get_device());

    // wait for the device to enter into sleep mode
    atca_delay_ms(2);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief The function reboot the device
 */
TEST(atca_cmd_basic_test, power_reboot)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t check_config_soft_reboot_enable;
    uint16_t config_size = sizeof(check_config_soft_reboot_enable);

    // skip if config is not locked
    test_assert_config_is_locked();

    // skip if setup is not locked
    test_assert_data_is_locked();

    // Read the soft reboot configuration byte
    status = talib_read_partial_element(atcab_get_device(), TA_HANDLE_CONFIG_MEMORY, 29, &config_size,
                                        &check_config_soft_reboot_enable);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (check_config_soft_reboot_enable & TA_POWER_SOFT_REBOOT_CONFIG)
    {
        status = talib_power_reboot(atcab_get_device());

        // Wait for the device to reboot
        atca_delay_ms(7);

        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    }
    else
    {

        TEST_IGNORE_MESSAGE("Ignoring the test as soft reboot is not enabled in configuration");

    }
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_power_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, power_sleep),             DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, power_reboot),            DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_power_tests[] = {
    talib_power_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif