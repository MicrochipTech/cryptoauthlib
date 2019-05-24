/**
 * \file
 * \brief Unity tests for the cryptoauthlib OTP zone
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

TEST(atca_cmd_unit_test, otp_zero)
{
    /* Not applicable... Leaving it as place holder */
}

TEST(atca_cmd_basic_test, otp_zero)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t config_chunk[4];
    uint8_t zero_otp[ATCA_OTP_SIZE];
    uint8_t read_otp[ATCA_OTP_SIZE];
    int i;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    // Make sure OTP is in consumption mode
    status = atcab_read_zone(ATCA_ZONE_CONFIG, 0, 0, 4, config_chunk, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    if (config_chunk[2] != 0x55)
    {
        TEST_IGNORE_MESSAGE("OTPMode must be consumption (0x55) for this test.");
    }

    // Read current state of OTP
    status = atcab_read_bytes_zone(ATCA_ZONE_OTP, 0, 0, read_otp, sizeof(read_otp));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Make sure we still have some bits we can change to 0
    for (i = 0; i < (int)sizeof(read_otp); i++)
    {
        if (read_otp[i] != 0)
        {
            break;
        }
    }
    if (i >= (int)sizeof(read_otp))
    {
        TEST_IGNORE_MESSAGE("OTP is already set to all zeros, can't test.");
    }

    // Zero OTP
    memset(zero_otp, 0, sizeof(zero_otp));
    status = atcab_write_bytes_zone(ATCA_ZONE_OTP, 0, 0, zero_otp, sizeof(zero_otp));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read current state of OTP
    status = atcab_read_bytes_zone(ATCA_ZONE_OTP, 0, 0, read_otp, sizeof(read_otp));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(zero_otp, read_otp, sizeof(zero_otp));
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info otpzero_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, otp_zero), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*


