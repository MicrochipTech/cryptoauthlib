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
#include "test_atcab.h"

#ifndef TEST_ATCAB_RANDOM_EN
#define TEST_ATCAB_RANDOM_EN            CALIB_RANDOM_EN || TALIB_RANDOM_EN
#endif

#if TEST_ATCAB_RANDOM_EN
TEST_CONDITION(atca_cmd_basic_test, random)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (atcab_is_ca_device(dev_type) && (ATSHA206A != dev_type))
           || atcab_is_ta_device(dev_type)
    ;
}

TEST(atca_cmd_basic_test, random)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t randomnum[32];

    status = atcab_random(randomnum);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info random_basic_test_info[] =
{
#if TEST_ATCAB_RANDOM_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, random), REGISTER_TEST_CONDITION(atca_cmd_basic_test, random) },
#endif
    { (fp_test_case)NULL,                     (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*
