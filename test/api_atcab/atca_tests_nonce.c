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

#ifndef TEST_ATCAB_NONCE_EN
#define TEST_ATCAB_NONCE_EN             CALIB_NONCE_EN
#endif

#if TEST_ATCAB_NONCE_EN

TEST_CONDITION(atca_cmd_basic_test, challenge)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return atcab_is_ca_device(dev_type) && (ATSHA206A != dev_type);
}

TEST(atca_cmd_basic_test, challenge)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t random_number[32];

    if ((SHA104 == gCfg->devtype) || (SHA105 == gCfg->devtype))
    {
        memset(random_number, 0, sizeof(random_number));
    }
    else
    {
    #if CALIB_RANDOM_EN
        status = atcab_random(random_number);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    #endif
    }

    status = atcab_nonce(random_number);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
#endif /* TEST_ATCAB_NONCE_EN */

// *INDENT-OFF* - Preserve formatting
t_test_case_info nonce_basic_test_info[] =
{
#if TEST_ATCAB_NONCE_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, challenge), REGISTER_TEST_CONDITION(atca_cmd_basic_test, challenge) },
#endif
    { (fp_test_case)NULL,                     (uint8_t)0 },/* Array Termination element*/
};

// *INDENT-ON*
