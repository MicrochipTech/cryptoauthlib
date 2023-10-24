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

#ifndef TEST_ATCAB_SELFEST_EN
#define TEST_ATCAB_SELFTEST_EN      CALIB_SELFTEST_EN
#endif

#if TEST_ATCAB_SELFTEST_EN

TEST(atca_cmd_basic_test, selftest_individual)
{
    ATCA_STATUS status;
    uint8_t result = 0;

    status = atcab_selftest(SELFTEST_MODE_RNG, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, result);

    status = atcab_selftest(SELFTEST_MODE_ECDSA_SIGN_VERIFY, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, result);

    status = atcab_selftest(SELFTEST_MODE_ECDH, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, result);

    status = atcab_selftest(SELFTEST_MODE_AES, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, result);

    status = atcab_selftest(SELFTEST_MODE_SHA, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, result);
}

TEST(atca_cmd_basic_test, selftest_all)
{
    ATCA_STATUS status;
    uint8_t result = 0;

    status = atcab_selftest(SELFTEST_MODE_ALL, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, result);
}

TEST_CONDITION(atca_cmd_basic_test, selftest_ecc204_ta010)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ECC204 == dev_type)
           || (TA010 == dev_type);
}

TEST(atca_cmd_basic_test, selftest_ecc204_ta010)
{
    ATCA_STATUS status;
    uint8_t result = 0;

    status = atcab_selftest(SELFTEST_MODE_RNG, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, (result & 0x01));

    status = atcab_selftest(SELFTEST_MODE_ECDSA_SIGN_VERIFY, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, (result & 0x02));

    status = atcab_selftest(SELFTEST_MODE_SHA, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, (result & 0x20));
}

TEST_CONDITION(atca_cmd_basic_test, selftest_sha10x)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (SHA104 == dev_type)
           || (SHA105 == dev_type);
}

TEST(atca_cmd_basic_test, selftest_sha10x)
{
    ATCA_STATUS status;
    uint8_t result = 0;

    status = atcab_selftest(SELFTEST_MODE_RNG, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, (result & 0x01));

    status = atcab_selftest(SELFTEST_MODE_SHA, 0, &result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, (result & 0x20));
}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info selftest_basic_test_info[] =
{
#if TEST_ATCAB_SELFTEST_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, selftest_individual),     atca_test_cond_ecc608 },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, selftest_all),            atca_test_cond_ecc608 },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, selftest_ecc204_ta010),   REGISTER_TEST_CONDITION(atca_cmd_basic_test, selftest_ecc204_ta010) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, selftest_sha10x),         REGISTER_TEST_CONDITION(atca_cmd_basic_test, selftest_sha10x) },
#endif
    { (fp_test_case)NULL, NULL },         /* Array Termination element*/
};
// *INDENT-ON*
