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

TEST(atca_cmd_unit_test, selftest)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    packet.param1 = SELFTEST_MODE_RNG;
    packet.param2 = 0x0000;
    status = atSelfTest(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(SELFTEST_RSP_SIZE, packet.data[ATCA_COUNT_IDX]);
}

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

// *INDENT-OFF* - Preserve formatting
t_test_case_info selftest_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, selftest_individual), DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, selftest_all),        DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },         /* Array Termination element*/
};

t_test_case_info selftest_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, selftest), DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*


