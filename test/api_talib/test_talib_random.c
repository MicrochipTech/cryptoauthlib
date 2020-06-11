/**
 * \file
 * \brief Basic test for Random command api - TA100
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

#ifndef RANDOM_RSP_SIZE
#define RANDOM_RSP_SIZE             (32)
#endif

/** \brief  This test cases generate 256bytes random data using random command.
 *          .
 */
TEST(atca_cmd_basic_test, random_256bytes)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t random[256];

    status = talib_random(atcab_get_device(), NULL, random, (uint16_t)sizeof(random));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief  This test cases generate random data using stir data as input.
 *          .
 */
TEST(atca_cmd_basic_test, random_with_stir_data)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t stir_data[TA_RANDOM_STIR_DATA_LENGTH] = { 0x1A, 0x3A, 0xA5, 0x45, 0x04, 0x94, 0x53, 0xAF,
                                                      0xDF, 0x17, 0xE9, 0x89, 0xA4, 0x1F, 0xA0, 0x97, };
    uint8_t random[RANDOM_RSP_SIZE];

    status = talib_random(atcab_get_device(), stir_data, random, RANDOM_RSP_SIZE);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_random_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, random_256bytes),            DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, random_with_stir_data),      DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_random_tests[] = {
    talib_random_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
