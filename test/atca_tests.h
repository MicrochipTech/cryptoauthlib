/**
 * \file
 * \brief Unity tests for the cryptoauthlib Basic API
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */

#ifndef ATCA_BASIC_TESTS_INC_H_
#define ATCA_BASIC_TESTS_INC_H_

TEST_GROUP(atca_cmd_basic_test);
TEST_SETUP(atca_cmd_basic_test)
{
    ATCA_STATUS status = atcab_init(gCfg);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
TEST_TEAR_DOWN(atca_cmd_basic_test)
{
    ATCA_STATUS status;

    status = atcab_wakeup();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_sleep();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_release();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST_GROUP(atca_cmd_unit_test);
TEST_SETUP(atca_cmd_unit_test)
{

    test_assert_interface_init();

}
TEST_TEAR_DOWN(atca_cmd_unit_test)
{

    test_assert_interface_deinit();
}

#endif /* ATCA_BASIC_TESTS_INC_H_ */