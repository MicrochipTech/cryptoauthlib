/**
 * \file
 * \brief Tests for host side software crypto methods
 *
 * \copyright (c) 2020-2025 Microchip Technology Inc. and its subsidiaries.
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
//Run the tests when either of OpenSSL/MbedTLS/WolfSSL is enabled
#if ATCA_HOSTLIB_EN
#include "atcacert/atcacert_host_sw.h"
#include "atca_basic.h"
#include <string.h>

TEST_GROUP(atcacert_host_sw);

TEST_SETUP(atcacert_host_sw)
{
    int ret = atcab_init(gCfg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
}

TEST_TEAR_DOWN(atcacert_host_sw)
{
    ATCA_STATUS status;

    status = atcab_wakeup();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_sleep();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_release();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

#if ATCAC_VERIFY_EN
TEST(atcacert_host_sw, test_atcacert_verify_response_sw_success)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    /* Created a SHA2-256 message digest for "Hello World!" */
    uint8_t msg[ATCA_SHA256_DIGEST_SIZE] = {
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53,
        0xb9, 0x2d, 0xc1, 0x81, 0x48, 0xa1, 0xd6, 0x5d,
        0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69 }; 
    cal_buffer msg_buf = CAL_BUF_INIT(sizeof(msg), msg);
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    cal_buffer pubkey_buf = CAL_BUF_INIT(sizeof(public_key), public_key);
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    cal_buffer sig_buf = CAL_BUF_INIT(sizeof(signature), signature);
    uint16_t private_key_id = 0;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_ECC_SIGN, &private_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Load the public key */
    if ((true == atcab_is_ca_device(gCfg->devtype)) || (true == atcab_is_ca2_device(gCfg->devtype)))
    {
#if ATCA_CA_SUPPORT
        status = atcab_get_pubkey(private_key_id, public_key);
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        status = talib_get_pubkey(atcab_get_device(), private_key_id, &pubkey_buf);
#endif
    }
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Sign message */
    if ((true == atcab_is_ca_device(gCfg->devtype)) || (true == atcab_is_ca2_device(gCfg->devtype)))
    {
#if ATCA_CA_SUPPORT
        status = atcab_sign(private_key_id, msg, signature);
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        status = talib_sign_external(atcab_get_device(), TA_KEY_TYPE_ECCP256, private_key_id, TA_HANDLE_INPUT_BUFFER, &msg_buf, &sig_buf);
#endif
    }
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcacert_verify_response_sw(&pubkey_buf, &msg_buf, &sig_buf);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}    

TEST(atcacert_host_sw, test_atcacert_verify_response_sw_null_buf)
{
    ATCA_STATUS status;
    uint8_t device_public_key[64] = { 0 };
    cal_buffer pubkey_buf = CAL_BUF_INIT(sizeof(device_public_key), device_public_key);
    uint8_t challenge[32] = { 0 };
    cal_buffer challenge_buf = CAL_BUF_INIT(sizeof(challenge), challenge);
    uint8_t response[64] = { 0 };
    cal_buffer response_buf = CAL_BUF_INIT(sizeof(response), response);
    
    status = atcacert_verify_response_sw(NULL, &challenge_buf, &response_buf);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, status);

    status = atcacert_verify_response_sw(&pubkey_buf, NULL, &response_buf);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, status);

    status = atcacert_verify_response_sw(&pubkey_buf, &challenge_buf, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, status);

}
#endif /* ATCAC_VERIFY_EN */

#if ATCAC_RANDOM_EN
TEST(atcacert_host_sw, test_atcacert_gen_challenge_sw_null_challenge)
{
    ATCA_STATUS status;
    status = atcacert_gen_challenge_sw(NULL);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
}

TEST(atcacert_host_sw, test_atcacert_gen_challenge_sw_success)
{
    uint8_t challenge[32];
    cal_buffer challenge_buf = CAL_BUF_INIT(sizeof(challenge), challenge);
    ATCA_STATUS status;
    status = atcacert_gen_challenge_sw(&challenge_buf);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
#endif /* ATCAC_RANDOM_EN */
#endif /* ATCA_HOSTLIB_EN */

t_test_case_info atcacert_host_sw_tests[] =
{
#if ATCA_HOSTLIB_EN
#if ATCAC_VERIFY_EN
    { REGISTER_TEST_CASE(atcacert_host_sw, test_atcacert_verify_response_sw_success),      NULL },
    { REGISTER_TEST_CASE(atcacert_host_sw, test_atcacert_verify_response_sw_null_buf),     NULL },   
#endif
#if ATCAC_RANDOM_EN
    { REGISTER_TEST_CASE(atcacert_host_sw, test_atcacert_gen_challenge_sw_null_challenge), NULL },
    { REGISTER_TEST_CASE(atcacert_host_sw, test_atcacert_gen_challenge_sw_success),        NULL },
#endif
#endif
    /* Array Termination element*/
    { (fp_test_case)NULL, NULL },
};
