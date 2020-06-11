/**
 * \file
 * \brief Basic test for Sign command api - TA100
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

/** \brief Execute sign operation using RSA2048 key type and verify it with same.
 */ 
TEST(atca_cmd_basic_test, rsa_key_sign_extern)
{
    ATCA_STATUS status;
    uint16_t private_key_handle;
    ta_element_attributes_t attr_priv_key_handle;
    uint8_t pub_key[TA_KEY_TYPE_RSA2048_SIZE];
    size_t pub_key_len = sizeof(pub_key);
    uint8_t message[32];
    uint8_t signature[TA_KEY_TYPE_RSA2048_SIZE];
    uint16_t sign_size = sizeof(signature);
    bool is_verified = false;

    status = talib_handle_init_private_key(&attr_priv_key_handle, TA_KEY_TYPE_RSA2048, TA_ALG_MODE_RSA_SSA_PSS, 
                                           TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_priv_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)private_key_handle, 
                               pub_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_random(message);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sign_external(atcab_get_device(), TA_KEY_TYPE_RSA2048, private_key_handle, 
                                 TA_HANDLE_INPUT_BUFFER, message, (uint16_t)sizeof(message), signature, 
                                 &sign_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_verify(atcab_get_device(), TA_KEY_TYPE_RSA2048, TA_HANDLE_INPUT_BUFFER, TA_HANDLE_INPUT_BUFFER, 
                          signature, sign_size, message, TA_VERIFY_OTHER_KEY_TYPE_MSG_SIZE, 
                          pub_key, TA_KEY_TYPE_RSA2048_SIZE, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute sign operation using ECCP224 key type and verify it with same.
 */ 
TEST(atca_cmd_basic_test, p224_key_sign_extern)
{
    ATCA_STATUS status;
    uint16_t private_key_handle;
    ta_element_attributes_t attr_priv_key_handle;
    uint8_t pub_key[TA_ECC224_PUB_KEY_SIZE];
    size_t pub_key_len = sizeof(pub_key);
    uint8_t message[TA_SIGN_P224_MSG_SIZE];
    const uint16_t message_len = sizeof(message);
    uint8_t signature[TA_SIGN_P224_SIG_SIZE];
    uint16_t sign_size = sizeof(signature);
    bool is_verified = false;

    status = talib_handle_init_private_key(&attr_priv_key_handle, TA_KEY_TYPE_ECCP224, TA_ALG_MODE_ECC_ECDSA, 
                                           TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_priv_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)private_key_handle, 
                               pub_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, message, message_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sign_external(atcab_get_device(), TA_KEY_TYPE_ECCP224, private_key_handle, 
                                 TA_HANDLE_INPUT_BUFFER, message, (uint16_t)sizeof(message), signature, 
                                 &sign_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_verify(atcab_get_device(), TA_KEY_TYPE_ECCP224, TA_HANDLE_INPUT_BUFFER, TA_HANDLE_INPUT_BUFFER, 
                          signature, sign_size, message, message_len, pub_key, (uint16_t)pub_key_len, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute sign operation using ECCP384 key type and verify it with same.
 */ 
TEST(atca_cmd_basic_test, p384_key_sign_extern)
{
    ATCA_STATUS status;
    uint16_t private_key_handle;
    ta_element_attributes_t attr_priv_key_handle;
    uint8_t pub_key[TA_ECC384_PUB_KEY_SIZE];
    size_t pub_key_len = sizeof(pub_key);
    uint8_t message[TA_SIGN_P384_MSG_SIZE];
    const uint16_t message_len = sizeof(message);
    uint8_t signature[TA_SIGN_P384_SIG_SIZE];
    uint16_t sign_size = sizeof(signature);
    bool is_verified = false;

    status = talib_handle_init_private_key(&attr_priv_key_handle, TA_KEY_TYPE_ECCP384, TA_ALG_MODE_ECC_ECDSA, 
                                           TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_priv_key_handle, 
                                 &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)private_key_handle, 
                               pub_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, message, message_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sign_external(atcab_get_device(), TA_KEY_TYPE_ECCP384, private_key_handle, 
                                 TA_HANDLE_INPUT_BUFFER, message, (uint16_t)sizeof(message), signature, 
                                 &sign_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_verify(atcab_get_device(), TA_KEY_TYPE_ECCP384, TA_HANDLE_INPUT_BUFFER, 
                          TA_HANDLE_INPUT_BUFFER, signature, sign_size, message, message_len, 
                          pub_key, (uint16_t)pub_key_len, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_sign_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, rsa_key_sign_extern),         DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, p224_key_sign_extern),        DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, p384_key_sign_extern),        DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_sign_tests[] = {
    talib_sign_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
