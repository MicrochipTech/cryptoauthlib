/**
 * \file
 * \brief Basic test for Key_Gen command api - TA100
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

/** \brief Execute key gen command to generate symmetric key to do aes encrypt and decrypt.
 */ 
TEST(atca_cmd_basic_test, genkey_symmetric_key)
{
    ATCA_STATUS status;
    ta_element_attributes_t attr_aes_handle;
    const uint16_t aes_handle = TA_HANDLE_VOLATILE_REGISTER2;
    const uint8_t plain_text[ATCA_AES128_BLOCK_SIZE] = { 0x1A, 0x3A, 0xA5, 0x45, 0x04, 0x94, 0x53, 0xAF,
                                                         0xDF, 0x17, 0xE9, 0x89, 0xA4, 0x1F, 0xA0, 0x97, };
    uint8_t cipher_text[ATCA_AES128_BLOCK_SIZE];
    uint8_t plain_text_out[ATCA_AES128_BLOCK_SIZE];

    // Skip test if setup isn't locked
    test_assert_data_is_locked();

    status = talib_handle_init_symmetric_key(&attr_aes_handle, TA_KEY_TYPE_AES128, TA_PROP_SYMM_KEY_USAGE_ANY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_hmac_element_with_handle(atcab_get_device(), TA_KEY_TYPE_AES128_SIZE, aes_handle, 
                                                   &attr_aes_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_genkey_symmetric_key(atcab_get_device(), (uint32_t)aes_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_encrypt(aes_handle, 0, plain_text, cipher_text);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_decrypt(aes_handle, 0, cipher_text, plain_text_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(plain_text_out, plain_text, ATCA_AES128_BLOCK_SIZE);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)aes_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute key gen command to generate RSA2048 key.
 */ 
TEST(atca_cmd_basic_test, genkey_rsa_key)
{
    ATCA_STATUS status;
    uint16_t private_key_handle;
    ta_element_attributes_t attr_priv_key_handle;
    uint8_t pub_key[TA_KEY_TYPE_RSA2048_SIZE];
    size_t pub_key_len = sizeof(pub_key);
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };

    status = talib_handle_init_private_key(&attr_priv_key_handle, TA_KEY_TYPE_RSA2048, TA_ALG_MODE_RSA_SSA_PSS, 
                                           TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_priv_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_genkey(atcab_get_device(), (uint32_t)private_key_handle, pub_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // spot check public key for bogus data, there should be none
    // pub key is random so can't check the full content anyway.
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pub_key, frag, 4));

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute key gen command to generate ECCP224 key.
 */ 
TEST(atca_cmd_basic_test, genkey_p224_key)
{
    ATCA_STATUS status;
    uint16_t private_key_handle;
    ta_element_attributes_t attr_priv_key_handle;
    uint8_t pub_key[TA_ECC224_PUB_KEY_SIZE];
    size_t pub_key_len = sizeof(pub_key);
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };

    status = talib_handle_init_private_key(&attr_priv_key_handle, TA_KEY_TYPE_ECCP224, TA_ALG_MODE_ECC_ECDSA, 
                                           TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_priv_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_genkey(atcab_get_device(), (uint32_t)private_key_handle, pub_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // spot check public key for bogus data, there should be none
    // pub key is random so can't check the full content anyway.
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pub_key, frag, 4));

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute key gen command to generate ECCP384 key.
 */ 
TEST(atca_cmd_basic_test, genkey_p384_key)
{
    ATCA_STATUS status;
    uint16_t private_key_handle;
    ta_element_attributes_t attr_priv_key_handle;
    uint8_t pub_key[TA_ECC384_PUB_KEY_SIZE];
    size_t pub_key_len = sizeof(pub_key);
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };

    status = talib_handle_init_private_key(&attr_priv_key_handle, TA_KEY_TYPE_ECCP384, TA_ALG_MODE_ECC_ECDSA, 
                                           TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_priv_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_genkey(atcab_get_device(), (uint32_t)private_key_handle, pub_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // spot check public key for bogus data, there should be none
    // pub key is random so can't check the full content anyway.
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pub_key, frag, 4));

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute key gen command to generate public key for existing private key.
 */
TEST(atca_cmd_basic_test, get_p224_pubkey)
{
    ATCA_STATUS status;
    uint16_t private_key_handle;
    ta_element_attributes_t attr_priv_key_handle;
    uint8_t pub_key[TA_ECC224_PUB_KEY_SIZE];
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };
    size_t pub_key_len = sizeof(pub_key);

    status = talib_handle_init_private_key(&attr_priv_key_handle, TA_KEY_TYPE_ECCP224, TA_ALG_MODE_ECC_ECDSA, 
                                           TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_priv_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_genkey(atcab_get_device(), (uint32_t)private_key_handle, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_get_pubkey(atcab_get_device(), private_key_handle, pub_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // spot check public key for bogus data, there should be none
    // pub key is random so can't check the full content anyway.
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pub_key, frag, 4));

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_genkey_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, genkey_symmetric_key),     DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, genkey_rsa_key),           DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, genkey_p224_key),          DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, genkey_p384_key),          DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, get_p224_pubkey),          DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_genkey_tests[] = {
    talib_genkey_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
