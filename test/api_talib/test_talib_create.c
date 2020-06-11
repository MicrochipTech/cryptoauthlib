/**
 * \file
 * \brief Basic test for Create command api - TA100
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

/** \brief Execute create command to create handle for data element on shared data memory
 */
TEST(atca_cmd_basic_test, create_data_element_handle)
{
    ATCA_STATUS status;
    ta_element_attributes_t attr_data_handle;
    uint16_t data_handle;
    uint8_t write_data[32];
    uint8_t read_data[32];
    uint16_t data_size = sizeof(write_data);

    // Skip test if setup isn't locked
    test_assert_data_is_locked();
    
    status = talib_handle_init_data(&attr_data_handle, data_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_data_handle, &data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_random(write_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_write_element(atcab_get_device(), data_handle, data_size, write_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_read_element(atcab_get_device(), data_handle, &data_size, read_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(write_data, read_data, data_size);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute create command to create handle for private key and public key on shared data memory
 */
TEST(atca_cmd_basic_test, create_priv_pub_handle)
{
    ATCA_STATUS status;
    uint16_t private_key_handle;
    uint16_t public_key_handle;
    ta_element_attributes_t attr_private_key_handle;
    ta_element_attributes_t attr_public_key_handle;
    uint8_t message[TA_SIGN_P256_MSG_SIZE];
    uint8_t signature[TA_SIGN_P256_SIG_SIZE];
    uint8_t pub_key[TA_ECC256_PUB_KEY_SIZE];
    bool is_verified = false;

    status = talib_handle_init_private_key(&attr_private_key_handle, TA_KEY_TYPE_ECCP256, 
                                          TA_ALG_MODE_ECC_ECDSA, TA_PROP_SIGN_INT_EXT_DIGEST,
                                          TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_private_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_init_public_key(&attr_public_key_handle, TA_KEY_TYPE_ECCP256,
                                          TA_ALG_MODE_ECC_ECDSA, TA_PROP_VAL_NO_SECURE_BOOT_SIGN, 
                                          TA_PROP_ROOT_PUB_KEY_VERIFY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_set_permissions(&attr_public_key_handle, TA_PERM_ALWAYS, TA_PERM_ALWAYS,
                                          TA_PERM_NEVER, TA_PERM_ALWAYS);

    status = talib_create_element(atcab_get_device(), &attr_public_key_handle, &public_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_genkey((uint32_t)private_key_handle, pub_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_write_pubkey(public_key_handle, pub_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_random(message);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_sign(private_key_handle, message, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_verify_stored(message, signature, public_key_handle, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)public_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute create command to create hmac handle for hmac symmetric key on shared data memory
 */
TEST(atca_cmd_basic_test, create_hmac_handle)
{
    ATCA_STATUS status;
    uint16_t hmac_handle;
    ta_element_attributes_t attr_hmac_symm_handle;
    uint8_t hmac[ATCA_SHA256_DIGEST_SIZE];
    uint8_t data_input[] = {
        0x6f, 0xb3, 0xec, 0x66, 0xf9, 0xeb, 0x07, 0x0a,
        0x71, 0x9b, 0xeb, 0xbe, 0x70, 0x8b, 0x93, 0xa6,
        0x5b, 0x20, 0x1b, 0x78, 0xe2, 0xd2, 0x6d, 0x8c,
        0xcc, 0xdf, 0x1c, 0x33, 0xf7, 0x41, 0x90, 0x4a,
        0x9a, 0xde, 0x64, 0x0f, 0xce, 0x00, 0x0c, 0x33,
        0x4d, 0x04, 0xbb, 0x30, 0x79, 0x56, 0x83, 0xdc,
        0xa0, 0x9d, 0xbf, 0x3e, 0x7e, 0x32, 0xae, 0xa1,
        0x03, 0xd7, 0x60, 0xe8, 0x57, 0xa6, 0xd6, 0x21,
        0x1c
    };
    const uint8_t hmac_ref[ATCA_SHA256_DIGEST_SIZE] = {
        0x29, 0x7f, 0x22, 0xb8, 0xd2, 0x51, 0xb0, 0x63,
        0xa7, 0xc0, 0x8d, 0xcf, 0x4d, 0xba, 0x0d, 0x1f,
        0xb3, 0x5d, 0x32, 0xa3, 0xba, 0xab, 0x15, 0xac,
        0xea, 0xf4, 0x39, 0x1c, 0x4a, 0xdb, 0x32, 0x77
    };

    // Skip test if setup isn't locked
    test_assert_data_is_locked();

    status = talib_handle_init_symmetric_key(&attr_hmac_symm_handle, TA_KEY_TYPE_HMAC, 
                                             TA_PROP_SYMM_KEY_USAGE_MAC);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_hmac_element(atcab_get_device(), TA_MAC_COMMAND_HMAC_SIZE, &attr_hmac_symm_handle,
                                       &hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_write_element(atcab_get_device(), hmac_handle, TA_MAC_COMMAND_HMAC_SIZE, g_slot4_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Calculating HMAC using the key in hmac_handle
    status = atcab_sha_hmac(data_input, sizeof(data_input), hmac_handle, hmac, SHA_MODE_TARGET_TEMPKEY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(hmac_ref, hmac, ATCA_SHA256_DIGEST_SIZE);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute create command to create symmetric key handle on volatile register
 */
TEST(atca_cmd_basic_test, create_volreg_handle)
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

/** \brief Execute create command to create ephemeral key on volatile register
 */
TEST(atca_cmd_basic_test, create_ephemeral_handle)
{
    ATCA_STATUS status;
    const uint16_t details = TA_CREATE_DETAILS_VOLATILE_DESTINATION | TA_CREATE_DETAILS_HMAC_KEY_LENGTH(32);
    const uint16_t dev_handle = TA_HANDLE_VOLATILE_REGISTER3;
    ta_element_attributes_t attr_dev_priv_key_handle;
    const uint8_t host_pub_key[64] = {
        0x8F, 0x8D, 0x18, 0x2B, 0xD8, 0x19, 0x04, 0x85, 0x82, 0xA9, 0x92, 0x7E, 0xA0, 0xC5, 0x6D, 0xEF,
        0xB4, 0x15, 0x95, 0x48, 0xE1, 0x1C, 0xA5, 0xF7, 0xAB, 0xAC, 0x45, 0xBB, 0xCE, 0x76, 0x81, 0x5B,
        0xE5, 0xC6, 0x4F, 0xCD, 0x2F, 0xD1, 0x26, 0x98, 0x54, 0x4D, 0xE0, 0x37, 0x95, 0x17, 0x26, 0x66,
        0x60, 0x73, 0x04, 0x61, 0x19, 0xAD, 0x5E, 0x11, 0xA9, 0x0A, 0xA4, 0x97, 0x73, 0xAE, 0xAC, 0x86
    };
    uint8_t dev_pub_key[ATCA_ECCP256_PUBKEY_SIZE];

    // Skip test if setup isn't locked
    test_assert_data_is_locked();

    status = talib_handle_init_symmetric_key(&attr_dev_priv_key_handle, TA_KEY_TYPE_HMAC, 
                                             TA_PROP_SYMM_KEY_USAGE_MAC);

    status = talib_create_ephemeral_element_with_handle(atcab_get_device(), details, dev_handle, 
                                                        &attr_dev_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_genkey((uint32_t)dev_handle, dev_pub_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_ecdh_to_handle(atcab_get_device(), dev_handle, dev_handle, host_pub_key, 
                                  sizeof(host_pub_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)dev_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_create_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, create_data_element_handle),  DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, create_priv_pub_handle),      DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, create_hmac_handle),          DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, create_volreg_handle),        DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, create_ephemeral_handle),     DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_create_tests[] = {
    talib_create_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif