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

/** \brief The test case sign the internally generated message and verify it
 *
*/
TEST(atca_cmd_basic_test, ta_sign_internal)
{
    ATCA_STATUS status;
    ta_element_attributes_t attr_private_key_handle;
    uint8_t template_attributes[TA_HANDLE_INFO_SIZE];
    uint8_t target_attributes[TA_HANDLE_INFO_SIZE];
    uint16_t template_handle;
    uint16_t data_handle;
    uint16_t target_priv_handle;
    uint16_t private_key_handle;
    uint32_t counter_value;
    uint8_t data[72];
    uint16_t data_size = sizeof(data);
    uint8_t dedicated_memory[TA_DEDICATED_MEMORY_SIZE];
    uint8_t target_pubkey[TA_ECC256_PUB_KEY_SIZE];
    uint8_t verify_pub_key[TA_ECC256_PUB_KEY_SIZE];
    const char test_template_text[] = "CAL Sign Internal Test";
    uint8_t message[194] = { 0 };
    uint8_t digest[TA_SHA256_DIGEST_SIZE];
    uint8_t signature[TA_SIGN_P256_SIG_SIZE];
    uint16_t sign_size = sizeof(signature);
    bool is_verified = false;
    uint8_t is_valid = false;
    uint16_t msg_index = 0;

    // Get the template data handle, which will be created during config
    status = atca_test_config_get_id(TEST_TYPE_TEMPLATE_DATA, &template_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Check the template data handle is being created
    status = talib_is_handle_valid(atcab_get_device(), template_handle, &is_valid);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (!is_valid)
    {
        TEST_IGNORE_MESSAGE("Ignoring the test as template handle is not created, do config before running this test");
    }


    // Get data handle and target handle
    status = atca_test_config_get_id(TEST_TYPE_DATA, &data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atca_test_config_get_id(TEST_TYPE_ECC_SIGN, &target_priv_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // Get the known data to form internal message on host before do sign operation
    // 1. target public key
    // 2. get dedicated memory which consists of serial number and group number
    // 3. data from data handle
    // 4. target private key attributes
    // 5. template attributes
    // 6. counter value
    // Generate public key from target private key handle
    status = talib_get_pubkey_compat(atcab_get_device(), target_priv_handle, target_pubkey);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_info_get_dedicated_memory(atcab_get_device(), dedicated_memory);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, data, data_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_write_element(atcab_get_device(), data_handle, data_size, data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_info_get_handle_info(atcab_get_device(), target_priv_handle, target_attributes);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_info_get_handle_info(atcab_get_device(), template_handle, template_attributes);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_counter_read(atcab_get_device(), TA_HANDLE_COUNTER1, &counter_value);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // Create private key handle which sign internal message and set req attributes
    status = talib_handle_init_private_key(&attr_private_key_handle, TA_KEY_TYPE_ECCP256,
                                          TA_ALG_MODE_ECC_ECDSA, TA_PROP_SIGN_ONLY_INT_DIGEST,
                                          TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    attr_private_key_handle.byte7_settings |= 0x01; // link counter1 to priv key handle

    status = talib_create_element(atcab_get_device(), &attr_private_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // Generate private key to sign
    status = atcab_genkey(private_key_handle, verify_pub_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // Sign the internally generated message
    status = talib_sign_internal(atcab_get_device(), TA_SIGN_MODE_INTERNAL_MSG, private_key_handle,
                                 template_handle, target_priv_handle, signature, &sign_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // Form internal message and calculate SHA256 digest of it
    memcpy(&message[msg_index], test_template_text, strlen(test_template_text));
    msg_index += strlen(test_template_text);

    memcpy(&message[msg_index], target_pubkey, sizeof(target_pubkey));
    msg_index += sizeof(target_pubkey);

    memcpy(&message[msg_index], dedicated_memory, 10);
    msg_index += 10;

    memcpy(&message[msg_index], data, sizeof(data));
    msg_index += sizeof(data);

    memcpy(&message[msg_index], target_attributes, TA_HANDLE_INFO_SIZE);
    msg_index += TA_HANDLE_INFO_SIZE;

    memcpy(&message[msg_index], template_attributes, TA_HANDLE_INFO_SIZE);
    msg_index += TA_HANDLE_INFO_SIZE;

    counter_value += 1;
    counter_value = ATCA_UINT32_BE_TO_HOST(counter_value);
    memcpy(&message[msg_index], (uint8_t*)&counter_value, sizeof(counter_value));
    msg_index += sizeof(counter_value);

    memcpy(&message[msg_index], (uint8_t*)&counter_value, sizeof(counter_value));
    msg_index += sizeof(counter_value);

    status = talib_sha(atcab_get_device(), msg_index, message, digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);




    // Verify the signature with public key (corresponding to sign private key)
    status = atcab_verify_extern(digest, signature, verify_pub_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);


    // delete handle
    status = talib_delete_handle(atcab_get_device(), private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_sign_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, rsa_key_sign_extern),         DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, p224_key_sign_extern),        DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, p384_key_sign_extern),        DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ta_sign_internal),            DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_sign_tests[] = {
    talib_sign_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
