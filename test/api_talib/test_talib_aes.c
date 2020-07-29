
#include "atca_config.h"
#include "cryptoauthlib.h"
#include "atca_test.h"

#if ATCA_TA_SUPPORT

#include "vectors/aes_gcm_nist_vectors.h"


/** \brief  This test cases load an AES key and perform AES-GCM encryption & decryption on Nist Vectors.
 *          .
 */
TEST(atca_cmd_basic_test, talib_aes_gcm_nist_vectors)
{
    ATCA_STATUS status;
    uint8_t test_index;
    uint16_t key_id;
    uint8_t aes_key_block = 0;
    uint8_t ciphertext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint8_t plaintext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint8_t tag[AES_DATA_SIZE];

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    for (test_index = 0; test_index < GCM_TEST_VECTORS_COUNT; test_index++)
    {

        //Skip the test case "Test case 5" as the IV size is small.
        if (test_index == 4)
        {
            continue;
        }

        status = atca_test_config_get_id(TEST_TYPE_AES, &key_id);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Load AES keys into slot
        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_id, 0, gcm_test_cases[test_index].key, 16);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Load the AES key to the engine in device
        status = talib_aes_gcm_keyload(atcab_get_device(), key_id, aes_key_block);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //////////////////////////////////////   Encryption /////////////////////////////////////////

        //Perform the AES-GCM encryption operation
        status = talib_aes_gcm_encrypt(atcab_get_device(), gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext, tag);

        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



        //Verify ciphertext with expected data
        if (gcm_test_cases[test_index].text_size > 0)
        {
            TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].ciphertext, ciphertext, gcm_test_cases[test_index].text_size);
        }

        //Verify calculated tag
        TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].tag, tag, sizeof(tag));


        //////////////////////////////////////   Decryption /////////////////////////////////////////

        //Load the AES key to the engine in device
        status = talib_aes_gcm_keyload(atcab_get_device(), key_id, aes_key_block);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Perform the AES-GCM decryption operation
        status = talib_aes_gcm_decrypt(atcab_get_device(), gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].tag, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext);

        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Verify plaintext with expected data
        if (gcm_test_cases[test_index].text_size > 0)
        {
            TEST_ASSERT_EQUAL_MEMORY(plaintext, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size);
        }

    }
}


/** \brief  This test cases load an AES key & 4 byte IV and perform AES-GCM encryption & decryption for Nist Vector "Test case 4" .
 *          The 4 IV is taken internally from the device and remaining 8 byte is given in the input buffer.
 *
 */
TEST(atca_cmd_basic_test, aes_gcm_test_implicit_iv)
{
    ATCA_STATUS status;
    uint16_t key_id = TA_HANDLE_VOLATILE_REGISTER2;
    uint8_t aes_key_block = 0;
    uint8_t iv_index;
    uint8_t ciphertext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint8_t plaintext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint8_t tag[AES_DATA_SIZE];
    uint8_t test_index = 3;
    uint8_t aes_key_with_iv[32] = { 0 };
    ta_element_attributes_t attr_hmac_symm_handle;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = talib_handle_init_symmetric_key(&attr_hmac_symm_handle, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_MAC);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_hmac_element_with_handle(atcab_get_device(), TA_MAC_COMMAND_HMAC_SIZE, key_id,
                                                   &attr_hmac_symm_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Copying the AES key and 4 byte to the local buffer
    memcpy(aes_key_with_iv, gcm_test_cases[test_index].key, sizeof(gcm_test_cases[test_index].key));
    memcpy(&aes_key_with_iv[16], gcm_test_cases[test_index].iv, 4);
    iv_index = 16;

    // Write AES key + 4 byte iv to the slot
    //Note: For TLS like operation, the output of KDF( AES key + iv)  to a slot is used but for simpicity we are writing to the slot.
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_id, 0, aes_key_with_iv, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Load the AES key and 4 byte iv to the engine in device
    status = talib_aes_gcm_keyload_with_implicit_iv(atcab_get_device(), key_id, aes_key_block, iv_index);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //Perform the AES-GCM encryption operation where the first 4 bytes IV is taken from inside the device and remaining 8 bytes are sent
    status = talib_aes_gcm_encrypt(atcab_get_device(), gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size, &gcm_test_cases[test_index].iv[4], gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext, tag);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Verify ciphertext with expected data
    TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].ciphertext, ciphertext, gcm_test_cases[test_index].text_size);

    //Verify calculated tag
    TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].tag, tag, sizeof(tag));


    //////////////////////////////////////   Decryption /////////////////////////////////////////

    //Load the AES key and 4 byte iv to the engine in device
    status = talib_aes_gcm_keyload_with_implicit_iv(atcab_get_device(), key_id, aes_key_block, iv_index);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Perform the AES-GCM decryption operation
    status = talib_aes_gcm_decrypt(atcab_get_device(), gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size, &gcm_test_cases[test_index].iv[4], gcm_test_cases[test_index].tag, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Verify plaintext with expected data
    TEST_ASSERT_EQUAL_MEMORY(plaintext, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size);

}


/** \brief  This test cases load an AES key and perform AES-GCM encryption & decryption with internally generated IV.
 *          .
 */
TEST(atca_cmd_basic_test, aes_gcm_test_random_iv)
{
    ATCA_STATUS status;
    uint16_t key_id;
    uint8_t aes_key_block = 0;
    uint8_t ciphertext[64];
    uint8_t plaintext[64];
    uint8_t plaintext_out[64];
    uint8_t tag[AES_DATA_SIZE];
    uint8_t aad[20];
    uint8_t iv[12];
    uint8_t aes_key[] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write AES key
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_id, 0, aes_key, sizeof(aes_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Load the AES key
    status = talib_aes_gcm_keyload(atcab_get_device(), key_id, aes_key_block);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Generating random plaintext to be encrypted
    status = talib_random(atcab_get_device(), NULL, plaintext, sizeof(plaintext));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Generating random AAD
    status = talib_random(atcab_get_device(), NULL, aad, sizeof(aad));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Perform the AES-GCM encryption operation with random 12 byte IV generated within device
    status = talib_aes_gcm_encrypt(atcab_get_device(), aad, sizeof(aad), iv, plaintext, sizeof(plaintext), ciphertext, tag);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    //////////////////////////////////////   Decryption /////////////////////////////////////////

    //Load the AES key
    status = talib_aes_gcm_keyload(atcab_get_device(), key_id, aes_key_block);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Perform the AES-GCM decryption operation
    status = talib_aes_gcm_decrypt(atcab_get_device(), aad, sizeof(aad), iv, tag, ciphertext, sizeof(ciphertext), plaintext_out);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Verify plaintext with expected data
    TEST_ASSERT_EQUAL_MEMORY(plaintext, plaintext_out, sizeof(plaintext));

}

t_test_case_info talib_aes_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, talib_aes_gcm_nist_vectors),      DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gcm_test_implicit_iv),        DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gcm_test_random_iv),          DEVICE_MASK(TA100) },
    /* Array Termination element*/
    { (fp_test_case)NULL,                    (uint8_t)0 },
};

t_test_case_info* talib_aes_tests[] = {
    talib_aes_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
