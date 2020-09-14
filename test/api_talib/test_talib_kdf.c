
#include "atca_config.h"
#include "cryptoauthlib.h"
#include "atca_test.h"

#if ATCA_TA_SUPPORT

// Test case 1 in https://tools.ietf.org/html/rfc5869.html
static const uint8_t hkdf_ikm[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const uint8_t hkdf_salt[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c
};
static const uint8_t hkdf_info[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
};
static const uint8_t hkdf_okm[] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64,
    0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
    0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
};


//https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Component-Testing#KDF135
static const uint8_t prf_key[] = {
    0x20, 0x2c, 0x88, 0xc0, 0x0f, 0x84, 0xa1, 0x7a, 0x20, 0x02, 0x70, 0x79,
    0x60, 0x47, 0x87, 0x46, 0x11, 0x76, 0x45, 0x55, 0x39, 0xe7, 0x05, 0xbe,
    0x73, 0x08, 0x90, 0x60, 0x2c, 0x28, 0x9a, 0x50, 0x01, 0xe3, 0x4e, 0xeb,
    0x3a, 0x04, 0x3e, 0x5d, 0x52, 0xa6, 0x5e, 0x66, 0x12, 0x51, 0x88, 0xbf
};

static const uint8_t prf_label_seed[] = {
    0x6b, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0xae, 0x6c, 0x80,
    0x6f, 0x8a, 0xd4, 0xd8, 0x07, 0x84, 0x54, 0x9d, 0xff, 0x28, 0xa4, 0xb5, 0x8f, 0xd8, 0x37, 0x68,
    0x1a, 0x51, 0xd9, 0x28, 0xc3, 0xe3, 0x0e, 0xe5, 0xff, 0x14, 0xf3, 0x98, 0x68, 0x62, 0xe1, 0xfd,
    0x91, 0xf2, 0x3f, 0x55, 0x8a, 0x60, 0x5f, 0x28, 0x47, 0x8c, 0x58, 0xcf, 0x72, 0x63, 0x7b, 0x89,
    0x78, 0x4d, 0x95, 0x9d, 0xf7, 0xe9, 0x46, 0xd3, 0xf0, 0x7b, 0xd1, 0xb6, 0x16
};


static const uint8_t prf_output_ref[] = {
    0xd0, 0x61, 0x39, 0x88, 0x9f, 0xff, 0xac, 0x1e, 0x3a, 0x71, 0x86, 0x5f, 0x50, 0x4a, 0xa5, 0xd0,
    0xd2, 0xa2, 0xe8, 0x95, 0x06, 0xc6, 0xf2, 0x27, 0x9b, 0x67, 0x0c, 0x3e, 0x1b, 0x74, 0xf5, 0x31,
    0x01, 0x6a, 0x25, 0x30, 0xc5, 0x1a, 0x3a, 0x0f, 0x7e, 0x1d, 0x65, 0x90, 0xd0, 0xf0, 0x56, 0x6b,
    0x2f, 0x38, 0x7f, 0x8d, 0x11, 0xfd, 0x4f, 0x73, 0x1c, 0xdd, 0x57, 0x2d, 0x2e, 0xae, 0x92, 0x7f,
    0x6f, 0x2f, 0x81, 0x41, 0x0b, 0x25, 0xe6, 0x96, 0x0b, 0xe6, 0x89, 0x85, 0xad, 0xd6, 0xc3, 0x84,
    0x45, 0xad, 0x9f, 0x8c, 0x64, 0xbf, 0x80, 0x68, 0xbf, 0x9a, 0x66, 0x79, 0x48, 0x5d, 0x96, 0x6f,
    0x1a, 0xd6, 0xf6, 0x8b, 0x43, 0x49, 0x5b, 0x10, 0xa6, 0x83, 0x75, 0x5e, 0xa2, 0xb8, 0x58, 0xd7,
    0x0c, 0xca, 0xc7, 0xec, 0x8b, 0x05, 0x3c, 0x6b, 0xd4, 0x1c, 0xa2, 0x99, 0xd4, 0xe5, 0x19, 0x28
};



/** \brief  The test case perform hkdf operation on the given input data and return the output on the bus.
 *
 */
TEST(atca_cmd_basic_test, kdf_hkdf_io)
{
    ATCA_STATUS status;
    uint8_t hkdf_output[sizeof(hkdf_okm)];
    uint16_t hkdf_output_len = sizeof(hkdf_output);
    uint16_t hmac_handle;
    ta_element_attributes_t attr_symm_hmac;

    status = talib_handle_init_symmetric_key(&attr_symm_hmac, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_KDF_SHA);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create a HMAC handle
    status = talib_create_hmac_element(atcab_get_device(), sizeof(hkdf_ikm), &attr_symm_hmac, &hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the key to the HMAC handle
    status = talib_write_element(atcab_get_device(), hmac_handle, sizeof(hkdf_ikm), hkdf_ikm);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // perform the hkdf operation with the given data and key in HMAC handle
    status = talib_hkdf_io(atcab_get_device(), hmac_handle, hkdf_salt, sizeof(hkdf_salt), hkdf_info, sizeof(hkdf_info), hkdf_output, &hkdf_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Compare the hkdf output with the reference data
    TEST_ASSERT_EQUAL_MEMORY(hkdf_okm, hkdf_output, sizeof(hkdf_okm));

    status = talib_delete_handle(_gDevice, (uint32_t)hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}


/** \brief  The test case perform hkdf operation on the given input data and store the output to the handle.
 *
 */
TEST(atca_cmd_basic_test, kdf_hkdf_stored)
{
    ATCA_STATUS status;
    uint8_t hkdf_output[sizeof(hkdf_okm)];
    uint16_t hkdf_output_len = sizeof(hkdf_output);
    uint16_t hmac_key_handle, hkdf_out_stored_handle;
    ta_element_attributes_t attr_symm_hmac;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    status = talib_handle_init_symmetric_key(&attr_symm_hmac, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_KDF_SHA);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create the HMAC handle
    status = talib_create_hmac_element(atcab_get_device(), sizeof(hkdf_ikm), &attr_symm_hmac, &hmac_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create the handle for the output data
    status = talib_create_hmac_element(atcab_get_device(), hkdf_output_len, &attr_symm_hmac,
                                       &hkdf_out_stored_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the key to the HMAC handle
    status = talib_write_element(atcab_get_device(), hmac_key_handle, sizeof(hkdf_ikm), hkdf_ikm);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // perform the hkdf operation with the given data, key in HMAC handle and store the output to handle in device.
    status = talib_hkdf_stored(atcab_get_device(), hmac_key_handle, hkdf_salt, sizeof(hkdf_salt), hkdf_info,
                               sizeof(hkdf_info), hkdf_out_stored_handle, &hkdf_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read the data from the stored handle
    status = talib_read_element(atcab_get_device(), hkdf_out_stored_handle, &hkdf_output_len, hkdf_output);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Compare the hkdf output with the reference data
    TEST_ASSERT_EQUAL_MEMORY(hkdf_okm, hkdf_output, sizeof(hkdf_okm));

    status = talib_delete_handle(_gDevice, (uint32_t)hmac_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(_gDevice, (uint32_t)hkdf_out_stored_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}

/** \brief  The test case perform kdf prf operation on the given input data and return the output on the bus.
 *
 */

TEST(atca_cmd_basic_test, kdf_prf_io)
{
    ATCA_STATUS status;
    uint8_t prf_output[sizeof(prf_output_ref)];
    uint16_t prf_output_len = sizeof(prf_output);
    uint16_t hmac_handle;
    ta_element_attributes_t attr_symm_hmac;

    status = talib_handle_init_symmetric_key(&attr_symm_hmac, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_KDF_SHA);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create a HMAC handle
    status = talib_create_hmac_element(atcab_get_device(), sizeof(prf_key), &attr_symm_hmac, &hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the key to the HMAC handle
    status = talib_write_element(atcab_get_device(), hmac_handle, sizeof(prf_key), prf_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // perform the kdf prf operation with the given data and key in HMAC handle
    status = talib_kdf_prf_io(atcab_get_device(), hmac_handle, sizeof(prf_key), prf_label_seed,
                              sizeof(prf_label_seed), prf_output, &prf_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Compare the kdf prf output with the reference data
    TEST_ASSERT_EQUAL_MEMORY(prf_output_ref, prf_output, sizeof(prf_output_ref));

    status = talib_delete_handle(_gDevice, (uint32_t)hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}



/** \brief  The test case perform kdf prf operation on the given input data and return the output on the bus.
 *
 */
TEST(atca_cmd_basic_test, kdf_prf_stored)
{
    ATCA_STATUS status;
    uint8_t prf_output[sizeof(prf_output_ref)];
    uint16_t prf_output_len = sizeof(prf_output);
    uint16_t hmac_handle, data_handle;
    ta_element_attributes_t attr_symm_hmac, attr_data;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    status = talib_handle_init_symmetric_key(&attr_symm_hmac, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_KDF_SHA);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create the HMAC handle
    status = talib_create_hmac_element(atcab_get_device(), sizeof(prf_key), &attr_symm_hmac, &hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_init_data(&attr_data, prf_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create handle for the output kdf prf operation
    status = talib_create_element(atcab_get_device(), &attr_data, &data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the key to the HMAC handle
    status = talib_write_element(atcab_get_device(), hmac_handle, sizeof(prf_key), prf_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // perform the kdf prf operation with the given data, key in HMAC handle and store the output to handle in device.
    status = talib_kdf_prf_stored(atcab_get_device(), hmac_handle, sizeof(prf_key), prf_label_seed,
                                  sizeof(prf_label_seed), data_handle, &prf_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read the data from the stored handle
    status = talib_read_element(atcab_get_device(), data_handle, &prf_output_len, prf_output);

    // Compare the hkdf output with the reference data
    TEST_ASSERT_EQUAL_MEMORY(prf_output_ref, prf_output, sizeof(prf_output_ref));

    status = talib_delete_handle(_gDevice, (uint32_t)hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(_gDevice, (uint32_t)data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}


/** \brief  The test case perform HMAC-counter operation on the data and return the output on the bus.
 *
 */
TEST(atca_cmd_basic_test, kdf_hmac_counter_io)
{
    ATCA_STATUS status;
    uint8_t hmac_counter_output[ATCA_SHA256_DIGEST_SIZE], hmac_key[ATCA_SHA256_DIGEST_SIZE];
    uint16_t hmac_counter_output_len = sizeof(hmac_counter_output);
    uint8_t label[100], context[100];
    uint16_t hmac_handle;
    ta_element_attributes_t attr_symm_hmac;

    status = talib_handle_init_symmetric_key(&attr_symm_hmac, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_KDF_SHA);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create the HMAC handle
    status = talib_create_hmac_element(atcab_get_device(), sizeof(hmac_key), &attr_symm_hmac, &hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    status = talib_random(atcab_get_device(), NULL, hmac_key, sizeof(hmac_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the key to the HMAC handle
    status = talib_write_element(atcab_get_device(), hmac_handle, sizeof(hmac_key), hmac_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    status = talib_random(atcab_get_device(), NULL, label, sizeof(label));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, context, sizeof(context));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // perform the hmac-counter operation with the data and key in HMAC handle.
    status = talib_kdf_hmac_counter_io(atcab_get_device(), hmac_handle,  label, sizeof(label), context,
                                       sizeof(context), hmac_counter_output, &hmac_counter_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(_gDevice, (uint32_t)hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}



/** \brief  The test case perform HMAC-counter operation on the data and store the output to the handle.
 *
 */
TEST(atca_cmd_basic_test, kdf_hmac_counter_stored)
{
    ATCA_STATUS status;
    uint8_t hmac_key[ATCA_SHA256_DIGEST_SIZE];
    uint16_t hmac_counter_output_len = ATCA_SHA256_DIGEST_SIZE;
    uint8_t label[100], context[100];
    uint16_t hmac_handle, data_handle;
    ta_element_attributes_t attr_symm_hmac, attr_data;

    status = talib_handle_init_symmetric_key(&attr_symm_hmac, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_KDF_SHA);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, hmac_key, sizeof(hmac_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create a HMAC handle
    status = talib_create_hmac_element(atcab_get_device(), sizeof(hmac_key), &attr_symm_hmac, &hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_init_data(&attr_data, hmac_counter_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create the handle for the output data
    status = talib_create_element(atcab_get_device(), &attr_data, &data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the key to the HMAC handle
    status = talib_write_element(atcab_get_device(), hmac_handle, sizeof(hmac_key), hmac_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, label, sizeof(label));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, context, sizeof(context));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // perform the hmac-counter operation with the given data, key in HMAC handle and store the output to handle in device.
    status = talib_kdf_hmac_counter_stored(atcab_get_device(), hmac_handle, label, sizeof(label),
                                           context, sizeof(context), data_handle, &hmac_counter_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(_gDevice, (uint32_t)hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(_gDevice, (uint32_t)data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}


/** \brief  The test case perform kdf-sha256 operation on the given input data and return the data on output buffer.
 *
 */

TEST(atca_cmd_basic_test, kdf_sha256_io)
{
    ATCA_STATUS status;
    uint8_t sha_output[ATCA_SHA256_DIGEST_SIZE], sha_output_ref[ATCA_SHA256_DIGEST_SIZE], hmac_key[ATCA_SHA256_DIGEST_SIZE];
    uint16_t sha_output_len = sizeof(sha_output);
    uint8_t pre_pad[100], post_pad[100];
    atcac_sha2_256_ctx ctx;
    uint16_t hmac_handle;
    ta_element_attributes_t attr_symm_hmac;

    status = talib_handle_init_symmetric_key(&attr_symm_hmac, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_KDF_SHA);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, hmac_key, sizeof(hmac_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, pre_pad, sizeof(pre_pad));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, post_pad, sizeof(post_pad));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create a HMAC handle
    status = talib_create_hmac_element(atcab_get_device(), sizeof(hmac_key), &attr_symm_hmac, &hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the key to the HMAC handle
    status = talib_write_element(atcab_get_device(), hmac_handle, sizeof(hmac_key), hmac_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // perform the kdf-sha256 operation with the given data and key in HMAC handle
    status = talib_kdf_sha256_io(atcab_get_device(), hmac_handle, pre_pad, sizeof(pre_pad), post_pad,
                                 sizeof(post_pad), sha_output, &sha_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Performing the same operation on software to verify the device calcualted
    status = atcac_sw_sha2_256_init(&ctx);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_sw_sha2_256_update(&ctx, pre_pad, sizeof(pre_pad));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_sw_sha2_256_update(&ctx, hmac_key, sizeof(hmac_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_sw_sha2_256_update(&ctx, post_pad, sizeof(post_pad));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_sw_sha2_256_finish(&ctx, sha_output_ref);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Comparing the data from device and software generated.
    TEST_ASSERT_EQUAL_MEMORY(sha_output_ref, sha_output, sizeof(sha_output_ref));

    status = talib_delete_handle(_gDevice, (uint32_t)hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}

/** \brief  The test case perform kdf-sha256 operation on the given input data and store the output to the handle.
 *
 */
TEST(atca_cmd_basic_test, kdf_sha256_stored)
{
    ATCA_STATUS status;
    uint8_t sha_output[ATCA_SHA256_DIGEST_SIZE], sha_output_ref[ATCA_SHA256_DIGEST_SIZE], hmac_key[ATCA_SHA256_DIGEST_SIZE];
    uint16_t sha_output_len = sizeof(sha_output);
    uint8_t pre_pad[100], post_pad[100];
    atcac_sha2_256_ctx ctx;

    uint16_t hmac_handle, sha256_stored_handle;
    ta_element_attributes_t attr_symm_hmac;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    status = talib_handle_init_symmetric_key(&attr_symm_hmac, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_KDF_SHA);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, hmac_key, sizeof(hmac_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, pre_pad, sizeof(pre_pad));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, post_pad, sizeof(post_pad));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create a HMAC handle
    status = talib_create_hmac_element(atcab_get_device(), sizeof(hmac_key), &attr_symm_hmac, &hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create handle for the output data to be stored
    status = talib_create_hmac_element(atcab_get_device(), sizeof(hmac_key), &attr_symm_hmac, &sha256_stored_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the key to the HMAC handle
    status = talib_write_element(atcab_get_device(), hmac_handle, sizeof(hmac_key), hmac_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // perform the kdf-sha256 operation with the given data and key in HMAC handle
    status = talib_kdf_sha256_stored(atcab_get_device(), hmac_handle, pre_pad, sizeof(pre_pad),
                                     post_pad, sizeof(post_pad), sha256_stored_handle, &sha_output_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read the data from the output handle
    status = talib_read_element(atcab_get_device(), sha256_stored_handle, &sha_output_len, sha_output);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Performing the same operation on software to verify the device calcualted
    status = atcac_sw_sha2_256_init(&ctx);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_sw_sha2_256_update(&ctx, pre_pad, sizeof(pre_pad));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_sw_sha2_256_update(&ctx, hmac_key, sizeof(hmac_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_sw_sha2_256_update(&ctx, post_pad, sizeof(post_pad));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_sw_sha2_256_finish(&ctx, sha_output_ref);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Comparing the data from device and software generated.
    TEST_ASSERT_EQUAL_MEMORY(sha_output_ref, sha_output, sizeof(sha_output_ref));

    status = talib_delete_handle(_gDevice, (uint32_t)hmac_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(_gDevice, (uint32_t)sha256_stored_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}


t_test_case_info talib_kdf_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_hkdf_io),             DEVICE_MASK(TA100)                           },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_hkdf_stored),         DEVICE_MASK(TA100)                           },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_prf_io),              DEVICE_MASK(TA100)                           },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_prf_stored),          DEVICE_MASK(TA100)                           },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_hmac_counter_io),     DEVICE_MASK(TA100)                           },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_hmac_counter_stored), DEVICE_MASK(TA100)                           },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_sha256_io),           DEVICE_MASK(TA100)                           },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_sha256_stored),       DEVICE_MASK(TA100)                           },

    /* Array Termination element*/
    { (fp_test_case)NULL,                     (uint8_t)0 },
};

t_test_case_info* talib_kdf_tests[] = {
    talib_kdf_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
