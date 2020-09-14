
#include "atca_config.h"
#include "cryptoauthlib.h"
#include "atca_test.h"

#include "test_ecc_certificate_chain.h"

#if ATCA_TA_SUPPORT

/** \brief  It verifies the certificate in the input buffer with the root public key in device.
 *
 */
TEST(atca_cmd_basic_test, managecert_verify_cert_io_buffer)
{
    ATCA_STATUS status;
    uint16_t root_key_id;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    //Get the root public key handle
    status = atca_test_config_get_id(TEST_TYPE_ECC_ROOT_KEY, &root_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Verify the given ecc signer certificate with the root public key
    status = talib_verify_cert_io(atcab_get_device(), root_key_id, test_ecc_signer_cert, sizeof(test_ecc_signer_cert));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}


/** \brief   Stores the given certificate to the device and
 *           verifies it with the root public key in device.
 */
TEST(atca_cmd_basic_test, managecert_verify_cert_shared_memory)
{
    ATCA_STATUS status;
    uint16_t root_key_id;
    ta_element_attributes_t data_attr;
    uint16_t certificate_handle;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    status = talib_handle_init_data(&data_attr, sizeof(test_ecc_signer_cert));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Create data handle for storing the signer certificate
    status = talib_create_element(atcab_get_device(), &data_attr, &certificate_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Write the complete signer certificate to the data handle in device
    status = talib_write_element(atcab_get_device(), certificate_handle, sizeof(test_ecc_signer_cert),
                                 test_ecc_signer_cert);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Get the root public key handle
    status = atca_test_config_get_id(TEST_TYPE_ECC_ROOT_KEY, &root_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Verify the ecc signer certificate stored in device with the root public key
    status = talib_verify_cert(atcab_get_device(), root_key_id, certificate_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)certificate_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}



/** \brief  This test cases verifies the certificate chain and stores leaf extracted certificate to volatile memory.
 *          The root public key is in the device and it verifies the certificate chain given in the input buffer.
 */
TEST(atca_cmd_basic_test, managecert_verify_cert_chain_volatile)
{
    ATCA_STATUS status;
    uint16_t root_key_id;
    ta_element_attributes_t extracted_cert_attr;
    uint16_t extracted_cert_handle = TA_HANDLE_VOLATILE_REGISTER3;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();

    status = talib_handle_init_extracated_certificate(&extracted_cert_attr, TA_KEY_TYPE_ECCP256, TA_ALG_MODE_ECC_ECDSA, 0, TA_PROP_CERT_CA_OK);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Create Element for the extracted certificate storage
    status = talib_create_element_with_handle(atcab_get_device(), extracted_cert_handle, &extracted_cert_attr);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Get the root public key handle
    status = atca_test_config_get_id(TEST_TYPE_ECC_ROOT_KEY, &root_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Verify the given signer certificate with root public key and store the signer extracted certificate to volatile handle
    status = talib_store_extracted_cert_io(atcab_get_device(), root_key_id, extracted_cert_handle,
                                           test_ecc_signer_cert, sizeof(test_ecc_signer_cert));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //The signer extracted certificate verifies the given leaf certificate and it stores leaf extraced certificate to same volatile handle
    status = talib_store_extracted_cert_io(atcab_get_device(), extracted_cert_handle, extracted_cert_handle,
                                           test_ecc_leaf_cert, sizeof(test_ecc_leaf_cert));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


}



/** \brief  This test cases verifies the certificate chain and stores signer & leaf extracted certificate to shared data memory.
 *          The root public key, signer and end device certificate are in device. The root verifies the certificate chain from
 *          shared data memory and stores signer & leaf extracted certificate in shared data memory.
 */
TEST(atca_cmd_basic_test, managecert_verify_cert_chain_data_shared_memory)
{
    ATCA_STATUS status;
    uint16_t root_key_id;
    ta_element_attributes_t extracted_cert_attr, data_attr;
    uint16_t signer_cert_handle, leaf_cert_handle;
    uint16_t signer_extracted_cert_handle, leaf_extracted_cert_handle;
    uint8_t leaf_public_key[ATCA_ECCP256_PUBKEY_SIZE];

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();

    status = talib_handle_init_data(&data_attr, sizeof(test_ecc_signer_cert));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Creating data handle for storing the complete signer certificate */
    status = talib_create_element(atcab_get_device(), &data_attr, &signer_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Write the complete signer certificate to the data handle in device
    status = talib_write_element(atcab_get_device(), signer_cert_handle, sizeof(test_ecc_signer_cert), test_ecc_signer_cert);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_init_data(&data_attr, sizeof(test_ecc_leaf_cert));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Creating data handle for storing the complete leaf certificate */
    status = talib_create_element(atcab_get_device(), &data_attr, &leaf_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Write the complete leaf certificate to the data handle in device
    status = talib_write_element(atcab_get_device(), leaf_cert_handle, sizeof(test_ecc_leaf_cert),
                                 test_ecc_leaf_cert);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    status = talib_handle_init_extracated_certificate(&extracted_cert_attr, TA_KEY_TYPE_ECCP256, TA_ALG_MODE_ECC_ECDSA, 0, TA_PROP_CERT_CA_OK);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Creating data handle for storing the extracted signer certificate */
    status = talib_create_element(atcab_get_device(), &extracted_cert_attr, &signer_extracted_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_init_extracated_certificate(&extracted_cert_attr, TA_KEY_TYPE_ECCP256, TA_ALG_MODE_ECC_ECDSA, 0, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Creating data handle for storing the extracted leaf certificate */
    status = talib_create_element(atcab_get_device(), &extracted_cert_attr, &leaf_extracted_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Get the root public key handle
    status = atca_test_config_get_id(TEST_TYPE_ECC_ROOT_KEY, &root_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Verify the signer certificate with root public key and store the signer extracted certificate to data handle
    status = talib_store_extracted_cert(atcab_get_device(), root_key_id, signer_extracted_cert_handle, signer_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Verify the given leaf certificate with signer extracted certificate and store its extracted certificate to handle.
    status = talib_store_extracted_cert(atcab_get_device(), signer_extracted_cert_handle, leaf_extracted_cert_handle, leaf_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //read the public key from the leaf extracted certificate
    status = atcab_read_pubkey(leaf_extracted_cert_handle, leaf_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Compare the read leaf public key with the refernce key
    TEST_ASSERT_EQUAL_MEMORY(test_ecc_leaf_public_key, leaf_public_key, ATCA_ECCP256_PUBKEY_SIZE);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_extracted_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)leaf_extracted_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)leaf_cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}

t_test_case_info talib_managecert_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, managecert_verify_cert_io_buffer),                DEVICE_MASK(TA100)                    },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, managecert_verify_cert_shared_memory),            DEVICE_MASK(TA100)                    },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, managecert_verify_cert_chain_volatile),           DEVICE_MASK(TA100)                    },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, managecert_verify_cert_chain_data_shared_memory), DEVICE_MASK(TA100)                    },


    /* Array Termination element*/
    { (fp_test_case)NULL,                     (uint8_t)0 },
};

t_test_case_info* talib_managecert_tests[] = {
    talib_managecert_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
