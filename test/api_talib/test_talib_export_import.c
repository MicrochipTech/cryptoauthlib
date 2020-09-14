/**
 * \file
 * \brief Basic test for Export/Import command api - TA100
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

/** \brief This test case export the private key from data handle and import it to
 *         different handle and verify by its public key
 *  NOTE: Both export and import handle should match value of its attribute fields
 *        except link keys (usage key, read key, write key)
 */
TEST(atca_cmd_basic_test, export_import_private_key)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t encrypted_blob[TA_EXPORT_BLOB_MAX_LEN];
    uint16_t encrypted_blob_len = sizeof(encrypted_blob);
    uint16_t export_priv_key_handle;
    uint16_t import_priv_key_handle;
    ta_element_attributes_t export_attr_priv_key_handle;
    ta_element_attributes_t import_attr_priv_key_handle;
    uint8_t exp_public_key[TA_ECC256_PUB_KEY_SIZE];
    uint8_t imp_public_key[TA_ECC256_PUB_KEY_SIZE];
    size_t pub_key_len = TA_ECC256_PUB_KEY_SIZE;

    // Create export and import handle without link keys and setting req attributes for handles
    status = talib_handle_init_private_key(&export_attr_priv_key_handle, TA_KEY_TYPE_ECCP256,
                                          TA_ALG_MODE_ECC_ECDSA, TA_PROP_SIGN_INT_EXT_DIGEST,
                                          TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    export_attr_priv_key_handle.byte7_settings |= TA_EXPORTABLE_FROM_CHIP_MASK;

    status = talib_create_element(atcab_get_device(), &export_attr_priv_key_handle, &export_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // import handle
    status = talib_handle_init_private_key(&import_attr_priv_key_handle, TA_KEY_TYPE_ECCP256,
                                          TA_ALG_MODE_ECC_ECDSA, TA_PROP_SIGN_INT_EXT_DIGEST,
                                          TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    import_attr_priv_key_handle.byte7_settings |= TA_EXPORTABLE_FROM_CHIP_MASK;

    status = talib_create_element(atcab_get_device(), &import_attr_priv_key_handle, &import_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // Genarate new private key on export handle and get the public key of it
    status = talib_genkey(atcab_get_device(), export_priv_key_handle, exp_public_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    status = talib_export(atcab_get_device(), export_priv_key_handle, encrypted_blob, &encrypted_blob_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_import_handle(atcab_get_device(), import_priv_key_handle, encrypted_blob, encrypted_blob_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // verify the imported handle by match its public key
    status = talib_get_pubkey_compat(atcab_get_device(), import_priv_key_handle, imp_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(exp_public_key, imp_public_key, TA_ECC256_PUB_KEY_SIZE);


    // delete handles
    status = talib_delete_handle(atcab_get_device(), export_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), import_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief This test case export the data from shared data handle and import it to
 *         different handle
 *  NOTE: Both export and import handle should match value of its attribute fields
 *        except link keys (usage key, read key, write key)
 */
TEST(atca_cmd_basic_test, export_import_data_element_with_links)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t encrypted_blob[TA_EXPORT_BLOB_MAX_LEN];
    uint16_t encrypted_blob_len = sizeof(encrypted_blob);
    uint16_t write_key_handle;
    uint16_t exp_data_handle;
    uint16_t imp_data_handle;
    ta_element_attributes_t attr_data_handle;
    ta_element_attributes_t attr_write_key_handle;
    uint8_t write_data[64];
    uint8_t read_data[64];
    uint16_t data_size = sizeof(write_data);
    uint8_t hmac_key[] = { 0xa2, 0x26, 0xe1, 0x65, 0x69, 0x01, 0x80, 0xeb, 0x1a, 0x0c, 0x9c, 0x5b, 0x64, 0x5e, 0x42, 0x02,
                           0xfa, 0x2f, 0x4f, 0xfd, 0x68, 0x75 };
    uint8_t hmac_i_nonce[] = { 0xd4, 0xe4, 0x9a, 0x02, 0x9f, 0xf2, 0xca, 0xff, 0x5e, 0x7c, 0xda, 0x2f, 0x13, 0x07, 0xa8, 0xb6 };
    uint8_t hmac_r_nonce[] = { 0xad, 0x23, 0x38, 0x09, 0x4e, 0xd3, 0xbf, 0xc3, 0x89, 0xc6, 0xf6, 0x35, 0xb6, 0xcf, 0xcf, 0xf0 };
    uint8_t key_buf[32] = { 0 };
    uint16_t auth_id = 0x4100;
    uint16_t details = (uint16_t)TA_CREATE_DETAILS_HMAC_KEY_LENGTH(sizeof(hmac_key));

    // Skip test if setup isn't locked
    test_assert_data_is_locked();

    // Create link (write) key, because export and import handle dependent on this keys
    // Here only one link key is created and shared by both export and import handle
    status = talib_handle_init_symmetric_key(&attr_write_key_handle, TA_KEY_TYPE_HMAC, TA_PROP_SYMM_KEY_USAGE_ANY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    attr_write_key_handle.property |= TA_PROP_SYMM_KEY_EITHER_OPTIONAL_MASK;

    status = talib_create_linked_shared_data(atcab_get_device(), details, &attr_write_key_handle,
                                             &write_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // write symmetric key into link (write) key
    status = talib_write_element(atcab_get_device(), write_key_handle, sizeof(hmac_key), hmac_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // Create export and import handle and setting req attributes
    status = talib_handle_init_data(&attr_data_handle, data_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_set_write_permission(&attr_data_handle, TA_PERM_AUTH);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    attr_data_handle.write_key = (uint8_t)(write_key_handle & 0x00FF);
    attr_data_handle.byte7_settings |= TA_EXPORTABLE_FROM_CHIP_MASK;

    status = talib_create_element(atcab_get_device(), &attr_data_handle, &exp_data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_data_handle, &imp_data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // Generate randome data to be written to export data handle
    status = talib_random(atcab_get_device(), NULL, write_data, data_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Establish Auth session to write a data into export data handle
    status = talib_auth_generate_nonce(atcab_get_device(), auth_id, 0, hmac_i_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // copying session key into key buf to start the suth session
    memcpy(key_buf, hmac_key, sizeof(hmac_key));

    status = talib_auth_startup(atcab_get_device(), write_key_handle, TA_AUTH_ALG_ID_HMAC, 2, 32,
                                key_buf, hmac_i_nonce, hmac_r_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_write_element(atcab_get_device(), exp_data_handle, data_size, write_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Terminate auth session
    status = talib_auth_terminate(atcab_get_device());
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    status = talib_export(atcab_get_device(), exp_data_handle, encrypted_blob, &encrypted_blob_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_import_handle(atcab_get_device(), imp_data_handle, encrypted_blob, encrypted_blob_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);




    // verifying the imported handle by reading the data from it and match with original data
    status = talib_read_element(atcab_get_device(), imp_data_handle, &data_size, read_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(write_data, read_data, data_size);


    // delete handles
    status = talib_delete_handle(atcab_get_device(), write_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), exp_data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), imp_data_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief This test case export the symmetric key from data handle and import it to
 *         different handle
 *  NOTE: Both export and import handle should match value of its attribute fields
 *        except link keys (usage key, read key, write key)
 */
TEST(atca_cmd_basic_test, export_import_symm_key_with_target_links)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint16_t export_symm_key_handle;
    uint16_t import_symm_key_handle;
    ta_element_attributes_t export_attr_symm_key_handle;
    ta_element_attributes_t import_attr_symm_key_handle;
    ta_element_attributes_t attr_read_key_handle;
    uint16_t exp_read_key_handle;
    uint16_t imp_read_key_handle;
    uint8_t encrypted_blob[TA_EXPORT_BLOB_MAX_LEN];
    uint16_t encrypted_blob_len = sizeof(encrypted_blob);
    uint8_t plain_text[ATCA_AES128_BLOCK_SIZE] = { 0x1A, 0x3A, 0xA5, 0x45, 0x04, 0x94, 0x53, 0xAF,
                                                   0xDF, 0x17, 0xE9, 0x89, 0xA4, 0x1F, 0xA0, 0x97 };
    uint8_t cipher_text[ATCA_AES128_BLOCK_SIZE];
    uint8_t plain_text_out[ATCA_AES128_BLOCK_SIZE];
    uint16_t details = (uint16_t)TA_CREATE_DETAILS_HMAC_KEY_LENGTH(TA_MAC_COMMAND_HMAC_SIZE);

    // Create link keys (read), because export and import handles are dependent on this keys.
    // Here two link keys are created and shared with export and import handle respectively.
    status = talib_handle_init_symmetric_key(&attr_read_key_handle, TA_KEY_TYPE_HMAC, TA_PROP_SYMM_KEY_USAGE_ANY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_linked_shared_data(atcab_get_device(), details, &attr_read_key_handle,
                                             &exp_read_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_linked_shared_data(atcab_get_device(), details, &attr_read_key_handle,
                                             &imp_read_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // write symmetric key into link read keys
    status = talib_write_element(atcab_get_device(), exp_read_key_handle, TA_MAC_COMMAND_HMAC_SIZE, g_slot4_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_write_element(atcab_get_device(), imp_read_key_handle, TA_MAC_COMMAND_HMAC_SIZE, g_slot4_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // Create export and import handle and set req attributes for handle
    status = talib_handle_init_symmetric_key(&export_attr_symm_key_handle, TA_KEY_TYPE_AES128, TA_PROP_SYMM_KEY_USAGE_ANY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_set_read_permission(&export_attr_symm_key_handle, TA_PERM_AUTH);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    export_attr_symm_key_handle.read_key = (uint8_t)(exp_read_key_handle & 0x00FF);
    export_attr_symm_key_handle.byte7_settings |= TA_EXPORTABLE_FROM_CHIP_MASK;

    status = talib_create_hmac_element(atcab_get_device(), TA_KEY_TYPE_AES128_SIZE, &export_attr_symm_key_handle,
                                       &export_symm_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Import handle
    status = talib_handle_init_symmetric_key(&import_attr_symm_key_handle, TA_KEY_TYPE_AES128, TA_PROP_SYMM_KEY_USAGE_ANY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_set_read_permission(&import_attr_symm_key_handle, TA_PERM_AUTH);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    import_attr_symm_key_handle.read_key = (uint8_t)(imp_read_key_handle & 0x00FF);
    import_attr_symm_key_handle.byte7_settings |= TA_EXPORTABLE_FROM_CHIP_MASK;

    status = talib_create_hmac_element(atcab_get_device(), TA_KEY_TYPE_AES128_SIZE, &import_attr_symm_key_handle,
                                       &import_symm_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // Generate new symmetric key for the export handle
    status = talib_genkey_symmetric_key(atcab_get_device(), export_symm_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt using the export handle
    status = atcab_aes_encrypt(export_symm_key_handle, 0, plain_text, cipher_text);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    status = talib_export(atcab_get_device(), export_symm_key_handle, encrypted_blob, &encrypted_blob_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_import_handle_with_target_links(atcab_get_device(), import_symm_key_handle, encrypted_blob,
                                                   encrypted_blob_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    // verifying the imported handle by decrypting cipher text and match with plain text
    status = atcab_aes_decrypt(import_symm_key_handle, 0, cipher_text, plain_text_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(plain_text_out, plain_text, ATCA_AES128_BLOCK_SIZE);


    // delete handles
    status = talib_delete_handle(atcab_get_device(), export_symm_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), import_symm_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), exp_read_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), imp_read_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_export_import_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, export_import_symm_key_with_target_links),    DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, export_import_private_key),                   DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, export_import_data_element_with_links),       DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_export_import_tests[] = {
    talib_export_import_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif