
#include "atca_config.h"
#include "cryptoauthlib.h"
#include "atca_test.h"
#include "test_talib.h"


#if ATCA_TA_SUPPORT

/** \brief  Change GPIO pin state and verify it.
 *
 */
TEST(atca_cmd_basic_test, write_gpio_state)
{
    ATCA_STATUS status;
    uint8_t set_gpio_state, read_gpio_state;
    uint8_t check_gpio_mode;
    uint16_t config_size = sizeof(check_gpio_mode);

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    //Read the gpio3 config from the configuration memory
    status = talib_read_partial_element(atcab_get_device(), TA_HANDLE_CONFIG_MEMORY, 24, &config_size, &check_gpio_mode);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if ((check_gpio_mode & TA_GPIO_MODE_MASK) == 0x01)
    {
        status = talib_read_gpio_pin_state(atcab_get_device(), TA_HANDLE_GPIO3, &read_gpio_state);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        set_gpio_state = (read_gpio_state & TA_GPIO_PIN_STATE_MASK) ^ 1;

        status = talib_write_gpio_pin_state(atcab_get_device(), TA_HANDLE_GPIO3, &set_gpio_state);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Read the entire data from the element
        status = talib_read_gpio_pin_state(atcab_get_device(), TA_HANDLE_GPIO3, &read_gpio_state);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        TEST_ASSERT_EQUAL(set_gpio_state, (read_gpio_state & TA_GPIO_PIN_STATE_MASK));
    }

    else
    {
        TEST_IGNORE_MESSAGE("Ignoring the test as GPIO mode 2 is not enabled in configuration");
    }

}


/** \brief  Transfer the key in volatile memory to the shared data memory and verify it.
 *          The symmetric key is written to the volatile memory and write command transfer the key to
 *          to shared memory. The symmetric operation is performed on the key in shared memory to verify it.
 *          to verify it.
 *          .
 */
TEST(atca_cmd_basic_test, write_key_transfer_volatile_shared)
{
    ATCA_STATUS status;
    ta_element_attributes_t attr_symm_key_handle;
    uint16_t sym_key_handle = TA_HANDLE_VOLATILE_REGISTER2;
    uint16_t sym_key_transfer_handle;
    uint8_t write_key[ATCA_AES128_KEY_SIZE];
    uint8_t plain_text[ATCA_AES128_BLOCK_SIZE];
    uint8_t cipher_text[ATCA_AES128_BLOCK_SIZE];
    uint8_t decrypted_text[ATCA_AES128_BLOCK_SIZE];
    uint8_t check_config_transfer_enable;
    uint16_t config_size = sizeof(check_config_transfer_enable);
    uint16_t data_size = sizeof(write_key);



    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    //Read the volatile to shared data transfer enable flag
    status = talib_read_partial_element(atcab_get_device(), TA_HANDLE_CONFIG_MEMORY, 18, &config_size,
                                        &check_config_transfer_enable);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    if ((check_config_transfer_enable & TA_COPY_VOL_REG_MASK))
    {
        status = talib_handle_init_symmetric_key(&attr_symm_key_handle, TA_KEY_TYPE_AES128, TA_PROP_SYMM_KEY_USAGE_ANY);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = talib_handle_set_read_permission(&attr_symm_key_handle, TA_PERM_NEVER);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = talib_create_element_with_handle(atcab_get_device(), sym_key_handle, &attr_symm_key_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = talib_create_element(atcab_get_device(), &attr_symm_key_handle, &sym_key_transfer_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Creating Random 16 key to write
        status = talib_random(atcab_get_device(), NULL, write_key, sizeof(write_key));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Creating Random 16 plain text
        status = talib_random(atcab_get_device(), NULL, plain_text, sizeof(plain_text));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Write the 16 byte key to the element
        status = talib_write_element(atcab_get_device(), sym_key_handle, data_size, write_key);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Transfer the key from Volatile memory to the shared memory
        status = talib_write_volatile_shared_transfer(atcab_get_device(), sym_key_handle, sym_key_transfer_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Perform encryption option with the key in shared memory
        status = atcab_aes_encrypt(sym_key_transfer_handle, 0, plain_text, cipher_text);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Perform decryption option with the key in shared memory
        status = atcab_aes_decrypt(sym_key_transfer_handle, 0, cipher_text, decrypted_text);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Verify the plain and decrypted data.
        TEST_ASSERT_EQUAL_MEMORY(plain_text, decrypted_text, data_size);

        status = talib_delete_handle(atcab_get_device(), (uint32_t)sym_key_transfer_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    }

    else
    {


        TEST_IGNORE_MESSAGE("Ignoring the test as Copy_Vol_reg is not enabled in configuration");


    }
}

/** \brief  Write the ecc private key to the handle and verify it.The private key is written to a handle
 *          and corresponding public is generated. It is then compared with the reference public key.
 *          It is not recommended to write private key from outside.
 *          .
 */
TEST(atca_cmd_basic_test, write_ecc_private_key)
{
    ATCA_STATUS status;
    ta_element_attributes_t attr_private_key_attr;
    uint16_t private_key_handle;
    uint8_t public_key[64];

    static const uint8_t private_key[32] = {
        0x87, 0x8F, 0x0A, 0xB6, 0xA5, 0x26, 0xD7, 0x11,
        0x1C, 0x26, 0xE6, 0x17, 0x08, 0x10, 0x79, 0x6E,
        0x7B, 0x33, 0x00, 0x7F, 0x83, 0x2B, 0x8D, 0x64,
        0x46, 0x7E, 0xD6, 0xF8, 0x70, 0x53, 0x7A, 0x19
    };

    static const uint8_t public_key_ref[64] = {
        0x8F, 0x8D, 0x18, 0x2B, 0xD8, 0x19, 0x04, 0x85, 0x82, 0xA9, 0x92, 0x7E,
        0xA0, 0xC5, 0x6D, 0xEF, 0xB4, 0x15, 0x95, 0x48, 0xE1, 0x1C, 0xA5, 0xF7,
        0xAB, 0xAC, 0x45, 0xBB, 0xCE, 0x76, 0x81, 0x5B, 0xE5, 0xC6, 0x4F, 0xCD,
        0x2F, 0xD1, 0x26, 0x98, 0x54, 0x4D, 0xE0, 0x37, 0x95, 0x17, 0x26, 0x66,
        0x60, 0x73, 0x04, 0x61, 0x19, 0xAD, 0x5E, 0x11, 0xA9, 0x0A, 0xA4, 0x97,
        0x73, 0xAE, 0xAC, 0x86
    };


    status = talib_handle_init_private_key(&attr_private_key_attr, TA_KEY_TYPE_ECCP256,
                                           TA_ALG_MODE_ECC_ECDSA, TA_PROP_SIGN_INT_EXT_DIGEST,
                                           TA_PROP_NO_KEY_AGREEMENT);
    attr_private_key_attr.property &= ~TA_PROP_EXECUTE_ONLY_KEY_GEN_MASK;
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_set_write_permission(&attr_private_key_attr, TA_PERM_ALWAYS);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create a private key handle
    status = talib_create_element(atcab_get_device(), &attr_private_key_attr, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the 32 byte private key to the handle
    status = talib_write_priv_key(atcab_get_device(), private_key_handle, sizeof(private_key), private_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Get the public key from the element
    status = atcab_get_pubkey(private_key_handle, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify the generated with the reference public key.
    TEST_ASSERT_EQUAL_MEMORY(public_key_ref, public_key, sizeof(public_key));

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}


/** \brief   Write the rsa public key to the handle and verify it.
 *           The rsa private key generates the signature with the given message and
 *           the signature is sent to the corresponding rsa public key for verifing it.
 *
 */
TEST(atca_cmd_basic_test, write_rsa_public_key)
{
    ATCA_STATUS status;
    uint16_t private_key_handle, public_key_handle;
    ta_element_attributes_t attr_private_key, attr_public_key;
    uint8_t pub_key[TA_KEY_TYPE_RSA2048_SIZE];
    size_t pub_key_len = sizeof(pub_key);
    uint8_t message[32];
    uint8_t signature[TA_KEY_TYPE_RSA2048_SIZE];
    uint16_t sign_size = sizeof(signature);
    bool is_verified = false;

    status = talib_handle_init_private_key(&attr_private_key, TA_KEY_TYPE_RSA2048, TA_ALG_MODE_RSA_SSA_PSS, 
                                           TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create RSA private key handle
    status = talib_create_element(atcab_get_device(), &attr_private_key, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_init_public_key(&attr_public_key, TA_KEY_TYPE_RSA2048, TA_ALG_MODE_RSA_SSA_PSS, 
                                          TA_PROP_VAL_NO_SECURE_BOOT_SIGN, TA_PROP_ROOT_PUB_KEY_VERIFY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create RSA public key handle
    status = talib_create_element(atcab_get_device(), &attr_public_key, &public_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // Generate a RSA private/public key pair
    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)private_key_handle,
                               pub_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the RSA public key to the handle.
    status = talib_write_pub_key(atcab_get_device(), public_key_handle, (uint16_t)pub_key_len, pub_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_random(message);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign a random message with RSA private key in handle.
    status = talib_sign_external(atcab_get_device(), TA_KEY_TYPE_RSA2048, private_key_handle, 
                                 TA_HANDLE_INPUT_BUFFER, message, (uint16_t)sizeof(message), signature, 
                                 &sign_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify the signature with RSA public key in handle.
    status = talib_verify(atcab_get_device(), TA_KEY_TYPE_RSA2048, TA_HANDLE_INPUT_BUFFER, public_key_handle, 
                          signature, sign_size, message, (uint16_t)sizeof(message), NULL, 
                          TA_KEY_TYPE_RSA2048_SIZE, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)public_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}


// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_write_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_gpio_state),                    DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_key_transfer_volatile_shared),  DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_ecc_private_key),               DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_rsa_public_key),                DEVICE_MASK(TA100) },

    /* Array Termination element*/
    { (fp_test_case)NULL,                    (uint8_t)0 },
};
// *INDENT-ON*

t_test_case_info * talib_write_tests[] = {
    talib_write_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
