
#include "atca_config.h"
#include "cryptoauthlib.h"
#include "atca_test.h"

#if ATCA_TA_SUPPORT

static const uint8_t rsa_public_key[] = {
    0xcc, 0xd1, 0x08, 0xae, 0x4e, 0x23, 0x9f, 0xa1, 0x64, 0x3e, 0x53, 0xdf, 0xae, 0xd8, 0xcc, 0x23,
    0x24, 0x1c, 0xcf, 0x7f, 0x6c, 0x7c, 0x3b, 0xdf, 0x38, 0x47, 0x7e, 0xd6, 0xc0, 0x9d, 0xd8, 0xd6,
    0xcb, 0xe2, 0x66, 0xc1, 0x16, 0xfb, 0xd0, 0x67, 0x29, 0xdc, 0x85, 0xd1, 0x39, 0x45, 0x1b, 0x0e,
    0xdf, 0x42, 0x18, 0xb8, 0xc7, 0x2a, 0x29, 0xd4, 0xc8, 0x44, 0x35, 0x5a, 0x81, 0x7f, 0x03, 0x38,
    0xd4, 0xa8, 0x2a, 0x9b, 0xc7, 0x95, 0xf7, 0x09, 0xec, 0xbc, 0xd0, 0xc8, 0xf8, 0x00, 0xbd, 0x1c,
    0x0b, 0x9d, 0x36, 0x1c, 0xa3, 0x89, 0x37, 0x69, 0x98, 0x27, 0xca, 0x23, 0x24, 0x4f, 0x25, 0xa6,
    0x6d, 0xce, 0x0c, 0xe8, 0xeb, 0x3e, 0xcf, 0x9f, 0xa1, 0xdb, 0x85, 0x5c, 0x45, 0x5e, 0x20, 0x89,
    0x0a, 0xa8, 0xdd, 0x90, 0x25, 0x21, 0xc8, 0x84, 0x2b, 0xd6, 0xb9, 0x06, 0x61, 0xa5, 0x01, 0xef,
};

static const uint8_t rsa_private_key[] = {
    0xf5, 0x7d, 0x50, 0xfe, 0x94, 0x02, 0x33, 0xe6, 0xe1, 0xdc, 0xd4, 0xbd, 0xdc, 0xa1, 0xf8, 0x38,
    0x81, 0x5d, 0x93, 0x80, 0xf5, 0x68, 0x65, 0xca, 0xec, 0x16, 0xb3, 0x86, 0xcd, 0xbd, 0x74, 0x77,
    0x48, 0xe8, 0xd1, 0x84, 0x6b, 0x67, 0xa6, 0x70, 0xd0, 0x14, 0x0d, 0x6a, 0x3c, 0xbb, 0xce, 0x10,
    0xaa, 0x7b, 0xef, 0x05, 0xb7, 0x43, 0xc8, 0x54, 0xfb, 0x26, 0x44, 0x16, 0x1a, 0x0f, 0x94, 0x81,
    0xd5, 0x95, 0xec, 0x0b, 0x48, 0xc1, 0x29, 0x37, 0x39, 0xec, 0x7c, 0x13, 0x1f, 0xeb, 0x27, 0x48,
    0x95, 0x98, 0x72, 0xcb, 0xaf, 0xc4, 0xae, 0xf3, 0xa7, 0x22, 0x90, 0x41, 0x43, 0x0a, 0x85, 0x31,
    0x7b, 0xf3, 0xcf, 0xd7, 0xfd, 0x31, 0x81, 0xa4, 0x57, 0x4f, 0x58, 0xec, 0x7d, 0x91, 0xc3, 0x43,
    0x64, 0xd6, 0x91, 0xf9, 0xad, 0x04, 0x8e, 0x57, 0x9a, 0xe3, 0x0e, 0xec, 0x29, 0x3c, 0x9e, 0x6f,
};

/** \brief  This test cases encrypts plain text with 1024 bit RSA public key in handle
 *          and decrypts it with 1024 bit RSA private key in handle
 *
 */
TEST(atca_cmd_basic_test, rsa_encrypt_decrypt_handle)
{
    ATCA_STATUS status;
    uint8_t ciphertext[TA_RSAENC_CIPHER_TEXT_SIZE];
    uint8_t plaintext[TA_RSAENC_PLAIN_TEXT_MAX_SIZE];
    uint8_t decrypted_text[TA_RSAENC_PLAIN_TEXT_MAX_SIZE];
    ta_element_attributes_t attr_private_key, attr_public_key;
    uint16_t private_key_handle, public_key_handle;


    status = talib_handle_init_private_key(&attr_private_key, TA_KEY_TYPE_RSA1024,
                                           TA_ALG_MODE_RSA_SSA_1_5, TA_PROP_SIGN_INT_EXT_DIGEST,
                                           TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_set_write_permission(&attr_private_key, TA_PERM_ALWAYS);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    attr_private_key.property |= TA_PROP_KEY_AGREEMENT_OUT_BUFF_MASK;
    //RSA1024 keygen is not possible, so here private key is written externally
    attr_private_key.property &= ~(TA_PROP_EXECUTE_ONLY_KEY_GEN_MASK);

    //Create RSA private key handle
    status = talib_create_element(atcab_get_device(), &attr_private_key, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the RSA private key to handle
    status = talib_write_priv_key(atcab_get_device(), private_key_handle, sizeof(rsa_private_key), rsa_private_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_init_public_key(&attr_public_key, TA_KEY_TYPE_RSA1024,
                                          TA_ALG_MODE_RSA_SSA_1_5, 0, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //Create RSA public key handle
    status = talib_create_element(atcab_get_device(), &attr_public_key, &public_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the RSA public key to handle
    status = talib_write_element(atcab_get_device(), public_key_handle, sizeof(rsa_public_key), rsa_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, plaintext, sizeof(plaintext));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // Encrypt the plaintext with the rsa public key in handle
    status = talib_rsaenc_encrypt(atcab_get_device(), public_key_handle, sizeof(plaintext),
                                  plaintext, sizeof(ciphertext), ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt the ciphertext with the rsa private key in handle
    status = talib_rsaenc_decrypt(atcab_get_device(), private_key_handle, sizeof(ciphertext),
                                  ciphertext, sizeof(decrypted_text), decrypted_text);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Compare plaintext with the decrypted text
    TEST_ASSERT_EQUAL_MEMORY(plaintext, decrypted_text, TA_RSAENC_PLAIN_TEXT_MAX_SIZE);

    status = talib_delete_handle(_gDevice, (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(_gDevice, (uint32_t)public_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}


/** \brief  This test cases encrypts plain text with an 1024 bit RSA public key in input buffer
 *          and decrypts it with 1024 bit RSA private key in handle
 *
 */
TEST(atca_cmd_basic_test, rsa_encrypt_decrypt_io_buffer)
{
    ATCA_STATUS status;
    uint8_t ciphertext[TA_RSAENC_CIPHER_TEXT_SIZE];
    uint8_t plaintext[TA_RSAENC_PLAIN_TEXT_MAX_SIZE];
    uint8_t decrypted_text[TA_RSAENC_PLAIN_TEXT_MAX_SIZE];
    ta_element_attributes_t attr_private_key;
    uint16_t private_key_handle;


    status = talib_handle_init_private_key(&attr_private_key, TA_KEY_TYPE_RSA1024,
                                           TA_ALG_MODE_RSA_SSA_1_5, TA_PROP_SIGN_INT_EXT_DIGEST,
                                           TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_set_write_permission(&attr_private_key, TA_PERM_ALWAYS);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    attr_private_key.property |= TA_PROP_KEY_AGREEMENT_OUT_BUFF_MASK;
    //RSA1024 keygen is not possible, so here private key is written externally
    attr_private_key.property &= ~(TA_PROP_EXECUTE_ONLY_KEY_GEN_MASK);

    // Create an RSA private key handle
    status = talib_create_element(atcab_get_device(), &attr_private_key, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write the RSA private key to handle
    status = talib_write_priv_key(atcab_get_device(), private_key_handle, sizeof(rsa_private_key), rsa_private_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, plaintext, sizeof(plaintext));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt the plain text with the rsa public key given in the input buffer
    status = talib_rsaenc_encrypt_with_iobuffer(atcab_get_device(), rsa_public_key,
                                                sizeof(plaintext), plaintext, sizeof(ciphertext), ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt the cipher text with the rsa private key in handle
    status = talib_rsaenc_decrypt(atcab_get_device(), private_key_handle, sizeof(ciphertext),
                                  ciphertext, sizeof(decrypted_text), decrypted_text);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Compare plaintext with the decrypted text
    TEST_ASSERT_EQUAL_MEMORY(plaintext, decrypted_text, TA_RSAENC_PLAIN_TEXT_MAX_SIZE);

    status = talib_delete_handle(_gDevice, (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}


// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_rsa_enc_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, rsa_encrypt_decrypt_handle),      DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, rsa_encrypt_decrypt_io_buffer),   DEVICE_MASK(TA100) },
    /* Array Termination element*/
    { (fp_test_case)NULL,                    (uint8_t)0 },
};
// *INDENT-ON*

t_test_case_info * talib_rsa_enc_tests[] = {
    talib_rsa_enc_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
