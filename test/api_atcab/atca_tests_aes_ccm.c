/**
 * \file
 * \brief Unity tests for the cryptoauthlib Basic API
 *
 * \copyright (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
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
#include <stdlib.h>
#ifdef _WIN32
#include <time.h>
#endif
#include "atca_test.h"

#ifdef ATCA_ATECC608_SUPPORT
typedef struct
{
    uint8_t key[16];
    uint8_t nonce[AES_DATA_SIZE - 2];
    uint8_t nonce_size;
    uint8_t aad[48];
    uint8_t aad_size;
    uint8_t plaintext[48];
    uint8_t plaintext_size;
    uint8_t tag[16];
    uint8_t tag_size;
    uint8_t ciphertext[48];
}aes_ccm_test_vectors;

const aes_ccm_test_vectors ccm_test_array[] =
{
    //https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38c.pdf
    {
        // C.1 Example  1
        { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f },
        { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 },
        7,
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 },
        8,
        { 0x20, 0x21, 0x22, 0x23 },
        4,
        { 0x4d, 0xac, 0x25, 0x5d },
        4,
        { 0x71, 0x62, 0x01, 0x5b },
    },
    {
        // C.2 Example  2
        { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f },
        { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
        8,
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f },
        16,
        { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f },
        16,
        { 0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd },
        6,
        { 0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62, 0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d },
    },
    {
        // C.3 Example  3
        { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f },
        { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b },
        12,
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13},
        20,
        { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37},
        24,
        { 0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51 },
        8,
        { 0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a, 0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b, 0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5},
    }
};

TEST(atca_cmd_basic_test, aes_ccm_auth_encrypt)
{
    ATCA_STATUS status;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t key_block = 0;
    aes_ccm_test_vectors* test_data;
    atca_aes_ccm_ctx_t ctx;
    uint8_t ciphertext[48];
    uint8_t tag[AES_DATA_SIZE];
    uint8_t tag_size;
    size_t i;

    for (i = 0; i < (sizeof(ccm_test_array) / sizeof(aes_ccm_test_vectors)); i++)
    {
        test_data = (aes_ccm_test_vectors*)&ccm_test_array[i];

        status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, test_data->key, 32);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcab_aes_ccm_init(&ctx, key_id, key_block, test_data->nonce, (size_t)test_data->nonce_size, (size_t)test_data->aad_size, (size_t)test_data->plaintext_size, (size_t)test_data->tag_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcab_aes_ccm_aad_update(&ctx, test_data->aad, test_data->aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcab_aes_ccm_encrypt_update(&ctx, test_data->plaintext, test_data->plaintext_size, ciphertext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcab_aes_ccm_encrypt_finish(&ctx, tag, &tag_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        TEST_ASSERT_EQUAL_MEMORY(test_data->tag, tag, test_data->tag_size);
        TEST_ASSERT_EQUAL_MEMORY(test_data->ciphertext, ciphertext, test_data->plaintext_size);
    }
}

TEST(atca_cmd_basic_test, aes_ccm_auth_decrypt)
{
    ATCA_STATUS status;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t key_block = 0;
    aes_ccm_test_vectors* test_data;
    atca_aes_ccm_ctx_t ctx;
    uint8_t plaintext[48];
    bool is_verified;
    size_t i;

    for (i = 0; i < (sizeof(ccm_test_array) / sizeof(aes_ccm_test_vectors)); i++)
    {
        test_data = (aes_ccm_test_vectors*)&ccm_test_array[i];

        status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, test_data->key, 32);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcab_aes_ccm_init(&ctx, key_id, key_block, test_data->nonce, (size_t)test_data->nonce_size, (size_t)test_data->aad_size, (size_t)test_data->plaintext_size, (size_t)test_data->tag_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcab_aes_ccm_aad_update(&ctx, test_data->aad, test_data->aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcab_aes_ccm_decrypt_update(&ctx, test_data->ciphertext, test_data->plaintext_size, plaintext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcab_aes_ccm_decrypt_finish(&ctx, test_data->tag, &is_verified);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL(true, is_verified);

        TEST_ASSERT_EQUAL_MEMORY(test_data->plaintext, plaintext, test_data->plaintext_size);
    }
}

TEST(atca_cmd_basic_test, aes_ccm_auth_encrypt_partial)
{
    ATCA_STATUS status;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t key_block = 0;
    aes_ccm_test_vectors* test_data;
    atca_aes_ccm_ctx_t ctx;
    uint8_t ciphertext[48];
    uint8_t tag[AES_DATA_SIZE];
    uint8_t tag_size;

    test_data = (aes_ccm_test_vectors*)&ccm_test_array[0];

    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, test_data->key, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_init(&ctx, key_id, key_block, test_data->nonce, (size_t)test_data->nonce_size, (size_t)test_data->aad_size, (size_t)test_data->plaintext_size, (size_t)test_data->tag_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_aad_update(&ctx, test_data->aad, test_data->aad_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_update(&ctx, &test_data->plaintext[0], 2, &ciphertext[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_update(&ctx, &test_data->plaintext[2], 2, &ciphertext[2]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_finish(&ctx, tag, &tag_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(test_data->tag, tag, test_data->tag_size);
    TEST_ASSERT_EQUAL_MEMORY(test_data->ciphertext, ciphertext, test_data->plaintext_size);


    test_data = (aes_ccm_test_vectors*)&ccm_test_array[1];

    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, test_data->key, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_init(&ctx, key_id, key_block, test_data->nonce, (size_t)test_data->nonce_size, (size_t)test_data->aad_size, (size_t)test_data->plaintext_size, (size_t)test_data->tag_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_aad_update(&ctx, test_data->aad, test_data->aad_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_update(&ctx, &test_data->plaintext[0], 4, &ciphertext[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_update(&ctx, &test_data->plaintext[4], 4, &ciphertext[4]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_update(&ctx, &test_data->plaintext[8], 8, &ciphertext[8]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_finish(&ctx, tag, &tag_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(test_data->tag, tag, test_data->tag_size);
    TEST_ASSERT_EQUAL_MEMORY(test_data->ciphertext, ciphertext, test_data->plaintext_size);


    test_data = (aes_ccm_test_vectors*)&ccm_test_array[2];

    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, test_data->key, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_init(&ctx, key_id, key_block, test_data->nonce, (size_t)test_data->nonce_size, (size_t)test_data->aad_size, (size_t)test_data->plaintext_size, (size_t)test_data->tag_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_aad_update(&ctx, test_data->aad, test_data->aad_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_update(&ctx, &test_data->plaintext[0], 8, &ciphertext[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_update(&ctx, &test_data->plaintext[8], 8, &ciphertext[8]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_update(&ctx, &test_data->plaintext[16], 8, &ciphertext[16]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_encrypt_finish(&ctx, tag, &tag_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(test_data->tag, tag, test_data->tag_size);
    TEST_ASSERT_EQUAL_MEMORY(test_data->ciphertext, ciphertext, test_data->plaintext_size);
}

TEST(atca_cmd_basic_test, aes_ccm_auth_decrypt_partial)
{
    ATCA_STATUS status;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t key_block = 0;
    aes_ccm_test_vectors* test_data;
    atca_aes_ccm_ctx_t ctx;
    uint8_t plaintext[48];
    bool is_verified;

    test_data = (aes_ccm_test_vectors*)&ccm_test_array[0];

    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, test_data->key, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_init(&ctx, key_id, key_block, test_data->nonce, (size_t)test_data->nonce_size, (size_t)test_data->aad_size, (size_t)test_data->plaintext_size, (size_t)test_data->tag_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_aad_update(&ctx, test_data->aad, test_data->aad_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_update(&ctx, &test_data->ciphertext[0], 2, &plaintext[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_update(&ctx, &test_data->ciphertext[2], 2, &plaintext[2]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_finish(&ctx, test_data->tag, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    TEST_ASSERT_EQUAL_MEMORY(test_data->plaintext, plaintext, test_data->plaintext_size);


    test_data = (aes_ccm_test_vectors*)&ccm_test_array[1];

    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, test_data->key, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_init(&ctx, key_id, key_block, test_data->nonce, (size_t)test_data->nonce_size, (size_t)test_data->aad_size, (size_t)test_data->plaintext_size, (size_t)test_data->tag_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_aad_update(&ctx, test_data->aad, test_data->aad_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_update(&ctx, &test_data->ciphertext[0], 4, &plaintext[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_update(&ctx, &test_data->ciphertext[4], 4, &plaintext[4]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_update(&ctx, &test_data->ciphertext[8], 8, &plaintext[8]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_finish(&ctx, test_data->tag, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    TEST_ASSERT_EQUAL_MEMORY(test_data->plaintext, plaintext, test_data->plaintext_size);


    test_data = (aes_ccm_test_vectors*)&ccm_test_array[2];

    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, test_data->key, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_init(&ctx, key_id, key_block, test_data->nonce, (size_t)test_data->nonce_size, (size_t)test_data->aad_size, (size_t)test_data->plaintext_size, (size_t)test_data->tag_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_aad_update(&ctx, test_data->aad, test_data->aad_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_update(&ctx, &test_data->ciphertext[0], 8, &plaintext[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_update(&ctx, &test_data->ciphertext[8], 8, &plaintext[8]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_update(&ctx, &test_data->ciphertext[16], 8, &plaintext[16]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_ccm_decrypt_finish(&ctx, test_data->tag, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    TEST_ASSERT_EQUAL_MEMORY(test_data->plaintext, plaintext, test_data->plaintext_size);
}
#endif

t_test_case_info aes_ccm_basic_test_info[] =
{
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_auth_encrypt),         DEVICE_MASK(ATECC608A)                                  },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_auth_encrypt_partial), DEVICE_MASK(ATECC608A)                                  },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_auth_decrypt),         DEVICE_MASK(ATECC608A)                                  },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_auth_decrypt_partial), DEVICE_MASK(ATECC608A)                                  },
#endif
    { (fp_test_case)NULL,                     (uint8_t)0 },                  /* Array Termination element*/
};
