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
#include "test_atcab.h"
#include "vectors/vector_utils.h"

#ifndef TEST_ATCAB_AES_CBC_EN
#define TEST_ATCAB_AES_CCM_EN           (ATCAB_AES_CCM_EN)
#endif

#if TEST_ATCAB_AES_CCM_EN
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

#if defined(_WIN32) || defined(__linux__)
#define SIZE_OF_TEXT    100
#define SIZE_OF_TEXT_MAX 255

typedef enum ccm_nist_vt_types_e{
    VADT_128,
    VNT_128,
    VPT_128,
    VTT_128
}ccm_nist_vt_types_t;

static ATCA_STATUS aes_ccm_nist_vector_test(ccm_nist_vt_types_t ccm_nist_type)
{
    ATCA_STATUS status;
    ATCADeviceType dev_type = atca_test_get_device_type();
    atca_aes_ccm_ctx_t ctx;

    FILE * rsp_file;

    size_t count = 0;
    size_t klen = 16;
    size_t nlen = 0;
    size_t ptlen = 0;
    size_t ctlen = 0;
    size_t aadlen = 0;
    size_t cipherlen = 0;
    size_t taglen = 0;

    size_t aad_size = 0;
    size_t pt_size = 0;

    uint16_t key_slot;
    uint16_t key_id;
#ifdef ATCA_ATECC608_SUPPORT    
    uint16_t key_id_ca = ATCA_TEMPKEY_KEYID;
#endif    

    uint8_t key[16];
    uint8_t nonce[16];
    uint8_t plaintext[SIZE_OF_TEXT];
    uint8_t ciphertext[24];
    uint8_t aad[SIZE_OF_TEXT];
    uint8_t ct[SIZE_OF_TEXT];
    uint8_t tag[16];
    uint8_t expected_ciphertext[24];
    uint8_t expected_tag[16];

    char *str;
    char *name_value;
    uint8_t line[SIZE_OF_TEXT];
    

#ifdef ATCA_PRINTF
    uint16_t test_count = 0;
    uint8_t displayStr[100];
    size_t displaySize;
#endif

    switch (ccm_nist_type)
    {
    case VADT_128:
        rsp_file = fopen("aes_ccm_vectors/VADT128.rsp", "r");
        TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open .rsp file");

        status = read_rsp_int_value(rsp_file, "Plen = ", NULL, (int*)&ptlen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Plen value in file.");

        status = read_rsp_int_value(rsp_file, "Nlen = ", NULL, (int*)&nlen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Nlen value in file.");

        status = read_rsp_int_value(rsp_file, "Tlen = ", NULL, (int*)&taglen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Tlen value in file.");
        break;

    case VNT_128:    
        rsp_file = fopen("aes_ccm_vectors/VNT128.rsp", "r");
        TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open .rsp file");

        status = read_rsp_int_value(rsp_file, "Alen = ", NULL, (int*)&aadlen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Plen value in file.");

        status = read_rsp_int_value(rsp_file, "Plen = ", NULL, (int*)&ptlen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Nlen value in file.");

        status = read_rsp_int_value(rsp_file, "Tlen = ", NULL, (int*)&taglen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Tlen value in file.");
        break;

    case VPT_128:
        rsp_file = fopen("aes_ccm_vectors/VPT128.rsp", "r");
        TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open .rsp file");

        status = read_rsp_int_value(rsp_file, "Alen = ", NULL, (int*)&aadlen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Plen value in file.");

        status = read_rsp_int_value(rsp_file, "Nlen = ", NULL, (int*)&nlen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Nlen value in file.");

        status = read_rsp_int_value(rsp_file, "Tlen = ", NULL, (int*)&taglen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Tlen value in file.");    
        break;

    case VTT_128:
        rsp_file = fopen("aes_ccm_vectors/VTT128.rsp", "r");
        TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open .rsp file");

        status = read_rsp_int_value(rsp_file, "Alen = ", NULL, (int*)&aadlen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Plen value in file.");

        status = read_rsp_int_value(rsp_file, "Plen = ", NULL, (int*)&ptlen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Plen value in file.");

        status = read_rsp_int_value(rsp_file, "Nlen = ", NULL, (int*)&nlen);
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Failed to find Nlen value in file.");
        break; 
    
    default:
        break;
    }
 
    if (atcab_is_ta_device(dev_type))
    {
        status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    }

    do
    {
        if (NULL == (str = fgets((char *)line, sizeof(line), rsp_file)))
        {
            continue;
        }
        else
        {
            size_t ln = strlen((const char *)line);
            if (ln > 0 && line[ln - 2] == '\r')
            {
                line[ln - 1] = 0;
            }
        }

        if (!memcmp(str, "[Alen = ", strlen("[Alen = ")))
        {
            name_value = (char*)&line[strlen("[Alen = ")];
            char* aad_token = name_value;
            char* aad_size_str = strtok_r(NULL, "]\n", &aad_token);
            if (NULL != aad_size_str)
            {
                aadlen = atoi(aad_size_str);
            }
        }

        if (!memcmp(str, "[Plen = ", strlen("[Plen = ")))
        {
            name_value = (char*)&line[strlen("[Plen = ")];
            char* pt_token = name_value;
            char* payload_size_str = strtok_r(NULL, "]\n", &pt_token);
            if (NULL != payload_size_str)
            {
                ptlen = atoi(payload_size_str);
            }
        }

        if (!memcmp(str, "[Tlen = ", strlen("[Tlen = ")))
        {
            name_value = (char*)&line[strlen("[Tlen = ")];
            char* tag_token = name_value;
            char* tag_size_str = strtok_r(NULL, "]\n", &tag_token);
            if (NULL != tag_size_str)
            {
                taglen = atoi(tag_size_str);
            }
        }
        
        if (!memcmp(str, "Key = ", strlen("Key = ")))
        {
            name_value = (char *)&line[strlen("Key = ")];
            klen = strlen(name_value) / 2;
            hex_to_data(name_value, key, klen);
        }
        else if (!memcmp(str, "Nonce = ", strlen("Nonce = ")))
        {
            name_value = (char *)&line[strlen("Nonce = ")];
            nlen = strlen(name_value) / 2;
            hex_to_data(name_value, nonce, nlen);
        }
        else if (!memcmp(str, "Adata = ", strlen("Adata = ")))
        {
            name_value = (char *)&line[strlen("Adata = ")];
            aad_size = strlen(name_value) / 2;
            hex_to_data(name_value, aad, aad_size);
        }
        else if (!memcmp(str, "Payload = ", strlen("Payload = ")))
        {
            name_value = (char *)&line[strlen("Payload = ")];
            pt_size = strlen(name_value) / 2;
            hex_to_data(name_value, plaintext, pt_size);
        }
        else if (!memcmp(str, "CT = ", strlen("CT = ")))
        {
            name_value = (char *)&line[strlen("CT = ")];
            ctlen = ((uint32_t)strlen(name_value) / 2);
            cipherlen = ctlen - taglen;
            hex_to_data(name_value, ct, ctlen);
            memcpy(expected_ciphertext, ct, cipherlen);
            memcpy(expected_tag, &ct[cipherlen], taglen);

#ifdef ATCA_PRINTF
            // Process read vector
            printf("\r\nCount: %04d\r\n", test_count++);
            displaySize = sizeof(displayStr);
            (void) atcab_bin2hex(aad, aad_size, displayStr, &displaySize);
            printf("Adata: \r\n%s\r\n", displayStr);
            displaySize = sizeof(displayStr);
            (void) atcab_bin2hex(plaintext, ptlen, displayStr, &displaySize);
            printf("Payload: \r\n%s\r\n", displayStr);
#endif

            if (ATECC608 == dev_type)
            {
#ifdef ATCA_ATECC608_SUPPORT                
                status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, key, 32);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

                status = atcab_aes_ccm_init(&ctx, key_id_ca, 0, nonce, nlen, aadlen, ptlen, taglen);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
            }
            
            if(atcab_is_ta_device(dev_type))
            {
                status = atca_test_config_get_id(TEST_TYPE_AES, &key_id);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        
                status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_id, 0, key, klen);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

                status = atcab_aes_ccm_init(&ctx, key_id, 0, nonce, nlen, aadlen, ptlen, taglen);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            }

            status = atcab_aes_ccm_aad_update(&ctx, aad, aadlen);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            if (0 == ptlen)
            {
                status = atcab_aes_ccm_aad_finish(&ctx);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            }

            status = atcab_aes_ccm_encrypt_update(&ctx, plaintext, ptlen, ciphertext);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            status = atcab_aes_ccm_encrypt_finish(&ctx, tag, &taglen);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            if(0 != cipherlen)
            {
                TEST_ASSERT_EQUAL_MEMORY(expected_ciphertext, ciphertext, cipherlen);
            }
            
            TEST_ASSERT_EQUAL_MEMORY(expected_tag, tag, taglen);    
        }        
    }
    while (!feof(rsp_file));

    fclose(rsp_file);

    return status;
}

TEST(atca_cmd_basic_test, aes_ccm_nist_vadt128)
{
    ATCA_STATUS status;
    ccm_nist_vt_types_t nist_vt_type = VADT_128;

    status = aes_ccm_nist_vector_test(nist_vt_type);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    printf("\n");
#endif
}

TEST(atca_cmd_basic_test, aes_ccm_nist_vnt128)
{
    ATCA_STATUS status;
    ccm_nist_vt_types_t nist_vt_type = VNT_128;

    status = aes_ccm_nist_vector_test(nist_vt_type);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    printf("\n");
#endif
}

TEST(atca_cmd_basic_test, aes_ccm_nist_vpt128)
{
    ATCA_STATUS status;
    ccm_nist_vt_types_t nist_vt_type = VPT_128;

    status = aes_ccm_nist_vector_test(nist_vt_type);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    printf("\n");
#endif
}

TEST(atca_cmd_basic_test, aes_ccm_nist_vtt128)
{
    ATCA_STATUS status;
    ccm_nist_vt_types_t nist_vt_type = VTT_128;

    status = aes_ccm_nist_vector_test(nist_vt_type);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    printf("\n");
#endif
}

#undef SIZE_OF_TEXT
#endif //_WIN32 / __linux__
#endif //TEST_ATCAB_AES_CCM_EN

t_test_case_info aes_ccm_basic_test_info[] =
{
#if TEST_ATCAB_AES_CCM_EN
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_auth_encrypt),         atca_test_cond_ecc608         },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_auth_encrypt_partial), atca_test_cond_ecc608         },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_auth_decrypt),         atca_test_cond_ecc608         },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_auth_decrypt_partial), atca_test_cond_ecc608         },
#endif
#if defined(_WIN32) || defined(__linux__)
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_nist_vadt128),         atca_test_cond_aes_ccm             },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_nist_vnt128),          atca_test_cond_aes_ccm             },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_nist_vpt128),          atca_test_cond_aes_ccm             },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ccm_nist_vtt128),          atca_test_cond_aes_ccm             },
#endif
#endif
    { (fp_test_case)NULL,                     NULL },                        /* Array Termination element*/
};
