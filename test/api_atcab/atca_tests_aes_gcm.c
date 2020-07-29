/**
 * \file
 * \brief Unity tests for the cryptoauthlib AES GCM functions.
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
#include <stdlib.h>
#ifdef _WIN32
#include <time.h>
#endif
#include "atca_test.h"
#include "atca_basic.h"

#ifdef ATCA_ATECC608_SUPPORT

//#include "calib/calib_aes_gcm.h"
#include "vectors/aes_gcm_nist_vectors.h"

typedef struct
{
    uint32_t text_size;
    uint8_t  plaintext[32];
    uint8_t  ciphertext[32];
    uint32_t aad_size;
    uint8_t  aad[32];
    uint8_t  tag[16];
} aes_gcm_partial_block_vectors;

// *INDENT-OFF* - Preserve formatting
const aes_gcm_partial_block_vectors test_vectors[] =
{
    {
        30,
        { 0x9f, 0xee, 0xbb, 0xdf, 0x16, 0x0f, 0x96, 0x52, 0x53, 0xd9, 0x99, 0x58, 0xcc, 0xb1, 0x76, 0xdf,
          0x9f, 0xee, 0xbb, 0xdf, 0x16, 0x0f, 0x96, 0x52, 0x53, 0xd9, 0x99, 0x58, 0xcc, 0xb1 },
        { 0xA6, 0x97, 0x10, 0x3A, 0x70, 0x29, 0x7A, 0xAA, 0xCD, 0x25, 0x9E, 0x1A, 0x85, 0x36, 0xA7, 0xDC,
          0x3E, 0x61, 0x7D, 0xA2, 0xA8, 0x66, 0x3F, 0xD2, 0xFC, 0x5D, 0x6A, 0x6C, 0x36, 0xEA },
        30,
        { 0x47, 0x6b, 0x48, 0x80, 0xf5, 0x93, 0x33, 0x14, 0xdc, 0xc2, 0x3d, 0xf5, 0xdc, 0xb0, 0x09, 0x66,
          0x47, 0x6b, 0x48, 0x80, 0xf5, 0x93, 0x33, 0x14, 0xdc, 0xc2, 0x3d, 0xf5, 0xdc, 0xb0 },
        { 0x72, 0xE3, 0x22, 0x8A, 0x06, 0xE5, 0x88, 0x14, 0x94, 0xC7, 0x08, 0xF3, 0xAC, 0x8B, 0xA9, 0xC5 }
    },
    {
        16,
        { 0x9f, 0xee, 0xbb, 0xdf, 0x16, 0x0f, 0x96, 0x52, 0x53, 0xd9, 0x99, 0x58, 0xcc, 0xb1, 0x76, 0xdf },
        { 0xA6, 0x97, 0x10, 0x3A, 0x70, 0x29, 0x7A, 0xAA, 0xCD, 0x25, 0x9E, 0x1A, 0x85, 0x36, 0xA7, 0xDC },
        16,
        { 0x47, 0x6b, 0x48, 0x80, 0xf5, 0x93, 0x33, 0x14, 0xdc, 0xc2, 0x3d, 0xf5, 0xdc, 0xb0, 0x09, 0x66 },
        { 0xE8, 0x8C, 0x95, 0x9A, 0xBC, 0x1E, 0x75, 0x93, 0xA0, 0x3E, 0xF0, 0x34, 0x84, 0x64, 0xF2, 0xD5 }
    },
    {
        32,
        { 0x9f, 0xee, 0xbb, 0xdf, 0x16, 0x0f, 0x96, 0x52, 0x53, 0xd9, 0x99, 0x58, 0xcc, 0xb1, 0x76, 0xdf,
          0x9f, 0xee, 0xbb, 0xdf, 0x16, 0x0f, 0x96, 0x52, 0x53, 0xd9, 0x99, 0x58, 0xcc, 0xb1, 0x76, 0xdf },
        { 0xA6, 0x97, 0x10, 0x3A, 0x70, 0x29, 0x7A, 0xAA, 0xCD, 0x25, 0x9E, 0x1A, 0x85, 0x36, 0xA7, 0xDC,
          0x3E, 0x61, 0x7D, 0xA2, 0xA8, 0x66, 0x3F, 0xD2, 0xFC, 0x5D, 0x6A, 0x6C, 0x36, 0xEA, 0x2C, 0xD8 },
        32,
        { 0x47, 0x6b, 0x48, 0x80, 0xf5, 0x93, 0x33, 0x14, 0xdc, 0xc2, 0x3d, 0xf5, 0xdc, 0xb0, 0x09, 0x66,
          0x47, 0x6b, 0x48, 0x80, 0xf5, 0x93, 0x33, 0x14, 0xdc, 0xc2, 0x3d, 0xf5, 0xdc, 0xb0, 0x09, 0x66 },
        { 0x3E, 0xCA, 0xD1, 0x08, 0xF6, 0x8D, 0xC4, 0x54, 0xE6, 0xA1, 0x17, 0x5B, 0x9D, 0x4E, 0x16, 0xB3 }
    },
    {
        24,
        { 0x9f, 0xee, 0xbb, 0xdf, 0x16, 0x0f, 0x96, 0x52, 0x53, 0xd9, 0x99, 0x58, 0xcc, 0xb1, 0x76, 0xdf,
          0x9f, 0xee, 0xbb, 0xdf, 0x16, 0x0f, 0x96, 0x52 },
        { 0xA6,0x97, 0x10, 0x3A, 0x70, 0x29, 0x7A, 0xAA, 0xCD, 0x25, 0x9E, 0x1A, 0x85, 0x36, 0xA7, 0xDC,
          0x3E, 0x61, 0x7D, 0xA2, 0xA8, 0x66, 0x3F, 0xD2 },
        24,
        { 0x47, 0x6b, 0x48, 0x80, 0xf5, 0x93, 0x33, 0x14, 0xdc, 0xc2, 0x3d, 0xf5, 0xdc, 0xb0, 0x09, 0x66,
          0x47, 0x6b, 0x48, 0x80, 0xf5, 0x93, 0x33, 0x14, },
        { 0x74, 0x99, 0x3B, 0x31, 0x06, 0xBA, 0x6B, 0xE5, 0x00, 0x8F, 0xD5, 0x3A, 0xA4, 0x91, 0xAA, 0xAF }
    },
};
// *INDENT-ON*

TEST(atca_cmd_basic_test, aes_gcm_encrypt_partial_blocks)
{
    ATCA_STATUS status;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t aes_key_block = 0;
    uint8_t ciphertext[32];
    uint8_t tag[AES_DATA_SIZE];
    atca_aes_gcm_ctx_t ctx;
    const aes_gcm_partial_block_vectors* current_vector;
    uint8_t key[] = { 0xb7, 0xcf, 0x6c, 0xf5, 0xe7, 0xf3, 0xca, 0x22, 0x3c, 0xa7, 0x3c, 0x81, 0x9d, 0xcd, 0x62, 0xfe };
    uint8_t iv[] = { 0xa4, 0x13, 0x60, 0x09, 0xc0, 0xa7, 0xfd, 0xac, 0xfe, 0x53, 0xf5, 0x07 };

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, key, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    current_vector = &test_vectors[0];
    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, sizeof(iv));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Add aad to gcm
    status = atcab_aes_gcm_aad_update(&ctx, current_vector->aad, 15);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_aad_update(&ctx, &current_vector->aad[15], 15);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Encrypt data
    status = atcab_aes_gcm_encrypt_update(&ctx, current_vector->plaintext, 15, ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_encrypt_update(&ctx, &current_vector->plaintext[15], 15, &ciphertext[15]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Calculate authentication tag
    status = atcab_aes_gcm_encrypt_finish(&ctx, tag, sizeof(tag));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->ciphertext, ciphertext, current_vector->text_size);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->tag, tag, sizeof(tag));

    current_vector = &test_vectors[1];
    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, sizeof(iv));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Add aad to gcm
    status = atcab_aes_gcm_aad_update(&ctx, current_vector->aad, 15);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_aad_update(&ctx, &current_vector->aad[15], 1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Encrypt data
    status = atcab_aes_gcm_encrypt_update(&ctx, current_vector->plaintext, 15, ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_encrypt_update(&ctx, &current_vector->plaintext[15], 1, &ciphertext[15]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Calculate authentication tag
    status = atcab_aes_gcm_encrypt_finish(&ctx, tag, sizeof(tag));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->ciphertext, ciphertext, current_vector->text_size);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->tag, tag, sizeof(tag));

    current_vector = &test_vectors[2];
    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, sizeof(iv));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Add aad to gcm
    status = atcab_aes_gcm_aad_update(&ctx, current_vector->aad, 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_aad_update(&ctx, &current_vector->aad[16], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Encrypt data
    status = atcab_aes_gcm_encrypt_update(&ctx, current_vector->plaintext, 16, ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_encrypt_update(&ctx, &current_vector->plaintext[16], 16, &ciphertext[16]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Calculate authentication tag
    status = atcab_aes_gcm_encrypt_finish(&ctx, tag, sizeof(tag));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->ciphertext, ciphertext, current_vector->text_size);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->tag, tag, sizeof(tag));

    current_vector = &test_vectors[3];
    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, sizeof(iv));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Add aad to gcm
    status = atcab_aes_gcm_aad_update(&ctx, current_vector->aad, 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_aad_update(&ctx, &current_vector->aad[16], 8);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Encrypt data
    status = atcab_aes_gcm_encrypt_update(&ctx, current_vector->plaintext, 16, ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_encrypt_update(&ctx, &current_vector->plaintext[16], 8, &ciphertext[16]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Calculate authentication tag
    status = atcab_aes_gcm_encrypt_finish(&ctx, tag, sizeof(tag));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->ciphertext, ciphertext, current_vector->text_size);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->tag, tag, sizeof(tag));
}

TEST(atca_cmd_basic_test, aes_gcm_decrypt_partial_blocks)
{
    ATCA_STATUS status;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t aes_key_block = 0;
    uint8_t plaintext[32];
    bool is_verified;
    atca_aes_gcm_ctx_t ctx;
    const aes_gcm_partial_block_vectors* current_vector;
    uint8_t key[] = { 0xb7, 0xcf, 0x6c, 0xf5, 0xe7, 0xf3, 0xca, 0x22, 0x3c, 0xa7, 0x3c, 0x81, 0x9d, 0xcd, 0x62, 0xfe };
    uint8_t iv[] = { 0xa4, 0x13, 0x60, 0x09, 0xc0, 0xa7, 0xfd, 0xac, 0xfe, 0x53, 0xf5, 0x07 };

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, key, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    current_vector = &test_vectors[0];
    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, sizeof(iv));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Add aad to gcm
    status = atcab_aes_gcm_aad_update(&ctx, current_vector->aad, 15);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_aad_update(&ctx, &current_vector->aad[15], 15);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Encrypt data
    status = atcab_aes_gcm_decrypt_update(&ctx, current_vector->ciphertext, 15, plaintext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_decrypt_update(&ctx, &current_vector->ciphertext[15], 15, &plaintext[15]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Calculate authentication tag
    status = atcab_aes_gcm_decrypt_finish(&ctx, current_vector->tag, sizeof(current_vector->tag), &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->plaintext, plaintext, current_vector->text_size);
    TEST_ASSERT(is_verified);

    current_vector = &test_vectors[1];
    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, sizeof(iv));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Add aad to gcm
    status = atcab_aes_gcm_aad_update(&ctx, current_vector->aad, 15);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_aad_update(&ctx, &current_vector->aad[15], 1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Encrypt data
    status = atcab_aes_gcm_decrypt_update(&ctx, current_vector->ciphertext, 15, plaintext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_decrypt_update(&ctx, &current_vector->ciphertext[15], 1, &plaintext[15]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Calculate authentication tag
    status = atcab_aes_gcm_decrypt_finish(&ctx, current_vector->tag, sizeof(current_vector->tag), &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->plaintext, plaintext, current_vector->text_size);
    TEST_ASSERT(is_verified);

    current_vector = &test_vectors[2];
    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, sizeof(iv));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Add aad to gcm
    status = atcab_aes_gcm_aad_update(&ctx, current_vector->aad, 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_aad_update(&ctx, &current_vector->aad[16], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Encrypt data
    status = atcab_aes_gcm_decrypt_update(&ctx, current_vector->ciphertext, 16, plaintext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_decrypt_update(&ctx, &current_vector->ciphertext[16], 16, &plaintext[16]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Calculate authentication tag
    status = atcab_aes_gcm_decrypt_finish(&ctx, current_vector->tag, sizeof(current_vector->tag), &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->plaintext, plaintext, current_vector->text_size);
    TEST_ASSERT(is_verified);

    current_vector = &test_vectors[3];
    //Initialize gcm ctx with IV
    status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, sizeof(iv));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Add aad to gcm
    status = atcab_aes_gcm_aad_update(&ctx, current_vector->aad, 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_aad_update(&ctx, &current_vector->aad[16], 8);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Encrypt data
    status = atcab_aes_gcm_decrypt_update(&ctx, current_vector->ciphertext, 16, plaintext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_gcm_decrypt_update(&ctx, &current_vector->ciphertext[16], 8, &plaintext[16]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Calculate authentication tag
    status = atcab_aes_gcm_decrypt_finish(&ctx, current_vector->tag, sizeof(current_vector->tag), &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(current_vector->plaintext, plaintext, current_vector->text_size);
    TEST_ASSERT(is_verified);
}

TEST(atca_cmd_basic_test, aes_gcm_nist_vectors)
{
    ATCA_STATUS status;
    uint8_t test_index;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t aes_key_block = 0;
    uint8_t ciphertext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint8_t plaintext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint8_t tag[AES_DATA_SIZE];
    bool is_verified;
    atca_aes_gcm_ctx_t ctx;

    check_config_aes_enable();

    for (test_index = 0; test_index < GCM_TEST_VECTORS_COUNT; test_index++)
    {
        // Load AES keys into TempKey
        status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, gcm_test_cases[test_index].key, 32);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //////////////////////////////////////   Encryption /////////////////////////////////////////
        //Initialize gcm ctx with IV
        status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].iv_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Add aad to gcm
        status = atcab_aes_gcm_aad_update(&ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Encrypt data
        status = atcab_aes_gcm_encrypt_update(&ctx, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Verify ciphertext with expected data
        if (gcm_test_cases[test_index].text_size > 0)
        {
            TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].ciphertext, ciphertext, gcm_test_cases[test_index].text_size);
        }

        //Calculate authentication tag
        status = atcab_aes_gcm_encrypt_finish(&ctx, tag, sizeof(tag));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Verify calculated tag
        TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].tag, tag, sizeof(tag));

        // Repeat, but skip unused calls
        if (gcm_test_cases[test_index].aad_size == 0 || gcm_test_cases[test_index].text_size == 0)
        {
            //Initialize gcm ctx with IV
            status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].iv_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add aad to gcm
            if (gcm_test_cases[test_index].aad_size > 0)
            {
                status = atcab_aes_gcm_aad_update(&ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            }

            //Encrypt data
            if (gcm_test_cases[test_index].text_size > 0)
            {
                status = atcab_aes_gcm_encrypt_update(&ctx, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
                TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].ciphertext, ciphertext, gcm_test_cases[test_index].text_size);
            }

            //Calculate authentication tag
            status = atcab_aes_gcm_encrypt_finish(&ctx, tag, sizeof(tag));
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Verify calculated tag
            TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].tag, tag, sizeof(tag));
        }


        //////////////////////////////////////   Decryption /////////////////////////////////////////
        //Initialize gcm ctx with IV
        status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].iv_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Add aad to gcm
        status = atcab_aes_gcm_aad_update(&ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Add ciphertext to gcm
        status = atcab_aes_gcm_decrypt_update(&ctx, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Verify plaintext with expected data
        if (gcm_test_cases[test_index].text_size > 0)
        {
            TEST_ASSERT_EQUAL_MEMORY(plaintext, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size);
        }

        status = atcab_aes_gcm_decrypt_finish(&ctx, gcm_test_cases[test_index].tag, sizeof(tag), &is_verified);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT(is_verified);

        // Repeat, but skip unused calls
        if (gcm_test_cases[test_index].aad_size == 0 || gcm_test_cases[test_index].text_size == 0)
        {
            //Initialize gcm ctx with IV
            status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].iv_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add aad to gcm
            if (gcm_test_cases[test_index].aad_size > 0)
            {
                status = atcab_aes_gcm_aad_update(&ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            }

            //Add ciphertext to gcm
            if (gcm_test_cases[test_index].text_size > 0)
            {
                status = atcab_aes_gcm_decrypt_update(&ctx, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

                //Verify plaintext with expected data
                TEST_ASSERT_EQUAL_MEMORY(plaintext, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size);
            }

            status = atcab_aes_gcm_decrypt_finish(&ctx, gcm_test_cases[test_index].tag, sizeof(tag), &is_verified);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT(is_verified);
        }
    }
}

TEST(atca_cmd_basic_test, aes_gcm_encrypt_cavp_vectors)
{
#ifndef _WIN32
    TEST_IGNORE_MESSAGE("Test only available under windows.");
#else
    ATCA_STATUS status;
    FILE* req_file = NULL;
    FILE* rsp_file = NULL;
    uint8_t line[255];
    char *str, *name_value;
    uint8_t key[128], iv[128], pt[128], ct[128], aad[128];
    size_t key_size, iv_size;
    uint32_t text_size, aad_size;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t aes_key_block = 0;
    uint8_t cal_tag[AES_DATA_SIZE];
    size_t i;
    uint16_t test_count = 0;
    atca_aes_gcm_ctx_t ctx;

    check_config_aes_enable();

    req_file = fopen("aes_gcm_cavp_vectors/gcmEncryptExtIV128.req", "r");
    TEST_ASSERT_NOT_NULL_MESSAGE(req_file, "Failed to open .req file");

    rsp_file = fopen("aes_gcm_cavp_vectors/gcmEncryptExtIV128.rsp", "w");
    TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open .rsp file");

    time_t current_time;
    current_time = time(NULL);
    fprintf(rsp_file, "# Executed Vectors on %s", ctime(&current_time));

    do
    {
        if (NULL == (str = fgets(line, sizeof(line), req_file)))
        {
            continue;
        }

        fputs(str, rsp_file);
        if (!memcmp(str, "Key = ", strlen("Key = ")))
        {
            name_value = &line[strlen("Key = ")];
            key_size = strlen(name_value) / 2;
            hex_to_data(name_value, key, key_size);
        }
        else if (!memcmp(str, "IV = ", strlen("IV = ")))
        {
            name_value = &line[strlen("IV = ")];
            iv_size = strlen(name_value) / 2;
            hex_to_data(name_value, iv, iv_size);
        }
        else if (!memcmp(str, "PT = ", strlen("PT = ")))
        {
            name_value = &line[strlen("PT = ")];
            text_size = (uint32_t)strlen(name_value) / 2;
            hex_to_data(name_value, pt, text_size);
        }
        else if (!memcmp(str, "AAD = ", strlen("AAD = ")))
        {
            name_value = &line[strlen("AAD = ")];
            aad_size = (uint32_t)strlen(name_value) / 2;
            hex_to_data(name_value, aad, aad_size);

#ifdef ATCA_PRINTF
            //Process read vector
            printf("%04d\r", test_count++);
#endif
            // Load AES keys into TempKey
            status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, key, 32);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Initialize gcm ctx with IV
            status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, iv_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add aad to gcm
            status = atcab_aes_gcm_aad_update(&ctx, aad, aad_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add plaintext to gcm
            status = atcab_aes_gcm_encrypt_update(&ctx, pt, text_size, ct);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Finish encrypt and get tag
            status = atcab_aes_gcm_encrypt_finish(&ctx, cal_tag, sizeof(cal_tag));
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            fputs("CT = ", rsp_file);
            for (i = 0; i < text_size; i++)
            {
                fprintf(rsp_file, "%02x", ct[i]);
            }
            fputs("\n", rsp_file);

            fputs("Tag = ", rsp_file);
            for (i = 0; i < AES_DATA_SIZE; i++)
            {
                fprintf(rsp_file, "%02x", cal_tag[i]);
            }
            fputs("\n", rsp_file);
        }


    }
    while (!feof(req_file));

    fclose(req_file);
    fclose(rsp_file);
#ifdef ATCA_PRINTF
    printf("\n");
#endif
#endif
}

TEST(atca_cmd_basic_test, aes_gcm_decrypt_cavp_vectors)
{
#ifndef _WIN32
    TEST_IGNORE_MESSAGE("Test only available under windows.");
#else
    ATCA_STATUS status;
    FILE* req_file = NULL;
    FILE* rsp_file = NULL;
    uint8_t line[255];
    char *str, *name_value;
    uint8_t key[128], iv[128], pt[128], ct[128], aad[128], tag[128];
    size_t key_size, iv_size, tag_size;
    uint32_t text_size, aad_size;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t aes_key_block = 0;
    size_t i;
    bool is_verified;
    uint16_t test_count = 0;
    atca_aes_gcm_ctx_t ctx;

    check_config_aes_enable();

    req_file = fopen("aes_gcm_cavp_vectors/gcmDecrypt128.req", "r");
    TEST_ASSERT_NOT_NULL_MESSAGE(req_file, "Failed to open .req file");

    rsp_file = fopen("aes_gcm_cavp_vectors/gcmDecrypt128.rsp", "w");
    TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open .rsp file");

    time_t current_time;
    current_time = time(NULL);
    fprintf(rsp_file, "# Executed Vectors on %s", ctime(&current_time));

    do
    {
        if (NULL == (str = fgets(line, sizeof(line), req_file)))
        {
            continue;
        }

        fputs(str, rsp_file);
        if (!memcmp(str, "Key = ", strlen("Key = ")))
        {
            name_value = &line[strlen("Key = ")];
            key_size = strlen(name_value) / 2;
            hex_to_data(name_value, key, key_size);
        }
        else if (!memcmp(str, "IV = ", strlen("IV = ")))
        {
            name_value = &line[strlen("IV = ")];
            iv_size = strlen(name_value) / 2;
            hex_to_data(name_value, iv, iv_size);
        }
        else if (!memcmp(str, "CT = ", strlen("CT = ")))
        {
            name_value = &line[strlen("CT = ")];
            text_size = (uint32_t)strlen(name_value) / 2;
            hex_to_data(name_value, ct, text_size);
        }
        else if (!memcmp(str, "AAD = ", strlen("AAD = ")))
        {
            name_value = &line[strlen("AAD = ")];
            aad_size = (uint32_t)strlen(name_value) / 2;
            hex_to_data(name_value, aad, aad_size);
        }
        else if (!memcmp(str, "Tag = ", strlen("Tag = ")))
        {
            name_value = &line[strlen("Tag = ")];
            tag_size = strlen(name_value) / 2;
            hex_to_data(name_value, tag, tag_size);

#ifdef ATCA_PRINTF
            //Process read vector
            printf("%04d\r", test_count++);
#endif
            // Load AES keys into TempKey
            status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, key, 32);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Initialize gcm ctx with IV
            status = atcab_aes_gcm_init(&ctx, key_id, aes_key_block, iv, iv_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add aad to gcm
            status = atcab_aes_gcm_aad_update(&ctx, aad, aad_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add cipher to gcm
            status = atcab_aes_gcm_decrypt_update(&ctx, ct, text_size, pt);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Complete GCM decrypt and validate tag
            status = atcab_aes_gcm_decrypt_finish(&ctx, tag, tag_size, &is_verified);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            if (!is_verified)
            {
                fputs("FAIL\n", rsp_file);
            }
            else
            {
                fputs("PT = ", rsp_file);
                for (i = 0; i < text_size; i++)
                {
                    fprintf(rsp_file, "%02x", pt[i]);
                }
                fputs("\n", rsp_file);
            }
        }
    }
    while (!feof(req_file));

    fclose(req_file);
    fclose(rsp_file);
#ifdef ATCA_PRINTF
    printf("\n");
#endif
#endif
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info aes_gcm_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gcm_nist_vectors),             DEVICE_MASK(ATECC608)  },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gcm_encrypt_partial_blocks),   DEVICE_MASK(ATECC608)  },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gcm_decrypt_partial_blocks),   DEVICE_MASK(ATECC608)  },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gcm_encrypt_cavp_vectors),     DEVICE_MASK(ATECC608)  },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gcm_decrypt_cavp_vectors),     DEVICE_MASK(ATECC608)  },
    { (fp_test_case)NULL,                     (uint8_t)0 },             /* Array Termination element*/
};

// *INDENT-ON*

#else
t_test_case_info aes_gcm_basic_test_info[] =
{
    { (fp_test_case)NULL,                     (uint8_t)0 },             /* Array Termination element*/
};
#endif
