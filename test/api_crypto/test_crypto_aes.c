/**
 * \file
 * \brief Tests for the CryptoAuthLib software crypto API.
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

#include "test_crypto.h"

#if defined(ATCA_OPENSSL) || defined(ATCA_MBEDTLS) || defined(ATCA_WOLFSSL)

#include "vectors/aes_gcm_nist_vectors.h"
#include "vectors/aes_cmac_nist_vectors.h"

TEST_GROUP(atcac_aes);

TEST_SETUP(atcac_aes)
{
    UnityMalloc_StartTest();
}

TEST_TEAR_DOWN(atcac_aes)
{
    UnityMalloc_EndTest();
}

TEST(atcac_aes, aes128_gcm_nist)
{
    ATCA_STATUS status;
    uint8_t test_index;
    uint8_t ciphertext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    uint8_t plaintext[GCM_TEST_VECTORS_DATA_SIZE_MAX];

#ifndef ATCA_WOLFSSL
    size_t ct_size;
    size_t pt_size;
#endif
    uint8_t tag[AES_DATA_SIZE];
    bool is_verified;
    struct atcac_aes_gcm_ctx * ctx;
#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    ctx = atcac_aes_gcm_ctx_new();
#else
    atcac_aes_gcm_ctx_t gcm_ctx;
    ctx = &pkey_ctx_inst;
#endif

    for (test_index = 0; test_index < GCM_TEST_VECTORS_COUNT; test_index++)
    {
        if (test_index == 13)
        {
            continue;
        }

        //////////////////////////////////////   Encryption /////////////////////////////////////////
        status = atcac_aes_gcm_encrypt_start(ctx, gcm_test_cases[test_index].key, 16, gcm_test_cases[test_index].iv, (uint8_t)gcm_test_cases[test_index].iv_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_WOLFSSL
        status = atcac_aes_gcm_encrypt(ctx, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext,
                                       tag, sizeof(tag), gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        //Add aad to gcm
        status = atcac_aes_gcm_aad_update(ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Encrypt data
        ct_size = GCM_TEST_VECTORS_DATA_SIZE_MAX;
        status = atcac_aes_gcm_encrypt_update(ctx, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext, &ct_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
        //Verify ciphertext with expected data
        if (gcm_test_cases[test_index].text_size > 0)
        {
            TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].ciphertext, ciphertext, gcm_test_cases[test_index].text_size);
        }

#ifndef ATCA_WOLFSSL
        //Calculate authentication tag
        status = atcac_aes_gcm_encrypt_finish(ctx, tag, sizeof(tag));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif

        //Verify calculated tag
        TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].tag, tag, sizeof(tag));

#ifndef ATCA_WOLFSSL
        // Repeat, but skip unused calls
        if (gcm_test_cases[test_index].aad_size == 0 || gcm_test_cases[test_index].text_size == 0)
        {
            //Initialize gcm ctx with IV
            status = atcac_aes_gcm_encrypt_start(ctx, gcm_test_cases[test_index].key, 16, gcm_test_cases[test_index].iv, (uint8_t)gcm_test_cases[test_index].iv_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add aad to gcm
            status = atcac_aes_gcm_aad_update(ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Encrypt data
            if (gcm_test_cases[test_index].text_size > 0)
            {
                ct_size = GCM_TEST_VECTORS_DATA_SIZE_MAX;
                status = atcac_aes_gcm_encrypt_update(ctx, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext, &ct_size);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
                TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].ciphertext, ciphertext, gcm_test_cases[test_index].text_size);
            }

            //Calculate authentication tag
            status = atcac_aes_gcm_encrypt_finish(ctx, tag, sizeof(tag));
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Verify calculated tag
            TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].tag, tag, sizeof(tag));
        }
#endif


        //////////////////////////////////////   Decryption /////////////////////////////////////////
        //Initialize gcm ctx with IV
        status = atcac_aes_gcm_decrypt_start(ctx, gcm_test_cases[test_index].key, 16, gcm_test_cases[test_index].iv, (uint8_t)gcm_test_cases[test_index].iv_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_WOLFSSL
        status = atcac_aes_gcm_decrypt(ctx, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext, tag, sizeof(tag),
                                       gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size, &is_verified);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else

        //Add aad to gcm
        status = atcac_aes_gcm_aad_update(ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Add ciphertext to gcm
        pt_size = GCM_TEST_VECTORS_DATA_SIZE_MAX;
        status = atcac_aes_gcm_decrypt_update(ctx, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext, &pt_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
        //Verify plaintext with expected data
        if (gcm_test_cases[test_index].text_size > 0)
        {
            TEST_ASSERT_EQUAL_MEMORY(plaintext, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size);
        }

#ifndef ATCA_WOLFSSL
        status = atcac_aes_gcm_decrypt_finish(ctx, gcm_test_cases[test_index].tag, sizeof(tag), &is_verified);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
        TEST_ASSERT(is_verified);

#ifndef ATCA_WOLFSSL
        // Repeat, but skip unused calls
        if (gcm_test_cases[test_index].aad_size == 0 || gcm_test_cases[test_index].text_size == 0)
        {
            //Initialize gcm ctx with IV
            status = atcac_aes_gcm_decrypt_start(ctx, gcm_test_cases[test_index].key, 16, gcm_test_cases[test_index].iv, (uint8_t)gcm_test_cases[test_index].iv_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add aad to gcm
            status = atcac_aes_gcm_aad_update(ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add ciphertext to gcm
            if (gcm_test_cases[test_index].text_size > 0)
            {
                pt_size = GCM_TEST_VECTORS_DATA_SIZE_MAX;
                status = atcac_aes_gcm_decrypt_update(ctx, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext, &pt_size);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

                //Verify plaintext with expected data
                TEST_ASSERT_EQUAL_MEMORY(plaintext, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size);
            }

            status = atcac_aes_gcm_decrypt_finish(ctx, gcm_test_cases[test_index].tag, sizeof(tag), &is_verified);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT(is_verified);
        }
#endif
    }

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    if (NULL != ctx)
    {
        atcac_aes_gcm_ctx_free(ctx);
    }
#endif
}

TEST(atcac_aes, aes128_cmac_nist)
{
    ATCA_STATUS status = 0;
    uint8_t key_block = 0;
    size_t msg_index = 0;
    uint8_t cmac[AES_DATA_SIZE];
    size_t cmac_size;

    struct atcac_aes_cmac_ctx * ctx;

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    ctx = atcac_aes_cmac_ctx_new();
#else
    atcac_aes_cmac_ctx_t cmac_ctx;
    ctx = &cmac_ctx;
#endif

    for (key_block = 0; key_block < 4; key_block++)
    {
        for (msg_index = 0; msg_index < sizeof(g_cmac_msg_sizes) / sizeof(g_cmac_msg_sizes[0]); msg_index++)
        {
            status = atcac_aes_cmac_init(ctx, g_aes_keys[key_block], 16);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            status = atcac_aes_cmac_update(ctx, g_plaintext, g_cmac_msg_sizes[msg_index]);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            cmac_size = sizeof(cmac);
            status = atcac_aes_cmac_finish(ctx, cmac, &cmac_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(g_cmacs[key_block][msg_index], cmac, sizeof(cmac));
        }
    }
#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    if (NULL != ctx)
    {
        atcac_aes_cmac_ctx_free(ctx);
    }
#endif
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info atcac_aes_test_info[] =
{
    { REGISTER_TEST_CASE(atcac_aes, aes128_gcm_nist),           NULL },
    { REGISTER_TEST_CASE(atcac_aes, aes128_cmac_nist),          NULL },
    { (fp_test_case)NULL, NULL },         /* Array Termination element*/
};
// *INDENT-ON*

#endif
