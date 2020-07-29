/**
 * \file
 * \brief Unity tests for the CryptoAuthLib software crypto API.
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

#ifdef _WIN32
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#include "atca_crypto_sw_tests.h"
#include "crypto/atca_crypto_sw.h"
#include "crypto/atca_crypto_sw_sha1.h"
#include "crypto/atca_crypto_sw_sha2.h"


#include "vectors/aes_gcm_nist_vectors.h"
#include "vectors/aes_cmac_nist_vectors.h"

static const uint8_t nist_hash_msg1[] = "abc";
static const uint8_t nist_hash_msg2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
static const uint8_t nist_hash_msg3[] = "a";

int atca_crypto_sw_tests(int argc, char * argv[])
{
    UnityBegin("atca_crypto_sw_tests.c");

    RUN_TEST(test_atcac_sw_sha1_nist1);
    RUN_TEST(test_atcac_sw_sha1_nist2);
    RUN_TEST(test_atcac_sw_sha1_nist3);
    RUN_TEST(test_atcac_sw_sha1_nist_short);
    RUN_TEST(test_atcac_sw_sha1_nist_long);
    RUN_TEST(test_atcac_sw_sha1_nist_monte);


    RUN_TEST(test_atcac_sw_sha2_256_nist1);
    RUN_TEST(test_atcac_sw_sha2_256_nist2);
    RUN_TEST(test_atcac_sw_sha2_256_nist3);
    RUN_TEST(test_atcac_sw_sha2_256_nist_short);
    RUN_TEST(test_atcac_sw_sha2_256_nist_long);
    RUN_TEST(test_atcac_sw_sha2_256_nist_monte);

    RUN_TEST(test_atcac_aes128_gcm);
    RUN_TEST(test_atcac_aes128_cmac);
    RUN_TEST(test_atcac_sha256_hmac);
    RUN_TEST(test_atcac_sha256_hmac_nist);

    return UnityEnd();
}

void test_atcac_sw_sha1_nist1(void)
{
    const uint8_t digest_ref[] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d
    };
    uint8_t digest[ATCA_SHA1_DIGEST_SIZE];
    int ret;

    TEST_ASSERT_EQUAL(ATCA_SHA1_DIGEST_SIZE, sizeof(digest_ref));

    ret = atcac_sw_sha1(nist_hash_msg1, sizeof(nist_hash_msg1) - 1, digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(digest_ref, digest, sizeof(digest_ref));
}

void test_atcac_sw_sha1_nist2(void)
{
    const uint8_t digest_ref[] = {
        0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5,
        0xe5, 0x46, 0x70, 0xf1
    };
    uint8_t digest[ATCA_SHA1_DIGEST_SIZE];
    int ret;

    TEST_ASSERT_EQUAL(ATCA_SHA1_DIGEST_SIZE, sizeof(digest_ref));

    ret = atcac_sw_sha1(nist_hash_msg2, sizeof(nist_hash_msg2) - 1, digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(digest_ref, digest, sizeof(digest_ref));
}

void test_atcac_sw_sha1_nist3(void)
{
    const uint8_t digest_ref[] = {
        0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31,
        0x65, 0x34, 0x01, 0x6f
    };
    uint8_t digest[ATCA_SHA1_DIGEST_SIZE];
    int ret;
    atcac_sha1_ctx ctx;
    uint32_t i;

    TEST_ASSERT_EQUAL(ATCA_SHA1_DIGEST_SIZE, sizeof(digest_ref));

    ret = atcac_sw_sha1_init(&ctx);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    for (i = 0; i < 1000000; i++)
    {
        ret = atcac_sw_sha1_update(&ctx, nist_hash_msg3, 1);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    }
    ret = atcac_sw_sha1_finish(&ctx, digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(digest_ref, digest, sizeof(digest_ref));
}

#ifdef _WIN32
static void hex_to_uint8(const char hex_str[2], uint8_t* num)
{
    *num = 0;

    if (hex_str[0] >= '0' && hex_str[0] <= '9')
    {
        *num += (hex_str[0] - '0') << 4;
    }
    else if (hex_str[0] >= 'A' && hex_str[0] <= 'F')
    {
        *num += (hex_str[0] - 'A' + 10) << 4;
    }
    else if (hex_str[0] >= 'a' && hex_str[0] <= 'f')
    {
        *num += (hex_str[0] - 'a' + 10) << 4;
    }
    else
    {
        TEST_FAIL_MESSAGE("Not a hex digit.");
    }

    if (hex_str[1] >= '0' && hex_str[1] <= '9')
    {
        *num += (hex_str[1] - '0');
    }
    else if (hex_str[1] >= 'A' && hex_str[1] <= 'F')
    {
        *num += (hex_str[1] - 'A' + 10);
    }
    else if (hex_str[1] >= 'a' && hex_str[1] <= 'f')
    {
        *num += (hex_str[1] - 'a' + 10);
    }
    else
    {
        TEST_FAIL_MESSAGE("Not a hex digit.");
    }
}

static void hex_to_data(const char* hex_str, uint8_t* data, size_t data_size)
{
    size_t i = 0;

    TEST_ASSERT_EQUAL_MESSAGE(data_size * 2, strlen(hex_str) - 1, "Hex string unexpected length.");

    for (i = 0; i < data_size; i++)
    {
        hex_to_uint8(&hex_str[i * 2], &data[i]);
    }
}

static int read_rsp_hex_value(FILE* file, const char* name, uint8_t* data, size_t data_size)
{
    char line[16384];
    char* str = NULL;
    size_t name_size = strlen(name);

    do
    {
        str = fgets(line, sizeof(line), file);
        if (str == NULL)
        {
            continue;
        }

        if (memcmp(line, name, name_size) == 0)
        {
            str = &line[name_size];
        }
        else
        {
            str = NULL;
        }
    }
    while (str == NULL && !feof(file));
    if (str == NULL)
    {
        return ATCA_GEN_FAIL;
    }
    hex_to_data(str, data, data_size);

    return ATCA_SUCCESS;
}

static int read_rsp_int_value(FILE* file, const char* name, int* value)
{
    char line[2048];
    char* str = NULL;
    size_t name_size = strlen(name);

    do
    {
        str = fgets(line, sizeof(line), file);
        if (str == NULL)
        {
            continue;
        }

        if (memcmp(line, name, name_size) == 0)
        {
            str = &line[name_size];
        }
        else
        {
            str = NULL;
        }
    }
    while (str == NULL && !feof(file));
    if (str == NULL)
    {
        return ATCA_GEN_FAIL;
    }
    *value = atoi(str);

    return ATCA_SUCCESS;
}

#endif

static void test_atcac_sw_sha1_nist_simple(const char* filename)
{
#ifndef _WIN32
    TEST_IGNORE_MESSAGE("Test only available under windows.");
#else
    FILE* rsp_file = NULL;
    int ret = ATCA_SUCCESS;
    uint8_t md_ref[ATCA_SHA1_DIGEST_SIZE];
    uint8_t md[sizeof(md_ref)];
    int len_bits = 0;
    uint8_t* msg = NULL;
    size_t count = 0;

    rsp_file = fopen(filename, "r");
    TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open file");

    do
    {
        ret = read_rsp_int_value(rsp_file, "Len = ", &len_bits);
        if (ret != ATCA_SUCCESS)
        {
            continue;
        }

        msg = malloc(len_bits == 0 ? 1 : len_bits / 8);
        TEST_ASSERT_NOT_NULL_MESSAGE(msg, "malloc failed");

        ret = read_rsp_hex_value(rsp_file, "Msg = ", msg, len_bits == 0 ? 1 : len_bits / 8);
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = read_rsp_hex_value(rsp_file, "MD = ", md_ref, sizeof(md_ref));
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = atcac_sw_sha1(msg, len_bits / 8, md);
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);
        TEST_ASSERT_EQUAL_MEMORY(md_ref, md, sizeof(md_ref));

        free(msg);
        msg = NULL;
        count++;
    }
    while (ret == ATCA_SUCCESS);
    TEST_ASSERT_MESSAGE(count > 0, "No long tests found in file.");
#endif
}

void test_atcac_sw_sha1_nist_short(void)
{
    test_atcac_sw_sha1_nist_simple("sha-byte-test-vectors/SHA1ShortMsg.rsp");
}

void test_atcac_sw_sha1_nist_long(void)
{
    test_atcac_sw_sha1_nist_simple("sha-byte-test-vectors/SHA1LongMsg.rsp");
}

void test_atcac_sw_sha1_nist_monte(void)
{
#ifndef _WIN32
    TEST_IGNORE_MESSAGE("Test only available under windows.");
#else
    FILE* rsp_file = NULL;
    int ret = ATCA_SUCCESS;
    uint8_t seed[ATCA_SHA1_DIGEST_SIZE];
    uint8_t md[4][sizeof(seed)];
    int i, j;
    uint8_t m[sizeof(seed) * 3];
    uint8_t md_ref[sizeof(seed)];

    rsp_file = fopen("sha-byte-test-vectors/SHA1Monte.rsp", "r");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(NULL, rsp_file, "Failed to open sha-byte-test-vectors/SHA1Monte.rsp");

    // Find the seed value
    ret = read_rsp_hex_value(rsp_file, "Seed = ", seed, sizeof(seed));
    TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, ret, "Failed to find Seed value in file.");

    for (j = 0; j < 100; j++)
    {
        memcpy(&md[0], seed, sizeof(seed));
        memcpy(&md[1], seed, sizeof(seed));
        memcpy(&md[2], seed, sizeof(seed));
        for (i = 0; i < 1000; i++)
        {
            memcpy(m, md, sizeof(m));
            ret = atcac_sw_sha1(m, sizeof(m), &md[3][0]);
            TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, ret, "atcac_sw_sha1 failed");
            memmove(&md[0], &md[1], sizeof(seed) * 3);
        }
        ret = read_rsp_hex_value(rsp_file, "MD = ", md_ref, sizeof(md_ref));
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, ret, "Failed to find MD value in file.");
        TEST_ASSERT_EQUAL_MEMORY(md_ref, &md[2], sizeof(md_ref));
        memcpy(seed, &md[2], sizeof(seed));
    }
#endif
}



void test_atcac_sw_sha2_256_nist1(void)
{
    const uint8_t digest_ref[] = {
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
        0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD
    };
    uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE];
    int ret;

    TEST_ASSERT_EQUAL(ATCA_SHA2_256_DIGEST_SIZE, sizeof(digest_ref));

    ret = atcac_sw_sha2_256(nist_hash_msg1, sizeof(nist_hash_msg1) - 1, digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(digest_ref, digest, sizeof(digest_ref));
}

void test_atcac_sw_sha2_256_nist2(void)
{
    const uint8_t digest_ref[] = {
        0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60, 0x39,
        0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB, 0x06, 0xC1
    };
    uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE];
    int ret;

    TEST_ASSERT_EQUAL(ATCA_SHA2_256_DIGEST_SIZE, sizeof(digest_ref));

    ret = atcac_sw_sha2_256(nist_hash_msg2, sizeof(nist_hash_msg2) - 1, digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(digest_ref, digest, sizeof(digest_ref));
}

void test_atcac_sw_sha2_256_nist3(void)
{
    const uint8_t digest_ref[] = {
        0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92, 0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7, 0x3E, 0x67,
        0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E, 0x04, 0x6D, 0x39, 0xCC, 0xC7, 0x11, 0x2C, 0xD0
    };
    uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE];
    int ret;
    atcac_sha2_256_ctx ctx;
    uint32_t i;

    TEST_ASSERT_EQUAL(ATCA_SHA2_256_DIGEST_SIZE, sizeof(digest_ref));

    ret = atcac_sw_sha2_256_init(&ctx);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    for (i = 0; i < 1000000; i++)
    {
        ret = atcac_sw_sha2_256_update(&ctx, nist_hash_msg3, 1);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    }
    ret = atcac_sw_sha2_256_finish(&ctx, digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(digest_ref, digest, sizeof(digest_ref));
}

static void test_atcac_sw_sha2_256_nist_simple(const char* filename)
{
#ifndef _WIN32
    TEST_IGNORE_MESSAGE("Test only available under windows.");
#else
    FILE* rsp_file = NULL;
    int ret = ATCA_SUCCESS;
    uint8_t md_ref[ATCA_SHA2_256_DIGEST_SIZE];
    uint8_t md[sizeof(md_ref)];
    int len_bits = 0;
    uint8_t* msg = NULL;
    size_t count = 0;

    rsp_file = fopen(filename, "r");
    TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open file");

    do
    {
        ret = read_rsp_int_value(rsp_file, "Len = ", &len_bits);
        if (ret != ATCA_SUCCESS)
        {
            continue;
        }

        msg = malloc(len_bits == 0 ? 1 : len_bits / 8);
        TEST_ASSERT_NOT_NULL_MESSAGE(msg, "malloc failed");

        ret = read_rsp_hex_value(rsp_file, "Msg = ", msg, len_bits == 0 ? 1 : len_bits / 8);
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = read_rsp_hex_value(rsp_file, "MD = ", md_ref, sizeof(md_ref));
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = atcac_sw_sha2_256(msg, len_bits / 8, md);
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);
        TEST_ASSERT_EQUAL_MEMORY(md_ref, md, sizeof(md_ref));

        free(msg);
        msg = NULL;
        count++;
    }
    while (ret == ATCA_SUCCESS);
    TEST_ASSERT_MESSAGE(count > 0, "No long tests found in file.");
#endif
}

void test_atcac_sw_sha2_256_nist_short(void)
{
    test_atcac_sw_sha2_256_nist_simple("sha-byte-test-vectors/SHA256ShortMsg.rsp");
}

void test_atcac_sw_sha2_256_nist_long(void)
{
    test_atcac_sw_sha2_256_nist_simple("sha-byte-test-vectors/SHA256LongMsg.rsp");
}

void test_atcac_sw_sha2_256_nist_monte(void)
{
#ifndef _WIN32
    TEST_IGNORE_MESSAGE("Test only available under windows.");
#else
    FILE* rsp_file = NULL;
    int ret = ATCA_SUCCESS;
    uint8_t seed[ATCA_SHA2_256_DIGEST_SIZE];
    uint8_t md[4][sizeof(seed)];
    int i, j;
    uint8_t m[sizeof(seed) * 3];
    uint8_t md_ref[sizeof(seed)];

    rsp_file = fopen("sha-byte-test-vectors/SHA256Monte.rsp", "r");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(NULL, rsp_file, "Failed to open sha-byte-test-vectors/SHA256Monte.rsp");

    // Find the seed value
    ret = read_rsp_hex_value(rsp_file, "Seed = ", seed, sizeof(seed));
    TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, ret, "Failed to find Seed value in file.");

    for (j = 0; j < 100; j++)
    {
        memcpy(&md[0], seed, sizeof(seed));
        memcpy(&md[1], seed, sizeof(seed));
        memcpy(&md[2], seed, sizeof(seed));
        for (i = 0; i < 1000; i++)
        {
            memcpy(m, md, sizeof(m));
            ret = atcac_sw_sha2_256(m, sizeof(m), &md[3][0]);
            TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, ret, "atcac_sw_sha1 failed");
            memmove(&md[0], &md[1], sizeof(seed) * 3);
        }
        ret = read_rsp_hex_value(rsp_file, "MD = ", md_ref, sizeof(md_ref));
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, ret, "Failed to find MD value in file.");
        TEST_ASSERT_EQUAL_MEMORY(md_ref, &md[2], sizeof(md_ref));
        memcpy(seed, &md[2], sizeof(seed));
    }
#endif
}

#if defined(ATCA_OPENSSL) || defined(ATCA_MBEDTLS) || defined(ATCA_WOLFSSL)

void test_atcac_aes128_gcm(void)
{
    ATCA_STATUS status;
    uint8_t test_index;
    uint8_t aes_key_block = 0;
    uint8_t ciphertext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    size_t ct_size;
    uint8_t plaintext[GCM_TEST_VECTORS_DATA_SIZE_MAX];
    size_t pt_size;
    uint8_t tag[AES_DATA_SIZE];
    bool is_verified;
    atcac_aes_gcm_ctx ctx;


    for (test_index = 0; test_index < GCM_TEST_VECTORS_COUNT; test_index++)
    {

        //////////////////////////////////////   Encryption /////////////////////////////////////////
        status = atcac_aes_gcm_encrypt_start(&ctx, gcm_test_cases[test_index].key, 16, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].iv_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_WOLFSSL
        status = atcac_aes_gcm_encrypt(&ctx, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext,
                                       tag, sizeof(tag), gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        //Add aad to gcm
        status = atcac_aes_gcm_aad_update(&ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Encrypt data
        ct_size = GCM_TEST_VECTORS_DATA_SIZE_MAX;
        status = atcac_aes_gcm_encrypt_update(&ctx, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext, &ct_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
        //Verify ciphertext with expected data
        if (gcm_test_cases[test_index].text_size > 0)
        {
            TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].ciphertext, ciphertext, gcm_test_cases[test_index].text_size);
        }

#ifndef ATCA_WOLFSSL
        //Calculate authentication tag
        status = atcac_aes_gcm_encrypt_finish(&ctx, tag, sizeof(tag));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif

        //Verify calculated tag
        TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].tag, tag, sizeof(tag));

#ifndef ATCA_WOLFSSL
        // Repeat, but skip unused calls
        if (gcm_test_cases[test_index].aad_size == 0 || gcm_test_cases[test_index].text_size == 0)
        {
            //Initialize gcm ctx with IV
            status = atcac_aes_gcm_encrypt_start(&ctx, gcm_test_cases[test_index].key, 16, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].iv_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add aad to gcm
            if (gcm_test_cases[test_index].aad_size > 0)
            {
                status = atcac_aes_gcm_aad_update(&ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            }

            //Encrypt data
            if (gcm_test_cases[test_index].text_size > 0)
            {
                ct_size = GCM_TEST_VECTORS_DATA_SIZE_MAX;
                status = atcac_aes_gcm_encrypt_update(&ctx, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size, ciphertext, &ct_size);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
                TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].ciphertext, ciphertext, gcm_test_cases[test_index].text_size);
            }

            //Calculate authentication tag
            status = atcac_aes_gcm_encrypt_finish(&ctx, tag, sizeof(tag));
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Verify calculated tag
            TEST_ASSERT_EQUAL_MEMORY(gcm_test_cases[test_index].tag, tag, sizeof(tag));
        }
#endif


        //////////////////////////////////////   Decryption /////////////////////////////////////////
        //Initialize gcm ctx with IV
        status = atcac_aes_gcm_decrypt_start(&ctx, gcm_test_cases[test_index].key, 16, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].iv_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_WOLFSSL
        status = atcac_aes_gcm_decrypt(&ctx, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext, tag, sizeof(tag),
                                       gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size, &is_verified);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else

        //Add aad to gcm
        status = atcac_aes_gcm_aad_update(&ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Add ciphertext to gcm
        pt_size = GCM_TEST_VECTORS_DATA_SIZE_MAX;
        status = atcac_aes_gcm_decrypt_update(&ctx, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext, &pt_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
        //Verify plaintext with expected data
        if (gcm_test_cases[test_index].text_size > 0)
        {
            TEST_ASSERT_EQUAL_MEMORY(plaintext, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size);
        }

#ifndef ATCA_WOLFSSL
        status = atcac_aes_gcm_decrypt_finish(&ctx, gcm_test_cases[test_index].tag, sizeof(tag), &is_verified);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
        TEST_ASSERT(is_verified);

#ifndef ATCA_WOLFSSL
        // Repeat, but skip unused calls
        if (gcm_test_cases[test_index].aad_size == 0 || gcm_test_cases[test_index].text_size == 0)
        {
            //Initialize gcm ctx with IV
            status = atcac_aes_gcm_decrypt_start(&ctx, gcm_test_cases[test_index].key, 16, gcm_test_cases[test_index].iv, gcm_test_cases[test_index].iv_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            //Add aad to gcm
//            if (gcm_test_cases[test_index].aad_size > 0)
            {
                status = atcac_aes_gcm_aad_update(&ctx, gcm_test_cases[test_index].aad, gcm_test_cases[test_index].aad_size);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            }

            //Add ciphertext to gcm
            if (gcm_test_cases[test_index].text_size > 0)
            {
                pt_size = GCM_TEST_VECTORS_DATA_SIZE_MAX;
                status = atcac_aes_gcm_decrypt_update(&ctx, gcm_test_cases[test_index].ciphertext, gcm_test_cases[test_index].text_size, plaintext, &pt_size);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

                //Verify plaintext with expected data
                TEST_ASSERT_EQUAL_MEMORY(plaintext, gcm_test_cases[test_index].plaintext, gcm_test_cases[test_index].text_size);
            }

            status = atcac_aes_gcm_decrypt_finish(&ctx, gcm_test_cases[test_index].tag, sizeof(tag), &is_verified);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT(is_verified);
        }
#endif
    }
}

void test_atcac_aes128_cmac(void)
{
    ATCA_STATUS status = 0;
    atcac_aes_cmac_ctx ctx;
    uint8_t key_block = 0;
    size_t msg_index = 0;
    uint8_t cmac[AES_DATA_SIZE];
    size_t cmac_size;

    for (key_block = 0; key_block < 4; key_block++)
    {
        for (msg_index = 0; msg_index < sizeof(g_cmac_msg_sizes) / sizeof(g_cmac_msg_sizes[0]); msg_index++)
        {
            status = atcac_aes_cmac_init(&ctx, g_aes_keys[key_block], 16);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            status = atcac_aes_cmac_update(&ctx, g_plaintext, g_cmac_msg_sizes[msg_index]);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            cmac_size = sizeof(cmac);
            status = atcac_aes_cmac_finish(&ctx, cmac, &cmac_size);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(g_cmacs[key_block][msg_index], cmac, sizeof(cmac));
        }
    }
}
#else
void test_atcac_aes128_gcm(void)
{
};
void test_atcac_aes128_cmac(void)
{
};
#endif

#define ATCA_SHA_DIGEST_SIZE        32

void test_atcac_sha256_hmac(void)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t hmac[ATCA_SHA_DIGEST_SIZE];
    size_t hmac_size;
    uint8_t data_input[] = {
        0x6f, 0xb3, 0xec, 0x66, 0xf9, 0xeb, 0x07, 0x0a,
        0x71, 0x9b, 0xeb, 0xbe, 0x70, 0x8b, 0x93, 0xa6,
        0x5b, 0x20, 0x1b, 0x78, 0xe2, 0xd2, 0x6d, 0x8c,
        0xcc, 0xdf, 0x1c, 0x33, 0xf7, 0x41, 0x90, 0x4a,
        0x9a, 0xde, 0x64, 0x0f, 0xce, 0x00, 0x0c, 0x33,
        0x4d, 0x04, 0xbb, 0x30, 0x79, 0x56, 0x83, 0xdc,
        0xa0, 0x9d, 0xbf, 0x3e, 0x7e, 0x32, 0xae, 0xa1,
        0x03, 0xd7, 0x60, 0xe8, 0x57, 0xa6, 0xd6, 0x21,
        0x1c
    };
    const uint8_t hmac_ref[ATCA_SHA_DIGEST_SIZE] = {
        0x29, 0x7f, 0x22, 0xb8, 0xd2, 0x51, 0xb0, 0x63,
        0xa7, 0xc0, 0x8d, 0xcf, 0x4d, 0xba, 0x0d, 0x1f,
        0xb3, 0x5d, 0x32, 0xa3, 0xba, 0xab, 0x15, 0xac,
        0xea, 0xf4, 0x39, 0x1c, 0x4a, 0xdb, 0x32, 0x77
    };

    const uint8_t hmac_key[] = {
        0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
        0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
        0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
        0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
    };
    atcac_hmac_sha256_ctx ctx;

    status = atcac_sha256_hmac_init(&ctx, hmac_key, sizeof(hmac_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_sha256_hmac_update(&ctx, data_input, sizeof(data_input));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    hmac_size = sizeof(hmac);
    status = atcac_sha256_hmac_finish(&ctx, hmac, &hmac_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(hmac_ref, hmac, ATCA_SHA_DIGEST_SIZE);
}

void test_atcac_sha256_hmac_nist(void)
{
#ifndef _WIN32
    TEST_IGNORE_MESSAGE("Test only available under windows.");
#else
    FILE* rsp_file = NULL;
    int ret = ATCA_SUCCESS;
    uint8_t hmac_ref[ATCA_SHA2_256_DIGEST_SIZE];
    uint8_t hmac[ATCA_SHA2_256_DIGEST_SIZE];
    size_t hmac_len = sizeof(hmac);
    uint8_t msg[128];
    uint8_t key[80];
    int count = 0;
    int klen = 0;
    int tlen = 0;
    atcac_hmac_sha256_ctx hmac_ctx;

    rsp_file = fopen("hmac_test_vectors/HMAC_sha256.rsp", "r");
    TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open file");

    do
    {
        ret = read_rsp_int_value(rsp_file, "Count = ", &count);
        if (ret)
        {
            break;
        }

        ret = read_rsp_int_value(rsp_file, "Klen = ", &klen);
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = read_rsp_int_value(rsp_file, "Tlen = ", &tlen);
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = read_rsp_hex_value(rsp_file, "Key = ", key, klen);
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = read_rsp_hex_value(rsp_file, "Msg = ", msg, sizeof(msg));
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = read_rsp_hex_value(rsp_file, "Mac = ", hmac_ref, tlen);
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = atcac_sha256_hmac_init(&hmac_ctx, key, klen);
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = atcac_sha256_hmac_update(&hmac_ctx, msg, sizeof(msg));
        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);

        ret = atcac_sha256_hmac_finish(&hmac_ctx, hmac, &hmac_len);

        TEST_ASSERT_EQUAL(ret, ATCA_SUCCESS);
        TEST_ASSERT_EQUAL_MEMORY(hmac_ref, hmac, tlen);
    }
    while (ret == ATCA_SUCCESS);

#endif
}