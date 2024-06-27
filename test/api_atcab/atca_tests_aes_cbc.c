/**
 * \file
 * \brief Unity tests for the cryptoauthlib Basic API
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
#include "test_atcab.h"

#ifndef TEST_ATCAB_AES_CBC_EN
#define TEST_ATCAB_AES_CBC_EN           (ATCAB_AES_CBC_ENCRYPT_EN || ATCAB_AES_CBC_DECRYPT_EN)
#endif

#ifndef TEST_ATCAB_AES_CBC_UPDATE_EN
#define TEST_ATCAB_AES_CBC_UPDATE_EN    ATCAB_AES_CBC_UPDATE_EN
#endif

#if TEST_ATCAB_AES_CBC_EN
extern const uint8_t g_aes_keys[4][16];
extern const uint8_t g_plaintext[64];

// Initialization vector for testing block cipher modes.
// Commonly used by NIST for some AES test vectors
const uint8_t g_iv[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// NIST text vector output for first key in AES128-CBC mode
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CBC.pdf
const uint8_t g_ciphertext_cbc[1][64] = {
    {
        0x76, 0x49, 0xAB, 0xAC, 0x81, 0x19, 0xB2, 0x46, 0xCE, 0xE9, 0x8E, 0x9B, 0x12, 0xE9, 0x19, 0x7D,
        0x50, 0x86, 0xCB, 0x9B, 0x50, 0x72, 0x19, 0xEE, 0x95, 0xDB, 0x11, 0x3A, 0x91, 0x76, 0x78, 0xB2,
        0x73, 0xBE, 0xD6, 0xB8, 0xE3, 0xC1, 0x74, 0x3B, 0x71, 0x16, 0xE6, 0x9E, 0x22, 0x22, 0x95, 0x16,
        0x3F, 0xF1, 0xCA, 0xA1, 0x68, 0x1F, 0xAC, 0x09, 0x12, 0x0E, 0xCA, 0x30, 0x75, 0x86, 0xE1, 0xA7,
    }
};

#ifdef ATCA_ATECC608_SUPPORT

TEST(atca_cmd_basic_test, aes_cbc_encrypt_block)
{
    uint8_t ciphertext[ATCA_AES128_BLOCK_SIZE];
    size_t data_block;
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CBC mode context using 1st key in TempKey
    status = atcab_aes_cbc_init(&ctx, ATCA_TEMPKEY_KEYID, 0, g_iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt blocks
    for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
    {
        status = atcab_aes_cbc_encrypt_block(&ctx, &g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], ciphertext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_cbc[0][data_block * ATCA_AES128_BLOCK_SIZE], ciphertext, ATCA_AES128_BLOCK_SIZE);
    }
}

TEST(atca_cmd_basic_test, aes_cbc_decrypt_block)
{
    uint8_t plaintext[ATCA_AES128_BLOCK_SIZE];
    size_t data_block;
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CBC mode context using 3rd key in TempKey
    status = atcab_aes_cbc_init(&ctx, ATCA_TEMPKEY_KEYID, 0, g_iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt blocks
    for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
    {
        status = atcab_aes_cbc_decrypt_block(&ctx, &g_ciphertext_cbc[0][data_block * ATCA_AES128_BLOCK_SIZE], plaintext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], plaintext, ATCA_AES128_BLOCK_SIZE);
    }
}

#endif

TEST(atca_cmd_basic_test, aes_cbc_encrypt_block_simple)
{
    uint8_t ciphertext[ATCA_AES128_BLOCK_SIZE];
    size_t data_block;
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CBC mode context using key in slot
    status = atcab_aes_cbc_init(&ctx, key_slot, 0, g_iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt blocks
    for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
    {
        status = atcab_aes_cbc_encrypt_block(&ctx, &g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], ciphertext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_cbc[0][data_block * ATCA_AES128_BLOCK_SIZE], ciphertext, ATCA_AES128_BLOCK_SIZE);
    }
}

TEST(atca_cmd_basic_test, aes_cbc_decrypt_block_simple)
{
    uint8_t plaintext[ATCA_AES128_BLOCK_SIZE];
    size_t data_block;
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CBC mode context using key in slot
    status = atcab_aes_cbc_init(&ctx, key_slot, 0, g_iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt blocks
    for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
    {
        status = atcab_aes_cbc_decrypt_block(&ctx, &g_ciphertext_cbc[0][data_block * ATCA_AES128_BLOCK_SIZE], plaintext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], plaintext, ATCA_AES128_BLOCK_SIZE);
    }
}

#if TEST_ATCAB_AES_CBC_UPDATE_EN
TEST(atca_cmd_basic_test, aes_cbc_encrypt_update_simple)
{
    uint8_t ciphertext[sizeof(g_plaintext)];
    uint8_t * cPtr = ciphertext;
    size_t length = sizeof(g_plaintext);
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CBC mode context using key in slot
    status = atcab_aes_cbc_init(&ctx, key_slot, 0, g_iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt the entire plaintext
    status = atcab_aes_cbc_encrypt_update(&ctx, (uint8_t*)g_plaintext, sizeof(g_plaintext), cPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(sizeof(g_plaintext), length);
    cPtr += length;

    // Finalize without padding
    length = sizeof(g_plaintext);
    status = atcab_aes_cbc_encrypt_finish(&ctx, cPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, length);
    TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_cbc[0][0], ciphertext, sizeof(g_plaintext));
}

TEST(atca_cmd_basic_test, aes_cbc_encrypt_update_chunks)
{
    uint8_t ciphertext[sizeof(g_plaintext)];
    uint8_t * cPtr = ciphertext;
    size_t length = sizeof(ciphertext);
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CBC mode context using key in slot
    status = atcab_aes_cbc_init(&ctx, key_slot, 0, g_iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt the a small chunk
    status = atcab_aes_cbc_encrypt_update(&ctx, (uint8_t*)g_plaintext, 8, cPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    cPtr += length;

    // Encrypt a large chunk
    length = sizeof(g_plaintext) - (cPtr - ciphertext);
    status = atcab_aes_cbc_encrypt_update(&ctx, (uint8_t*)&g_plaintext[8], 24, cPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    cPtr += length;

    // Finish it up
    length = sizeof(g_plaintext) - (cPtr - ciphertext);
    status = atcab_aes_cbc_encrypt_update(&ctx, (uint8_t*)&g_plaintext[32], sizeof(g_plaintext) - 32, cPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    cPtr += length;
    length = sizeof(g_plaintext);

    // Finalize without padding
    status = atcab_aes_cbc_encrypt_finish(&ctx, ciphertext, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, length);
    TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_cbc[0][0], ciphertext, sizeof(ciphertext));
}

TEST(atca_cmd_basic_test, aes_cbc_decrypt_update_simple)
{
    uint8_t plaintext[sizeof(g_plaintext)];
    size_t length;
    uint8_t * pPtr;
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CBC mode context using key in slot
    status = atcab_aes_cbc_init(&ctx, key_slot, 0, g_iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt the entire plaintext
    pPtr = plaintext;
    length = sizeof(plaintext);
    status = atcab_aes_cbc_decrypt_update(&ctx, (uint8_t*)&g_ciphertext_cbc[0][0], sizeof(g_plaintext), pPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(sizeof(g_plaintext), length);

    pPtr += length;
    length = sizeof(plaintext);

    // Finalize without padding
    status = atcab_aes_cbc_decrypt_finish(&ctx, pPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, length);
    TEST_ASSERT_EQUAL_MEMORY(&g_plaintext, plaintext, sizeof(plaintext));
}

TEST(atca_cmd_basic_test, aes_cbc_decrypt_update_chunks)
{
    uint8_t plaintext[sizeof(g_plaintext)];
    uint8_t * pPtr = plaintext;
    size_t length = sizeof(plaintext);
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CBC mode context using key in slot
    status = atcab_aes_cbc_init(&ctx, key_slot, 0, g_iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt the a small chunk
    status = atcab_aes_cbc_decrypt_update(&ctx, (uint8_t*)&g_ciphertext_cbc[0][0], 8, pPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    pPtr += length;

    // Encrypt a large chunk
    length = sizeof(plaintext) - (pPtr - plaintext);
    status = atcab_aes_cbc_decrypt_update(&ctx, (uint8_t*)&g_ciphertext_cbc[0][8], 24, pPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    pPtr += length;

    // Finish it up
    length = sizeof(plaintext) - (pPtr - plaintext);
    status = atcab_aes_cbc_decrypt_update(&ctx, (uint8_t*)&g_ciphertext_cbc[0][32], sizeof(plaintext) - 32, pPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    pPtr += length;

    // There should be no more remaining bytes
    TEST_ASSERT_EQUAL(sizeof(plaintext), (pPtr - plaintext));

    // Finalize without padding
    length = sizeof(plaintext);
    status = atcab_aes_cbc_decrypt_finish(&ctx, pPtr, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, length);
    TEST_ASSERT_EQUAL_MEMORY(g_plaintext, plaintext, sizeof(plaintext));
}


TEST(atca_cmd_basic_test, aes_cbc_padding_simple)
{
    uint8_t ciphertext[sizeof(g_plaintext) + ATCA_AES128_BLOCK_SIZE];
    uint8_t plaintext[sizeof(g_plaintext) + ATCA_AES128_BLOCK_SIZE];
    size_t length = sizeof(ciphertext);
    size_t exp_len = sizeof(g_plaintext) + (ATCA_AES128_BLOCK_SIZE - sizeof(g_plaintext) % 16);
    size_t res_len;
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CBC mode context using key in slot
    status = atcab_aes_cbc_init_ext(atcab_get_device(), &ctx, key_slot, 0, g_iv, 1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt the entire plaintext
    status = atcab_aes_cbc_encrypt_update(&ctx, (uint8_t*)g_plaintext, sizeof(g_plaintext), ciphertext, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    res_len = length;
    TEST_ASSERT_EQUAL(sizeof(g_plaintext), res_len);

    // Finalize with padding
    length = sizeof(ciphertext) - length;
    status = atcab_aes_cbc_encrypt_finish(&ctx, &ciphertext[res_len], &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_cbc[0][0], ciphertext, sizeof(g_plaintext));
    res_len += length;
    TEST_ASSERT_EQUAL(exp_len, res_len);

    // Init CBC mode context using key in slot
    status = atcab_aes_cbc_init_ext(atcab_get_device(), &ctx, key_slot, 0, g_iv, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt the entire plaintext
    length = sizeof(plaintext);
    status = atcab_aes_cbc_decrypt_update(&ctx, ciphertext, exp_len, plaintext, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    res_len = length;

    // Finalize without padding
    length = sizeof(plaintext) - length;
    status = atcab_aes_cbc_decrypt_finish(&ctx, &plaintext[res_len], &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, length);
    res_len += length;
    TEST_ASSERT_EQUAL_MEMORY(&g_plaintext, plaintext, sizeof(g_plaintext));

    // Check Padding
    unsigned int i;
    for (i = 0; i < ATCA_AES128_BLOCK_SIZE; i++)
    {
        TEST_ASSERT_EQUAL((ATCA_AES128_BLOCK_SIZE - sizeof(g_plaintext) % 16), plaintext[sizeof(g_plaintext) + i]);
    }

    // Init CBC mode context using key in slot
    status = atcab_aes_cbc_init_ext(atcab_get_device(), &ctx, key_slot, 0, g_iv, 1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt the entire plaintext
    length = sizeof(plaintext);
    status = atcab_aes_cbc_decrypt_update(&ctx, ciphertext, exp_len, plaintext, &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(sizeof(g_plaintext), length);
    res_len = length;

    // Finalize without padding
    length = sizeof(plaintext) - length;
    status = atcab_aes_cbc_decrypt_finish(&ctx, &plaintext[res_len], &length);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, length);
    res_len += length;
    TEST_ASSERT_EQUAL(sizeof(g_plaintext), res_len);
    TEST_ASSERT_EQUAL_MEMORY(&g_plaintext, plaintext, sizeof(g_plaintext));
}

#if defined(_WIN32) || defined(__linux__)
#define SIZE_OF_TEXT    340
TEST(atca_cmd_basic_test, aes_cbc_mmt_cavp_vectors)
{
    uint8_t plaintext[SIZE_OF_TEXT];
    uint8_t * pPtr = plaintext;
    uint8_t ciphertext[SIZE_OF_TEXT];
    uint8_t * cPtr = ciphertext;
    size_t length = SIZE_OF_TEXT;
    atca_aes_cbc_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_slot;
    FILE* rsp_file = NULL;
    uint8_t line[SIZE_OF_TEXT];
    bool enc_oper = true;
    char *str;
    char *name_value;
    uint8_t key[32];
    uint8_t iv[32];
    uint8_t pt[SIZE_OF_TEXT];
    uint8_t ct[SIZE_OF_TEXT];
    size_t key_size = 0;
    size_t iv_size = 0;
    uint32_t pt_size =0;
    uint32_t ct_size =0;
#ifdef ATCA_PRINTF
    uint16_t test_count = 0;
#endif

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    rsp_file = fopen("aesmmt_cbc_cavp_vectors/CBCMMT128.rsp", "r");
    TEST_ASSERT_NOT_NULL_MESSAGE(rsp_file, "Failed to open .rsp file");

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

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

        if (!memcmp(str, "[ENCRYPT]", strlen("[ENCRYPT]")))
        {
            enc_oper = true;
        }
        else if (!memcmp(str, "[DECRYPT]", strlen("[DECRYPT]")))
        {
            enc_oper = false;
        }
        else if (!memcmp(str, "KEY = ", strlen("KEY = ")))
        {
            name_value = (char *)&line[strlen("KEY = ")];
            key_size = strlen(name_value) / 2;
            hex_to_data(name_value, key, key_size);
        }
        else if (!memcmp(str, "IV = ", strlen("IV = ")))
        {
            name_value = (char *)&line[strlen("IV = ")];
            iv_size = strlen(name_value) / 2;
            hex_to_data(name_value, iv, iv_size);
        }
        else if (!memcmp(str, "PLAINTEXT = ", strlen("PLAINTEXT = ")))
        {
            name_value = (char *)&line[strlen("PLAINTEXT = ")];
            pt_size = (uint32_t)strlen(name_value) / 2;
            hex_to_data(name_value, pt, pt_size);

            /* Check to reconcile decrypted text */
            if (false == enc_oper)
            {
#ifdef ATCA_PRINTF
                //Process read vector
                printf("%04d\r", test_count++);
#endif

                // Load AES keys into slot
                status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, &key[0], 16);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

                // Init CBC mode context using key in slot
                status = atcab_aes_cbc_init(&ctx, key_slot, 0, iv);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

                // Decrypt the entire plaintext
                pPtr = plaintext;
                length = sizeof(plaintext);
                status = atcab_aes_cbc_decrypt_update(&ctx, (uint8_t*)ct, ct_size, pPtr, &length);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
                TEST_ASSERT_EQUAL(pt_size, length);

                pPtr += length;
                length = sizeof(pt);

                // Finalize without padding
                status = atcab_aes_cbc_decrypt_finish(&ctx, pPtr, &length);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
                TEST_ASSERT_EQUAL(0, length);
                TEST_ASSERT_EQUAL_MEMORY(plaintext, pt, pt_size);
            }
        }
        else if (!memcmp(str, "CIPHERTEXT = ", strlen("CIPHERTEXT = ")))
        {
            name_value = (char *)&line[strlen("CIPHERTEXT = ")];
            ct_size = (uint32_t)strlen(name_value) / 2;
            hex_to_data(name_value, ct, ct_size);

            /* Check to reconcile encrypted text */
            if (true == enc_oper)
            {
#ifdef ATCA_PRINTF
                //Process read vector
                printf("%04d\r", test_count++);
#endif

                // Load AES keys into slot
                status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, &key[0], 16);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

                // Init CBC mode context using key in slot
                status = atcab_aes_cbc_init(&ctx, key_slot, 0, iv);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

                // Encrypt the entire plaintext
                cPtr = ciphertext;
                length = sizeof(ciphertext);
                status = atcab_aes_cbc_encrypt_update(&ctx, (uint8_t*)pt, pt_size, cPtr, &length);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
                TEST_ASSERT_EQUAL(ct_size, length);
                cPtr += length;

                // Finalize without padding
                length = sizeof(pt);
                status = atcab_aes_cbc_encrypt_finish(&ctx, cPtr, &length);
                TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
                TEST_ASSERT_EQUAL(0, length);
                TEST_ASSERT_EQUAL_MEMORY(ciphertext, ct, ct_size);
            }
        }
    }
    while (!feof(rsp_file));

    fclose(rsp_file);

#ifdef ATCA_PRINTF
    printf("\n");
#endif
}
#undef SIZE_OF_TEXT
#endif //_WIN32 / __linux__
#endif /* TEST_ATCAB_AES_CBC_EN */
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info aes_cbc_basic_test_info[] =
{
#if TEST_ATCAB_AES_CBC_EN
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_encrypt_block),            atca_test_cond_ecc608 },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_decrypt_block),            atca_test_cond_ecc608 },
#endif
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_encrypt_block_simple),     atca_test_cond_ta    },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_decrypt_block_simple),     atca_test_cond_ta    },
#ifdef TEST_ATCAB_AES_CBC_UPDATE_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_encrypt_update_simple),    atca_test_cond_ta    },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_encrypt_update_chunks),    atca_test_cond_ta    },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_decrypt_update_simple),    atca_test_cond_ta    },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_decrypt_update_chunks),    atca_test_cond_ta    },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_padding_simple),           atca_test_cond_ta    },
#if defined(_WIN32) || defined(__linux__)
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_mmt_cavp_vectors),         atca_test_cond_ta    },
#endif  //_WIN32 / __linux__
#endif /* TEST_ATCAB_AES_CBC_UPDATE_EN */
#endif /* TEST_ATCAB_AES_CBC_EN */
    { (fp_test_case)NULL, NULL },             /* Array Termination element*/
};

// *INDENT-ON*
