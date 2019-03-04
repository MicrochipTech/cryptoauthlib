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
#include "basic/atca_basic.h"
#include "host/atca_host.h"
#include "test/atca_tests.h"

extern const uint8_t g_aes_keys[4][16];
extern const uint8_t g_plaintext[64];

// NIST text vectors for AES128-CTR mode
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CTR.pdf
const uint8_t g_ctr_counter[16] = {
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

const uint8_t g_ciphertext_ctr[1][64] = {
    {
        0x87, 0x4D, 0x61, 0x91, 0xB6, 0x20, 0xE3, 0x26, 0x1B, 0xEF, 0x68, 0x64, 0x99, 0x0D, 0xB6, 0xCE,
        0x98, 0x06, 0xF6, 0x6B, 0x79, 0x70, 0xFD, 0xFF, 0x86, 0x17, 0x18, 0x7B, 0xB9, 0xFF, 0xFD, 0xFF,
        0x5A, 0xE4, 0xDF, 0x3E, 0xDB, 0xD5, 0xD3, 0x5E, 0x5B, 0x4F, 0x09, 0x02, 0x0D, 0xB0, 0x3E, 0xAB,
        0x1E, 0x03, 0x1D, 0xDA, 0x2F, 0xBE, 0x03, 0xD1, 0x79, 0x21, 0x70, 0xA0, 0xF3, 0x00, 0x9C, 0xEE,
    }
};

TEST(atca_cmd_basic_test, aes_ctr_encrypt_block)
{
    atca_aes_ctr_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t aes_key_block = 0;
    uint16_t key_block = 0;
    size_t data_block;
    uint8_t ciphertext[AES_DATA_SIZE];

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CTR mode context using key in TempKey
    status = atcab_aes_ctr_init(&ctx, key_id, aes_key_block, 4, g_ctr_counter);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypt blocks
    for (data_block = 0; data_block < sizeof(g_plaintext) / AES_DATA_SIZE; data_block++)
    {
        status = atcab_aes_ctr_encrypt_block(&ctx, &g_plaintext[data_block * AES_DATA_SIZE], ciphertext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_ctr[key_block][data_block * AES_DATA_SIZE], ciphertext, AES_DATA_SIZE);
    }
}

TEST(atca_cmd_basic_test, aes_ctr_decrypt_block)
{
    atca_aes_ctr_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t key_block = 0;
    size_t data_block;
    uint8_t plaintext[AES_DATA_SIZE];

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Init CTR mode context using key in TempKey
    status = atcab_aes_ctr_init(&ctx, key_id, key_block, 4, g_ctr_counter);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt blocks
    for (data_block = 0; data_block < sizeof(g_plaintext) / AES_DATA_SIZE; data_block++)
    {
        status = atcab_aes_ctr_decrypt_block(&ctx, &g_ciphertext_ctr[0][data_block * AES_DATA_SIZE], plaintext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[data_block * AES_DATA_SIZE], plaintext, AES_DATA_SIZE);
    }
}

TEST(atca_cmd_basic_test, aes_ctr_increment)
{
    atca_aes_ctr_ctx_t ctx;
    ATCA_STATUS status;
    uint16_t key_id = ATCA_TEMPKEY_KEYID;
    uint8_t aes_key_block = 0;
    uint8_t iv[AES_DATA_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0xFF, 0xFF
    };
    const uint8_t iv_inc[AES_DATA_SIZE] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00
    };
    uint8_t ciphertext[AES_DATA_SIZE];
    uint8_t zero[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Test chained carry
    status = atcab_aes_ctr_init(&ctx, key_id, aes_key_block, 4, iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_ctr_encrypt_block(&ctx, &g_plaintext[0], ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(iv_inc, ctx.cb, AES_DATA_SIZE);

    // Test overflow
    iv[12] = 0xFF;
    status = atcab_aes_ctr_init(&ctx, key_id, aes_key_block, 4, iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_ctr_encrypt_block(&ctx, &g_plaintext[0], ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(zero, &ctx.cb[12], 4);

    // Rerun test with a counter as the entire iv. Should never happen in
    // practice, but good to be thorough.
    memset(iv, 0xFF, sizeof(iv));
    status = atcab_aes_ctr_init(&ctx, key_id, aes_key_block, AES_DATA_SIZE, iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_ctr_encrypt_block(&ctx, &g_plaintext[0], ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(zero, ctx.cb, AES_DATA_SIZE);

    // Test with ctx.counter_size corrupted larger than the block
    memset(iv, 0xFF, sizeof(iv));
    status = atcab_aes_ctr_init(&ctx, key_id, aes_key_block, AES_DATA_SIZE, iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    ctx.counter_size = AES_DATA_SIZE + 1; // Corrupt counter_size
    status = atcab_aes_ctr_encrypt_block(&ctx, &g_plaintext[0], ciphertext);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
}


// *INDENT-OFF* - Preserve formatting
t_test_case_info aes_ctr_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ctr_encrypt_block),            DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ctr_decrypt_block),            DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ctr_increment),                DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },             /* Array Termination element*/
};

// *INDENT-ON*
