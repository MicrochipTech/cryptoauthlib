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
#include "atca_test.h"
#include "atca_basic.h"
#include "cryptoauthlib.h"

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
// *INDENT-OFF* - Preserve formatting
t_test_case_info aes_cbc_basic_test_info[] =
{
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_encrypt_block),            DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_decrypt_block),            DEVICE_MASK(ATECC608) },
#endif
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_encrypt_block_simple),     DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_decrypt_block_simple),     DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },             /* Array Termination element*/
};

// *INDENT-ON*
