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

extern const uint8_t g_aes_keys[4][16];
extern const uint8_t g_plaintext[64];

#ifdef ATCA_ATECC608_SUPPORT
// Expected CBC-MACs for g_plaintext with all keys
static const uint8_t g_cbc_mac[4][16] = {
    { 0xA7, 0x35, 0x6E, 0x12, 0x07, 0xBB, 0x40, 0x66, 0x39, 0xE5, 0xE5, 0xCE, 0xB9, 0xA9, 0xED, 0x93 },
    { 0xA8, 0x2D, 0xD8, 0xBE, 0x90, 0x80, 0x40, 0xBE, 0xA4, 0x56, 0x26, 0x0D, 0x0A, 0x81, 0xAE, 0x07 },
    { 0x7F, 0xE5, 0x65, 0x9C, 0xBA, 0x0E, 0x01, 0xD9, 0xCA, 0xC1, 0x6F, 0xCA, 0x1B, 0x6F, 0x66, 0x2E },
    { 0xE1, 0xD0, 0xC0, 0x85, 0x49, 0xBF, 0xF7, 0xFB, 0xA9, 0xE0, 0xCF, 0x6B, 0x49, 0x32, 0x36, 0xF1 }
};

TEST(atca_cmd_basic_test, aes_cbc_mac)
{
    uint8_t cbc_mac[AES_DATA_SIZE];
    uint8_t key_block;
    atca_aes_cbcmac_ctx_t ctx;
    ATCA_STATUS status;

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Positive test case for AES CBC-MAC with different AES keys
    for (key_block = 0; key_block < 4; key_block++)
    {
        // Init CBC-MAC context using 1st key in TempKey
        status = atcab_aes_cbcmac_init(&ctx, ATCA_TEMPKEY_KEYID, key_block);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        // Updating data in to the cbcmac function
        status = atcab_aes_cbcmac_update(&ctx, g_plaintext, sizeof(g_plaintext));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        // Finishing the cbcmac operation and getting the MAC output.
        status = atcab_aes_cbcmac_finish(&ctx, cbc_mac, AES_DATA_SIZE);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(g_cbc_mac[key_block], cbc_mac, AES_DATA_SIZE);
    }

    // Negative Test case for data set with incomplete blocks
    // Init CBC-MAC context using 1st key in TempKey
    status = atcab_aes_cbcmac_init(&ctx, ATCA_TEMPKEY_KEYID, key_block);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    // Updating data in to the cbcmac function with incomplete block
    status = atcab_aes_cbcmac_update(&ctx, g_plaintext, sizeof(g_plaintext) - 8);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    // Check if the incomplete block is copied to the context buffer.
    TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[sizeof(g_plaintext) - 16], ctx.block, AES_DATA_SIZE - 8);
    // cbcmac_fininsh operation should fail because of the incomplete block
    status = atcab_aes_cbcmac_finish(&ctx, cbc_mac, AES_DATA_SIZE);
    TEST_ASSERT_NOT_EQUAL(ATCA_SUCCESS, status);
}
#endif


t_test_case_info aes_cbcmac_basic_test_info[] =
{
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_mac), DEVICE_MASK(ATECC608A)             },
#endif
    { (fp_test_case)NULL,                     (uint8_t)0 }, /* Array Termination element*/
};
