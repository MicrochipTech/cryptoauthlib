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

#include "vectors/aes_cmac_nist_vectors.h"

#ifdef ATCA_ATECC608_SUPPORT
TEST(atca_cmd_basic_test, aes_cmac)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t msg_index;
    atca_aes_cmac_ctx_t ctx;
    uint8_t cmac[ATCA_AES128_BLOCK_SIZE];

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    for (key_block = 0; key_block < 4; key_block++)
    {
        for (msg_index = 0; msg_index < sizeof(g_cmac_msg_sizes) / sizeof(g_cmac_msg_sizes[0]); msg_index++)
        {
            status = atcab_aes_cmac_init(&ctx, ATCA_TEMPKEY_KEYID, key_block);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            status = atcab_aes_cmac_update(&ctx, g_plaintext, g_cmac_msg_sizes[msg_index]);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            status = atcab_aes_cmac_finish(&ctx, cmac, sizeof(cmac));
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(g_cmacs[key_block][msg_index], cmac, sizeof(cmac));
        }
    }
}
#endif

TEST(atca_cmd_basic_test, aes_cmac_simple)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t msg_index;
    atca_aes_cmac_ctx_t ctx;
    uint8_t cmac[ATCA_AES128_BLOCK_SIZE];
    uint16_t key_id;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    for (key_block = 0; key_block < 4; key_block++)
    {
        // Load AES keys into slot
        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_id, 0, &g_aes_keys[key_block][0], 16);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        for (msg_index = 0; msg_index < sizeof(g_cmac_msg_sizes) / sizeof(g_cmac_msg_sizes[0]); msg_index++)
        {
            status = atcab_aes_cmac_init(&ctx, key_id, 0);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            status = atcab_aes_cmac_update(&ctx, g_plaintext, g_cmac_msg_sizes[msg_index]);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            status = atcab_aes_cmac_finish(&ctx, cmac, sizeof(cmac));
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(g_cmacs[key_block][msg_index], cmac, sizeof(cmac));
        }
    }
}
// *INDENT-OFF* - Preserve formatting
t_test_case_info aes_cmac_basic_test_info[] =
{
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cmac),                         DEVICE_MASK(ATECC608) },
#endif
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cmac_simple),                  DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },             /* Array Termination element*/
};

// *INDENT-ON*
