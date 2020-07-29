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

// Output ciphertext for AES-ECB mode for the g_plaintext and g_aes_keys keys
// First output is from the NIST AES-ECB test vectors
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
const uint8_t g_ciphertext_ecb[4][64] = {
    {
        0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66, 0xEF, 0x97,
        0xF5, 0xD3, 0xD5, 0x85, 0x03, 0xB9, 0x69, 0x9D, 0xE7, 0x85, 0x89, 0x5A, 0x96, 0xFD, 0xBA, 0xAF,
        0x43, 0xB1, 0xCD, 0x7F, 0x59, 0x8E, 0xCE, 0x23, 0x88, 0x1B, 0x00, 0xE3, 0xED, 0x03, 0x06, 0x88,
        0x7B, 0x0C, 0x78, 0x5E, 0x27, 0xE8, 0xAD, 0x3F, 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5D, 0xD4,
    },
    {
        0x53, 0x5A, 0x0D, 0x67, 0x77, 0x7A, 0x96, 0xAF, 0x77, 0x98, 0x30, 0x03, 0xA6, 0xDF, 0x85, 0x5A,
        0xAC, 0xFC, 0xDE, 0xD1, 0xB3, 0x36, 0x53, 0x07, 0x6C, 0x27, 0x6D, 0x15, 0xD9, 0xD1, 0xEC, 0x1B,
        0x04, 0x06, 0x65, 0x92, 0xA3, 0xFA, 0x7C, 0x4C, 0x6E, 0xC3, 0x4B, 0x91, 0x8F, 0xDB, 0x54, 0x2A,
        0x4B, 0x7E, 0xFC, 0x64, 0x53, 0x48, 0xB5, 0x80, 0xD2, 0x3C, 0x02, 0x4C, 0xE2, 0x65, 0x54, 0x01,
    },
    {
        0x28, 0x61, 0xA0, 0xFA, 0x39, 0x25, 0xE2, 0x02, 0x5E, 0x41, 0xDC, 0xDE, 0x53, 0xDF, 0x7C, 0xA7,
        0x4D, 0xEB, 0x73, 0xED, 0x68, 0x3C, 0x55, 0x56, 0x9F, 0x10, 0x29, 0x14, 0x45, 0x16, 0x90, 0x86,
        0x92, 0x12, 0x82, 0x5D, 0xC2, 0xC8, 0xB2, 0x88, 0x01, 0x26, 0x60, 0x7D, 0x74, 0x40, 0xD8, 0x6D,
        0x44, 0x31, 0x51, 0x85, 0xBD, 0x22, 0xE6, 0x9B, 0xD6, 0xA6, 0xDF, 0xE9, 0xCE, 0x1C, 0x06, 0x83,
    },
    {
        0xB1, 0x24, 0xD6, 0x3C, 0x41, 0xD8, 0x5B, 0xFD, 0x2E, 0xB4, 0xA4, 0xA8, 0xF4, 0x45, 0x02, 0xB9,
        0xED, 0x78, 0xD6, 0x95, 0xE7, 0xCA, 0x77, 0x37, 0x91, 0xFE, 0x3B, 0x80, 0x59, 0xA8, 0x4A, 0x4B,
        0xBA, 0xCF, 0x40, 0x1F, 0xD1, 0x9A, 0x34, 0x43, 0x2D, 0xDC, 0xE2, 0xC3, 0xCC, 0xFE, 0x2F, 0x69,
        0x87, 0xAE, 0x9A, 0xAE, 0x96, 0x51, 0x40, 0x19, 0xA3, 0x2E, 0xE5, 0x7B, 0x19, 0xCE, 0x6A, 0x56,
    }
};

#ifdef ATCA_ATECC608_SUPPORT

TEST(atca_cmd_basic_test, aes_encrypt_key_tempkey)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t data_block;
    uint8_t encrypted_data_out[16];

    // Skip test if AES is not enabled
    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Test encryption with the AES keys
    for (key_block = 0; key_block < 4; key_block++)
    {
        for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
        {
            status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, key_block, &g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], encrypted_data_out);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_ecb[key_block][data_block * ATCA_AES128_BLOCK_SIZE], encrypted_data_out, ATCA_AES128_BLOCK_SIZE);
        }
    }
}

TEST(atca_cmd_basic_test, aes_decrypt_key_tempkey)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t data_block;
    uint8_t decrypted_data_out[16];

    // Skip test if AES is not enabled
    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Test decryption with the AES keys
    for (key_block = 0; key_block < 4; key_block++)
    {
        for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
        {
            status = atcab_aes_decrypt(ATCA_TEMPKEY_KEYID, key_block, &g_ciphertext_ecb[key_block][data_block * ATCA_AES128_BLOCK_SIZE], decrypted_data_out);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], decrypted_data_out, ATCA_AES128_BLOCK_SIZE);
        }
    }
}

#endif

TEST(atca_cmd_basic_test, aes_encrypt_key_slot)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t data_block;
    uint8_t encrypted_data_out[16];
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Test encryption with the AES keys
    for (key_block = 0; key_block < 4; key_block++)
    {
        for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
        {
            status = atcab_aes_encrypt(key_slot, key_block, &g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], encrypted_data_out);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_ecb[key_block][data_block * ATCA_AES128_BLOCK_SIZE], encrypted_data_out, ATCA_AES128_BLOCK_SIZE);
        }
    }
}

TEST(atca_cmd_basic_test, aes_encrypt_key_slot_simple)
{
    ATCA_STATUS status;
    size_t data_block;
    uint8_t encrypted_data_out[16];
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, (const uint8_t*)&g_aes_keys[0], 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
    {
        status = atcab_aes_encrypt(key_slot, 0, &g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], encrypted_data_out);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_ecb[0][data_block * ATCA_AES128_BLOCK_SIZE], encrypted_data_out, ATCA_AES128_BLOCK_SIZE);
    }
}


TEST(atca_cmd_basic_test, aes_decrypt_key_slot)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t data_block;
    uint8_t decrypted_data_out[16];
    uint16_t key_slot;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Test decryption with the AES keys
    for (key_block = 0; key_block < 4; key_block++)
    {
        for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
        {
            status = atcab_aes_decrypt(key_slot, key_block, &g_ciphertext_ecb[key_block][data_block * ATCA_AES128_BLOCK_SIZE], decrypted_data_out);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], decrypted_data_out, ATCA_AES128_BLOCK_SIZE);
        }
    }
}

TEST(atca_cmd_basic_test, aes_decrypt_key_slot_simple)
{
    ATCA_STATUS status;
    size_t data_block;
    uint8_t decrypted_data_out[16];
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

    for (data_block = 0; data_block < sizeof(g_plaintext) / ATCA_AES128_BLOCK_SIZE; data_block++)
    {
        status = atcab_aes_decrypt(key_slot, 0, &g_ciphertext_ecb[0][data_block * ATCA_AES128_BLOCK_SIZE], decrypted_data_out);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[data_block * ATCA_AES128_BLOCK_SIZE], decrypted_data_out, ATCA_AES128_BLOCK_SIZE);
    }

}

#ifdef ATCA_ATECC608_SUPPORT
TEST(atca_cmd_basic_test, aes_gfm)
{
    ATCA_STATUS status;
    uint8_t gfm_data[16];
    const uint8_t h[] = {
        0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0X88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E
    };
    const uint8_t input[] = {
        0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 0XF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78
    };
    const uint8_t expected_gfm_data[16] = {
        0x5E, 0x2E, 0xC7, 0x46, 0x91, 0x70, 0x62, 0x88, 0X2C, 0x85, 0xB0, 0x68, 0x53, 0x53, 0xDE, 0xB7
    };

    //Calculating GFM for the input data data_input
    status = atcab_aes_gfm(h, input, gfm_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(expected_gfm_data, gfm_data, 16);
}
#endif

#ifdef ATCA_ATECC608_SUPPORT
TEST(atca_cmd_basic_test, volatile_key_permit)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint16_t key_id = 0x0004;
    uint8_t response[MAC_SIZE];
    uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_nonce_in_out_t nonce_params;
    uint8_t sn[ATCA_SERIAL_NUM_SIZE];
    atca_check_mac_in_out_t checkmac_params;
    size_t i;
    uint8_t encrypted_data_out[16];
    uint8_t key_slot = 5;
    bool persistent_latch_state = false;

    uint8_t data_in[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    test_assert_data_is_locked();

    status = atcab_info_get_latch(&persistent_latch_state); //Get the State of the persistent latch
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (persistent_latch_state)
    {
        TEST_IGNORE_MESSAGE("Ignoring the test, persistent latch already set");
    }

    check_config_aes_enable();                   //Checking the AES enable bit in configuration zone,if not set it skips the test

    //Loading AES key to slot 10
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_encrypt(key_slot, 0, data_in, encrypted_data_out); //Encrypting data with first 16 bytes in slot 10 as key

    TEST_ASSERT_EQUAL(ATCA_EXECUTION_ERROR, status);                      //Encryption fails as the persistent latch is not set


    // Read SN
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform random nonce
    memset(&temp_key, 0, sizeof(temp_key));
    memset(num_in, 0, sizeof(num_in));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;
    status = atcab_nonce_rand(nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate nonce value
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate response
    for (i = 0; i < sizeof(other_data); i++)
    {
        other_data[i] = (uint8_t)(i + 0xF0);
    }
    checkmac_params.mode = CHECKMAC_MODE_BLOCK2_TEMPKEY;
    checkmac_params.key_id = key_id;
    checkmac_params.client_chal = NULL;
    checkmac_params.client_resp = response;
    checkmac_params.other_data = other_data;
    checkmac_params.sn = sn;
    checkmac_params.otp = NULL;
    checkmac_params.slot_key = g_slot4_key;
    checkmac_params.target_key = NULL;
    checkmac_params.temp_key = &temp_key;
    status = atcah_check_mac(&checkmac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform CheckMac
    status = atcab_checkmac(
        checkmac_params.mode,
        checkmac_params.key_id,
        checkmac_params.client_chal,
        checkmac_params.client_resp,
        checkmac_params.other_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_info_set_latch(true); //persistent latch is set
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    status = atcab_aes_encrypt(key_slot, 0, data_in, encrypted_data_out); //Encrypting data with first 16 bytes in slot 10 as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);                              //Encryption should pass as persistent latch is set

}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info aes_basic_test_info[] =
{
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, volatile_key_permit),              DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gfm),                          DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_encrypt_key_tempkey),          DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_decrypt_key_tempkey),          DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_encrypt_key_slot),             DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_decrypt_key_slot),             DEVICE_MASK(ATECC608) },
#endif
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_encrypt_key_slot_simple),      DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_decrypt_key_slot_simple),      DEVICE_MASK(TA100) },
    /* Array Termination element*/
    { (fp_test_case)NULL,                     (uint8_t)0 },
};
// *INDENT-ON*
