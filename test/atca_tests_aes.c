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
#include "atca_test.h"
#include "basic/atca_basic.h"
#include "host/atca_host.h"
#include "test/atca_tests.h"
#include "atca_execution.h"

// These keys are chosen specifically to test the CMAC subkey generation code.
// When the keys are used to encrypt an all-zero block we need all bit
// combinations of the uppermost 2 bits (0b00, 0b01, 0b10, 0b11)
// 2B7E151628AED2A6ABF7158809CF4F3C AESEnc(0)=7DF76B0C1AB899B33E42F047B91B546F 7D=0b01 111101
// 6BE163D42B623E70D164FA145DB1D463 AESEnc(0)=EEA8C3FD920AC8D3D3A424E473C56B4A EE=0b11 101110
// 7058710B58E1E665D3D2F5B465176403 AESEnc(0)=38AE4CF5CAB844CF6D1463044C8749AE 38=0b00 111000
// 114443FA8E9614845EC7296CD13BC9DC AESEnc(0)=863496604DDD579049A63908D49853D5 86=0b10 000110
// The first key is one commonly used by NIST for some AES test vectors
static const uint8_t g_aes_keys[4][16] = {
    { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C },
    { 0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63 },
    { 0x70, 0x58, 0x71, 0x0B, 0x58, 0xE1, 0xE6, 0x65, 0xD3, 0xD2, 0xF5, 0xB4, 0x65, 0x17, 0x64, 0x03 },
    { 0x11, 0x44, 0x43, 0xFA, 0x8E, 0x96, 0x14, 0x84, 0x5E, 0xC7, 0x29, 0x6C, 0xD1, 0x3B, 0xC9, 0xDC }
};

// Input plaintext for testing.
// This input test data is commonly used by NIST for some AES test vectors
static const uint8_t g_plaintext[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

// Output ciphertext for AES-ECB mode for the g_plaintext and g_aes_keys keys
// First output is from the NIST AES-ECB test vectors
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf
static const uint8_t g_ciphertext_ecb[4][64] = {
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
// Message sizes from the g_plaintext array to try when testing the AES128-CMAC
// functions
const uint32_t g_cmac_msg_sizes[] = { 0, 16, 20, 64 };
// Expected CMACs for all keys and message sizes
// The first set of entries is from the the NIST CMAC test vectors
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
const uint8_t g_cmacs[4][4][16] = {
    {
        { 0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46 },
        { 0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c },
        { 0x7d, 0x85, 0x44, 0x9e, 0xa6, 0xea, 0x19, 0xc8, 0x23, 0xa7, 0xbf, 0x78, 0x83, 0x7d, 0xfa, 0xde },
        { 0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe },
    },
    {
        { 0xfc, 0xfd, 0x69, 0xfe, 0x15, 0x80, 0xc0, 0x95, 0xa7, 0x83, 0x54, 0x89, 0x31, 0xf3, 0x01, 0x70 },
        { 0x5e, 0x36, 0xdc, 0x8f, 0x6a, 0xd2, 0xbe, 0x40, 0xb3, 0x87, 0xae, 0x78, 0x52, 0x28, 0xfe, 0x56 },
        { 0x03, 0xcc, 0x26, 0x2a, 0xfe, 0x76, 0x91, 0x5f, 0xe5, 0x6a, 0x52, 0xe0, 0x57, 0x98, 0xf2, 0xeb },
        { 0xd5, 0x29, 0x4e, 0xe1, 0x19, 0xb6, 0x70, 0x44, 0xb5, 0x57, 0xbc, 0x94, 0x65, 0x0b, 0x3f, 0xa5 },
    },
    {
        { 0xe2, 0x86, 0xa8, 0x0e, 0xd6, 0xbd, 0x92, 0xa4, 0xaa, 0xaf, 0x20, 0x6e, 0xb3, 0x27, 0x21, 0x29 },
        { 0xac, 0xac, 0x7d, 0x25, 0x9e, 0x9d, 0x26, 0x69, 0x52, 0x66, 0xa6, 0xb8, 0xed, 0x09, 0x76, 0xcf },
        { 0xba, 0x12, 0x9f, 0x42, 0x27, 0x1f, 0x7d, 0x5f, 0x7d, 0x3f, 0x57, 0xf3, 0x08, 0xee, 0x37, 0xb2 },
        { 0x4d, 0xd1, 0x67, 0x53, 0xe3, 0xd3, 0x61, 0xc6, 0x36, 0x3b, 0xf5, 0x16, 0x04, 0x45, 0x2e, 0x85 },
    },
    {
        { 0xbf, 0xb7, 0x21, 0xb5, 0x2c, 0xc2, 0x13, 0x66, 0x99, 0xca, 0x97, 0x8b, 0x50, 0xb9, 0xa0, 0xa3 },
        { 0x82, 0x84, 0xbe, 0x95, 0x59, 0xcd, 0x27, 0xf2, 0x4d, 0x9b, 0x07, 0x33, 0x93, 0x56, 0xc2, 0x3e },
        { 0xb9, 0xc7, 0xa3, 0x5f, 0xc5, 0x83, 0xf1, 0x3f, 0x4d, 0x0f, 0x8c, 0x79, 0x8d, 0xac, 0xc8, 0xc5 },
        { 0x91, 0xed, 0x39, 0x68, 0xff, 0x64, 0xbe, 0x68, 0x8f, 0x43, 0x6e, 0xbc, 0xeb, 0x57, 0x72, 0xe7 },
    }
};

TEST(atca_cmd_unit_test, aes)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build read command
    packet.param1 = ATCA_ZONE_CONFIG;
    packet.param2 = 0x0003;

    status = atRead(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    if ((packet.data[2] & AES_CONFIG_ENABLE_BIT_MASK) == 0) //packet.data[2] contains the AES enable bit
    {
        TEST_IGNORE_MESSAGE("Ignoring the test ,AES is not enabled in Configuration zone");
    }

    //build a nonce command (pass through mode) to store the aes key in tempkey
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memcpy(packet.data, g_aes_keys[0], ATCA_KEY_SIZE);    // a 32-byte nonce

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[ATCA_RSP_DATA_IDX]);

    packet.param1 = AES_MODE_ENCRYPT;                //selects encrypt mode and use first 16 byte data in tempkey as key
    packet.param2 = 0xFFFF;
    memcpy(packet.data, g_plaintext, AES_DATA_SIZE); // a 16-byte data to be encrypted

    status = atAES(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(g_ciphertext_ecb[0], &packet.data[ATCA_RSP_DATA_IDX], AES_DATA_SIZE);

    packet.param1 = AES_MODE_DECRYPT;                        //selects decrypt mode and use first 16 byte data in tempkey as key
    packet.param2 = 0xFFFF;
    memcpy(packet.data, g_ciphertext_ecb[0], AES_DATA_SIZE); // a 16-byte data to be encrypted

    status = atAES(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(g_plaintext, &packet.data[ATCA_RSP_DATA_IDX], AES_DATA_SIZE);
}



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
        for (data_block = 0; data_block < sizeof(g_plaintext) / AES_DATA_SIZE; data_block++)
        {
            status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, key_block, &g_plaintext[data_block * AES_DATA_SIZE], encrypted_data_out);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_ecb[key_block][data_block * AES_DATA_SIZE], encrypted_data_out, AES_DATA_SIZE);
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
        for (data_block = 0; data_block < sizeof(g_plaintext) / AES_DATA_SIZE; data_block++)
        {
            status = atcab_aes_decrypt(ATCA_TEMPKEY_KEYID, key_block, &g_ciphertext_ecb[key_block][data_block * AES_DATA_SIZE], decrypted_data_out);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[data_block * AES_DATA_SIZE], decrypted_data_out, AES_DATA_SIZE);
        }
    }
}

TEST(atca_cmd_basic_test, aes_encrypt_key_slot)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t data_block;
    uint8_t encrypted_data_out[16];
    uint16_t key_slot = 10;
    bool persistent_latch_state;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    // Skip test if persistent latch isn't set
    status = atcab_info_get_latch(&persistent_latch_state);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    if (!persistent_latch_state)
    {
        TEST_IGNORE_MESSAGE("Ignoring the test, persistent latch should be set");
    }

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Test encryption with the AES keys
    for (key_block = 0; key_block < 4; key_block++)
    {
        for (data_block = 0; data_block < sizeof(g_plaintext) / AES_DATA_SIZE; data_block++)
        {
            status = atcab_aes_encrypt(key_slot, key_block, &g_plaintext[data_block * AES_DATA_SIZE], encrypted_data_out);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_ecb[key_block][data_block * AES_DATA_SIZE], encrypted_data_out, AES_DATA_SIZE);
        }
    }
}

TEST(atca_cmd_basic_test, aes_decrypt_key_slot)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t data_block;
    uint8_t decrypted_data_out[16];
    uint16_t key_slot = 10;
    bool persistent_latch_state;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if AES is not enabled
    check_config_aes_enable();

    // Skip test if persistent latch isn't set
    status = atcab_info_get_latch(&persistent_latch_state);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    if (!persistent_latch_state)
    {
        TEST_IGNORE_MESSAGE("Ignoring the test, persistent latch should be set");
    }

    // Load AES keys into slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Test decryption with the AES keys
    for (key_block = 0; key_block < 4; key_block++)
    {
        for (data_block = 0; data_block < sizeof(g_plaintext) / AES_DATA_SIZE; data_block++)
        {
            status = atcab_aes_decrypt(key_slot, key_block, &g_ciphertext_ecb[key_block][data_block * AES_DATA_SIZE], decrypted_data_out);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
            TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[data_block * AES_DATA_SIZE], decrypted_data_out, AES_DATA_SIZE);
        }
    }
}

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
    uint8_t key_slot = 10;
    bool persistent_latch_state;

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

TEST(atca_cmd_basic_test, aes_cbc_encrypt_block)
{
    uint8_t ciphertext[AES_DATA_SIZE];
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
    for (data_block = 0; data_block < sizeof(g_plaintext) / AES_DATA_SIZE; data_block++)
    {
        status = atcab_aes_cbc_encrypt_block(&ctx, &g_plaintext[data_block * AES_DATA_SIZE], ciphertext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_ciphertext_cbc[0][data_block * AES_DATA_SIZE], ciphertext, AES_DATA_SIZE);
    }
}

TEST(atca_cmd_basic_test, aes_cbc_decrypt_block)
{
    uint8_t plaintext[AES_DATA_SIZE];
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
    for (data_block = 0; data_block < sizeof(g_plaintext) / AES_DATA_SIZE; data_block++)
    {
        status = atcab_aes_cbc_decrypt_block(&ctx, &g_ciphertext_cbc[0][data_block * AES_DATA_SIZE], plaintext);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(&g_plaintext[data_block * AES_DATA_SIZE], plaintext, AES_DATA_SIZE);
    }
}

TEST(atca_cmd_basic_test, aes_cmac)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t msg_index;
    atca_aes_cmac_ctx_t ctx;
    uint8_t cmac[AES_DATA_SIZE];

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

    check_config_aes_enable();

    // Load AES keys into TempKey
    status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, g_aes_keys[0], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Test chained carry
    status = atcab_aes_ctr_init(&ctx, key_id, aes_key_block, 4, iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_ctr_encrypt_block(&ctx, &g_plaintext[0], ciphertext);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(iv_inc, ctx.iv, AES_DATA_SIZE);

    // Test overflow
    iv[12] = 0xFF;
    status = atcab_aes_ctr_init(&ctx, key_id, aes_key_block, 4, iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_ctr_encrypt_block(&ctx, &g_plaintext[0], ciphertext);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    // Rerun test with a counter as the entire iv. Should never happen in
    // practice, but good to be thorough.
    memset(iv, 0xFF, sizeof(iv));
    status = atcab_aes_ctr_init(&ctx, key_id, aes_key_block, AES_DATA_SIZE, iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_aes_ctr_encrypt_block(&ctx, &g_plaintext[0], ciphertext);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);

    // Test with ctx.counter_size corrupted larger than the block
    memset(iv, 0xFF, sizeof(iv));
    status = atcab_aes_ctr_init(&ctx, key_id, aes_key_block, AES_DATA_SIZE, iv);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    ctx.counter_size = AES_DATA_SIZE + 1; // Corrupt counter_size
    status = atcab_aes_ctr_encrypt_block(&ctx, &g_plaintext[0], ciphertext);
    TEST_ASSERT_EQUAL(ATCA_INVALID_SIZE, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info aes_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, volatile_key_permit),     DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_encrypt_key_tempkey), DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_decrypt_key_tempkey), DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_encrypt_key_slot),    DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_decrypt_key_slot),    DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gfm),                 DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_encrypt_block),   DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cbc_decrypt_block),   DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_cmac),                DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ctr_encrypt_block),   DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ctr_decrypt_block),   DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_ctr_increment),       DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },             /* Array Termination element*/
};

t_test_case_info aes_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, aes), DEVICE_MASK(ATECC608A)  },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*
