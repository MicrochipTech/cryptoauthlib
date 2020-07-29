/**
 * \file
 * \brief Unity tests for the cryptoauthlib Write Command
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
#include "atca_test.h"

#ifndef ATCA_BLOCK_SIZE
#define ATCA_BLOCK_SIZE     (32)
#endif

#if ATCA_CA_SUPPORT
TEST(atca_cmd_basic_test, write_boundary_conditions)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t write_data[ATCA_BLOCK_SIZE];
    uint8_t block = 2;

    if (gCfg->devtype == ATSHA204A)
    {
        block = 0;
    }

    test_assert_config_is_locked();
    test_assert_data_is_unlocked();

    memset(write_data, 0xA5, ATCA_BLOCK_SIZE);
    // test slot = 0, write block size
    status = atcab_write_zone(ATCA_ZONE_DATA, 0, 0, 0, write_data, 0);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    status = atcab_write_zone(ATCA_ZONE_DATA, 0, 0, 0, write_data, ATCA_BLOCK_SIZE);
    TEST_ASSERT_EQUAL(gCfg->devtype == ATSHA204A ? ATCA_SUCCESS : ATCA_EXECUTION_ERROR, status); // should fail on ECC device, because config has slot 0 as a key

    status = atcab_write_zone(ATCA_ZONE_DATA, 0, 0, 0, write_data, ATCA_BLOCK_SIZE + 1);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);

    // less than a block size (less than 32-bytes)
    status = atcab_write_zone(ATCA_ZONE_DATA, 10, block, 0, write_data, 31);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    // less than a block size (less than 4-bytes)
    status = atcab_write_zone(ATCA_ZONE_DATA, 10, block, 0, write_data, 3);
    TEST_ASSERT_EQUAL(ATCA_BAD_PARAM, status);
    // equal to block(4-bytes) size, this is not permitted bcos 4-byte writes are not allowed when zone unlocked
    status = atcab_write_zone(ATCA_ZONE_DATA, 10, block, 0, write_data, ATCA_WORD_SIZE);
    TEST_ASSERT_EQUAL(ATCA_EXECUTION_ERROR, status);
    // equal to block(32-bytes) size,
    status = atcab_write_zone(ATCA_ZONE_DATA, 10, block, 0, write_data, ATCA_BLOCK_SIZE);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);  //pass for both locked and unlocked case
}

TEST(atca_cmd_basic_test, write_upper_slots)
{
    uint8_t slot;
    uint8_t write_data[32];
    uint8_t read_data[32];
    uint8_t config88[4];
    uint16_t slot_locked;
    char msg[8];
    bool is_data_locked = false;

    ATCA_STATUS status = ATCA_SUCCESS;

    // Testing the larger size of the ECC device upper slots
    test_assert_config_is_locked();

    status = atcab_is_data_locked(&is_data_locked);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read slot lock status
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 88, config88, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    slot_locked = (uint16_t)config88[0] | ((uint16_t)config88[1] << 8);

    for (slot = 10; slot <= 15; slot++)
    {
        if (((slot_locked >> slot) & 1) == 0)
        {
            continue;  // Slot is locked and can't be written to

        }
        sprintf(msg, "Slot %d", (int)slot);

        status = atcab_random(write_data);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcab_write_zone(ATCA_ZONE_DATA, slot, 0, 0, write_data, sizeof(write_data));
        TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, msg);

        // Can only validate the data if the data zone is unlocked
        // Slot 14 is validated, which means its validation flag changes the read value
        if (is_data_locked && slot != 14)
        {
            status = atcab_read_zone(ATCA_ZONE_DATA, slot, 0, 0, read_data, sizeof(read_data));
            TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, msg);

            TEST_ASSERT_EQUAL_MEMORY_MESSAGE(write_data, read_data, sizeof(write_data), msg);
        }
    }
}


TEST(atca_cmd_basic_test, write_invalid_block)
{
    uint8_t write_data[ATCA_BLOCK_SIZE];
    // invalid block

    ATCA_STATUS status = ATCA_SUCCESS;

    // Testing invalid blocks for ECC devices
    // TODO: Update to work with ATSHA204A
    test_assert_config_is_locked();
    test_assert_data_is_unlocked();

    // valid slot and last offset, invalid block
    status = atcab_write_zone(ATCA_ZONE_DATA, 8, 4, 7, write_data, ATCA_WORD_SIZE);
    TEST_ASSERT(ATCA_PARSE_ERROR == status || ATCA_EXECUTION_ERROR == status);
    // invalid slot, valid block and offset
    status = atcab_write_zone(ATCA_ZONE_DATA, 16, 0, 0, write_data, ATCA_BLOCK_SIZE);
    TEST_ASSERT(ATCA_PARSE_ERROR == status || ATCA_EXECUTION_ERROR == status);
    // valid slot, invalid block and offset
    status = atcab_write_zone(ATCA_ZONE_DATA, 10, 4, 8, write_data, ATCA_WORD_SIZE);
    TEST_ASSERT(ATCA_PARSE_ERROR == status || ATCA_EXECUTION_ERROR == status);
    // valid block(4-bytes size) and slot, invalid offset
    status = atcab_write_zone(ATCA_ZONE_DATA, 10, 2, 2, write_data, ATCA_WORD_SIZE);
    TEST_ASSERT(ATCA_PARSE_ERROR == status || ATCA_EXECUTION_ERROR == status);
}

TEST(atca_cmd_basic_test, write_invalid_block_len)
{
    uint8_t write_data[ATCA_BLOCK_SIZE];
    uint8_t write_data1[ATCA_BLOCK_SIZE];
    uint8_t write_data2[ATCA_BLOCK_SIZE];
    // invalid block and write word len combination

    ATCA_STATUS status = ATCA_SUCCESS;

    // Tests assume ECC slot sizes
    // TODO: Update for ATSHA204A
    test_assert_config_is_locked();
    test_assert_data_is_unlocked();

    memset(write_data, 0xAB, ATCA_BLOCK_SIZE);
    memset(write_data1, 0xAA, ATCA_BLOCK_SIZE);
    memset(write_data2, 0xBB, ATCA_BLOCK_SIZE);


    //writing 4bytes into 32 byte slot size
    status = atcab_write_zone(ATCA_ZONE_DATA, 10, 0, 0, write_data1, ATCA_WORD_SIZE);
    // not success for unlocked case(4 byte write command not allowed for data zone unlocked case only 32 byte write), success for locked case
    TEST_ASSERT_EQUAL(ATCA_EXECUTION_ERROR, status);
    //writing 32 bytes into 4bytes block => 32-byte Write command writes only 4 bytes and ignores the rest
    status = atcab_write_zone(ATCA_ZONE_DATA, 10, 2, 1, write_data, ATCA_BLOCK_SIZE);
    //pass for both locked and unlocked case
    TEST_ASSERT_EQUAL(gCfg->devtype == ATSHA204A ? ATCA_PARSE_ERROR : ATCA_SUCCESS, status);
}

TEST(atca_cmd_basic_test, write_bytes_zone_config)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t pattern_config[ATCA_ECC_CONFIG_SIZE];
    uint8_t read_config[ATCA_ECC_CONFIG_SIZE];
    uint8_t orig_config[ATCA_ECC_CONFIG_SIZE];
    size_t config_size;
    size_t i;

    test_assert_config_is_unlocked();

    // Build test pattern
    for (i = 0; i < sizeof(pattern_config); i++)
    {
        pattern_config[i] = (uint8_t)i;
    }

    // Lock bytes won't be written and must be unlocked for this test
    pattern_config[86] = 0x55;
    pattern_config[87] = 0x55;

    status = atcab_get_zone_size(ATCA_ZONE_CONFIG, 0, &config_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read config zone so we can return it to the original state
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 0, orig_config, config_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // UserExtra and Selector (UserExtraAdd for 608) bytes won't be changed either
    pattern_config[84] = orig_config[84];
    pattern_config[85] = orig_config[85];

    // Write pattern config, skip the first 20 bytes some we don't mess with any device settings
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 20, &pattern_config[20], config_size - 20);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read config to check write
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 0, read_config, config_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Make sure read data matches what was written
    TEST_ASSERT_EQUAL_MEMORY(&pattern_config[20], &read_config[20], config_size - 20);

    // Return config zone to original state
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, 16, &orig_config[16], config_size - 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read config to check write
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 0, read_config, config_size);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    // Make sure read data matches what was written
    TEST_ASSERT_EQUAL_MEMORY(orig_config, read_config, config_size);
}

uint8_t g_nolock_otp[ATCA_OTP_SIZE];
bool g_is_otp_nolock = false;

TEST(atca_cmd_basic_test, write_otp_zone_nolock)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    test_assert_config_is_locked();
    test_assert_data_is_unlocked();

    memset(g_nolock_otp, 0xFF, sizeof(g_nolock_otp));
    g_nolock_otp[4] = 0x7F;
    g_nolock_otp[sizeof(g_nolock_otp) - 1] = 0xFE;

    // Update OTP
    status = atcab_write_bytes_zone(ATCA_ZONE_OTP, 0, 0, &g_nolock_otp[0], sizeof(g_nolock_otp));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    g_is_otp_nolock = true;
    // Checked in test_basic_write_otp_zone_nolock_check() once reads are allowed
}

TEST(atca_cmd_basic_test, write_otp_zone_nolock_check)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t read_otp[ATCA_OTP_SIZE];

    if (!g_is_otp_nolock)
    {
        TEST_IGNORE_MESSAGE("test_basic_write_otp_zone_nolock() wasn't run beforehand.");
    }

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    // Read current state of OTP
    status = atcab_read_bytes_zone(ATCA_ZONE_OTP, 0, 0, read_otp, sizeof(read_otp));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(g_nolock_otp, read_otp, sizeof(g_nolock_otp));

    g_is_otp_nolock = false; // reset
}

TEST(atca_cmd_basic_test, write_otp_zone)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t config_chunk[4];
    uint8_t new_otp[ATCA_OTP_SIZE];
    uint8_t read_otp[ATCA_OTP_SIZE];
    int i;
    int j;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    //since the 608 eliminated consumption mode, run a simpler test
    if (ATECC608 == (gCfg->devtype))
    {
        //initialize some data to try to write into OTP
        for (i = 0; i < ATCA_OTP_SIZE; i++)
        {
            new_otp[i] = i;
        }

        //try to write - this shouldn't succeed
        status = atcab_write_bytes_zone(ATCA_ZONE_OTP, 0, 4, &new_otp[4], sizeof(new_otp) - 4);
        TEST_ASSERT_EQUAL(ATCA_EXECUTION_ERROR, status);

        return;
    }

    // Make sure OTP is in consumption mode
    status = atcab_read_zone(ATCA_ZONE_CONFIG, 0, 0, 4, config_chunk, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    if (config_chunk[2] != 0x55)
    {
        TEST_IGNORE_MESSAGE("OTPMode must be consuption (0x55) for this test.");
    }

    // Read current state of OTP
    status = atcab_read_bytes_zone(ATCA_ZONE_OTP, 0, 0, read_otp, sizeof(read_otp));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Make sure we still have some bits we can change to 0
    for (i = 4; i < (int)sizeof(read_otp); i++)
    {
        if (read_otp[i] != 0)
        {
            break;
        }
    }
    if (i >= (int)sizeof(read_otp))
    {
        TEST_IGNORE_MESSAGE("OTP is already set to all zeros past byte 4, can't test.");
    }

    memcpy(new_otp, read_otp, sizeof(new_otp));
    // Flip the first 1 bit to a zero
    for (i = 4; i < (int)sizeof(new_otp); i++)
    {
        if (new_otp[i] != 0)
        {
            for (j = 7; j >= 0; j--)
            {
                if (new_otp[i] & (1 << j))
                {
                    new_otp[i] &= ~(1 << j);
                    break;
                }
            }
            break;
        }
    }
    // Flip the last 1 bit to a zero
    for (i = sizeof(new_otp) - 1; i >= 0; i--)
    {
        if (new_otp[i] != 0)
        {
            for (j = 0; j < 8; j++)
            {
                if (new_otp[i] & (1 << j))
                {
                    new_otp[i] &= ~(1 << j);
                    break;
                }
            }
            break;
        }
    }

    // Update OTP
    status = atcab_write_bytes_zone(ATCA_ZONE_OTP, 0, 4, &new_otp[4], sizeof(new_otp) - 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read current state of OTP
    status = atcab_read_bytes_zone(ATCA_ZONE_OTP, 0, 0, read_otp, sizeof(read_otp));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(new_otp, read_otp, sizeof(new_otp));
}

TEST(atca_cmd_basic_test, write_slot4_key)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    test_assert_config_is_locked();

    status = atcab_write_zone(ATCA_ZONE_DATA, 4, 0, 0, g_slot4_key, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
#endif

TEST(atca_cmd_basic_test, write_data_zone_blocks)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t write_data[ATCA_BLOCK_SIZE * 2];
    uint8_t read_data[sizeof(write_data)];
    uint16_t slot;

    // Test assumes ECC slot sizes
    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_DATA, &slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate random data to be written
    status = atcab_random(&write_data[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_random(&write_data[ATCA_BLOCK_SIZE]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Test cross-block writes
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, slot, 4, write_data, sizeof(write_data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, 4, read_data, sizeof(read_data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(write_data, read_data, sizeof(write_data));

    // Test mid-block word writes
    status = atcab_write_zone(ATCA_ZONE_DATA, slot, 1, 6, write_data, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_read_bytes_zone(ATCA_ZONE_DATA, slot, 56, read_data, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(write_data, read_data, 4);
}

#if ATCA_CA_SUPPORT
TEST(atca_cmd_basic_test, write_bytes_zone_slot8)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t write_data[64];

    //uint8_t read_data[sizeof(write_data)];
    test_assert_config_is_locked();
    test_assert_data_is_unlocked();

    // Generate random data to be written
    status = atcab_random(&write_data[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_random(&write_data[ATCA_BLOCK_SIZE]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Writes must be block-level when the data zone is unlocked
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, 8, 10 * 32, write_data, sizeof(write_data));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Can't read data when the data zone is unlocked
    //status = atcab_read_bytes_zone(ATCA_ZONE_DATA, 8, 10*32, read_data, sizeof(read_data));
    //TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //TEST_ASSERT_EQUAL_MEMORY(write_data, read_data, sizeof(write_data));
}

TEST(atca_cmd_basic_test, write_enc)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint16_t key_id = 8;
    uint8_t block = 5;
    uint8_t write_data[ATCA_KEY_SIZE];
    uint8_t read_data[ATCA_KEY_SIZE];
    uint8_t host_num_in[NONCE_NUMIN_SIZE] = { 0 };

    test_assert_data_is_locked();

    // Test assumes ECC sized slot 8.. Whereas slot 8 for SHA204A
    if (gCfg->devtype == ATSHA204A)
    {
        key_id = 3; block = 0;
    }

    status = atcab_random(&write_data[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
    status = atcab_write_enc(key_id, block, write_data, g_slot4_key, 4);
#else
    status = atcab_write_enc(key_id, block, write_data, g_slot4_key, 4, host_num_in);
#endif
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
    status = atcab_read_enc(key_id, block, read_data, g_slot4_key, 4);
#else
    status = atcab_read_enc(key_id, block, read_data, g_slot4_key, 4, host_num_in);
#endif
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(write_data, read_data, sizeof(write_data));
}

/*
   Test brief - This test demonstrates Write encryption when DATA zone is unlocked.
   When it is unlocked, write command paramete zone.bit6 decides whether the input data is encryted or not.
 */
TEST(atca_cmd_basic_test, write_enc_data_unlock)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint16_t key_id = 8;
    uint8_t block = 0;
    uint8_t write_data[ATCA_KEY_SIZE];
    uint8_t host_num_in[NONCE_NUMIN_SIZE] = { 0 };

    uint8_t other_data[13];
    uint8_t response[32];
    uint8_t sn[9];
    atca_check_mac_in_out_t checkmac_params;
    const uint8_t challenge[32] = {
        0x10, 0x04, 0xbb, 0x7b, 0xc7, 0xe2, 0x40, 0xd4, 0xca, 0x1d, 0x6b, 0x04, 0x73, 0x22, 0xd5, 0xfd,
        0xad, 0x69, 0x2a, 0x73, 0x39, 0x8e, 0xaa, 0xc3, 0x3a, 0x5a, 0xc4, 0x9e, 0x02, 0xb4, 0x8b, 0x5d
    };

    /*Ensure DATA zone is unlocked */
    test_assert_config_is_locked();
    test_assert_data_is_unlocked();

    /*Get random data and do encrypted write*/
    status = atcab_random(&write_data[0]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
    status = atcab_write_enc(key_id, block, write_data, g_slot4_key, 4);
#else
    status = atcab_write_enc(key_id, block, write_data, g_slot4_key, 4, host_num_in);
#endif
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /*Verify write using Checkmac*/

    /*Populate parameters for Checkmac*/
    memset(&checkmac_params, 0, sizeof(checkmac_params));
    memset(&other_data, 0, sizeof(other_data));
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /*Calculate response for challenge on the host */
    checkmac_params.mode = CHECKMAC_MODE_CHALLENGE;
    checkmac_params.key_id = key_id;
    checkmac_params.client_chal = challenge;
    checkmac_params.client_resp = response;
    checkmac_params.other_data = other_data;
    checkmac_params.sn = sn;
    checkmac_params.slot_key = write_data;
    checkmac_params.temp_key = NULL;
    status = atcah_check_mac(&checkmac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /*Issue Checkmac command to device with host challenge and response */
    status = atcab_checkmac(checkmac_params.mode, checkmac_params.key_id, checkmac_params.client_chal, checkmac_params.client_resp, checkmac_params.other_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
#endif

TEST(atca_cmd_basic_test, write_zone)
{
    //ATCA_STATUS status = ATCA_GEN_FAIL;

    // TODO - implement write zone basic api test
}
TEST(atca_cmd_basic_test, write_config_zone)
{
    ATCA_STATUS status = ATCA_NO_DEVICES;

    test_assert_config_is_unlocked();

    switch (gCfg->devtype)
    {
#ifdef ATCA_ATSHA204A_SUPPORT
    case ATSHA204A:
        status = atcab_write_config_zone(sha204_default_config);
        break;
#endif

#if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
    case ATECC108A:
    case ATECC508A:
        status = atcab_write_config_zone(test_ecc_configdata);
        break;
#endif
#ifdef ATCA_ATECC608_SUPPORT
    case ATECC608:
        status = atcab_write_config_zone(test_ecc608_configdata);
        break;
#endif

#if ATCA_TA_SUPPORT
    case TA100:
        status = atcab_write_config_zone(test_ta100_configdata);
        break;
#endif

    default:
        break;
    }

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_basic_test, write_pubkey)
{
    uint16_t public_key_id;
    ATCA_STATUS status = ATCA_GEN_FAIL;
    bool is_data_locked;
    const uint8_t public_key_ref[64] = {
        0x44, 0xCE, 0xAE, 0x5E, 0x80, 0x2E, 0xE7, 0x16, 0x9D, 0x77, 0xDB, 0x0A, 0x55, 0x5A, 0x38, 0xED,
        0xB2, 0x88, 0xAC, 0x73, 0x61, 0x56, 0xCA, 0x5B, 0x20, 0x0B, 0x57, 0x94, 0x7A, 0x48, 0x63, 0x50,
        0xE9, 0x72, 0xC4, 0x11, 0x3D, 0x71, 0x9A, 0xAF, 0x83, 0x72, 0x0E, 0xEF, 0x94, 0x3B, 0xDA, 0x69,
        0xD8, 0x39, 0x20, 0xD5, 0x23, 0xB8, 0x1C, 0x96, 0x49, 0x7C, 0x26, 0x62, 0x00, 0x3B, 0x7C, 0x01
    };
    uint8_t public_key[sizeof(public_key_ref)];

    test_assert_config_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_ECC_VERIFY, &public_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_write_pubkey(public_key_id, public_key_ref);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_is_data_locked(&is_data_locked);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (is_data_locked)
    {
        status = atcab_read_pubkey(public_key_id, public_key);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(public_key_ref, public_key, sizeof(public_key_ref));
    }
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info write_basic_test_info[] =
{
#if ATCA_CA_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_boundary_conditions),   DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    //{ REGISTER_TEST_CASE(atca_cmd_basic_test, write_upper_slots),                                    DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_invalid_block),         DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_invalid_block_len),     DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_bytes_zone_config),     DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_otp_zone_nolock),       DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_otp_zone_nolock_check), DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_otp_zone),              DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_slot4_key),             DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
#endif
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_data_zone_blocks),                               DEVICE_MASK_ECC | DEVICE_MASK(TA100) },
#if ATCA_CA_SUPPORT
    //{ REGISTER_TEST_CASE(atca_cmd_basic_test, write_bytes_zone_slot8),                               DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_enc),                   DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_enc_data_unlock),       DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC                      },
#endif
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_zone),                  DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC | DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_config_zone),           DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC | DEVICE_MASK(TA100)},
    { REGISTER_TEST_CASE(atca_cmd_basic_test, write_pubkey),                                         DEVICE_MASK_ECC | DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },                 /* Array Termination element*/
};
// *INDENT-ON*

