/**
 * \file
 * \brief Unity tests for the cryptoauthlib Verify Command
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

TEST(atca_cmd_unit_test, derivekey)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t keyID = 9;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();

    //build a nonce command
    packet.param1 = NONCE_MODE_SEED_UPDATE;
    packet.param2 = 0x0000;
    memset(packet.data, 0x00, 32);

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_SHORT, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_LONG, packet.data[ATCA_COUNT_IDX]);

    // build a deriveKey command (Roll Key operation)
    packet.param1 = 0;
    packet.param2 = keyID;
    status = atDeriveKey(ca_cmd, &packet, true);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // check for derive key response if it's success or not
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[ATCA_RSP_DATA_IDX]);
}

TEST(atca_cmd_basic_test, derivekey)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint16_t target_key_id = 9;
    const uint8_t parent_key[32] = {
        0x55, 0xe1, 0xe1, 0x97, 0x53, 0xf8, 0xee, 0x0b, 0x20, 0x4b, 0x97, 0x09, 0xfd, 0xd0, 0xf0, 0xf9,
        0x75, 0x14, 0x60, 0x21, 0xcc, 0x5f, 0x96, 0x7d, 0xa1, 0xe1, 0x30, 0xfe, 0xed, 0xb0, 0xfe, 0x87
    };
    const uint8_t nonce_seed[20] = {
        0xe5, 0x1e, 0xb3, 0xcb, 0x5d, 0x27, 0x59, 0xfa, 0x03, 0xd8, 0x88, 0xbb, 0x54, 0x35, 0x35, 0xb6,
        0x74, 0x25, 0x10, 0x21
    };
    uint8_t sn[9];
    uint8_t rand_out[32];
    atca_temp_key_t temp_key_params;
    atca_nonce_in_out_t nonce_params;
    uint8_t derived_key[32];
    struct atca_derive_key_in_out derivekey_params;
    const uint8_t challenge[32] = {
        0x10, 0x04, 0xbb, 0x7b, 0xc7, 0xe2, 0x40, 0xd4, 0xca, 0x1d, 0x6b, 0x04, 0x73, 0x22, 0xd5, 0xfd,
        0xad, 0x69, 0x2a, 0x73, 0x39, 0x8e, 0xaa, 0xc3, 0x3a, 0x5a, 0xc4, 0x9e, 0x02, 0xb4, 0x8b, 0x5d
    };
    const uint8_t other_data[13] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t response[32];
    atca_check_mac_in_out_t checkmac_params;

    test_assert_data_is_locked();

    // Read the device serial number
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Initialize the slot with a known key
    status = atcab_write_enc(target_key_id, 0, parent_key, g_slot4_key, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    memset(&temp_key_params, 0, sizeof(temp_key_params));

    // Use a random nonce for the derive key command
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = nonce_seed;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key_params;
    status = atcab_nonce_rand(nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate TempKey from nonce command
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Run the derive key command assuming target/roll mode
    derivekey_params.mode = 0; // Random nonce generated TempKey
    derivekey_params.target_key_id = target_key_id;
    derivekey_params.parent_key = parent_key;
    derivekey_params.sn = sn;
    derivekey_params.target_key = derived_key;
    derivekey_params.temp_key = &temp_key_params;
    status = atcab_derivekey(derivekey_params.mode, derivekey_params.target_key_id, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate the derived key
    status = atcah_derive_key(&derivekey_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate new random nonce for validating derived key
    status = atcab_nonce_rand(nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate TempKey from nonce command
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate checkmac response for validation
    memset(&checkmac_params, 0, sizeof(checkmac_params));
    checkmac_params.mode = CHECKMAC_MODE_CHALLENGE; // Checkmac with challenge and random nonce
    checkmac_params.key_id = target_key_id;
    checkmac_params.client_chal = challenge;
    checkmac_params.client_resp = response;
    checkmac_params.other_data = other_data;
    checkmac_params.sn = sn;
    checkmac_params.slot_key = derived_key;
    checkmac_params.temp_key = &temp_key_params;
    status = atcah_check_mac(&checkmac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Run the checkmac command to validate the derived key
    status = atcab_checkmac(checkmac_params.mode, checkmac_params.key_id, checkmac_params.client_chal, checkmac_params.client_resp, checkmac_params.other_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_basic_test, derivekey_mac)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint16_t target_key_id = 3;
    const uint8_t nonce_seed[20] = {
        0xe5, 0x1e, 0xb3, 0xcb, 0x5d, 0x27, 0x59, 0xfa, 0x03, 0xd8, 0x88, 0xbb, 0x54, 0x35, 0x35, 0xb6,
        0x74, 0x25, 0x10, 0x21
    };
    uint8_t sn[9];
    uint8_t rand_out[32];
    atca_temp_key_t temp_key_params;
    atca_nonce_in_out_t nonce_params;
    uint8_t mac[32];
    struct atca_derive_key_mac_in_out derivekey_mac_params;
    uint8_t derived_key[32];
    struct atca_derive_key_in_out derivekey_params;
    const uint8_t challenge[32] = {
        0x10, 0x04, 0xbb, 0x7b, 0xc7, 0xe2, 0x40, 0xd4, 0xca, 0x1d, 0x6b, 0x04, 0x73, 0x22, 0xd5, 0xfd,
        0xad, 0x69, 0x2a, 0x73, 0x39, 0x8e, 0xaa, 0xc3, 0x3a, 0x5a, 0xc4, 0x9e, 0x02, 0xb4, 0x8b, 0x5d
    };
    const uint8_t other_data[13] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t response[32];
    atca_check_mac_in_out_t checkmac_params;

    test_assert_data_is_locked();

    // Read the device serial number
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    memset(&temp_key_params, 0, sizeof(temp_key_params));

    // Use a random nonce for the derive key command
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = nonce_seed;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key_params;
    status = atcab_nonce_rand(nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate TempKey from nonce command
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate the DeriveKey MAC required
    derivekey_mac_params.mode = 0; // Random nonce generated TempKey
    derivekey_mac_params.target_key_id = target_key_id;
    derivekey_mac_params.sn = sn;
    derivekey_mac_params.parent_key = g_slot4_key;
    derivekey_mac_params.mac = mac;
    status = atcah_derive_key_mac(&derivekey_mac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Run the derive key command assuming target/roll mode
    derivekey_params.mode = derivekey_mac_params.mode;
    derivekey_params.target_key_id = derivekey_mac_params.target_key_id;
    derivekey_params.parent_key = derivekey_mac_params.parent_key;
    derivekey_params.sn = derivekey_mac_params.sn;
    derivekey_params.target_key = derived_key;
    derivekey_params.temp_key = &temp_key_params;
    status = atcab_derivekey(derivekey_params.mode, derivekey_params.target_key_id, mac);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate the derived key
    status = atcah_derive_key(&derivekey_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate new random nonce for validating derived key
    status = atcab_nonce_rand(nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate TempKey from nonce command
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate checkmac response for validation
    memset(&checkmac_params, 0, sizeof(checkmac_params));
    checkmac_params.mode = CHECKMAC_MODE_CHALLENGE; // Checkmac with challenge and random nonce
    checkmac_params.key_id = target_key_id;
    checkmac_params.client_chal = challenge;
    checkmac_params.client_resp = response;
    checkmac_params.other_data = other_data;
    checkmac_params.sn = sn;
    checkmac_params.slot_key = derived_key;
    checkmac_params.temp_key = &temp_key_params;
    status = atcah_check_mac(&checkmac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Run the checkmac command to validate the derived key
    status = atcab_checkmac(checkmac_params.mode, checkmac_params.key_id, checkmac_params.client_chal, checkmac_params.client_resp, checkmac_params.other_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info derivekey_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, derivekey),     DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, derivekey_mac), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};

t_test_case_info derivekey_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, derivekey), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

