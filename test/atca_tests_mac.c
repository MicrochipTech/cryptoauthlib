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

TEST(atca_cmd_basic_test, mac_key_challenge)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t sn[9];
    atca_temp_key_t temp_key;
    atca_mac_in_out_t mac_params;
    uint8_t challenge[ATCA_KEY_SIZE];
    uint8_t host_response[ATCA_KEY_SIZE];
    uint8_t client_response[ATCA_KEY_SIZE];

    test_assert_data_is_locked();

    // Read serial number for host-side MAC calculations
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Use a random challenge
    status = atcab_random(challenge);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Setup MAC command
    memset(&temp_key, 0, sizeof(temp_key));
    mac_params.mode = MAC_MODE_CHALLENGE | MAC_MODE_INCLUDE_SN; // Block 1 is a key, block 2 is a challenge
    mac_params.key_id = 4;
    mac_params.challenge = challenge;
    mac_params.key = g_slot4_key;
    mac_params.otp = NULL;
    mac_params.sn = sn;
    mac_params.response = host_response;
    mac_params.temp_key = &temp_key;

    // Run MAC command
    status = atcab_mac(mac_params.mode, mac_params.key_id, mac_params.challenge, client_response);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate expected MAC
    status = atcah_mac(&mac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(host_response, client_response, sizeof(host_response));
}

TEST(atca_cmd_basic_test, mac_key_tempkey)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t sn[9];
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_nonce_in_out_t nonce_params;
    atca_mac_in_out_t mac_params;
    uint8_t host_response[ATCA_KEY_SIZE];
    uint8_t client_response[ATCA_KEY_SIZE];

    test_assert_data_is_locked();

    // Read serial number for host-side MAC calculations
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Setup nonce command
    memset(&temp_key, 0, sizeof(temp_key));
    memset(num_in, 0, sizeof(num_in));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;

    // Create random nonce
    status = atcab_nonce_base(nonce_params.mode, nonce_params.zero, nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate nonce
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Setup MAC command
    memset(&mac_params, 0, sizeof(mac_params));
    mac_params.mode = MAC_MODE_BLOCK2_TEMPKEY | MAC_MODE_INCLUDE_SN; // Block 1 is a key, block 2 is TempKey
    mac_params.key_id = 4;
    mac_params.challenge = NULL;
    mac_params.key = g_slot4_key;
    mac_params.otp = NULL;
    mac_params.sn = sn;
    mac_params.response = host_response;
    mac_params.temp_key = &temp_key;

    // Run MAC command
    status = atcab_mac(mac_params.mode, mac_params.key_id, mac_params.challenge, client_response);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate expected MAC
    status = atcah_mac(&mac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(host_response, client_response, sizeof(host_response));
}

TEST(atca_cmd_basic_test, mac_tempkey_challenge)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t sn[9];
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_nonce_in_out_t nonce_params;
    atca_mac_in_out_t mac_params;
    uint8_t challenge[ATCA_KEY_SIZE];
    uint8_t host_response[ATCA_KEY_SIZE];
    uint8_t client_response[ATCA_KEY_SIZE];

    test_assert_data_is_locked();

    // Read serial number for host-side MAC calculations
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Use a random challenge
    status = atcab_random(challenge);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Setup nonce command
    memset(&temp_key, 0, sizeof(temp_key));
    memset(num_in, 0, sizeof(num_in));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;

    // Create random nonce
    status = atcab_nonce_base(nonce_params.mode, nonce_params.zero, nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate nonce
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Setup MAC command
    memset(&mac_params, 0, sizeof(mac_params));
    mac_params.mode = MAC_MODE_BLOCK1_TEMPKEY | MAC_MODE_INCLUDE_SN; // Block 1 is a TempKey, block 2 is a Challenge
    mac_params.key_id = 0;
    mac_params.challenge = challenge;
    mac_params.key = NULL;
    mac_params.otp = NULL;
    mac_params.sn = sn;
    mac_params.response = host_response;
    mac_params.temp_key = &temp_key;

    // Run MAC command
    status = atcab_mac(mac_params.mode, mac_params.key_id, mac_params.challenge, client_response);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate expected MAC
    status = atcah_mac(&mac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(host_response, client_response, sizeof(host_response));
}

TEST(atca_cmd_basic_test, mac_tempkey_tempkey)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t sn[9];
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_nonce_in_out_t nonce_params;
    atca_mac_in_out_t mac_params;
    uint8_t host_response[ATCA_KEY_SIZE];
    uint8_t client_response[ATCA_KEY_SIZE];

    test_assert_data_is_locked();

    // Read serial number for host-side MAC calculations
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Setup nonce command
    memset(&temp_key, 0, sizeof(temp_key));
    memset(num_in, 0, sizeof(num_in));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;

    // Create random nonce
    status = atcab_nonce_base(nonce_params.mode, nonce_params.zero, nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate nonce
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Setup MAC command
    memset(&mac_params, 0, sizeof(mac_params));
    mac_params.mode = MAC_MODE_BLOCK1_TEMPKEY | MAC_MODE_BLOCK2_TEMPKEY | MAC_MODE_INCLUDE_SN; // Block 1 is TempKey, block 2 is TempKey
    mac_params.key_id = 0;
    mac_params.challenge = NULL;
    mac_params.key = NULL;
    mac_params.otp = NULL;
    mac_params.sn = sn;
    mac_params.response = host_response;
    mac_params.temp_key = &temp_key;

    // Run MAC command
    status = atcab_mac(mac_params.mode, mac_params.key_id, mac_params.challenge, client_response);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate expected MAC
    status = atcah_mac(&mac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(host_response, client_response, sizeof(host_response));
}

TEST(atca_cmd_basic_test, checkmac)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t mode = MAC_MODE_CHALLENGE;
    uint16_t key_id = 0x0004;
    uint8_t challenge[RANDOM_NUM_SIZE];
    uint8_t response[MAC_SIZE];
    uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_nonce_in_out_t nonce_params;
    uint8_t sn[ATCA_SERIAL_NUM_SIZE];
    atca_check_mac_in_out_t checkmac_params;
    size_t i;

    test_assert_data_is_locked();


    memset(challenge, 0x55, 32);    // a 32-byte challenge

    status = atcab_mac(mode, key_id, challenge, response);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    memset(other_data, 0, sizeof(other_data));
    other_data[0] = ATCA_MAC;
    other_data[2] = (uint8_t)key_id;

    status = atcab_checkmac(mode, key_id, challenge, response, other_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // This next part tests the atcah_check_mac() function

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
}

TEST(atca_cmd_unit_test, mac)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t keyID = 0x01;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();

    // build a mac command
    packet.param1 = MAC_MODE_CHALLENGE;
    packet.param2 = keyID;
    memset(packet.data, 0x55, 32);    // a 32-byte challenge

    //memcpy(packet.data, challenge, sizeof(challenge));
    status = atMAC(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    atca_delay_ms(1);
}
TEST(atca_cmd_unit_test, checkmac)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t keyID = 0x0004;
    static uint8_t response_mac[MAC_RSP_SIZE];              // Make the response buffer the size of a MAC response.
    static uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];    // First four bytes of Mac command are needed for CheckMac command.
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();
    unit_test_assert_data_is_locked();

    if (_gDevice->mIface->mIfaceCFG->devtype == ATSHA204A)
    {
        keyID = 0x0001;
    }
    else
    {
        keyID = 0x0004;
    }

    // build a mac command
    packet.param1 = MAC_MODE_CHALLENGE;
    packet.param2 = keyID;
    memset(packet.data, 0x55, 32);    // a 32-byte challenge

    status = atMAC(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.data[ATCA_COUNT_IDX]);
    memcpy(response_mac, packet.data, sizeof(response_mac));

    // build a checkmac command
    packet.param1 = MAC_MODE_CHALLENGE;
    packet.param2 = keyID;
    memset(packet.data, 0x55, 32);    // a 32-byte challenge
    memcpy(&packet.data[32], &response_mac[1], 32);
    memset(other_data, 0, sizeof(other_data));
    other_data[0] = ATCA_MAC;
    other_data[2] = (uint8_t)keyID;
    memcpy(&packet.data[64], other_data, sizeof(other_data));

    status = atCheckMAC(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(CHECKMAC_RSP_SIZE, packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info mac_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mac_key_challenge),     DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mac_key_tempkey),       DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mac_tempkey_challenge), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mac_tempkey_tempkey),   DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, checkmac),              DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },           /* Array Termination element*/
};

t_test_case_info mac_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, mac),      DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, checkmac), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

