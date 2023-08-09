/**
 * \file
 * \brief Unity tests for the cryptoauthlib Verify Command
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
#include "test_atcab.h"

#ifndef TEST_ATCAB_MAC_EN
#define TEST_ATCAB_MAC_EN       CALIB_MAC_EN
#endif

#ifndef TEST_ATCAB_CHECKMAC_SHA105_EN
#define TEST_ATCAB_CHECKMAC_SHA105_EN      CALIB_CHECKMAC_EN
#endif

#if TEST_ATCAB_MAC_EN

TEST_CONDITION(atca_cmd_basic_test, mac_key_challenge)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (atcab_is_ca_device(dev_type) && (ATSHA206A != dev_type)) || (SHA104 == dev_type);
}

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
    if (SHA104 == gCfg->devtype)
    {
        memset(challenge, 0, sizeof(challenge));
    }
    else
    {
    #if CALIB_RANDOM_EN
        status = atcab_random(challenge);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    #endif
    }

    // Setup MAC command
    memset(&temp_key, 0, sizeof(temp_key));
    mac_params.mode = MAC_MODE_CHALLENGE | MAC_MODE_INCLUDE_SN; // Block 1 is a key, block 2 is a challenge
    mac_params.key_id = (SHA104 != gCfg->devtype) ? (4) : (MAC_SHA104_DEFAULT_KEYID);
    mac_params.challenge = challenge;
    mac_params.key = g_slot4_key; // Ensure that g_slot4_key is written into key_id
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

TEST_CONDITION(atca_cmd_basic_test, mac_key_tempkey)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return atcab_is_ca_device(dev_type) && (ATSHA206A != dev_type);
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
    mac_params.key_id = (SHA104 != gCfg->devtype) ? (4) : (MAC_SHA104_DEFAULT_KEYID);
    mac_params.challenge = NULL;
    mac_params.key = g_slot4_key; // Ensure that g_slot4_key is written into key_id
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
    if (SHA104 != gCfg->devtype)
    {
    #if CALIB_RANDOM_EN
        status = atcab_random(challenge);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    #endif
    }
    else
    {
        memset(challenge, 0, sizeof(challenge));
    }

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
    mac_params.key_id = (SHA104 != gCfg->devtype) ? (0) : (MAC_SHA104_DEFAULT_KEYID);
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
    mac_params.key_id = (SHA104 != gCfg->devtype) ? (0) : (MAC_SHA104_DEFAULT_KEYID);
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

TEST_CONDITION(atca_cmd_basic_test, checkmac)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return atcab_is_ca_device(dev_type) && (ATSHA206A != dev_type);
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
#endif

#if TEST_ATCAB_CHECKMAC_SHA105_EN

TEST_CONDITION(atca_cmd_basic_test, checkmac_sha105)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return SHA105 == dev_type;
}

TEST(atca_cmd_basic_test, checkmac_sha105_without_resp_mac)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t challenge[RANDOM_NUM_SIZE];
    uint8_t response[MAC_SIZE], client_response[MAC_SIZE];
    uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];
    atca_temp_key_t temp_key;
    atca_mac_in_out_t mac_params;
    atca_check_mac_in_out_t checkmac_params;
    uint16_t key_id;
    // Assuming SN of Client device
    uint8_t sn[ATCA_SERIAL_NUM_SIZE] = { 0x01, 0x23, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xEE };

    // CSZ0 and CSZ1 should be locked
    test_assert_config_is_locked();
    test_assert_data_is_locked();

    memset(challenge, 0x55, 32);    // a 32-byte challenge

    // Get key_id
    status = atca_test_config_get_id(TEST_TYPE_HMAC, &key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read SN
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Setup MAC command
    memset(&temp_key, 0, sizeof(temp_key));
    mac_params.mode = MAC_MODE_CHALLENGE | MAC_MODE_INCLUDE_SN; // Block 1 is a key, block 2 is a challenge
    mac_params.key_id = key_id;
    mac_params.challenge = challenge;
    mac_params.key = g_slot4_key; // Ensure that g_slot4_key is written into key_id
    mac_params.otp = NULL;
    mac_params.sn = sn;
    mac_params.response = response;
    mac_params.temp_key = &temp_key;

    // Calculate MAC
    status = atcah_mac(&mac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    other_data[0] = ATCA_MAC;
    other_data[1] = mac_params.mode;
    memcpy(&other_data[2], &mac_params.key_id, 2);
    memset(&other_data[4], 0, 3);  // 0 if mac is performed with SHA104 else OTP[8:10]
    memcpy(&other_data[7], &sn[4], 4);
    memcpy(&other_data[11], &sn[2], 2);

    // Perform CheckMac
    status = atcab_checkmac(CHECKMAC_MODE_CHALLENGE, CHECKMAC_SHA105_DEFAULT_KEYID, challenge, response, other_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform host side checkmac calculations
    checkmac_params.mode = CHECKMAC_MODE_CHALLENGE;
    checkmac_params.key_id = key_id;
    checkmac_params.client_chal = challenge;
    checkmac_params.client_resp = client_response;
    checkmac_params.other_data = other_data;
    checkmac_params.sn = sn;
    checkmac_params.otp = NULL;
    checkmac_params.slot_key = g_slot4_key;
    checkmac_params.target_key = NULL;
    checkmac_params.temp_key = &temp_key;
    status = atcah_check_mac(&checkmac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(response, client_response, sizeof(response));
}

TEST(atca_cmd_basic_test, checkmac_sha105_nonce)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_nonce_in_out_t nonce_params;
    atca_mac_in_out_t mac_params;
    uint8_t response[ATCA_KEY_SIZE];
    uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];
    uint16_t key_id;
    // Assuming SN of Client device
    uint8_t sn[ATCA_SERIAL_NUM_SIZE] = { 0x01, 0x23, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xEE };

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    // Read SN
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Get key_id
    status = atca_test_config_get_id(TEST_TYPE_HMAC, &key_id);
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
    mac_params.key_id = key_id;
    mac_params.challenge = NULL;
    mac_params.key = g_slot4_key; // Ensure that g_slot4_key is written into key_id
    mac_params.otp = NULL;
    mac_params.sn = sn;
    mac_params.response = response;
    mac_params.temp_key = &temp_key;

    // Calculate MAC
    status = atcah_mac(&mac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    other_data[0] = ATCA_MAC;
    other_data[1] = mac_params.mode;
    memcpy(&other_data[2], &mac_params.key_id, 2);
    memset(&other_data[4], 0, 3);  // 0 if mac is performed with SHA104 else OTP[8:10]
    memcpy(&other_data[7], &sn[4], 4);
    memcpy(&other_data[11], &sn[2], 2);

    // Perform CheckMac
    status = atcab_checkmac(CHECKMAC_MODE_CHALLENGE, CHECKMAC_SHA105_DEFAULT_KEYID, temp_key.value, response, other_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_basic_test, checkmac_sha105_with_resp_mac)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t challenge[RANDOM_NUM_SIZE];
    uint8_t response[MAC_SIZE], client_response[MAC_SIZE];
    uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];
    atca_temp_key_t temp_key;
    atca_mac_in_out_t mac_params;
    atca_check_mac_in_out_t checkmac_params;
    atca_resp_mac_in_out_t respmac_params;
    uint16_t key_id;
    uint8_t mac[MAC_SIZE];
    uint8_t resp_mac[MAC_SIZE];
    // Assuming SN of Client device
    uint8_t sn[ATCA_SERIAL_NUM_SIZE] = { 0x01, 0x23, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xEE };

    // I/O protection key should be written into Data Zone 0 and locked
    test_assert_data_is_locked();
    // CSZ0 and CSZ1 should be locked
    test_assert_config_is_locked();

    memset(challenge, 0x55, 32);    // a 32-byte challenge

    // Read SN
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Get key_id
    status = atca_test_config_get_id(TEST_TYPE_HMAC, &key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Setup MAC command
    memset(&temp_key, 0, sizeof(temp_key));
    mac_params.mode = MAC_MODE_CHALLENGE | MAC_MODE_INCLUDE_SN; // Block 1 is a key, block 2 is a challenge
    mac_params.key_id = key_id;
    mac_params.challenge = challenge;
    mac_params.key = g_slot4_key; // Ensure that g_slot4_key is written into key_id
    mac_params.otp = NULL;
    mac_params.sn = sn;
    mac_params.response = response;
    mac_params.temp_key = &temp_key;

    // Calculate MAC
    status = atcah_mac(&mac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    other_data[0] = ATCA_MAC;
    other_data[1] = mac_params.mode;
    memcpy(&other_data[2], &mac_params.key_id, 2);
    memset(&other_data[4], 0, 3); // 0 if mac is performed with SHA104 else OTP[8:10]
    memcpy(&other_data[7], &sn[4], 4);
    memcpy(&other_data[11], &sn[2], 2);

    // Perform CheckMac
    status = atcab_checkmac_with_response_mac(CHECKMAC_MODE_OUTPUT_MAC_RESPONSE, challenge, response, other_data, mac);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform host side checkmac calculation
    checkmac_params.mode = CHECKMAC_MODE_OUTPUT_MAC_RESPONSE;
    checkmac_params.key_id = key_id;
    checkmac_params.client_chal = challenge;
    checkmac_params.client_resp = client_response;
    checkmac_params.other_data = other_data;
    checkmac_params.sn = sn;
    checkmac_params.otp = NULL;
    checkmac_params.slot_key = g_slot4_key;
    checkmac_params.target_key = NULL;
    checkmac_params.temp_key = &temp_key;
    status = atcah_check_mac(&checkmac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(response, client_response, sizeof(response));

    // Perform host side output mac calculation
    respmac_params.slot_key = g_slot4_key;
    respmac_params.mode = CHECKMAC_MODE_OUTPUT_MAC_RESPONSE;
    respmac_params.key_id = CHECKMAC_SHA105_DEFAULT_KEYID;
    respmac_params.sn = sn;
    respmac_params.client_resp = response;
    respmac_params.checkmac_result = 0;
    respmac_params.mac_output = resp_mac;
    status = atcah_gen_output_resp_mac(&respmac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(mac, resp_mac, sizeof(mac));
}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info mac_basic_test_info[] =
{
#if TEST_ATCAB_MAC_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mac_key_challenge),     REGISTER_TEST_CONDITION(atca_cmd_basic_test, mac_key_challenge) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mac_key_tempkey),       REGISTER_TEST_CONDITION(atca_cmd_basic_test, mac_key_tempkey) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mac_tempkey_challenge), REGISTER_TEST_CONDITION(atca_cmd_basic_test, mac_key_tempkey) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mac_tempkey_tempkey),   REGISTER_TEST_CONDITION(atca_cmd_basic_test, mac_key_tempkey) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, checkmac),              REGISTER_TEST_CONDITION(atca_cmd_basic_test, checkmac) },
#endif
#if TEST_ATCAB_CHECKMAC_SHA105_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, checkmac_sha105_without_resp_mac),  REGISTER_TEST_CONDITION(atca_cmd_basic_test, checkmac_sha105) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, checkmac_sha105_nonce),             REGISTER_TEST_CONDITION(atca_cmd_basic_test, checkmac_sha105) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, checkmac_sha105_with_resp_mac),     REGISTER_TEST_CONDITION(atca_cmd_basic_test, checkmac_sha105) },
#endif
    /* Array Termination element*/
    { (fp_test_case)NULL, NULL },
};
// *INDENT-ON*
