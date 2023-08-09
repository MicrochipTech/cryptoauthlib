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

#ifndef TEST_ATCAB_GENDIG_EN
#define TEST_ATCAB_GENDIG_EN         (ATCAB_GENDIG_EN && CALIB_FULL_FEATURE)
#endif

#ifndef TEST_ATCAB_GENDIVKEY_EN
#define TEST_ATCAB_GENDIVKEY_EN      (CALIB_GENDIVKEY_EN)
#endif

#if TEST_ATCAB_GENDIG_EN
TEST_CONDITION(atca_cmd_basic_test, gendig_shared_nonce)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ATECC508A == dev_type) || (ATECC608 == dev_type);
}

TEST(atca_cmd_basic_test, gendig_shared_nonce)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t i, sn[9];
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_nonce_in_out_t nonce_params;
    atca_mac_in_out_t mac_params;
    uint8_t host_response[ATCA_KEY_SIZE];
    uint8_t client_response[ATCA_KEY_SIZE];
    atca_gen_dig_in_out_t gen_dig_params;
    uint8_t other_data[32];

    test_assert_data_is_locked();

    uint16_t key_id[] = { 0x0004, 0x8004 };
    // Read serial number for host-side MAC calculations
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    for (i = 0; i < sizeof(key_id) / sizeof(key_id[0]); i++)
    {
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

        memset(other_data, 0x00, sizeof(other_data));
        // Use GenDig to create an initial digest across the internal key to be signed
        memset(&gen_dig_params, 0, sizeof(gen_dig_params));
        gen_dig_params.zone = GENDIG_ZONE_SHARED_NONCE;
        gen_dig_params.key_id = key_id[i];
        gen_dig_params.is_key_nomac = false;
        gen_dig_params.stored_value = NULL;
        gen_dig_params.sn = sn;
        gen_dig_params.other_data = other_data;
        gen_dig_params.temp_key = &temp_key;
        status = atcab_gendig(gen_dig_params.zone, gen_dig_params.key_id, other_data, 32);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcah_gen_dig(&gen_dig_params);
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
}

TEST(atca_cmd_basic_test, gendig_keyconfig)
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
    atca_gen_dig_in_out_t gen_dig_params;
    uint8_t config_zone[128];
    uint32_t counter_read_value;

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

    status = atcab_counter_read(0, &counter_read_value);         //Read the counter_value from counter0
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    atcab_read_config_zone(config_zone);

    // Use GenDig to create an initial digest across the internal key to be signed
    memset(&gen_dig_params, 0, sizeof(gen_dig_params));
    gen_dig_params.zone = GENDIG_ZONE_KEY_CONFIG;
    gen_dig_params.slot_conf = (uint16_t)(config_zone[20 + (4 * 2)] | config_zone[21 + (4 * 2)] << 8);
    gen_dig_params.key_conf = (uint16_t)(config_zone[96 + (4 * 2)] | config_zone[97 + (4 * 2)] << 8);
    gen_dig_params.slot_locked = 1;
    gen_dig_params.key_id = 4;
    gen_dig_params.is_key_nomac = false;
    gen_dig_params.stored_value = NULL;
    gen_dig_params.counter = counter_read_value;
    gen_dig_params.sn = sn;
    gen_dig_params.other_data = NULL;
    gen_dig_params.temp_key = &temp_key;
    status = atcab_gendig(gen_dig_params.zone, gen_dig_params.key_id, NULL, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcah_gen_dig(&gen_dig_params);
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

TEST(atca_cmd_basic_test, gendig_counter)
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
    atca_gen_dig_in_out_t gen_dig_params;
    uint32_t counter_read_value;

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

    status = atcab_counter_read(0, &counter_read_value);         //Read the counter_value from counter0
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Use GenDig to create an initial digest across the internal key to be signed
    memset(&gen_dig_params, 0, sizeof(gen_dig_params));
    gen_dig_params.zone = GENDIG_ZONE_COUNTER;
    gen_dig_params.key_id = 0;
    gen_dig_params.is_key_nomac = false;
    gen_dig_params.stored_value = NULL;
    gen_dig_params.counter = counter_read_value;
    gen_dig_params.sn = sn;
    gen_dig_params.other_data = NULL;
    gen_dig_params.temp_key = &temp_key;
    status = atcab_gendig(gen_dig_params.zone, gen_dig_params.key_id, NULL, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcah_gen_dig(&gen_dig_params);
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

TEST_CONDITION(atca_cmd_basic_test, gendig_config_otp_data)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return atcab_is_ca_device(dev_type) && (ATSHA206A != dev_type);
}

TEST(atca_cmd_basic_test, gendig_config_otp_data)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t i, sn[9];
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_nonce_in_out_t nonce_params;
    atca_mac_in_out_t mac_params;
    uint8_t host_response[ATCA_KEY_SIZE];
    uint8_t client_response[ATCA_KEY_SIZE];
    atca_gen_dig_in_out_t gen_dig_params;
    uint8_t config_zone[ATCA_ECC_CONFIG_SIZE];
    uint8_t read_otp[ATCA_OTP_SIZE];

    test_assert_data_is_locked();


    uint8_t gendig_modes[] = { GENDIG_ZONE_CONFIG, GENDIG_ZONE_OTP, GENDIG_ZONE_DATA };
    const uint8_t* gendig_modes_data[] = { config_zone, read_otp, g_slot4_key };
    uint8_t gendig_modes_key[] = { 0, 0, 4 };


    // Read current state of OTP
    status = atcab_read_bytes_zone(ATCA_ZONE_OTP, 0, 0, read_otp, sizeof(read_otp));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    atcab_read_config_zone(config_zone);

    // Read serial number for host-side MAC calculations
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    for (i = 0; i < sizeof(gendig_modes) / sizeof(gendig_modes[0]); i++)
    {
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

        // Use GenDig to create an initial digest across the internal key to be signed
        memset(&gen_dig_params, 0, sizeof(gen_dig_params));
        gen_dig_params.zone = gendig_modes[i];
        gen_dig_params.key_id = gendig_modes_key[i];
        gen_dig_params.is_key_nomac = false;
        gen_dig_params.stored_value = gendig_modes_data[i];
        gen_dig_params.sn = sn;
        gen_dig_params.other_data = NULL;
        gen_dig_params.temp_key = &temp_key;
        status = atcab_gendig(gen_dig_params.zone, gen_dig_params.key_id, NULL, 0);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcah_gen_dig(&gen_dig_params);
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
}
#endif

#if TEST_ATCAB_GENDIVKEY_EN
TEST_CONDITION(atca_cmd_basic_test, gendivkey)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return SHA105 == dev_type;
}

TEST(atca_cmd_basic_test, gendivkey)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    atca_nonce_in_out_t nonce_params;
    atca_diversified_key_in_out_t gen_div_params;
    uint8_t other_data[ATCA_WORD_SIZE];
    // Assuming SN of client device
    uint8_t sn[ATCA_SERIAL_NUM_SIZE] = { 0x01, 0x23, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0xEE };

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    // Setup nonce command
    memset(&temp_key, 0, sizeof(temp_key));
    memset(num_in, 0, sizeof(num_in));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_PASSTHROUGH;
    nonce_params.zero = 0;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = NULL;
    nonce_params.temp_key = &temp_key;

    // Load fixed mode nonce into tempkey
    status = atcab_nonce_base(nonce_params.mode, nonce_params.zero, nonce_params.num_in, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    memset(other_data, 0x00, sizeof(other_data));

    // Use GenDivkey to create an diversified key
    memset(&gen_div_params, 0, sizeof(gen_div_params));

    gen_div_params.parent_key = g_slot4_key;  // Ensure to write key into slot 3
    gen_div_params.other_data = other_data;
    gen_div_params.sn = sn;
    gen_div_params.input_data = num_in;
    gen_div_params.temp_key = &temp_key;

    // Run GenDivKey command
    status = atcab_gendivkey(other_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Update tempkey with diversified key
    status = atcah_gendivkey(&gen_div_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info gendig_basic_test_info[] =
{
#if TEST_ATCAB_GENDIG_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, gendig_config_otp_data),  REGISTER_TEST_CONDITION(atca_cmd_basic_test, gendig_config_otp_data) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, gendig_counter),          atca_test_cond_ecc608 },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, gendig_keyconfig),        atca_test_cond_ecc608 },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, gendig_shared_nonce),     REGISTER_TEST_CONDITION(atca_cmd_basic_test, gendig_shared_nonce) },
#endif
#if TEST_ATCAB_GENDIVKEY_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, gendivkey),               REGISTER_TEST_CONDITION(atca_cmd_basic_test, gendivkey) },
#endif
    /* Array Termination element*/
    { (fp_test_case)NULL, NULL },
};
// *INDENT-ON*
