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

TEST(atca_cmd_unit_test, sign)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t keyID = 0;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();

    // set up message to sign
    //build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[ATCA_RSP_DATA_IDX]);

    // build a sign command
    packet.param1 = SIGN_MODE_EXTERNAL;
    packet.param2 = keyID;
    status = atSign(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_basic_test, sign)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t msg[ATCA_SHA_DIGEST_SIZE];
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    uint8_t signature[ATCA_SIG_SIZE];
    uint16_t private_key_id = 0;
    bool is_verified = false;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    // Generate random message
    status = atcab_random(msg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate key pair
    status = atcab_genkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign message
    status = atcab_sign(private_key_id, msg, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify signature
    status = atcab_verify_extern(msg, signature, public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);
}

TEST(atca_cmd_basic_test, sign_internal)
{
    uint8_t internal_key_id = 4; // Which slot to sign digest of (via GenDig)
    uint16_t private_key_id = 0; // Slot with private key to do the signing

    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t config[128];
    uint8_t sn[9];
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    uint8_t num_in[NONCE_NUMIN_SIZE];
    atca_temp_key_t temp_key;
    atca_nonce_in_out_t nonce_params;
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_gen_dig_in_out_t gen_dig_params;
    uint8_t signature[ATCA_SIG_SIZE];
    atca_sign_internal_in_out_t sign_params;
    uint8_t msg[ATCA_SHA_DIGEST_SIZE];
    bool is_verified = false;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    // Read the config zone
    status = atcab_read_config_zone(config);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    memcpy(&sn[0], &config[0], 4);
    memcpy(&sn[4], &config[8], 5);

    // Generate key pair and get public key
    status = atcab_genkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Start with random nonce
    memset(&temp_key, 0, sizeof(temp_key));
    memset(&num_in, 0, sizeof(num_in));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;
    status = atcab_nonce_rand(nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Use GenDig to create an initial digest across the internal key to be signed
    memset(&gen_dig_params, 0, sizeof(gen_dig_params));
    gen_dig_params.zone = ATCA_ZONE_DATA;
    gen_dig_params.key_id = internal_key_id;
    gen_dig_params.is_key_nomac = false;
    gen_dig_params.stored_value = g_slot4_key;
    gen_dig_params.sn = sn;
    gen_dig_params.other_data = NULL;
    gen_dig_params.temp_key = &temp_key;
    status = atcab_gendig(gen_dig_params.zone, gen_dig_params.key_id, NULL, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcah_gen_dig(&gen_dig_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform a internal data sign
    memset(&sign_params, 0, sizeof(sign_params));
    sign_params.mode = SIGN_MODE_INTERNAL | SIGN_MODE_INCLUDE_SN;
    sign_params.key_id = private_key_id;
    sign_params.sn = sn;
    sign_params.temp_key = &temp_key;
    sign_params.digest = msg;
    status = atcab_sign_internal(sign_params.key_id, sign_params.for_invalidate, sign_params.mode & SIGN_MODE_INCLUDE_SN, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Build the message used by Sign(Internal)
    status = atcah_config_to_sign_internal(gCfg->devtype, &sign_params, config);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcah_sign_internal_msg(gCfg->devtype, &sign_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify the signature
    status = atcab_verify_extern(sign_params.digest, signature, public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);
}


TEST(atca_cmd_basic_test, read_sig)
{
    TEST_IGNORE_MESSAGE("Pending");
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info sign_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sign),          DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sign_internal), DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_sig),      DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};

t_test_case_info sign_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, sign), DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-OFN*

