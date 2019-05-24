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

TEST(atca_cmd_unit_test, ecdh)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint8_t sn[9];
    uint16_t private_key_id_bob = 0;
    uint8_t public_key_bob[ATCA_PUB_KEY_SIZE];
    uint8_t pms_bob[ATCA_KEY_SIZE];
    uint16_t pms_read_key_id_bob = 4;
    uint16_t private_key_id_alice = 2;
    uint8_t public_key_alice[ATCA_PUB_KEY_SIZE];
    uint8_t pms_alice[ATCA_KEY_SIZE];
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_temp_key_t temp_key;
    atca_nonce_in_out_t nonce_params;
    atca_gen_dig_in_out_t gen_dig_params;
    int i;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_data_is_locked();

    // Read SN
    packet.param1 = ATCA_ZONE_CONFIG | ATCA_ZONE_READWRITE_32;
    packet.param2 = 0;
    status = atRead(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);

    memcpy(&sn[0], &packet.data[ATCA_RSP_DATA_IDX], 4);
    memcpy(&sn[4], &packet.data[ATCA_RSP_DATA_IDX + 8], 5);

    // Generate key pair for bob
    packet.param1 = GENKEY_MODE_PRIVATE;
    packet.param2 = private_key_id_bob;
    status = atGenKey(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_PUB_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);
    memcpy(public_key_bob, &packet.data[ATCA_RSP_DATA_IDX], ATCA_PUB_KEY_SIZE);

    // Generate key pair for alice
    packet.param1 = GENKEY_MODE_PRIVATE;
    packet.param2 = private_key_id_alice;
    status = atGenKey(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_PUB_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);
    memcpy(public_key_alice, &packet.data[ATCA_RSP_DATA_IDX], ATCA_PUB_KEY_SIZE);

    // Perform ECDH operation on bob's side
    packet.param1 = ECDH_PREFIX_MODE;
    packet.param2 = private_key_id_bob;
    memcpy(packet.data, public_key_alice, sizeof(public_key_alice));
    status = atECDH(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(4, packet.data[ATCA_COUNT_IDX]);

    // Bob's PMS is written to the next slot, read that value

    //packet.param1 = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    //packet.param2 = 4 << 3;
    //memcpy(packet.data, g_slot4_key, 32);
    //status = atWrite(ca_cmd, &packet);
    //TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //status = atca_execute_command(&packet, _gDevice);
    //TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Random nonce
    memset(&temp_key, 0, sizeof(temp_key));
    memset(num_in, 0, sizeof(num_in));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;
    packet.param1 = nonce_params.mode;
    packet.param2 = nonce_params.zero;
    memcpy(packet.data, nonce_params.num_in, NONCE_NUMIN_SIZE);
    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(RANDOM_NUM_SIZE + 3, packet.data[ATCA_COUNT_IDX]);
    memcpy(rand_out, &packet.data[ATCA_RSP_DATA_IDX], RANDOM_NUM_SIZE);

    // Perform host-side nonce calculation
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // GenDig with Bob's PMS Read Key
    memset(&gen_dig_params, 0, sizeof(gen_dig_params));
    gen_dig_params.zone = ATCA_ZONE_DATA;
    gen_dig_params.key_id = pms_read_key_id_bob;
    gen_dig_params.is_key_nomac = false;
    gen_dig_params.sn = sn;
    gen_dig_params.stored_value = g_slot4_key;
    gen_dig_params.other_data = NULL;
    gen_dig_params.temp_key = &temp_key;
    packet.param1 = gen_dig_params.zone;
    packet.param2 = gen_dig_params.key_id;
    status = atGenDig(ca_cmd, &packet, false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform host-side nonce calculation
    status = atcah_gen_dig(&gen_dig_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypted read
    packet.param1 = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    packet.param2 = (private_key_id_bob + 1) << 3;
    status = atRead(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);

    // Decrypt bob's PMS
    for (i = 0; i < ATCA_KEY_SIZE; i++)
    {
        pms_bob[i] = packet.data[ATCA_RSP_DATA_IDX + i] ^ temp_key.value[i];
    }

    // Perform ECDH operation on alice's side
    packet.param1 = ECDH_PREFIX_MODE;
    packet.param2 = private_key_id_alice;
    memcpy(packet.data, public_key_bob, sizeof(public_key_bob));
    status = atECDH(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);

    // Alice's PMS is returned in the clear
    memcpy(pms_alice, &packet.data[ATCA_RSP_DATA_IDX], ATCA_KEY_SIZE);

    TEST_ASSERT_EQUAL_MEMORY(pms_bob, pms_alice, ATCA_KEY_SIZE);
}

TEST(atca_cmd_basic_test, ecdh)
{
    ATCA_STATUS status;
    uint8_t read_key_id = 0x04;
    uint8_t pub_alice[ATCA_PUB_KEY_SIZE], pub_bob[ATCA_PUB_KEY_SIZE];
    uint8_t pms_alice[ECDH_KEY_SIZE], pms_bob[ECDH_KEY_SIZE];
    uint8_t read_key[ATCA_KEY_SIZE];
    uint8_t key_id_alice = 0, key_id_bob = 2;
    char displaystr[256];
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };
    size_t displen = sizeof(displaystr);

    test_assert_data_is_locked();

    // set to known values that should be overwritten, so these can be tested
    memset(pub_alice, 0x44, ATCA_PUB_KEY_SIZE);
    memset(pub_bob, 0x44, ATCA_PUB_KEY_SIZE);

    status = atcab_genkey(key_id_alice, pub_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_alice, ATCA_PUB_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice slot %d pubkey:\r\n%s\r\n", key_id_alice, displaystr);

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_alice, frag, sizeof(frag)), "Alice key not initialized");

    status = atcab_genkey(key_id_bob, pub_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_bob, frag, sizeof(frag)), "Bob key not initialized");

    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_bob, ATCA_PUB_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob slot %d pubkey:\r\n%s\r\n", key_id_bob, displaystr);

    memcpy(read_key, g_slot4_key, 32);
    status = atcab_write_zone(ATCA_ZONE_DATA, read_key_id, 0, 0, &read_key[0], ATCA_BLOCK_SIZE);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // slot 0 is a non-clear response - "Write Slot N|1" is in slot config
    // generate premaster secret from alice's key and bob's pubkey
    status = atcab_ecdh_enc(key_id_alice, pub_bob, pms_alice, g_slot4_key, read_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pub_alice, frag, sizeof(frag)));

    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_alice, ECDH_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);

    status = atcab_ecdh(key_id_bob, pub_alice, pms_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pms_bob, frag, sizeof(frag)));

    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_bob, ECDH_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob's pms:\r\n%s\r\n", displaystr);

    TEST_ASSERT_EQUAL_MEMORY(pms_alice, pms_bob, sizeof(pms_alice));
}


TEST(atca_cmd_basic_test, ecdh_protection_key)
{
    ATCA_STATUS status;
    uint8_t pub_alice[ATCA_PUB_KEY_SIZE], pub_bob[ATCA_PUB_KEY_SIZE];
    uint8_t pms_alice[ECDH_KEY_SIZE], pms_bob[ECDH_KEY_SIZE];
    uint8_t key_id_bob = 2;
    uint16_t tempkey_alice = 0xFFFF;
    char displaystr[256];
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };
    size_t displen = sizeof(displaystr);

    test_assert_data_is_locked();

    // set to known values that should be overwritten, so these can be tested
    memset(pub_alice, 0x44, ATCA_PUB_KEY_SIZE);
    memset(pub_bob, 0x44, ATCA_PUB_KEY_SIZE);

    //Generating Alice private key in tempkey and public key from tempkey.
    status = atcab_genkey(tempkey_alice, pub_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_alice, frag, sizeof(frag)), "Alice key not initialized");
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_alice, ATCA_PUB_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice  pubkey:\r\n%s\r\n", displaystr);

    //Generating Bob public key from private key in slot
    status = atcab_genkey(key_id_bob, pub_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_bob, frag, sizeof(frag)), "Bob key not initialized");
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_bob, ATCA_PUB_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob slot %d pubkey:\r\n%s\r\n", key_id_bob, displaystr);

    //Generating Alice PMS with bob public key.
    status = atcab_ecdh_tempkey(pub_bob, pms_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_alice, ECDH_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);

    //Generating Bob encrypted PMS with Alice public key.
    status = atcab_ecdh_ioenc(key_id_bob, pub_alice, pms_bob, g_slot4_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pms_bob, frag, sizeof(frag)));
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_bob, ECDH_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob's encrypted pms  :\r\n%s\r\n", displaystr);

    //display bob's decrypted pms
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_bob, ECDH_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob's decrypted pms:\r\n%s\r\n", displaystr);

    TEST_ASSERT_EQUAL_MEMORY(pms_alice, pms_bob, sizeof(pms_alice));
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info ecdh_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ecdh),                DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ecdh_protection_key),                          DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },         /* Array Termination element*/
};

t_test_case_info ecdh_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, ecdh), DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

