/**
 * \file
 * \brief  Cryptoauthlib Testing: CALIB "Unit" Tests
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

#include "atca_test.h"
#include "test_calib.h"

#if ATCA_CA_SUPPORT

extern const uint8_t g_aes_keys[4][16];
extern const uint8_t g_plaintext[64];
extern const uint8_t g_ciphertext_ecb[4][64];

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

TEST(atca_cmd_unit_test, counter)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint8_t increased_bin_val[4] = { 0x00 };
    uint32_t test;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build a counter command
    packet.param1 = COUNTER_MODE_INCREMENT;
    packet.param2 = 0x0000;
    status = atCounter(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(COUNTER_RSP_SIZE, packet.data[ATCA_COUNT_IDX]);
    memcpy(increased_bin_val, &packet.data[ATCA_RSP_DATA_IDX], sizeof(increased_bin_val));

    // build a counter command
    packet.param1 = COUNTER_MODE_READ;
    packet.param2 = 0x0000;
    status = atCounter(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(increased_bin_val, &packet.data[ATCA_RSP_DATA_IDX], 4);
    memcpy(&test, &packet.data[ATCA_RSP_DATA_IDX], 4);
}

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

TEST(atca_cmd_unit_test, gendig)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t keyID = 0x0004;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();

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

    //build a gendig command
    packet.param1 = GENDIG_ZONE_DATA;
    packet.param2 = keyID;

    status = atGenDig(ca_cmd, &packet, false);
    TEST_ASSERT_EQUAL_INT(GENDIG_COUNT, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);
}

TEST(atca_cmd_unit_test, genkey)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t keyID = 0;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();

    // build a genkey command
    packet.param1 = 0x04; // a random private key is generated and stored in slot keyID
    packet.param2 = keyID;
    status = atGenKey(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_PUB_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);
}

TEST(atca_cmd_unit_test, hmac)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t keyID = 0x01;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();

    //-- Start Optionally run GenDig command
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[ATCA_RSP_DATA_IDX]);

    packet.param1 = GENDIG_ZONE_DATA;
    packet.param2 = keyID;
    status = atGenDig(ca_cmd, &packet, false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(GENDIG_COUNT, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);

    //-- Option Test End

    // build a random command
    packet.param1 = RANDOM_SEED_UPDATE;
    packet.param2 = 0x0000;
    status = atRandom(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.data[ATCA_COUNT_IDX]);


    //build a nonce command
    packet.param1 = NONCE_MODE_SEED_UPDATE;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // build a HMAC command
    packet.param1 = ATCA_ZONE_DATA;
    packet.param2 = keyID;
    status = atHMAC(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // check if the response has the 32 bytes HMAC digest
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.data[ATCA_COUNT_IDX]);

    atca_delay_ms(1);
}

TEST(atca_cmd_unit_test, info)
{
    ATCA_STATUS status;
    ATCAPacket packet;

    uint32_t devrev = 0;
    uint32_t devrev_min = 0;
    uint32_t devrev_max = 0;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build an info command
    packet.param1 = INFO_MODE_REVISION;   // these tests are for communication testing mainly,
                                          // but if testing the entire chip, would need to go through all the modes.
                                          // this tests version mode only
    status = atInfo(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_4, packet.data[ATCA_COUNT_IDX]);

    switch (gCfg->devtype)
    {
    case ATSHA204A:
        devrev_min = 0x00020008;
        devrev_max = 0x000200FF;
        break;
    case ATECC108A:
        devrev_min = 0x00001002;
        devrev_max = 0x000010FF;
        break;
    case ATECC508A:
        devrev_min = 0x00005000;
        devrev_max = 0x000050FF;
        break;
    case ATECC608:
        devrev_min = 0x00006000;
        devrev_max = 0x000060FF;
        break;
    default:
        TEST_FAIL_MESSAGE("Unknown device type");
        break;
    }

    devrev = ((uint32_t)packet.data[1] << 24) |
             ((uint32_t)packet.data[2] << 16) |
             ((uint32_t)packet.data[3] << 8) |
             ((uint32_t)packet.data[4] << 0);

    if (devrev < devrev_min || devrev > devrev_max)
    {
        TEST_FAIL_MESSAGE("Unexpected DevRev");
    }
}

TEST(atca_cmd_unit_test, kdf)
{

    ATCA_STATUS status = ATCA_GEN_FAIL;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    uint8_t data_input_32[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    unit_test_assert_data_is_locked();

    // build read command
    packet.param1 = ATCA_ZONE_CONFIG;
    packet.param2 = 0x0003;

    status = atRead(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    if ((packet.data[2] & AES_CONFIG_ENABLE_BIT_MASK) == 0)  //packet.data[2] contains the AES enable bit
    {
        TEST_IGNORE_MESSAGE("Ignoring the test, AES is not enabled in Configuration zone");
    }

    //32 bytes key in Alternate key buffer ,32 bytes data in and 32 byte data out in tempkey
    packet.param1 = NONCE_MODE_PASSTHROUGH | NONCE_MODE_TARGET_ALTKEYBUF;
    packet.param2 = 0x0000;
    memcpy(packet.data, nonce, 32);    // a 32-byte nonce

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(NONCE_COUNT_LONG, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, packet.data[1]);

    packet.param1 = KDF_MODE_ALG_AES | KDF_MODE_SOURCE_ALTKEYBUF | KDF_MODE_TARGET_TEMPKEY;
    packet.param2 = 0x0000;
    memset(packet.data, 0x00, 4);                  // a 4 byte details related to AES
    memcpy(&packet.data[4], data_input_32, 32);    // a 32 byte input data to AES KDF
    packet.txsize = ATCA_CMD_SIZE_MIN + KDF_DETAILS_SIZE + AES_DATA_SIZE;
    status = atKDF(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_unit_test, lock)
{
    /* Implementation not available at this time */
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

TEST(atca_cmd_unit_test, nonce)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    //build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[ATCA_RSP_DATA_IDX]);
}

TEST(atca_cmd_unit_test, otp_zero)
{
    /* Not applicable... Leaving it as place holder */
}

TEST(atca_cmd_unit_test, pause)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build a pause command
    packet.param1 = 0x00;
    packet.param2 = 0x0000;

    status = atPause(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(PAUSE_COUNT, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(PAUSE_RSP_SIZE, packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);

    atca_delay_ms(1);
}

TEST(atca_cmd_unit_test, privwrite)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();
    unit_test_assert_data_is_unlocked();

    // build an PrivWrite command
    packet.param1 = 0x00;
    packet.param2 = 0x0000;
    memset(&packet.data[4], 0x55, 32);

    status = atPrivWrite(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(PRIVWRITE_RSP_SIZE, packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);

    atca_delay_ms(1);
}

TEST(atca_cmd_unit_test, random)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build an random command
    packet.param1 = RANDOM_SEED_UPDATE;
    packet.param2 = 0x0000;
    status = atRandom(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.data[ATCA_COUNT_IDX]);

    atca_delay_ms(1);
}

TEST(atca_cmd_unit_test, read)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build read command
    packet.param1 = ATCA_ZONE_CONFIG;
    packet.param2 = 0x0000;

    status = atRead(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x07, packet.data[ATCA_COUNT_IDX]);
}

#ifdef ATCA_ATECC608_SUPPORT
extern const uint8_t sboot_dummy_image[];

TEST(atca_cmd_unit_test, sboot)
{

    ATCA_STATUS status;
    ATCAPacket packet;
    const uint16_t private_key_id = 2;
    uint8_t public_key[72];
    uint8_t zone;
    uint16_t addr = 0x00;
    uint8_t digest[ATCA_KEY_SIZE];
    uint8_t signature[ATCA_SIG_SIZE];
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_data_is_locked();


    //Generating the public key with the private key in slot
    packet.param1 = GENKEY_MODE_PRIVATE;
    packet.param2 = private_key_id;
    status = atGenKey(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_PUB_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);
    memcpy(public_key, &packet.data[ATCA_RSP_DATA_IDX], ATCA_PUB_KEY_SIZE);

    // Reformat public key into padded format
    memmove(&public_key[40], &public_key[32], 32);     // Move Y to padded position
    memset(&public_key[36], 0, 4);                     // Add Y padding bytes
    memmove(&public_key[4], &public_key[0], 32);       // Move X to padded position
    memset(&public_key[0], 0, 4);                      // Add X padding bytes

    //Writing the first 32 bytes of padded public key to slot 11
    zone = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    addr = 0x58;
    // build a write command to the data zone
    packet.param1 = zone;
    packet.param2 = addr;
    memset(packet.data, 0x00, sizeof(packet.data));
    memcpy(packet.data, public_key, 32);

    status = atWrite(ca_cmd, &packet, false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);

    //Writing the second 32 bytes of padded public key to slot 11
    zone = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    addr = 0x158;
    // build a write command to the data zone
    packet.param1 = zone;
    packet.param2 = addr;
    memset(packet.data, 0x00, sizeof(packet.data));
    memcpy(packet.data, &public_key[32], 32);

    status = atWrite(ca_cmd, &packet, false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);

    //Writing the next 4 bytes of padded public key to slot 11
    zone = ATCA_ZONE_DATA;
    addr = 0x258;
    // build a write command to the data zone
    packet.param1 = zone;
    packet.param2 = addr;
    memset(packet.data, 0x00, sizeof(packet.data));
    memcpy(packet.data, &public_key[64], 4);

    status = atWrite(ca_cmd, &packet, false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);


    //Writing the next 4 bytes of padded public key to slot 11
    zone = ATCA_ZONE_DATA;
    addr = 0x259;
    // build a write command to the data zone
    packet.param1 = zone;
    packet.param2 = addr;
    memset(packet.data, 0x00, sizeof(packet.data));
    memcpy(packet.data, &public_key[68], 4);

    status = atWrite(ca_cmd, &packet, false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);



    // initialize SHA calculation engine, initializes TempKey
    packet.param1 = SHA_MODE_SHA256_START;
    packet.param2 = 0x0000;

    status = atSHA(ca_cmd, &packet, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(SHA_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, packet.data[ATCA_RSP_DATA_IDX]);



    // Update SHA calculation engine
    packet.param1 = SHA_MODE_SHA256_UPDATE;
    packet.param2 = 0x0000;
    memcpy(packet.data, sboot_dummy_image, 64);
    status = atSHA(ca_cmd, &packet, 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(SHA_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, packet.data[ATCA_RSP_DATA_IDX]);

    // Compute the SHA 256 digest if TempKey is loaded correctly
    packet.param1 = SHA_MODE_SHA256_END;
    packet.param2 = 0x0000;
    status = atSHA(ca_cmd, &packet, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(SHA_RSP_SIZE_LONG, packet.data[ATCA_COUNT_IDX]);

    // Copy the response into digest
    memcpy(&digest[0], &packet.data[ATCA_RSP_DATA_IDX], SECUREBOOT_DIGEST_SIZE);


    // build an random command
    packet.param1 = RANDOM_SEED_UPDATE;
    packet.param2 = 0x0000;
    status = atRandom(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.data[ATCA_COUNT_IDX]);

    // set up message to sign
    //build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memcpy(packet.data, digest, 32);        // a 32-byte nonce

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[ATCA_RSP_DATA_IDX]);


    // build a sign command
    packet.param1 = SIGN_MODE_EXTERNAL;
    packet.param2 = private_key_id;
    status = atSign(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    // Copy the signature
    memcpy(signature, &packet.data[ATCA_RSP_DATA_IDX], ATCA_SIG_SIZE);


    // build a sboot command
    packet.param1 = SECUREBOOT_MODE_FULL;
    packet.param2 = 0;
    memcpy(packet.data, digest, SECUREBOOT_DIGEST_SIZE);                    // a 32-byte Digest is copied to packet
    memcpy(&packet.data[SECUREBOOT_DIGEST_SIZE], signature, ATCA_SIG_SIZE); // a 64-byte signature is copied to packet
    status = atSecureBoot(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_unit_test, selftest)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    packet.param1 = SELFTEST_MODE_RNG;
    packet.param2 = 0x0000;
    status = atSelfTest(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(SELFTEST_RSP_SIZE, packet.data[ATCA_COUNT_IDX]);
}
#endif

TEST(atca_cmd_unit_test, sha)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint8_t sha_success = 0x00;
    uint8_t sha_digest_out[ATCA_SHA_DIGEST_SIZE];
    ATCACommand ca_cmd = _gDevice->mCommands;

    // initialize SHA calculation engine, initializes TempKey
    packet.param1 = SHA_MODE_SHA256_START;
    packet.param2 = 0x0000;

    status = atSHA(ca_cmd, &packet, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(SHA_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);

    // check the response, if error then TempKey not initialized
    TEST_ASSERT_EQUAL_INT8(sha_success, packet.data[ATCA_RSP_DATA_IDX]);

    // Compute the SHA 256 digest if TempKey is loaded correctly
    packet.param1 = SHA_MODE_SHA256_END;
    packet.param2 = 0x0000;

    status = atSHA(ca_cmd, &packet, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(SHA_RSP_SIZE_LONG, packet.data[ATCA_COUNT_IDX]);

    // Copy the response into digest_out
    memcpy(&sha_digest_out[0], &packet.data[ATCA_RSP_DATA_IDX], ATCA_SHA_DIGEST_SIZE);
}

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

TEST(atca_cmd_unit_test, updateextra)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();

    // build a UpdateExtra command
    packet.param1 = UPDATE_MODE_USER_EXTRA;
    packet.param2 = 0x0000;

    status = atUpdateExtra(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(UPDATE_RSP_SIZE, packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);
}

TEST(atca_cmd_unit_test, verify)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t keyID = 0x00;
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    uint8_t signature[VERIFY_256_SIGNATURE_SIZE];
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();

    // build a genkey command
    packet.param1 = 0x04; // a random private key is generated and stored in slot keyID
    packet.param2 = keyID;
    status = atGenKey(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(GENKEY_RSP_SIZE_LONG, packet.data[ATCA_COUNT_IDX]);

    // copy the data response into the public key
    memcpy(&public_key[0], &packet.data[ATCA_RSP_DATA_IDX], ATCA_PUB_KEY_SIZE);

    // build a random command
    packet.param1 = RANDOM_SEED_UPDATE;
    packet.param2 = 0x0000;
    status = atRandom(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);


    // build a sign command
    packet.param1 = SIGN_MODE_EXTERNAL; //verify the signature
    packet.param2 = keyID;
    status = atSign(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // copy the data response into the signature
    memcpy(&signature[0], &packet.data[ATCA_RSP_DATA_IDX], ATCA_SIG_SIZE);

    // build an random command
    packet.param1 = RANDOM_SEED_UPDATE;
    packet.param2 = 0x0000;
    status = atRandom(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);


    // build a verify command
    packet.param1 = VERIFY_MODE_EXTERNAL; //verify the signature
    packet.param2 = VERIFY_KEY_P256;
    memcpy(&packet.data[0], signature, sizeof(signature));
    memcpy(&packet.data[64], public_key, sizeof(public_key));

    status = atVerify(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);
}

TEST(atca_cmd_unit_test, write)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint8_t zone;
    uint16_t addr = 0x00;
    ATCACommand ca_cmd = _gDevice->mCommands;

    unit_test_assert_config_is_locked();


    zone = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    addr = 0x20;    // slot 4 - always writable per the config

    // build a write command to the data zone
    packet.param1 = zone;
    packet.param2 = addr;
    memset(packet.data, 0x00, sizeof(packet.data));
    memcpy(packet.data, g_slot4_key, 32);

    status = atWrite(ca_cmd, &packet, false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);
}


t_test_case_info calib_commands_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, aes),                                                                                     DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, checkmac),     DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, counter),                                                        DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, derivekey),    DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, ecdh),                                                           DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, gendig),       DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, genkey),                                DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, hmac),         DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A)                          },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, info),         DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, kdf),                                                                                     DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, mac),          DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, nonce),        DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, pause),        DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A)                          },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, privwrite),                             DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, random),       DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, read),         DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_unit_test, sboot),                                                                                   DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, selftest),                                                                                DEVICE_MASK(ATECC608) },
#endif
    { REGISTER_TEST_CASE(atca_cmd_unit_test, sha),          DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, sign),                                  DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, updateextra),  DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, verify),                                DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, write),        DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
    /* Array Termination element*/
    { (fp_test_case)NULL,                                   (uint8_t)0 },
};

#endif
