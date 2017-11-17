/**
 * \file
 * \brief  Unit tests for CryptoAuthLib.  These tests are based on the Unity C unit test framework.
 *
 * \copyright Copyright (c) 2017 Microchip Technology Inc. and its subsidiaries (Microchip). All rights reserved.
 *
 * \page License
 *
 * You are permitted to use this software and its derivatives with Microchip
 * products. Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Microchip may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with a
 *    Microchip integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL MICROCHIP BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "atca_test.h"
#include "basic/atca_basic.h"
#include "atca_unit_tests.h"
#include "host/atca_host.h"

// Unity's RUN_TEST_CASE macro in the test runners declares the function as
// well, which triggers this warning.
#pragma GCC diagnostic ignored "-Wnested-externs"
// Unity's TEST and RUN_TEST_CASE macros both declare the same function,
// which triggers this warning when the test and runner are in the same file.
#pragma GCC diagnostic ignored "-Wredundant-decls"

static ATCADevice gDevice;
static ATCACommand gCommandObj;
static ATCAIface gIface;
static ATCAIfaceCfg* gIfaceCfg;

/**
 * \brief Initialize the interface and check it was successful
 */
static void test_assert_interface_init(void)
{
    /* If the device is still connected - disconnect it */
    if (gDevice)
    {
        deleteATCADevice(&gDevice);
        TEST_ASSERT_NULL(gDevice);
    }

    /* Get the device */
    gDevice = newATCADevice(gCfg);
    TEST_ASSERT_NOT_NULL(gDevice);

    gCommandObj = atGetCommands(gDevice);
    TEST_ASSERT_NOT_NULL(gCommandObj);

    gIface = atGetIFace(gDevice);
    TEST_ASSERT_NOT_NULL(gIface);

    gIfaceCfg = atgetifacecfg(gIface);
    TEST_ASSERT_NOT_NULL(gIfaceCfg);
}

/**
 * \brief Clean up the allocated interface
 */
static void test_assert_interface_deinit(void)
{
    if (gDevice)
    {
        deleteATCADevice(&gDevice);
        TEST_ASSERT_NULL(gDevice);
    }

    gCommandObj = NULL;
    gIface = NULL;
    gIfaceCfg = NULL;
}

/**
 * \brief Sleep/Wake/Idle tests
 */
TEST_GROUP(atca_it_feature_idle);

TEST_SETUP(atca_it_feature_idle)
{
    test_assert_interface_init();
}

TEST_TEAR_DOWN(atca_it_feature_idle)
{
    test_assert_interface_deinit();
}

TEST(atca_it_feature_idle, wake_sleep)
{
    ATCA_STATUS status;

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atsleep(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_it_feature_idle, wake_idle)
{
    ATCA_STATUS status;

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/**
 * \brief Integration Tests of Device Features
 */
TEST_GROUP(atca_it_feature);

TEST_SETUP(atca_it_feature)
{
    ATCA_STATUS status;

    test_assert_interface_init();
    status = atwake(gIface);
    TEST_ASSERT_SUCCESS(status);
}

TEST_TEAR_DOWN(atca_it_feature)
{
    ATCA_STATUS status = atsleep(gIface);

    TEST_ASSERT_SUCCESS(status);
    test_assert_interface_deinit();
}

int atcau_get_addr(uint8_t zone, uint8_t slot, uint8_t block, uint8_t offset, uint16_t* addr)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if (addr == NULL)
        return ATCA_BAD_PARAM;
    if (zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_DATA && zone != ATCA_ZONE_OTP)
    {
        return ATCA_BAD_PARAM;;
    }
    *addr = 0;
    offset = offset & (uint8_t)0x07;

    if ((zone == ATCA_ZONE_CONFIG) || (zone == ATCA_ZONE_OTP))
    {
        *addr = block << 3;
        *addr |= offset;
    }
    else if (zone == ATCA_ZONE_DATA)
    {
        *addr = slot << 3;
        *addr  |= offset;
        *addr |= block << 8;
    }
    else
    {
        status = ATCA_BAD_PARAM;
    }
    return status;
}

static ATCA_STATUS test_command(ATCACommand commandObj, ATCAIface iface, ATCA_CmdMap cmd, ATCAPacket* packet)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint16_t execution_time = atGetExecTime(commandObj, cmd);

    // Send command
    status = atsend(iface, (uint8_t*)packet, packet->txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // Receive the response
    status = atreceive(iface, packet->data, &(packet->rxsize));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Check for command errors
    status = isATCAError(packet->data);

    return status;
}

bool atcau_is_locked(uint8_t zone)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    ATCAPacket packet;

    // build an read command
    packet.param1 = 0x00;
    packet.param2 = 0x15;
    status = atRead(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = test_command(gCommandObj, gIface, CMD_READMEM, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    switch (zone)
    {
    case LOCK_ZONE_DATA:
        return packet.data[ATCA_RSP_DATA_IDX + 2] == 0;
        break;
    case LOCK_ZONE_CONFIG:
        return packet.data[ATCA_RSP_DATA_IDX + 3] == 0;
        break;
    default:
        TEST_FAIL_MESSAGE("Invalid lock zone");
        break;
    }

    return false;
}

static void test_assert_config_is_locked(void)
{
    if (!atcau_is_locked(LOCK_ZONE_CONFIG))
        TEST_IGNORE_MESSAGE("Config zone must be locked for this test.");
}

static void test_assert_data_is_locked(void)
{
    if (!atcau_is_locked(LOCK_ZONE_DATA))
        TEST_IGNORE_MESSAGE("Data zone must be locked for this test.");
}

static void test_assert_data_is_unlocked(void)
{
    if (atcau_is_locked(LOCK_ZONE_DATA))
        TEST_IGNORE_MESSAGE("Data zone must be unlocked for this test.");
}

void test_lock_zone(void)
{
    atcau_is_locked(ATCA_ZONE_CONFIG);
    atcau_is_locked(ATCA_ZONE_DATA);
}

TEST(atca_it_feature, crcerror)
{
    ATCA_STATUS status;
    ATCAPacket packet;

    if (gIfaceCfg->iface_type == ATCA_HID_IFACE)
        TEST_IGNORE_MESSAGE("Kit protocol corrects CRC errors.");
    if (gIfaceCfg->iface_type == ATCA_UART_IFACE)
        TEST_IGNORE_MESSAGE("Kit protocol corrects CRC errors.");

    uint16_t execution_time = 0;

    // build an info command
    packet.param1 = INFO_MODE_REVISION;   // these tests are for communication testing mainly,
    // but if testing the entire chip, would need to go through all the modes.
    // this tests version mode only
    status = atInfo(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_INFO);

    // hack up the packet so CRC is broken
    packet.data[0] = 0xff;
    packet.data[1] = 0xff;

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // test to make sure CRC error is in the packet
    TEST_ASSERT_EQUAL_INT8_MESSAGE(0x04, packet.data[0], "Failed error response length test");
    TEST_ASSERT_EQUAL_INT8_MESSAGE(0xff, packet.data[1], "Failed bad CRC test");
}

TEST(atca_it_feature, checkmac)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint16_t keyID = 0x0004;
    static uint8_t response_mac[MAC_RSP_SIZE];              // Make the response buffer the size of a MAC response.
    static uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];    // First four bytes of Mac command are needed for CheckMac command.

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    if (gIfaceCfg->devtype == ATSHA204A)
        keyID = 0x0001;
    else
        keyID = 0x0004;

    // build a mac command
    packet.param1 = MAC_MODE_CHALLENGE;
    packet.param2 = keyID;
    memset(packet.data, 0x55, 32);    // a 32-byte challenge

    status = atMAC(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_MAC);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    memcpy(response_mac, packet.data, sizeof(response_mac));

    // sleep or idle
    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // build a checkmac command
    packet.param1 = MAC_MODE_CHALLENGE;
    packet.param2 = keyID;
    memset(packet.data, 0x55, 32);    // a 32-byte challenge
    memcpy(&packet.data[32], &response_mac[1], 32);
    memset(other_data, 0, sizeof(other_data));
    other_data[0] = ATCA_MAC;
    other_data[2] = (uint8_t)keyID;
    memcpy(&packet.data[64], other_data, sizeof(other_data));

    status = atCheckMAC(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_CHECKMAC);
    TEST_ASSERT_EQUAL(CHECKMAC_RSP_SIZE, packet.rxsize);

    // wakeup
    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);
}

TEST(atca_it_feature, counter)
{
    ATCA_STATUS status;
    ATCAPacket packet;

    uint16_t execution_time = 0;
    uint8_t increased_bin_val[4] = { 0x00 };

    if ((ATSHA204A == gIfaceCfg->devtype) || (ATECC108A == gIfaceCfg->devtype))
        TEST_IGNORE_MESSAGE("Device has no counter");

    // build a counter command
    packet.param1 = COUNTER_MODE_INCREASE;
    packet.param2 = 0x0000;
    status = atCounter(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(COUNTER_RSP_SIZE, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_COUNTER);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    memcpy(increased_bin_val, &packet.data[ATCA_RSP_DATA_IDX], sizeof(increased_bin_val));

    // build a counter command
    packet.param1 = COUNTER_MODE_READ;
    packet.param2 = 0x0000;
    status = atCounter(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(COUNTER_RSP_SIZE, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_COUNTER);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(increased_bin_val, &packet.data[ATCA_RSP_DATA_IDX], 4);
}

TEST(atca_it_feature, derivekey)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint16_t keyID = 9;

    test_assert_config_is_locked();

    //build a nonce command
    packet.param1 = NONCE_MODE_SEED_UPDATE;
    packet.param2 = 0x0000;
    memset(packet.data, 0x00, 32);

    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_SHORT, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_LONG, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_NONCE);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = isATCAError(packet.data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // build a deriveKey command (Roll Key operation)
    packet.param1 = 0;
    packet.param2 = keyID;

    status = atDeriveKey(gCommandObj, &packet, true);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    execution_time = atGetExecTime(gCommandObj, CMD_DERIVEKEY);
    TEST_ASSERT_EQUAL(DERIVE_KEY_RSP_SIZE, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = isATCAError(packet.data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // check for derive key response if it's success or not
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[1]);
}

TEST(atca_it_feature, ecdh)
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

    test_assert_data_is_locked();

    if ((ATSHA204A == gIfaceCfg->devtype) || (ATECC108A == gIfaceCfg->devtype))
        TEST_IGNORE_MESSAGE("Test is unsupported by the device ");

    // Read SN
    packet.param1 = ATCA_ZONE_CONFIG | ATCA_ZONE_READWRITE_32;
    packet.param2 = 0;
    status = atRead(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = test_command(gCommandObj, gIface, CMD_WRITEMEM, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(packet.rxsize >= packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(32 + 3, packet.data[ATCA_COUNT_IDX]);
    memcpy(&sn[0], &packet.data[ATCA_RSP_DATA_IDX], 4);
    memcpy(&sn[4], &packet.data[ATCA_RSP_DATA_IDX + 8], 5);

    // Generate key pair for bob
    packet.param1 = GENKEY_MODE_PRIVATE;
    packet.param2 = private_key_id_bob;
    status = atGenKey(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = test_command(gCommandObj, gIface, CMD_GENKEY, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(packet.rxsize >= packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(ATCA_PUB_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);
    memcpy(public_key_bob, &packet.data[ATCA_RSP_DATA_IDX], ATCA_PUB_KEY_SIZE);

    // Generate key pair for alice
    packet.param1 = GENKEY_MODE_PRIVATE;
    packet.param2 = private_key_id_alice;
    status = atGenKey(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = test_command(gCommandObj, gIface, CMD_GENKEY, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(packet.rxsize >= packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(ATCA_PUB_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);
    memcpy(public_key_alice, &packet.data[ATCA_RSP_DATA_IDX], ATCA_PUB_KEY_SIZE);

    // Perform ECDH operation on bob's side
    packet.param1 = ECDH_PREFIX_MODE;
    packet.param2 = private_key_id_bob;
    memcpy(packet.data, public_key_alice, sizeof(public_key_alice));
    status = atECDH(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = test_command(gCommandObj, gIface, CMD_ECDH, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(packet.rxsize >= packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(4, packet.data[ATCA_COUNT_IDX]);

    // Bob's PMS is written to the next slot, read that value

    //packet.param1 = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    //packet.param2 = 4 << 3;
    //memcpy(packet.data, g_slot4_key, 32);
    //status = atWrite(gCommandObj, &packet);
    //TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //status = test_command(gCommandObj, gIface, CMD_WRITEMEM, &packet);
    //TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Random nonce
    memset(&temp_key, 0, sizeof(temp_key));
    memset(num_in, 0, sizeof(num_in));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;
    packet.param1 = nonce_params.mode;
    packet.param2 = 0;
    memcpy(packet.data, nonce_params.num_in, NONCE_NUMIN_SIZE);
    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = test_command(gCommandObj, gIface, CMD_NONCE, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(packet.rxsize >= packet.data[ATCA_COUNT_IDX]);
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
    status = atGenDig(gCommandObj, &packet, false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = test_command(gCommandObj, gIface, CMD_GENDIG, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(packet.rxsize >= packet.data[ATCA_COUNT_IDX]);

    // Perform host-side nonce calculation
    status = atcah_gen_dig(&gen_dig_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Encrypted read
    packet.param1 = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    packet.param2 = (private_key_id_bob + 1) << 3;
    status = atRead(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = test_command(gCommandObj, gIface, CMD_READMEM, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(packet.rxsize >= packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(ATCA_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);

    // Decrypt bob's PMS
    for (i = 0; i < ATCA_KEY_SIZE; i++)
        pms_bob[i] = packet.data[ATCA_RSP_DATA_IDX + i] ^ temp_key.value[i];

    // Perform ECDH operation on alice's side
    packet.param1 = ECDH_PREFIX_MODE;
    packet.param2 = private_key_id_alice;
    memcpy(packet.data, public_key_bob, sizeof(public_key_bob));
    status = atECDH(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = test_command(gCommandObj, gIface, CMD_ECDH, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(packet.rxsize >= packet.data[ATCA_COUNT_IDX]);
    TEST_ASSERT_EQUAL(ATCA_KEY_SIZE + 3, packet.data[ATCA_COUNT_IDX]);

    // Alice's PMS is returned in the clear
    memcpy(pms_alice, &packet.data[ATCA_RSP_DATA_IDX], ATCA_KEY_SIZE);

    TEST_ASSERT_EQUAL_MEMORY(pms_bob, pms_alice, ATCA_KEY_SIZE);
}

TEST(atca_it_feature, gendig)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint16_t keyID = 0x0004;

    test_assert_config_is_locked();

    //build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_NONCE);
    TEST_ASSERT_EQUAL(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = isATCAError(packet.data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[1]);

    // idle so tempkey will remain valid
    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //build a gendig command
    packet.param1 = GENDIG_ZONE_DATA;
    packet.param2 = keyID;

    status = atGenDig(gCommandObj, &packet, false);
    TEST_ASSERT_EQUAL_INT(GENDIG_COUNT, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_GENDIG);

    // wakeup
    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);
}

/** \brief this test assumes a specific configuration and locked config zone
 * test will generate a private key if data zone is unlocked and return a public key
 * test will generate a public key based on the private key if data zone is locked
 */

TEST(atca_it_feature, genkey)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint16_t keyID = 0;

    test_assert_config_is_locked();

    if (ATSHA204A == gIfaceCfg->devtype)
        TEST_IGNORE_MESSAGE("Test is unsupported by the device");

    // build a genkey command
    packet.param1 = 0x04; // a random private key is generated and stored in slot keyID
    packet.param2 = keyID;
    status = atGenKey(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(GENKEY_RSP_SIZE_LONG, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_GENKEY);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(67, packet.data[0]);
}

TEST(atca_it_feature, hmac)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint16_t keyID = 0x01;

    test_assert_config_is_locked();

    //-- Start Optionally run GenDig command
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);

    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_NONCE);
    TEST_ASSERT_EQUAL(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    atca_delay_ms(execution_time);

    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = isATCAError(packet.data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[1]);

    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    packet.param1 = GENDIG_ZONE_DATA;
    packet.param2 = keyID;

    status = atGenDig(gCommandObj, &packet, false);
    TEST_ASSERT_EQUAL_INT(GENDIG_COUNT, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_GENDIG);

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    atca_delay_ms(execution_time);

    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //-- Option Test End

    // build a random command
    packet.param1 = RANDOM_SEED_UPDATE;
    packet.param2 = 0x0000;
    status = atRandom(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.rxsize);
    execution_time = atGetExecTime(gCommandObj, CMD_RANDOM);

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //build a nonce command
    packet.param1 = NONCE_MODE_SEED_UPDATE;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_NONCE);

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // build a HMAC command
    packet.param1 = ATCA_ZONE_DATA;
    packet.param2 = keyID;
    status = atHMAC(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    execution_time = atGetExecTime(gCommandObj, CMD_HMAC);

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // check if the response has the 32 bytes HMAC digest
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.rxsize);

    atca_delay_ms(1);
}

TEST(atca_it_feature, info)
{
    ATCA_STATUS status;
    ATCAPacket packet;

    uint16_t execution_time = 0;
    uint32_t devrev = 0;
    uint32_t devrev_min = 0;
    uint32_t devrev_max = 0;

    // build an info command
    packet.param1 = INFO_MODE_REVISION;   // these tests are for communication testing mainly,
    // but if testing the entire chip, would need to go through all the modes.
    // this tests version mode only
    status = atInfo(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_4, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_INFO);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

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
    default:
        TEST_FAIL_MESSAGE("Unknown device type");
        break;
    }

    devrev = ((uint32_t)packet.data[1] << 24) |
             ((uint32_t)packet.data[2] << 16) |
             ((uint32_t)packet.data[3] << 8)  |
             ((uint32_t)packet.data[4] << 0);

    if (devrev < devrev_min || devrev > devrev_max)
        TEST_FAIL_MESSAGE("Unexpected DevRev");
}

TEST(atca_it_feature, mac)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint16_t keyID = 0x01;

    test_assert_config_is_locked();

    // build a mac command
    packet.param1 = MAC_MODE_CHALLENGE;
    packet.param2 = keyID;
    memset(packet.data, 0x55, 32);    // a 32-byte challenge

    //memcpy(packet.data, challenge, sizeof(challenge));
    status = atMAC(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_MAC);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    atca_delay_ms(1);
}

TEST(atca_it_feature, nonce_passthrough)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;

    //build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_NONCE);
    TEST_ASSERT_EQUAL(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = isATCAError(packet.data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[1]);
}

TEST(atca_it_feature, pause)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;

    // build a pause command
    packet.param1 = 0x00;
    packet.param2 = 0x0000;

    status = atPause(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_INT(PAUSE_COUNT, packet.txsize);
    TEST_ASSERT_EQUAL_INT(PAUSE_RSP_SIZE, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_NONCE);
    TEST_ASSERT_EQUAL(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);

    atca_delay_ms(1);
}

TEST(atca_it_feature, privwrite)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;

    test_assert_config_is_locked();

    test_assert_data_is_unlocked();

    if (ATSHA204A == gIfaceCfg->devtype)
        TEST_IGNORE_MESSAGE("Test is not supported by the device");

    // build an PrivWrite command
    packet.param1 = 0x00;
    packet.param2 = 0x0000;
    memset(&packet.data[4], 0x55, 32);

    status = atPrivWrite(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(PRIVWRITE_RSP_SIZE, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_PRIVWRITE);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);

    atca_delay_ms(1);
}

TEST(atca_it_feature, random)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;

    // build an random command
    packet.param1 = RANDOM_SEED_UPDATE;
    packet.param2 = 0x0000;
    status = atRandom(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_RANDOM);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    atca_delay_ms(1);
}

TEST(atca_it_feature, read)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;

    // build read command
    packet.param1 = ATCA_ZONE_CONFIG;
    packet.param2 = 0x0400;

    status = atRead(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_READMEM);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0x0f, packet.data[1]);
}

TEST(atca_it_feature, sha)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint8_t sha_success = 0x00;
    uint8_t sha_digest_out[ATCA_SHA_DIGEST_SIZE];

    // initialize SHA calculation engine, initializes TempKey
    packet.param1 = SHA_MODE_SHA256_START;
    packet.param2 = 0x0000;

    status = atSHA(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_SHA);
    TEST_ASSERT_EQUAL(SHA_RSP_SIZE_SHORT, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // check the response, if error then TempKey not initialized
    TEST_ASSERT_EQUAL_INT8(sha_success,  packet.data[1]);

    // Compute the SHA 256 digest if TempKey is loaded correctly
    packet.param1 = SHA_MODE_SHA256_END;
    packet.param2 = 0x0000;

    status = atSHA(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_SHA);
    TEST_ASSERT_EQUAL(SHA_RSP_SIZE_LONG, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Copy the response into digest_out
    memcpy(&sha_digest_out[0], &packet.data[1], ATCA_SHA_DIGEST_SIZE);
}

TEST(atca_it_feature, sign)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint16_t keyID = 0;

    test_assert_config_is_locked();

    if (ATSHA204A == gIfaceCfg->devtype)
        TEST_IGNORE_MESSAGE("Test is unsupported by the device ");

    // set up message to sign
    //build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_NONCE);
    TEST_ASSERT_EQUAL(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = isATCAError(packet.data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[1]);

    // idle so tempkey will remain valid
    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // build a sign command
    packet.param1 = SIGN_MODE_EXTERNAL;
    packet.param2 = keyID;
    status = atSign(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_SIGN);

    // since sign is a relatively long execution time, do wake right before command send otherwise
    // chip could watchdog timeout before the last bytes of the response are received (depends
    // upon bus speed and watchdog timeout configuration.

    // wakeup
    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = isATCAError(packet.data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_it_feature, updateextra)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;

    test_assert_config_is_locked();

    // build a UpdateExtra command
    packet.param1 = UPDATE_MODE_SELECTOR;
    packet.param2 = 0x0000;

    status = atUpdateExtra(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_UPDATEEXTRA);
    TEST_ASSERT_EQUAL(UPDATE_RSP_SIZE, packet.rxsize);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[1]);
}

TEST(atca_it_feature, verify)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint16_t keyID = 0x00;
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    uint8_t signature[VERIFY_256_SIGNATURE_SIZE];

    test_assert_config_is_locked();

    if (ATSHA204A == gIfaceCfg->devtype)
        TEST_IGNORE_MESSAGE("Test is unsupported by the device ");

    // build a genkey command
    packet.param1 = 0x04; // a random private key is generated and stored in slot keyID
    packet.param2 = keyID;
    status = atGenKey(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(GENKEY_RSP_SIZE_LONG, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_GENKEY);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // copy the data response into the public key
    memcpy(&public_key[0], &packet.data[ATCA_RSP_DATA_IDX], ATCA_PUB_KEY_SIZE);

    // build a random command
    packet.param1 = RANDOM_SEED_UPDATE;
    packet.param2 = 0x0000;
    status = atRandom(gCommandObj, &packet);
    execution_time = atGetExecTime(gCommandObj, CMD_RANDOM);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.rxsize);

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;

    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_NONCE);
    TEST_ASSERT_EQUAL(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // idle so tempkey will remain valid
    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // build a sign command
    packet.param1 = SIGN_MODE_EXTERNAL; //verify the signature
    packet.param2 = keyID;

    status = atSign(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    execution_time = atGetExecTime(gCommandObj, CMD_SIGN);

    // since sign is a relatively long execution time, do wake right before command send otherwise
    // chip could watchdog timeout before the last bytes of the response are received (depends
    // upon bus speed and watchdog timeout configuration.

    // wakeup
    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // copy the data response into the signature
    memcpy(&signature[0], &packet.data[ATCA_RSP_DATA_IDX], ATCA_SIG_SIZE);

    // build an random command
    packet.param1 = RANDOM_SEED_UPDATE;
    packet.param2 = 0x0000;
    status = atRandom(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_RANDOM);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_32, packet.rxsize);

    // send the random command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &packet.rxsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // build a nonce command (pass through mode)
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memset(packet.data, 0x55, 32);    // a 32-byte nonce

    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    execution_time = atGetExecTime(gCommandObj, CMD_NONCE);
    TEST_ASSERT_EQUAL(NONCE_RSP_SIZE_SHORT, packet.rxsize);

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atidle(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // build a verify command
    packet.param1 = VERIFY_MODE_EXTERNAL; //verify the signature
    packet.param2 = VERIFY_KEY_P256;
    memcpy(&packet.data[0], signature, sizeof(signature));
    memcpy(&packet.data[64], public_key, sizeof(public_key));

    status = atVerify(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    execution_time = atGetExecTime(gCommandObj, CMD_VERIFY);

    status = atwake(gIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize) );
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);
}

TEST(atca_it_feature, write)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    uint16_t execution_time = 0;
    uint8_t zone;
    uint16_t addr = 0x00;

    test_assert_config_is_locked();


    zone = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    addr = 0x20;    // slot 4 - always writable per the config

    // build a write command to the data zone
    packet.param1 = zone;
    packet.param2 = addr;
    memset(packet.data, 0x00, sizeof(packet.data) );
    memcpy(packet.data, g_slot4_key, 32);

    status = atWrite(gCommandObj, &packet, false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    execution_time = atGetExecTime(gCommandObj, CMD_WRITEMEM);

    // send the command
    status = atsend(gIface, (uint8_t*)&packet, packet.txsize);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // delay the appropriate amount of time for command to execute
    atca_delay_ms(execution_time);

    // receive the response
    status = atreceive(gIface, packet.data, &(packet.rxsize));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x00, packet.data[ATCA_RSP_DATA_IDX]);
}

TEST_GROUP_RUNNER(atca_it_feature_idle)
{
    RUN_TEST_CASE(atca_it_feature_idle, wake_sleep);
    RUN_TEST_CASE(atca_it_feature_idle, wake_idle);
}

TEST_GROUP_RUNNER(atca_it_feature)
{
    // Tests that can run when config is unlocked
    RUN_TEST_CASE(atca_it_feature, info); // Command is named DevRev for ATSHA204A
    RUN_TEST_CASE(atca_it_feature, random);
    RUN_TEST_CASE(atca_it_feature, sha);
    RUN_TEST_CASE(atca_it_feature, crcerror);
    RUN_TEST_CASE(atca_it_feature, read);
    RUN_TEST_CASE(atca_it_feature, counter);

    // Tests that can run when data is unlocked
    RUN_TEST_CASE(atca_it_feature, pause);
    RUN_TEST_CASE(atca_it_feature, random);
    RUN_TEST_CASE(atca_it_feature, nonce_passthrough);
    RUN_TEST_CASE(atca_it_feature, privwrite);

    //// Tests that require config and data locked
    RUN_TEST_CASE(atca_it_feature, checkmac);
    RUN_TEST_CASE(atca_it_feature, derivekey);
    RUN_TEST_CASE(atca_it_feature, gendig);
    RUN_TEST_CASE(atca_it_feature, hmac);
    RUN_TEST_CASE(atca_it_feature, mac);
    RUN_TEST_CASE(atca_it_feature, updateextra);
    RUN_TEST_CASE(atca_it_feature, write);
    RUN_TEST_CASE(atca_it_feature, genkey);
    RUN_TEST_CASE(atca_it_feature, sign);
    RUN_TEST_CASE(atca_it_feature, verify);
    RUN_TEST_CASE(atca_it_feature, ecdh);
}

void RunAllFeatureTests(void)
{
    RUN_TEST_GROUP(atca_it_feature_idle);
    RUN_TEST_GROUP(atca_it_feature);
}
