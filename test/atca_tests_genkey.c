/**
 * \file
 * \brief Unity tests for the cryptoauthlib Genkey Command
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


/** \brief this test assumes a specific configuration and locked config zone
 * test will generate a private key if data zone is unlocked and return a public key
 * test will generate a public key based on the private key if data zone is locked
 */

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

TEST(atca_cmd_basic_test, genkey)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t public_key[64];
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };

    memset(public_key, 0x44, 64); // mark the key with bogus data

    test_assert_config_is_locked();

    status = atcab_genkey(0, public_key);
    TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Key generation failed");

    // spot check public key for bogus data, there should be none
    // pub key is random so can't check the full content anyway.
    TEST_ASSERT_NOT_EQUAL(0, memcmp(public_key, frag, 4));
}
TEST(atca_cmd_basic_test, get_pubkey)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t public_key[64];
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };

    memset(public_key, 0x44, 64); // mark the key with bogus data

    test_assert_config_is_locked();

    status = atcab_get_pubkey(0, public_key);
    TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, status, "Key generation failed");

    // spot check public key for bogus data, there should be none
    // pub key is random so can't check the full content anyway.
    TEST_ASSERT_NOT_EQUAL(0, memcmp(public_key, frag, 4));
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info genkey_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, genkey),     DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, get_pubkey), DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },/* Array Termination element*/
};

t_test_case_info genkey_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, genkey), DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

