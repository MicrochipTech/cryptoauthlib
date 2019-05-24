/**
 * \file
 * \brief Unity tests for the cryptoauthlib Basic API
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


const uint8_t message[] =
{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

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
    memcpy(packet.data, message, 64);
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

TEST(atca_cmd_basic_test, sboot_digest)
{
    ATCA_STATUS status;
    const uint16_t private_key_id = 2;
    const uint16_t public_key_id = 11;
    uint8_t digest[ATCA_KEY_SIZE];
    uint8_t signature[ATCA_SIG_SIZE];
    uint8_t public_key[72];

    test_assert_data_is_locked();

    // Generate new key pair
    status = atcab_genkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Reformat public key into padded format
    memmove(&public_key[40], &public_key[32], 32); // Move Y to padded position
    memset(&public_key[36], 0, 4);                 // Add Y padding bytes
    memmove(&public_key[4], &public_key[0], 32);   // Move X to padded position
    memset(&public_key[0], 0, 4);                  // Add X padding bytes


    // Write public key to slot
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, public_key_id, 0, public_key, 72);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Calculate the digest for the message using software SHA256
    status = atcac_sw_sha2_256(message, sizeof(message), digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign the digest
    status = atcab_sign(private_key_id, digest, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify the secure boot mode full
    status = atcab_secureboot(SECUREBOOT_MODE_FULL, 0, digest, signature, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify the secure boot mode Full copy and copies the digest to the slot after verifying
    status = atcab_secureboot(SECUREBOOT_MODE_FULL_COPY, 0, digest, signature, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify the secure boot mode Full store with the digest in the slot
    status = atcab_secureboot(SECUREBOOT_MODE_FULL_STORE, 0, digest, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


}

TEST(atca_cmd_basic_test, sboot_digest_full_encrypted)
{
    ATCA_STATUS status;
    bool is_verified = false;
    const uint16_t private_key_id = 2;
    uint8_t randomnum[RANDOM_RSP_SIZE];
    uint8_t digest[ATCA_KEY_SIZE];
    uint8_t signature[ATCA_SIG_SIZE];



    test_assert_data_is_locked();


    // Calculate the digest for the message using software SHA256
    status = atcac_sw_sha2_256(message, sizeof(message), digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign the message
    status = atcab_sign(private_key_id, digest, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generating Random number from device
    status = atcab_random(randomnum);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform SecureBoot command in encrypted digest / validation MAC mode
    status = atcab_secureboot_mac(SECUREBOOT_MODE_FULL, digest, signature, randomnum, g_slot4_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);
}



TEST(atca_cmd_basic_test, sboot_digest_fullstore_encrypted)
{
    ATCA_STATUS status;
    bool is_verified = false;
    const uint16_t private_key_id = 2;
    uint8_t randomnum[RANDOM_RSP_SIZE];
    uint8_t digest[ATCA_KEY_SIZE];
    uint8_t signature[ATCA_SIG_SIZE];



    test_assert_data_is_locked();

    //Calculate the digest for the message using software SHA256
    status = atcac_sw_sha2_256(message, sizeof(message), digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign the message
    status = atcab_sign(private_key_id, digest, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Genrating Random number from device
    status = atcab_random(randomnum);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform SecureBoot command in encrypted digest / validation MAC mode
    status = atcab_secureboot_mac(SECUREBOOT_MODE_FULL_COPY, digest, signature, randomnum, g_slot4_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);


    // Rerun the SecureBoot in FullStore mode to test digest got stored

    // Generating Random number from device
    status = atcab_random(randomnum);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform SecureBoot command in encrypted digest / validation MAC mode
    status = atcab_secureboot_mac(SECUREBOOT_MODE_FULL_STORE, digest, signature, randomnum, g_slot4_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info sboot_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_digest),                     DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_digest_full_encrypted),      DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_digest_fullstore_encrypted), DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },                      /* Array Termination element*/
};

t_test_case_info sboot_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, sboot), DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

