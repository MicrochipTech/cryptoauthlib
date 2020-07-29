/**
 * \file
 * \brief Unity tests for the cryptoauthlib Basic API
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
#include "atca_test.h"

#ifdef ATCA_ATECC608_SUPPORT
const uint8_t sboot_dummy_image[] =
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

    //Calculate the digest for the sboot_dummy_image using software SHA256
    status = atcac_sw_sha2_256(sboot_dummy_image, sizeof(sboot_dummy_image), digest);
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
    status = atcac_sw_sha2_256(sboot_dummy_image, sizeof(sboot_dummy_image), digest);
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
    status = atcac_sw_sha2_256(sboot_dummy_image, sizeof(sboot_dummy_image), digest);
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
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info sboot_basic_test_info[] =
{
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_digest),                     DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_digest_full_encrypted),      DEVICE_MASK(ATECC608) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sboot_digest_fullstore_encrypted), DEVICE_MASK(ATECC608) },
#endif
    { (fp_test_case)NULL,                     (uint8_t)0 },                      /* Array Termination element*/
};
// *INDENT-ON*

