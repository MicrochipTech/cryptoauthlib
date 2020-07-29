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
#include "atca_test.h"

#ifdef ATCA_ECC_SUPPORT
TEST(atca_cmd_basic_test, ecdh)
{
    ATCA_STATUS status;
    uint8_t read_key_id = 0x04;
    uint8_t pub_alice[ATCA_PUB_KEY_SIZE], pub_bob[ATCA_PUB_KEY_SIZE];
    uint8_t pms_alice[ECDH_KEY_SIZE], pms_bob[ECDH_KEY_SIZE];
    uint8_t read_key[ATCA_KEY_SIZE];
    uint16_t key_id_alice, key_id_bob;
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };
    uint8_t host_num_in[NONCE_NUMIN_SIZE] = { 0 };

#ifdef ATCA_PRINTF
    char displaystr[256];
    size_t displen = sizeof(displaystr);
#endif


    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_ECDH, &key_id_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atca_test_config_get_id(TEST_TYPE_ECC_GENKEY, &key_id_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // set to known values that should be overwritten, so these can be tested
    memset(pub_alice, 0x44, ATCA_PUB_KEY_SIZE);
    memset(pub_bob, 0x44, ATCA_PUB_KEY_SIZE);

    status = atcab_genkey(key_id_alice, pub_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_alice, ATCA_PUB_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice slot %d pubkey:\r\n%s\r\n", key_id_alice, displaystr);
#endif

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_alice, frag, sizeof(frag)), "Alice key not initialized");

    status = atcab_genkey(key_id_bob, pub_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_bob, frag, sizeof(frag)), "Bob key not initialized");

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_bob, ATCA_PUB_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob slot %d pubkey:\r\n%s\r\n", key_id_bob, displaystr);
#endif

    memcpy(read_key, g_slot4_key, 32);
    status = atcab_write_zone(ATCA_ZONE_DATA, read_key_id, 0, 0, &read_key[0], ATCA_BLOCK_SIZE);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // slot 0 is a non-clear response - "Write Slot N|1" is in slot config
    // generate premaster secret from alice's key and bob's pubkey
#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
    status = atcab_ecdh_enc(key_id_alice, pub_bob, pms_alice, g_slot4_key, read_key_id);
#else
    status = atcab_ecdh_enc(key_id_alice, pub_bob, pms_alice, g_slot4_key, read_key_id, host_num_in);
#endif
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pub_alice, frag, sizeof(frag)));

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_alice, ECDH_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);
#endif

    status = atcab_ecdh(key_id_bob, pub_alice, pms_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pms_bob, frag, sizeof(frag)));

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_bob, ECDH_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob's pms:\r\n%s\r\n", displaystr);
#endif

    TEST_ASSERT_EQUAL_MEMORY(pms_alice, pms_bob, sizeof(pms_alice));
}
#endif

TEST(atca_cmd_basic_test, ecdh_simple)
{
    ATCA_STATUS status;
    uint8_t pub_alice[ATCA_ECCP256_PUBKEY_SIZE], pub_bob[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t pms_alice[ATCA_ECCP256_KEY_SIZE], pms_bob[ATCA_ECCP256_KEY_SIZE];
    uint16_t key_id_alice, key_id_bob;
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };

#ifdef ATCA_PRINTF
    char displaystr[256];
    size_t displen = sizeof(displaystr);
#endif

    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_ECDH, &key_id_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atca_test_config_get_id(TEST_TYPE_ECC_GENKEY, &key_id_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // set to known values that should be overwritten, so these can be tested
    memset(pub_alice, 0x44, ATCA_ECCP256_PUBKEY_SIZE);
    memset(pub_bob, 0x44, ATCA_ECCP256_PUBKEY_SIZE);

    status = atcab_genkey(key_id_alice, pub_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_alice, ATCA_ECCP256_PUBKEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("\r\nalice slot %04x pubkey:\r\n%s\r\n", key_id_alice, displaystr);
#endif

    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_alice, frag, sizeof(frag)), "Alice key not initialized");

    status = atcab_genkey(key_id_bob, pub_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_bob, frag, sizeof(frag)), "Bob key not initialized");

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_bob, ATCA_ECCP256_PUBKEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob slot %04x pubkey:\r\n%s\r\n", key_id_bob, displaystr);
#endif

    status = atcab_ecdh(key_id_alice, pub_bob, pms_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pub_alice, frag, sizeof(frag)));

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_alice, ATCA_ECCP256_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);
#endif

    status = atcab_ecdh(key_id_bob, pub_alice, pms_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pms_bob, frag, sizeof(frag)));

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_bob, ATCA_ECCP256_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob's pms:\r\n%s\r\n", displaystr);
#endif

    TEST_ASSERT_EQUAL_MEMORY(pms_alice, pms_bob, sizeof(pms_alice));
}

#ifdef ATCA_ATECC608_SUPPORT
TEST(atca_cmd_basic_test, ecdh_protection_key)
{
    ATCA_STATUS status;
    uint8_t pub_alice[ATCA_PUB_KEY_SIZE], pub_bob[ATCA_PUB_KEY_SIZE];
    uint8_t pms_alice[ECDH_KEY_SIZE], pms_bob[ECDH_KEY_SIZE];
    uint8_t key_id_bob = 2;
    uint16_t tempkey_alice = 0xFFFF;
    uint8_t frag[4] = { 0x44, 0x44, 0x44, 0x44 };

#ifdef ATCA_PRINTF
    char displaystr[256];
    size_t displen = sizeof(displaystr);
#endif

    test_assert_data_is_locked();

    // set to known values that should be overwritten, so these can be tested
    memset(pub_alice, 0x44, ATCA_PUB_KEY_SIZE);
    memset(pub_bob, 0x44, ATCA_PUB_KEY_SIZE);

    //Generating Alice private key in tempkey and public key from tempkey.
    status = atcab_genkey(tempkey_alice, pub_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_alice, frag, sizeof(frag)), "Alice key not initialized");

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_alice, ATCA_PUB_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice  pubkey:\r\n%s\r\n", displaystr);
#endif

    //Generating Bob public key from private key in slot
    status = atcab_genkey(key_id_bob, pub_bob);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL_MESSAGE(0, memcmp(pub_bob, frag, sizeof(frag)), "Bob key not initialized");

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pub_bob, ATCA_PUB_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob slot %d pubkey:\r\n%s\r\n", key_id_bob, displaystr);
#endif

    //Generating Alice PMS with bob public key.
    status = atcab_ecdh_tempkey(pub_bob, pms_alice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_alice, ECDH_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);
#endif

    //Generating Bob encrypted PMS with Alice public key.
    status = atcab_ecdh_ioenc(key_id_bob, pub_alice, pms_bob, g_slot4_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(pms_bob, frag, sizeof(frag)));

#ifdef ATCA_PRINTF
    //display bob's decrypted pms
    displen = sizeof(displaystr);
    status = atcab_bin2hex(pms_bob, ECDH_KEY_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("bob's decrypted pms:\r\n%s\r\n", displaystr);
#endif

    TEST_ASSERT_EQUAL_MEMORY(pms_alice, pms_bob, sizeof(pms_alice));
}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info ecdh_basic_test_info[] =
{
#ifdef ATCA_ECC_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ecdh),                DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608) },
#endif
#if defined(ATCA_ECC_SUPPORT) || defined(ATCA_TA100_SUPPORT)
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ecdh_simple),                DEVICE_MASK(TA100) },
#endif
#ifdef ATCA_ATECC608_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ecdh_protection_key),                          DEVICE_MASK(ATECC608) },
#endif
    { (fp_test_case)NULL,                     (uint8_t)0 },         /* Array Termination element*/
};
// *INDENT-ON*
