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

#ifndef TEST_ATCAB_VERIFY_STORED_EN
#define TEST_ATCAB_VERIFY_STORED_EN         (CALIB_VERIFY_STORED_EN || TALIB_VERIFY_STORED_EN)
#endif

#ifndef TEST_ATCAB_VERIFY_EXTERN_EN
#define TEST_ATCAB_VERIFY_EXTERN_EN         (CALIB_VERIFY_EXTERN_EN || TALIB_VERIFY_EXTERN_EN)
#endif

#ifndef TEST_ATCAB_VERIFY_MAC_EN
#define TEST_ATCAB_VERIFY_MAC_EN            CALIB_VERIFY_MAC_EN
#endif

#ifndef TEST_ATCAB_VERIFY_VALIDATE_EN
#define TEST_ATCAB_VERIFY_VALIDATE_EN       CALIB_VERIFY_VALIDATE_EN
#endif

#ifndef TEST_ATCAB_VERIFY_REQRANDOM_EN
#define TEST_ATCAB_VERIFY_REQRANDOM_EN      CALIB_ECC108_EN || CALIB_ECC508_EN || CALIB_ECC608_EN || ATCA_HOSTLIB_EN
#endif

#include "vectors/ecdsa_nist_vectors.h"
#include "vectors/ecdh_nist_vectors.h"


void print_buffer(uint8_t *buf, int len)
{
    for (int i = 0; i < len; i++, buf++)
    {
        if (i && !(i % 16))
        {
            printf("\n");
        }
        printf("%02x", *buf);
    }
    printf("\n");
}

#if TEST_ATCAB_VERIFY_EXTERN_EN
TEST(atca_cmd_basic_test, verify_extern_nist)
{
    uint8_t pubkey[64];
    uint8_t signature[64];
    uint8_t digest[32];
    ATCA_STATUS status;
    size_t i;
    bool is_verified = false;

    /* Test verification using [P-256,SHA-256] vectors */
    for (i = 0; i < ecdsa_p256_test_vectors_count; i++)
    {
        /* Copy pubkey */
        memcpy(pubkey, ecdsa_p256_test_vectors[i].Qx, 32);
        memcpy(&pubkey[32], ecdsa_p256_test_vectors[i].Qy, 32);


//	printf("Public key for test %d\n", i);
//        print_buffer(pubkey, 64);

        /* Copy the signature */
        memcpy(signature, ecdsa_p256_test_vectors[i].R, 32);
        memcpy(&signature[32], ecdsa_p256_test_vectors[i].S, 32);

        /* Hash the message */
        status = atcac_sw_sha2_256(ecdsa_p256_test_vectors[i].Msg, sizeof(ecdsa_p256_test_vectors[i].Msg), digest);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


        /* Perform the verification */
        status = atcab_verify_extern(digest, signature, pubkey, &is_verified);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Check verification result against the expected success/failure */
        if (ecdsa_p256_test_vectors[i].Result)
        {
            TEST_ASSERT(is_verified);
        }
        else
        {
            TEST_ASSERT(!is_verified);
        }
    }
}

TEST(atca_cmd_basic_test, verify_extern)
{
    ATCA_STATUS status;
    bool is_verified = false;
    uint8_t message[ATCA_SHA256_DIGEST_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    uint8_t pubkey[ATCA_ECCP256_PUBKEY_SIZE];
    uint16_t private_key_id;

    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_ECC_SIGN, &private_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_get_pubkey(private_key_id, pubkey);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_random(message);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_sign(private_key_id, message, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_verify_extern(message, signature, pubkey, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    // Verify with bad message, should fail
    message[0]++;
    status = atcab_verify_extern(message, signature, pubkey, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(!is_verified);
}

#if TEST_ATCAB_VERIFY_MAC_EN
TEST(atca_cmd_basic_test, verify_extern_mac)
{
    ATCA_STATUS status;
    uint8_t message[ATCA_KEY_SIZE];
    uint8_t system_nonce[ATCA_KEY_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    uint8_t pubkey[ATCA_ECCP256_PUBKEY_SIZE];
    bool is_verified = false;
    uint16_t private_key_id;

    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_ECC_SIGN, &private_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Get current public key
    status = atcab_get_pubkey(private_key_id, pubkey);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate random message to be signed
    status = atcab_random(message);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate system nonce (typically this should not come from the CryptoAuth device).
    status = atcab_random(system_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign the message to get a signature
    status = atcab_sign(private_key_id, message, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_verify_extern_mac(message, signature, pubkey, system_nonce, g_slot4_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    // Verify with bad message, should fail
    message[0]++;
    status = atcab_verify_extern_mac(message, signature, pubkey, system_nonce, g_slot4_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(!is_verified);
}
#endif /* TEST_ATCAB_VERIFY_MAC_EN */

#endif /* TEST_ATCAB_VERIFY_EXTERN_EN */

#if TEST_ATCAB_VERIFY_STORED_EN
TEST(atca_cmd_basic_test, verify_stored)
{
    ATCA_STATUS status;
    bool is_verified = false;
    uint16_t private_key_id;
    uint16_t public_key_id;
    uint8_t message[ATCA_SHA256_DIGEST_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];

    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_ECC_GENKEY, &private_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atca_test_config_get_id(TEST_TYPE_ECC_VERIFY, &public_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate new key pair
    status = atca_test_genkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write public key to slot
    status = atcab_write_pubkey(public_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate random message to be signed
    status = atcab_random(message);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign the message
    status = atcab_sign(private_key_id, message, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify the signature
    is_verified = false;
    status = atcab_verify_stored(message, signature, public_key_id, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    // Verify with bad message, should fail
    message[0]++;
    status = atcab_verify_stored(message, signature, public_key_id, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(!is_verified);
}

#if TEST_ATCAB_VERIFY_REQRANDOM_EN
TEST_CONDITION(atca_cmd_basic_test, verify_stored_on_reqrandom_set)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ATECC108A == dev_type)
           || (ATECC508A == dev_type)
           || (ATECC608 == dev_type);
}

TEST(atca_cmd_basic_test, verify_stored_on_reqrandom_set)
{
    ATCA_STATUS status;
    bool is_verified = false;
    uint16_t public_key_id;
    uint8_t message[ATCA_SHA256_DIGEST_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    atca_nonce_in_out_t nonce_params;
    atca_temp_key_t temp_key;

    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_ECC_VERIFY, &public_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#if defined(ATCA_MBEDTLS) || defined(ATCA_OPENSSL) || defined(ATCA_WOLFSSL)
    atcac_pk_ctx_t sign_ctx;
    uint8_t private_key_pem[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEICFZhAyzqkUgyheo51bhg3mcp+qwfl+koE+Mhs/sRyzBoAoGCCqGSM49\n"
        "AwEHoUQDQgAExAE2yqujppBzD0hIpdqdXmMgtlXT90QqllaQYWEVBjdf+LmY5DCf\n"
        "Mx8PXEVxhbDmgo6HHbz0S4VaZjShBLMaPw==\n"
        "-----END EC PRIVATE KEY-----\n";
    size_t sig_size = sizeof(signature);
    size_t pubkey_len = sizeof(public_key);

    /* Initialization of a private key with a pem encoded key (without password) */
    status = atcac_pk_init_pem(&sign_ctx, private_key_pem, sizeof(private_key_pem), false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Retrieve the public key */
    status = atcac_pk_public(&sign_ctx, public_key, &pubkey_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
    uint16_t private_key_id;

    status = atca_test_config_get_id(TEST_TYPE_ECC_GENKEY, &private_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate new key pair
    status = atca_test_genkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif

    // Write public key to slot
    status = atcab_write_pubkey(public_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate random message to be signed
    status = atcab_random(message);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Send the random nonce command
    status = atcab_nonce_rand(message, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate Tempkey
    memset(&temp_key, 0, sizeof(temp_key));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = (uint8_t*)&message[0];
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign the message
#if defined(ATCA_MBEDTLS) || defined(ATCA_OPENSSL) || defined(ATCA_WOLFSSL)
    status = atcac_pk_sign(&sign_ctx, nonce_params.temp_key->value, ATCA_SHA256_DIGEST_SIZE, signature, &sig_size);
#else
    // Only the 608 has the message digest buffer - other devices will invalidate tempkey
    status = atcab_sign(private_key_id, nonce_params.temp_key->value, signature);
#endif
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify the signature (Message is already loaded into tempkey)
    is_verified = false;
    status = atcab_verify_stored_with_tempkey(signature, public_key_id, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);
}
#endif /* TEST_ATCAB_VERIFY_REQRANDOM_EN */

#if TEST_ATCAB_VERIFY_MAC_EN
TEST(atca_cmd_basic_test, verify_stored_mac)
{
    ATCA_STATUS status;
    const uint16_t private_key_id = 2;
    const uint16_t public_key_id = 11;
    uint8_t message[ATCA_KEY_SIZE];
    uint8_t system_nonce[ATCA_KEY_SIZE];
    uint8_t signature[ATCA_SIG_SIZE];
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    bool is_verified = false;

    test_assert_data_is_locked();

    // Generate new key pair
    status = atca_test_genkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write public key to slot
    status = atcab_write_pubkey(public_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate random message to be signed
    status = atcab_random(message);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign the message
    status = atcab_sign(private_key_id, message, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate system nonce (typically this should not come from the CryptoAuth device).
    status = atcab_random(system_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_verify_stored_mac(message, signature, public_key_id, system_nonce, g_slot4_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    // Verify with bad message, should fail
    message[0]++;
    status = atcab_verify_stored_mac(message, signature, public_key_id, system_nonce, g_slot4_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(!is_verified);
}
#endif /* TEST_ATCAB_VERIFY_MAC_EN */

#endif /* TEST_ATCAB_VERIFY_STORED_EN */

#if TEST_ATCAB_VERIFY_VALIDATE_EN
static void test_basic_verify_validate(void)
{
    const uint16_t public_key_id = 14;
    const uint16_t private_key_id = 0;
    const uint16_t validation_private_key_id = 2;

    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t config[128];
    uint8_t sn[9];
    uint8_t validation_public_key[ATCA_PUB_KEY_SIZE];
    uint16_t validation_public_key_id = 0;
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    uint8_t test_msg[32];
    uint8_t test_signature[ATCA_SIG_SIZE];
    bool is_verified = false;
    uint8_t valid_buf[4];
    uint8_t nonce[32];
    uint8_t rand_out[ATCA_KEY_SIZE];
    atca_temp_key_t temp_key;
    atca_nonce_in_out_t nonce_params;
    uint8_t gen_key_other_data[3];
    atca_gen_key_in_out_t gen_key_params;
    uint8_t verify_other_data[19];
    uint8_t validation_msg[55];
    uint8_t validation_digest[32];
    atca_sign_internal_in_out_t sign_params;
    uint8_t validation_signature[ATCA_SIG_SIZE];

    test_assert_data_is_locked();

    // Read config zone
    status = atcab_read_config_zone(config);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    memcpy(&sn[0], &config[0], 4);
    memcpy(&sn[4], &config[8], 5);

    // SETUP: Initialize device data to support a validated public key test

    // Generate key pair for validation
    // Typically, the validation private key wouldn't be on the same device as its public key
    status = atca_test_genkey(validation_private_key_id, validation_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Write validation public key
    // Typically, this would be locked into the device during initial programming.
    validation_public_key_id = config[20 + public_key_id * 2] & 0x0F; // Validation public key ID is the validated public key's ReadKey
    status = atcab_write_pubkey(validation_public_key_id, validation_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // RUN: Run through the validated public key update process
    // This process has two parties. First is the device with a validated public key slot.
    // Whenever that slot gets updated, a Validation Authority (which has the validation private
    // key) is required to validate the new public key before it can be used.

    // Validation Authority: Generate new key pair.
    status = atca_test_genkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create and sign some data for testing the new key pair
    status = atcab_random(test_msg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_sign(private_key_id, test_msg, test_signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_verify_extern(test_msg, test_signature, public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    // Validated Device: Write the new public key to the validate public key slot
    status = atcab_write_pubkey(public_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Make sure the previous write invalidated the public key
    status = atcab_read_zone(ATCA_ZONE_DATA, public_key_id, 0, 0, valid_buf, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0xA, valid_buf[0] >> 4); // Validation status is the 4 upper-most bits in the slot

    // Additionally, check to make sure a verify(stored) command with it fails.
    status = atcab_verify_stored(test_msg, test_signature, public_key_id, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_EXECUTION_ERROR, status);

    // Validated Device: Validation process needs to start with a nonce (random is most secure)
    // Not using random due to limitations with simulating the validated device and validation
    // authority on the same device.
    memset(nonce, 0, sizeof(nonce));
    memset(&temp_key, 0, sizeof(temp_key));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_PASSTHROUGH;
    nonce_params.zero = 0;
    nonce_params.num_in = nonce;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;
    status = atcab_nonce(nonce_params.num_in);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validation Authority: Calculate same nonce
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validated Authority: GenKey format is then used to combine the nonce with the new public key to be validated
    memset(gen_key_other_data, 0, sizeof(gen_key_other_data));
    gen_key_params.mode = GENKEY_MODE_PUBKEY_DIGEST;
    gen_key_params.key_id = public_key_id;
    gen_key_params.public_key = public_key;
    gen_key_params.public_key_size = sizeof(public_key);
    gen_key_params.other_data = gen_key_other_data;
    gen_key_params.sn = sn;
    gen_key_params.temp_key = &temp_key;
    status = atcah_gen_key_msg(&gen_key_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validation Authority: Build validation message which uses the Sign(Internal) format
    memset(&sign_params, 0, sizeof(sign_params));
    sign_params.sn = sn;
    sign_params.verify_other_data = verify_other_data;
    sign_params.message = validation_msg;
    sign_params.digest = validation_digest;
    sign_params.temp_key = &temp_key;
    status = atcah_sign_internal_msg(gCfg->devtype, &sign_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validation Authority: Sign the validation message
    status = atcab_sign(validation_private_key_id, validation_digest, validation_signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // The previous sign cleared TempKey, so we have to reset it. This is because the unit test is trying
    // to perform the actions of the Validation Authority and the Validated Device on the same device.
    // This wouldn't be needed normally.
    status = atcab_nonce(nonce_params.num_in);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validated Device: Combine the public key with the nonce
    status = atcab_genkey_base(gen_key_params.mode, gen_key_params.key_id, gen_key_params.other_data, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validated Device: Use Verify(Validate) command to validate the new public key
    status = atcab_verify_validate(public_key_id, validation_signature, verify_other_data, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    // Make sure public key is validated now
    status = atcab_read_zone(ATCA_ZONE_DATA, public_key_id, 0, 0, valid_buf, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x5, valid_buf[0] >> 4); // Validation status is the 4 upper-most bits in the slot

    // Additionally, check to make sure a verify(stored) command works now.
    status = atcab_verify_stored(test_msg, test_signature, public_key_id, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);
}

TEST_CONDITION(atca_cmd_basic_test, verify_validate)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ATECC108A == dev_type)
           || (ATECC508A == dev_type)
           || (ATECC608 == dev_type);
}

TEST(atca_cmd_basic_test, verify_validate)
{
    test_basic_verify_validate();
}

TEST_CONDITION(atca_cmd_basic_test, verify_invalidate)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ATECC508A == dev_type) || (ATECC608 == dev_type);
}

TEST(atca_cmd_basic_test, verify_invalidate)
{
    const uint16_t public_key_id = 14;
    const uint16_t private_key_id = 0;
    const uint16_t validation_private_key_id = 2;

    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t config[128];
    uint8_t sn[9];
    //uint8_t validation_public_key[ATCA_PUB_KEY_SIZE];
    //uint16_t validation_public_key_id = 0;
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    uint8_t test_msg[32];
    uint8_t test_signature[ATCA_SIG_SIZE];
    bool is_verified = false;
    uint8_t valid_buf[4];
    uint8_t nonce[32];
    uint8_t rand_out[ATCA_KEY_SIZE];
    atca_temp_key_t temp_key;
    atca_nonce_in_out_t nonce_params;
    uint8_t gen_key_other_data[3];
    atca_gen_key_in_out_t gen_key_params;
    uint8_t verify_other_data[19];
    uint8_t validation_msg[55];
    uint8_t validation_digest[32];
    atca_sign_internal_in_out_t sign_params;
    uint8_t validation_signature[ATCA_SIG_SIZE];

    // We need to start with the slot validated. This test will do that.
    test_basic_verify_validate();

    test_assert_data_is_locked();

    // Read config zone
    status = atcab_read_config_zone(config);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    memcpy(&sn[0], &config[0], 4);
    memcpy(&sn[4], &config[8], 5);

    // RUN: Run through the public invalidation process
    // This process has two parties. First is the device with a validated public key slot.
    // Whenever that slot gets updated, a Validation Authority (which has the validation private
    // key) is required to validate the new public key before it can be used.

    // Validation Authority: Get the public key to be invalidated
    status = atcab_get_pubkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create and sign some data for testing
    status = atcab_random(test_msg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_sign(private_key_id, test_msg, test_signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atcab_verify_extern(test_msg, test_signature, public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    // Make sure public key is currently validated
    status = atcab_read_zone(ATCA_ZONE_DATA, public_key_id, 0, 0, valid_buf, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0x5, valid_buf[0] >> 4); // Validation status is the 4 upper-most bits in the slot

    // Additionally, check to make sure a verify(stored) command works
    status = atcab_verify_stored(test_msg, test_signature, public_key_id, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    // Validated Device: Invalidation process needs to start with a nonce (random is most secure)
    // Not using random due to limitations with simulating the validated device and validation
    // authority on the same device.
    memset(nonce, 0, sizeof(nonce));
    memset(&temp_key, 0, sizeof(temp_key));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_PASSTHROUGH;
    nonce_params.zero = 0;
    nonce_params.num_in = nonce;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;
    status = atcab_nonce(nonce_params.num_in);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validation Authority: Calculate same nonce
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validated Authority: GenKey format is then used to combine the nonce with the new public key to be validated
    memset(gen_key_other_data, 0, sizeof(gen_key_other_data));
    gen_key_params.mode = GENKEY_MODE_PUBKEY_DIGEST;
    gen_key_params.key_id = public_key_id;
    gen_key_params.public_key = public_key;
    gen_key_params.public_key_size = sizeof(public_key);
    gen_key_params.other_data = gen_key_other_data;
    gen_key_params.sn = sn;
    gen_key_params.temp_key = &temp_key;
    status = atcah_gen_key_msg(&gen_key_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validation Authority: Build validation message which uses the Sign(Internal) format
    memset(&sign_params, 0, sizeof(sign_params));
    sign_params.sn = sn;
    sign_params.verify_other_data = verify_other_data;
    sign_params.for_invalidate = true;
    sign_params.message = validation_msg;
    sign_params.digest = validation_digest;
    sign_params.temp_key = &temp_key;
    status = atcah_sign_internal_msg(gCfg->devtype, &sign_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validation Authority: Sign the validation message
    status = atcab_sign(validation_private_key_id, validation_digest, validation_signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // The previous sign cleared TempKey, so we have to reset it. This is because the unit test is trying
    // to perform the actions of the Validation Authority and the Validate Device on the same device.
    // This wouldn't be needed normally.
    status = atcab_nonce(nonce_params.num_in);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validated Device: Combine the public key with the nonce
    status = atcab_genkey_base(gen_key_params.mode, gen_key_params.key_id, gen_key_params.other_data, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Validated Device: Use Verify(Invalidate) command to invalidate the existing public key
    status = atcab_verify_invalidate(public_key_id, validation_signature, verify_other_data, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);

    // Make sure the previous command invalidated the public key
    status = atcab_read_zone(ATCA_ZONE_DATA, public_key_id, 0, 0, valid_buf, 4);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(0xA, valid_buf[0] >> 4); // Validation status is the 4 upper-most bits in the slot

    // Additionally, check to make sure a verify(stored) command with it fails.
    status = atcab_verify_stored(test_msg, test_signature, public_key_id, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_EXECUTION_ERROR, status);
}
#endif /* TEST_ATCAB_VERIFY_VALIDATE_EN */

// *INDENT-OFF* - Preserve formatting
t_test_case_info verify_basic_test_info[] =
{
#if TEST_ATCAB_VERIFY_EXTERN_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_extern_nist),  atca_test_cond_p256_sign_verify  },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_extern),       atca_test_cond_p256_sign_verify  },
#if TEST_ATCAB_VERIFY_MAC_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_extern_mac),   atca_test_cond_ecc608 },
#endif
#endif /* TEST_ATCAB_VERIFY_EXTERN_EN */
#if TEST_ATCAB_VERIFY_STORED_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_stored),       atca_test_cond_p256_sign_verify  },
#if TEST_ATCAB_VERIFY_REQRANDOM_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_stored_on_reqrandom_set), REGISTER_TEST_CONDITION(atca_cmd_basic_test, verify_stored_on_reqrandom_set) },
#endif
#if TEST_ATCAB_VERIFY_MAC_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_stored_mac),   atca_test_cond_ecc608 },
#endif
#endif /* TEST_ATCAB_VERIFY_STORED_EN */
#if TEST_ATCAB_VERIFY_VALIDATE_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_validate),     REGISTER_TEST_CONDITION(atca_cmd_basic_test, verify_validate) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_invalidate),   REGISTER_TEST_CONDITION(atca_cmd_basic_test, verify_invalidate) },
#endif

    /* Array Termination element*/
    { (fp_test_case)NULL, NULL },
};
// *INDENT-ON*
