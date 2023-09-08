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

#ifndef TEST_ATCAB_SIGN_EN
#define TEST_ATCAB_SIGN_EN         (CALIB_SIGN_EN || CALIB_SIGN_ECC204_EN || TALIB_SIGN_EN)
#endif

#if TEST_ATCAB_SIGN_EN

TEST(atca_cmd_basic_test, sign)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t msg[ATCA_SHA256_DIGEST_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    uint16_t private_key_id = 0;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    status = atca_test_config_get_id(TEST_TYPE_ECC_SIGN, &private_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign message
    status = atcab_sign(private_key_id, msg, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

#if defined(ATCA_MBEDTLS) || defined(ATCA_OPENSSL) || defined(ATCA_WOLFSSL)
#include "crypto/atca_crypto_sw.h"

TEST(atca_cmd_basic_test, sign_sw_verify)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t msg[ATCA_SHA256_DIGEST_SIZE];
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    struct atcac_pk_ctx* pkey;
    uint16_t private_key_id = 0;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    /* Create a message digest */
    status = atcac_sw_sha2_256((uint8_t*)"abcd", 4, msg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atca_test_config_get_id(TEST_TYPE_ECC_SIGN, &private_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Load the public key */
    status = atcab_get_pubkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Initialize a software public key context */
#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    pkey = atcac_pk_ctx_new();
#else
    atcac_pk_ctx_t pkey_ctx;
    pkey = &pkey_ctx;
#endif
    status = atcac_pk_init(pkey, public_key, ATCA_ECCP256_PUBKEY_SIZE, 0, true);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Sign message */
    status = atcab_sign(private_key_id, msg, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Verify the signature */
    status = atcac_pk_verify(pkey, msg, sizeof(msg), signature, sizeof(signature));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    if (NULL != pkey)
    {
        atcac_pk_ctx_free(pkey);
    }
#endif
}
#endif

TEST(atca_cmd_basic_test, sign_hw_verify)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t msg[ATCA_SHA256_DIGEST_SIZE];
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    uint16_t private_key_id = 0;
    bool is_verified = false;

    test_assert_config_is_locked();
    test_assert_data_is_locked();

    // Generate random message
    status = atcab_random(msg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atca_test_config_get_id(TEST_TYPE_ECC_GENKEY, &private_key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate key pair
    status = atca_test_genkey(private_key_id, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Sign message
    status = atcab_sign(private_key_id, msg, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Verify signature
    status = atcab_verify_extern(msg, signature, public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(true, is_verified);
}

#ifdef ATCA_ECC_SUPPORT
TEST_CONDITION(atca_cmd_basic_test, sign_internal_ecc)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return (ATECC108A == dev_type)
           || (ATECC508A == dev_type)
           || (ATECC608 == dev_type);
}

TEST(atca_cmd_basic_test, sign_internal_ecc)
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
    status = atca_test_genkey(private_key_id, public_key);
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
#endif
#endif

#if 0
TEST(atca_cmd_basic_test, read_sig)
{
    TEST_IGNORE_MESSAGE("Pending");
}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info sign_basic_test_info[] =
{
#if TEST_ATCAB_SIGN_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sign),            atca_test_cond_p256_sign },
#if ATCA_HOSTLIB_EN
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sign_sw_verify),  atca_test_cond_p256_sign },
#endif
#if !ATCA_HOSTLIB_EN && (defined(ATCA_ECC_SUPPORT) || ATCA_TA_SUPPORT)
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sign_hw_verify),  atca_test_cond_p256_sign_verify },
#endif
#ifdef ATCA_ECC_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sign_internal_ecc), REGISTER_TEST_CONDITION(atca_cmd_basic_test, sign_internal_ecc) },
#endif
#if 0
    { REGISTER_TEST_CASE(atca_cmd_basic_test, read_sig),        atca_test_cond_p256_sign },
#endif
#endif

    /* Array Termination element*/
    { (fp_test_case)NULL, NULL },
};
// *INDENT-OFN*
