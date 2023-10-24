/**
 * \file
 * \brief Tests for the CryptoAuthLib software crypto API.
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

#include "test_crypto.h"

#if defined(ATCA_MBEDTLS) || defined(ATCA_OPENSSL) || defined(ATCA_WOLFSSL)

#include "vectors/ecdsa_nist_vectors.h"
#include "vectors/ecdh_nist_vectors.h"

TEST_GROUP(atcac_pk);

TEST_SETUP(atcac_pk)
{
    UnityMalloc_StartTest();
}

TEST_TEAR_DOWN(atcac_pk)
{
    UnityMalloc_EndTest();
}

TEST(atcac_pk, verify_nist)
{
    uint8_t pubkey[64];
    uint8_t signature[64];
    uint8_t digest[32];
    ATCA_STATUS status;
    size_t i;

    struct atcac_pk_ctx * pkey_ctx;

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    pkey_ctx = atcac_pk_ctx_new();
    TEST_ASSERT_NOT_NULL(pkey_ctx);
#else
    atcac_pk_ctx_t pkey_ctx_inst;
    pkey_ctx = &pkey_ctx_inst;
#endif

    /* Test verification using [P-256,SHA-256] vectors */
    for (i = 0; i < ecdsa_p256_test_vectors_count; i++)
    {
        /* Copy pubkey */
        memcpy(pubkey, ecdsa_p256_test_vectors[i].Qx, 32);
        memcpy(&pubkey[32], ecdsa_p256_test_vectors[i].Qy, 32);

        /* Copy the signature */
        memcpy(signature, ecdsa_p256_test_vectors[i].R, 32);
        memcpy(&signature[32], ecdsa_p256_test_vectors[i].S, 32);

        /* Hash the message */
        status = atcac_sw_sha2_256(ecdsa_p256_test_vectors[i].Msg, sizeof(ecdsa_p256_test_vectors[i].Msg), digest);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Initialize the key using the provided X,Y cordinantes */
        status = atcac_pk_init(pkey_ctx, pubkey, sizeof(pubkey), 0, true);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Perform the verification */
        status = atcac_pk_verify(pkey_ctx, digest, sizeof(digest), signature, sizeof(signature));

        /* Make sure to free the key before testing the result of the verify */
        atcac_pk_free(pkey_ctx);

        /* Check verification result against the expected success/failure */
        if (ecdsa_p256_test_vectors[i].Result)
        {
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        }
        else
        {
            TEST_ASSERT_NOT_EQUAL(ATCA_SUCCESS, status);
        }
    }

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    atcac_pk_ctx_free(pkey_ctx);
#endif
}

static uint8_t private_key_pem[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEICFZhAyzqkUgyheo51bhg3mcp+qwfl+koE+Mhs/sRyzBoAoGCCqGSM49\n"
    "AwEHoUQDQgAExAE2yqujppBzD0hIpdqdXmMgtlXT90QqllaQYWEVBjdf+LmY5DCf\n"
    "Mx8PXEVxhbDmgo6HHbz0S4VaZjShBLMaPw==\n"
    "-----END EC PRIVATE KEY-----\n";

static uint8_t public_key_pem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExAE2yqujppBzD0hIpdqdXmMgtlXT\n"
    "90QqllaQYWEVBjdf+LmY5DCfMx8PXEVxhbDmgo6HHbz0S4VaZjShBLMaPw==\n"
    "-----END PUBLIC KEY-----\n";

static uint8_t public_key_bytes[64] = {
    0xc4, 0x01, 0x36, 0xca, 0xab, 0xa3, 0xa6, 0x90, 0x73, 0x0f, 0x48, 0x48, 0xa5, 0xda, 0x9d, 0x5e,
    0x63, 0x20, 0xb6, 0x55, 0xd3, 0xf7, 0x44, 0x2a, 0x96, 0x56, 0x90, 0x61, 0x61, 0x15, 0x06, 0x37,
    0x5f, 0xf8, 0xb9, 0x98, 0xe4, 0x30, 0x9f, 0x33, 0x1f, 0x0f, 0x5c, 0x45, 0x71, 0x85, 0xb0, 0xe6,
    0x82, 0x8e, 0x87, 0x1d, 0xbc, 0xf4, 0x4b, 0x85, 0x5a, 0x66, 0x34, 0xa1, 0x04, 0xb3, 0x1a, 0x3f
};

TEST(atcac_pk, init_public)
{
    uint8_t public_key[64];
    size_t public_key_size = 64;
    ATCA_STATUS status;

    struct atcac_pk_ctx * pkey_ctx;

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    pkey_ctx = atcac_pk_ctx_new();
    TEST_ASSERT_NOT_NULL(pkey_ctx);
#else
    atcac_pk_ctx_t pkey_ctx_inst;
    pkey_ctx = &pkey_ctx_inst;
#endif

    /* Test initialization of a private key with a pem encoded key (without password) */
    status = atcac_pk_init_pem(pkey_ctx, private_key_pem, sizeof(private_key_pem), false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcac_pk_public(pkey_ctx, public_key, &public_key_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(public_key_bytes, public_key, 64);

    status = atcac_pk_free(pkey_ctx);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    atcac_pk_ctx_free(pkey_ctx);
#endif
}

TEST(atcac_pk, sign_simple)
{
    struct atcac_pk_ctx * sign_ctx;
    struct atcac_pk_ctx * verify_ctx;
    uint8_t digest[32] = { 0x1A, 0x3A, 0xA5, 0x45, 0x04, 0x94, 0x53, 0xAF,
                           0xDF, 0x17, 0xE9, 0x89, 0xA4, 0x1F, 0xA0, 0x97,
                           0x94, 0xA5, 0x1B, 0xD5, 0xDB, 0x91, 0x36, 0x37,
                           0x67, 0x55, 0x0C, 0x0F, 0x0A, 0xF3, 0x27, 0xD4 };
    uint8_t signature[128];
    size_t sig_size = sizeof(signature);
    ATCA_STATUS status;

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    sign_ctx = atcac_pk_ctx_new();
    TEST_ASSERT_NOT_NULL(sign_ctx);
    verify_ctx = atcac_pk_ctx_new();
    TEST_ASSERT_NOT_NULL(verify_ctx);
#else
    atcac_pk_ctx_t sign_ctx_inst;
    atcac_pk_ctx_t verify_ctx_inst;
    sign_ctx = &sign_ctx_inst;
    verify_ctx = &verify_ctx_inst;
#endif

    memset(signature, 0, sig_size);

    /* Test initialization of a private key with a pem encoded key (without password) */
    status = atcac_pk_init_pem(sign_ctx, private_key_pem, sizeof(private_key_pem), false);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Test signing with the private key */
    status = atcac_pk_sign(sign_ctx, digest, sizeof(digest), signature, &sig_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Test initialization of a public key with a pem encoded key */
    status = atcac_pk_init_pem(verify_ctx, public_key_pem, sizeof(public_key_pem), true);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Test verification of the siguature */
    status = atcac_pk_verify(verify_ctx, digest, sizeof(digest), &signature[sig_size - 64], 64);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    signature[10] ^= signature[10];

    /* Test failure to validate a corrupted signature */
    status = atcac_pk_verify(verify_ctx, digest, sizeof(digest), &signature[sig_size - 64], 64);
    TEST_ASSERT_NOT_EQUAL(ATCA_SUCCESS, status);

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    atcac_pk_ctx_free(sign_ctx);
    atcac_pk_ctx_free(verify_ctx);
#endif
}

TEST(atcac_pk, derive_ecdh_p256_nist)
{
    ATCA_STATUS status;
    struct atcac_pk_ctx * pri_ctx;
    struct atcac_pk_ctx * pub_ctx;
    uint8_t result[32];
    size_t result_size;
    size_t i;

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    pri_ctx = atcac_pk_ctx_new();
    TEST_ASSERT_NOT_NULL(pri_ctx);
    pub_ctx = atcac_pk_ctx_new();
    TEST_ASSERT_NOT_NULL(pub_ctx);
#else
    atcac_pk_ctx_t pri_ctx_inst;
    atcac_pk_ctx_t pub_ctx_inst;
    pri_ctx = &pri_ctx_inst;
    pub_ctx = &pub_ctx_inst;
#endif

    /* Test verification using [P-256] vectors */
    for (i = 0; i < ecdh_p256_test_vectors_count; i++)
    {
        uint8_t pubkey[64];

        memcpy(pubkey, ecdh_p256_test_vectors[i].QCAVSx, 32);
        memcpy(&pubkey[32], ecdh_p256_test_vectors[i].QCAVSy, 32);

        (void)atcac_pk_init(pub_ctx, pubkey, sizeof(pubkey), 0, true);
        (void)atcac_pk_init(pri_ctx, (uint8_t*)ecdh_p256_test_vectors[i].dIUT, 32, 0, false);

        result_size = sizeof(result);
        status = atcac_pk_derive(pri_ctx, pub_ctx, result, &result_size);

        (void)atcac_pk_free(pri_ctx);
        (void)atcac_pk_free(pub_ctx);

        /* Check Test Results */
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(ecdh_p256_test_vectors[i].ZIUT, result, 32);
    }

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
    atcac_pk_ctx_free(pri_ctx);
    atcac_pk_ctx_free(pub_ctx);
#endif
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info atcac_pk_test_info[] =
{
    { REGISTER_TEST_CASE(atcac_pk, verify_nist),                NULL },
    { REGISTER_TEST_CASE(atcac_pk, init_public),                NULL },
    { REGISTER_TEST_CASE(atcac_pk, sign_simple),                NULL },
    { REGISTER_TEST_CASE(atcac_pk, derive_ecdh_p256_nist),      NULL },
    { (fp_test_case)NULL, NULL },         /* Array Termination element*/
};
// *INDENT-ON*

#endif
