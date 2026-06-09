/**
 * \file
 * \brief Validation test of the mbedtls integration of hardware accelerated
 * ECDSA operations
 *
 * \copyright (c) 2015-2026 Microchip Technology Inc. and its subsidiaries.
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
#include "cal_internal.h"

#ifdef ATCA_MBEDTLS

#ifdef MBEDTLS_ECDSA_C
#include "third_party/atca_mbedtls_patch.h"
#include "vectors/ecdsa_nist_vectors.h"
#endif

#include "mbedtls/atca_mbedtls_wrap.h"

TEST_GROUP(mbedtls_ecdsa_ecdh);

TEST_SETUP(mbedtls_ecdsa_ecdh)
{
    UnityMalloc_StartTest();

    ATCA_STATUS status = atcab_init(gCfg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST_TEAR_DOWN(mbedtls_ecdsa_ecdh)
{
    ATCA_STATUS status;

    status = atcab_wakeup();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_sleep();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_release();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    UnityMalloc_EndTest();
}

#ifdef MBEDTLS_ECDSA_C
/** \brief  This test uses NIST provided vectors for testing verify integration - It may be hardware accelerated         .
 */
TEST(mbedtls_ecdsa_ecdh, verify_nist)
{
    uint8_t pubkey[64];
    uint8_t signature[74];
    uint8_t digest[32];
    atcac_pk_ctx_t pkey_ctx;
    int status;
    size_t i;
    mbedtls_mpi r;
    mbedtls_mpi s;

    /* Test verification using [P-256,SHA-256] vectors */
    for (i = 0; i < ecdsa_p256_test_vectors_count; i++)
    {
        size_t sig_len = sizeof(signature);

        /* Copy pubkey */
        memcpy(pubkey, ecdsa_p256_test_vectors[i].Qx, 32);
        memcpy(&pubkey[32], ecdsa_p256_test_vectors[i].Qy, 32);

        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        /* Copy the signature */
        mbedtls_mpi_read_binary(&r, ecdsa_p256_test_vectors[i].R, 32);
        mbedtls_mpi_read_binary(&s, ecdsa_p256_test_vectors[i].S, 32);

        /* Create the asn.1 signature  */
        status = mbedtls_ecdsa_signature_to_asn1(&r, &s, signature, &sig_len);

        /* Clean up before checking the result */
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Hash the message */
        status = atcac_sw_sha2_256(ecdsa_p256_test_vectors[i].Msg, sizeof(ecdsa_p256_test_vectors[i].Msg), digest);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Initialize the key using the provided X,Y cordinantes */
        status = atcac_pk_init(&pkey_ctx, pubkey, sizeof(pubkey), 0, true);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Perform the verification */
        status = mbedtls_pk_verify((mbedtls_pk_context*)&pkey_ctx, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, sig_len);

        /* Make sure to free the key before testing the result of the verify */
        atcac_pk_free(&pkey_ctx);

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
}

/** \brief  Check verify with a stored key in a device
 */
TEST(mbedtls_ecdsa_ecdh, verify_nist_stored_key)
{
    uint8_t pubkey[64];
    uint8_t signature[74];
    uint8_t digest[32];
    mbedtls_pk_context pkey_ctx;
    ATCA_STATUS status;
    mbedtls_mpi r;
    mbedtls_mpi s;
    size_t i;
    uint16_t key_slot;

    status = atca_test_config_get_id(TEST_TYPE_ECC_VERIFY, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Test verification using [P-256,SHA-256] vectors */
    for (i = 0; i < ecdsa_p256_test_vectors_count; i++)
    {
        size_t sig_len = sizeof(signature);

        /* Copy pubkey */
        memcpy(pubkey, ecdsa_p256_test_vectors[i].Qx, 32);
        memcpy(&pubkey[32], ecdsa_p256_test_vectors[i].Qy, 32);

        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        /* Copy the signature */
        mbedtls_mpi_read_binary(&r, ecdsa_p256_test_vectors[i].R, 32);
        mbedtls_mpi_read_binary(&s, ecdsa_p256_test_vectors[i].S, 32);

        /* Create the asn.1 signature  */
        status = mbedtls_ecdsa_signature_to_asn1(&r, &s, signature, &sig_len);

        /* Clean up before checking the result */
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Hash the message */
        status = atcac_sw_sha2_256(ecdsa_p256_test_vectors[i].Msg, sizeof(ecdsa_p256_test_vectors[i].Msg), digest);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Initialize the key using the provided X,Y cordinantes */
        status = atcab_write_pubkey(key_slot, pubkey);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atca_mbedtls_pk_init(&pkey_ctx, key_slot);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Perform the verification */
        status = mbedtls_pk_verify(&pkey_ctx, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, sig_len);

        /* Make sure to free the key before testing the result of the verify */
        mbedtls_pk_free(&pkey_ctx);

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
}


/** \brief  Having confirmed the verify passes the NIST vectors the sign operation can be tested
 */
TEST(mbedtls_ecdsa_ecdh, sign_stored_key)
{
    int status;
    atcac_pk_ctx_t pkey_ctx;
    uint8_t digest[32];
    uint8_t signature[74] = { 0 };
    size_t sig_len = ATCA_ECCP256_SIG_SIZE;
    uint16_t key_slot;

    status = atca_test_config_get_id(TEST_TYPE_ECC_SIGN, &key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atca_mbedtls_pk_init((mbedtls_pk_context*)&pkey_ctx, key_slot);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = mbedtls_pk_sign((mbedtls_pk_context*)&pkey_ctx, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, sizeof(signature), &sig_len, atca_mbedtls_random_ctx, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Perform the verification */
    status = mbedtls_pk_verify((mbedtls_pk_context*)&pkey_ctx, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, sig_len);

    /* Make sure to free the key before testing the result of the verify */
    atcac_pk_free(&pkey_ctx);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}
#endif

#if defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT) && defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)

// IO Protection key to perform ECDH operations
int atca_mbedtls_ecdh_ioprot_cb(uint8_t secret[32])
{
    uint8_t secret_key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0f,
                             0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
    (void)memcpy(secret, secret_key, 32);
    return 0;
}

// Slot ID of private key used in ECDH operations
#define ECDH_KEY_SLOT_NUM   2

int atca_mbedtls_ecdh_slot_cb(void)
{
    return ECDH_KEY_SLOT_NUM;
}

/** \brief Generate ECDH keypair and get the secret key
 */
TEST(mbedtls_ecdsa_ecdh, ecdh_keypair_derivekey)
{
    ATCA_STATUS status;
    mbedtls_pk_context pctx;
    mbedtls_ecp_group* grp;
    mbedtls_mpi* d;
    mbedtls_mpi z;
    mbedtls_ecp_point* Q;
    uint8_t secret[ATCA_KEY_SIZE];

    // Initialize pctx and z
    mbedtls_pk_init(&pctx);
    mbedtls_mpi_init(&z);
#ifdef MBEDTLS_ECDSA_SIGN_ALT
    status = mbedtls_pk_setup(&pctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
#else
    ret = mbedtls_pk_setup(pkey, &atca_mbedtls_eckey_info);
#endif

    // Initialize grp, d and Q
    grp = &mbedtls_pk_ec(pctx)->MBEDTLS_PRIVATE(grp);
    d = &mbedtls_pk_ec(pctx)->MBEDTLS_PRIVATE(d);
    Q = &mbedtls_pk_ec(pctx)->MBEDTLS_PRIVATE(Q);

    // Load ECCP256 keytype 
    status = mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Register callback functions
    atca_register_ecdh_ioprot_cb(atca_mbedtls_ecdh_ioprot_cb);
    atca_register_ecdh_slot_cb(atca_mbedtls_ecdh_slot_cb);

    // Generate ECDH keypair
    status = mbedtls_ecdh_gen_public(grp, d, Q, atca_mbedtls_random_ctx, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Get secret key
    status = mbedtls_ecdh_compute_shared(grp, &z, Q, d, atca_mbedtls_random_ctx, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Load secret key into output buffer
    (void)mbedtls_mpi_write_binary(&z, secret, sizeof(secret));

    // unregister callbacks
    atca_unregister_ecdh_ioprot_cb();
    atca_unregister_ecdh_slot_cb();

    // Free pctx and z
    mbedtls_pk_free(&pctx);
    mbedtls_mpi_free(&z);
}
#endif

t_test_case_info mbedtls_ecdsa_ecdh_test_info[] =
{
#ifdef MBEDTLS_ECDSA_C
    { REGISTER_TEST_CASE(mbedtls_ecdsa_ecdh, verify_nist),            atca_test_cond_p256_sign_verify                                  },
    { REGISTER_TEST_CASE(mbedtls_ecdsa_ecdh, verify_nist_stored_key), atca_test_cond_p256_sign_verify                                  },
    { REGISTER_TEST_CASE(mbedtls_ecdsa_ecdh, sign_stored_key),        atca_test_cond_p256_sign_verify                                  },
#endif
#if defined(MBEDTLS_ECDH_C) && defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT) && defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
    { REGISTER_TEST_CASE(mbedtls_ecdsa_ecdh, ecdh_keypair_derivekey), atca_test_cond_ecc608                                            },
#endif
    /* Array Termination element*/
    { (fp_test_case)NULL,               NULL },
};

#endif
