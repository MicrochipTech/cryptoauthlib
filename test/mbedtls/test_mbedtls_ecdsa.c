/**
 * \file
 * \brief Validation test of the mbedtls integration of hardware accelerated
 * ECDSA operations
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

#if defined(ATCA_MBEDTLS) && defined(MBEDTLS_ECDSA_C)
#include "third_party/atca_mbedtls_patch.h"

#include "mbedtls/atca_mbedtls_wrap.h"
#include "vectors/ecdsa_nist_vectors.h"

/** \brief  This test uses NIST provided vectors for testing verify integration - It may be hardware accelerated         .
 */
TEST(atca_cmd_basic_test, mbedtls_ecdsa_verify_nist)
{
    uint8_t pubkey[64];
    uint8_t signature[74];
    uint8_t digest[32];
    atcac_pk_ctx pkey_ctx;
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
        status = mbedtls_pk_verify(&pkey_ctx, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, sig_len);

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
TEST(atca_cmd_basic_test, mbedtls_ecdsa_verify_nist_stored_key)
{
    uint8_t pubkey[64];
    uint8_t signature[74];
    uint8_t digest[32];
    atcac_pk_ctx pkey_ctx;
    ATCA_STATUS status;
    mbedtls_mpi r;
    mbedtls_mpi s;
    size_t i;

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
        status = atcab_write_pubkey(15, pubkey);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atca_mbedtls_pk_init(&pkey_ctx, 15);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Perform the verification */
        status = mbedtls_pk_verify(&pkey_ctx, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, sig_len);

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


/** \brief  Having confirmed the verify passes the NIST vectors the sign operation can be tested
 */
TEST(atca_cmd_basic_test, mbedtls_ecdsa_sign)
{
    int status;
    atcac_pk_ctx pkey_ctx;
    uint8_t digest[32];
    uint8_t signature[74] = { 0 };
    size_t sig_len = sizeof(signature);

    status = atca_mbedtls_pk_init(&pkey_ctx, 0);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = mbedtls_pk_sign(&pkey_ctx, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, &sig_len, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    /* Perform the verification */
    status = mbedtls_pk_verify(&pkey_ctx, MBEDTLS_MD_SHA256, digest, sizeof(digest), signature, sig_len);

    /* Make sure to free the key before testing the result of the verify */
    atcac_pk_free(&pkey_ctx);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

}

t_test_case_info test_mbedtls_ecdsa_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mbedtls_ecdsa_verify_nist),            DEVICE_MASK_ECC | DEVICE_MASK(TA100)                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mbedtls_ecdsa_verify_nist_stored_key), DEVICE_MASK_ECC | DEVICE_MASK(TA100)                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mbedtls_ecdsa_sign),                   DEVICE_MASK_ECC | DEVICE_MASK(TA100)                      },
    /* Array Termination element*/
    { (fp_test_case)NULL,                     (uint8_t)0 },
};

#endif
