/**
 * \file
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

#include "third_party/unity/unity_fixture.h"
#include "atca_test.h"
#include "app/tng/tng_atca.h"
#include "app/tng/tng_atcacert_client.h"
#include "app/tng/tngtls_cert_def_1_signer.h"
#include "app/tng/tngtls_cert_def_2_device.h"
#include "atcacert/atcacert_def.h"

TEST_GROUP(tng_atcacert_client);

TEST_SETUP(tng_atcacert_client)
{
}

TEST_TEAR_DOWN(tng_atcacert_client)
{
}

TEST(tng_atcacert_client, tng_atcacert_root_public_key)
{
    int ret;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    size_t i;
    bool is_all_zero;

    memset(public_key, 0, sizeof(public_key));

    ret = tng_atcacert_root_public_key(public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    // Make sure we got something back
    is_all_zero = true;
    for (i = 0; i < sizeof(public_key); i++)
    {
        if (public_key[i] != 0)
        {
            is_all_zero = false;
            break;
        }
    }
    TEST_ASSERT(!is_all_zero);
}

TEST(tng_atcacert_client, tng_atcacert_root_cert)
{
    int ret;
    uint8_t cert[1024];
    size_t cert_size = 0;

    ret = tng_atcacert_root_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(sizeof(cert) >= cert_size);

    ret = tng_atcacert_root_cert(cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
}

TEST(tng_atcacert_client, tng_atcacert_root_cert_small_buf)
{
    int ret;
    uint8_t cert[1024];
    size_t cert_size = 0;

    ret = tng_atcacert_root_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(sizeof(cert) >= cert_size);

    cert_size--;
    ret = tng_atcacert_root_cert(cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BUFFER_TOO_SMALL, ret);
}

TEST(tng_atcacert_client, tng_atcacert_max_signer_cert_size)
{
    int ret;
    size_t cert_size = 0;

    ret = tng_atcacert_max_signer_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(cert_size != 0);
}

TEST(tng_atcacert_client, tng_atcacert_read_signer_cert)
{
    int ret;
    uint8_t cert[1024];
    size_t cert_size = 0;
    uint8_t ca_public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t tbs_digest[ATCA_SHA2_256_DIGEST_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    bool is_verified = false;

    ret = tng_atcacert_max_signer_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(sizeof(cert) >= cert_size);

    ret = tng_atcacert_read_signer_cert(cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = tng_atcacert_root_public_key(ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    // TNG 22 cert def will work for both 22 and TG here as the certificate is
    // the same once reconstructed

    ret = atcacert_get_tbs_digest(
        &g_tngtls_cert_def_1_signer,
        cert,
        cert_size,
        tbs_digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcacert_get_signature(
        &g_tngtls_cert_def_1_signer,
        cert,
        cert_size,
        signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcab_verify_extern(tbs_digest, signature, ca_public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT(is_verified);
}

TEST(tng_atcacert_client, tng_atcacert_signer_public_key_no_cert)
{
    int ret;
    uint8_t cert[1024];
    size_t cert_size = 0;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t cert_public_key[ATCA_ECCP256_PUBKEY_SIZE];

    ret = tng_atcacert_max_signer_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(sizeof(cert) >= cert_size);

    ret = tng_atcacert_read_signer_cert(cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    // TNG 22 cert def will work for both 22 and TG here as the certificate is
    // the same once reconstructed
    ret = atcacert_get_subj_public_key(
        &g_tngtls_cert_def_1_signer,
        cert,
        cert_size,
        cert_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = tng_atcacert_signer_public_key(public_key, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(cert_public_key, public_key, sizeof(public_key));
}

TEST(tng_atcacert_client, tng_atcacert_signer_public_key_cert)
{
    int ret;
    uint8_t cert[1024];
    size_t cert_size = 0;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t cert_public_key[ATCA_ECCP256_PUBKEY_SIZE];

    ret = tng_atcacert_max_signer_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(sizeof(cert) >= cert_size);

    ret = tng_atcacert_read_signer_cert(cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    // TNG 22 cert def will work for both 22 and TG here as the certificate is
    // the same once reconstructed
    ret = atcacert_get_subj_public_key(
        &g_tngtls_cert_def_1_signer,
        cert,
        cert_size,
        cert_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = tng_atcacert_signer_public_key(public_key, cert);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(cert_public_key, public_key, sizeof(public_key));
}

TEST(tng_atcacert_client, tng_atcacert_max_device_cert_size)
{
    int ret;
    size_t cert_size = 0;

    ret = tng_atcacert_max_device_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(cert_size != 0);
}

TEST(tng_atcacert_client, tng_atcacert_read_device_cert_no_signer)
{
    int ret;
    uint8_t cert[1024];
    size_t cert_size = 0;
    const atcacert_def_t* cert_def = NULL;
    uint8_t ca_public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t tbs_digest[ATCA_SHA2_256_DIGEST_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    bool is_verified = false;

    ret = tng_atcacert_max_device_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(sizeof(cert) >= cert_size);

    ret = tng_atcacert_read_device_cert(cert, &cert_size, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = tng_atcacert_signer_public_key(ca_public_key, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = (int)tng_get_device_cert_def(&cert_def);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_get_tbs_digest(
        cert_def,
        cert,
        cert_size,
        tbs_digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcacert_get_signature(
        cert_def,
        cert,
        cert_size,
        signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcab_verify_extern(tbs_digest, signature, ca_public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT(is_verified);
}

TEST(tng_atcacert_client, tng_atcacert_read_device_cert_signer)
{
    int ret;
    uint8_t signer_cert[1024];
    size_t signer_cert_size = 0;
    uint8_t cert[1024];
    size_t cert_size = 0;
    const atcacert_def_t* cert_def = NULL;
    uint8_t ca_public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t tbs_digest[ATCA_SHA2_256_DIGEST_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    bool is_verified = false;

    ret = tng_atcacert_max_signer_cert_size(&signer_cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(sizeof(signer_cert) >= signer_cert_size);

    ret = tng_atcacert_read_signer_cert(signer_cert, &signer_cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = tng_atcacert_max_device_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(sizeof(cert) >= cert_size);

    ret = tng_atcacert_read_device_cert(cert, &cert_size, signer_cert);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = tng_atcacert_signer_public_key(ca_public_key, signer_cert);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = (int)tng_get_device_cert_def(&cert_def);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_get_tbs_digest(
        cert_def,
        cert,
        cert_size,
        tbs_digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcacert_get_signature(
        cert_def,
        cert,
        cert_size,
        signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcab_verify_extern(tbs_digest, signature, ca_public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT(is_verified);
}

TEST(tng_atcacert_client, tng_atcacert_device_public_key_no_cert)
{
    int ret;
    uint8_t cert[1024];
    size_t cert_size = 0;
    const atcacert_def_t* cert_def = NULL;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t cert_public_key[ATCA_ECCP256_PUBKEY_SIZE];

    ret = tng_atcacert_max_device_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = tng_atcacert_read_device_cert(cert, &cert_size, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = (int)tng_get_device_cert_def(&cert_def);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_get_subj_public_key(
        cert_def,
        cert,
        cert_size,
        cert_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = tng_atcacert_device_public_key(public_key, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(cert_public_key, public_key, sizeof(public_key));
}

TEST(tng_atcacert_client, tng_atcacert_device_public_key_cert)
{
    int ret;
    uint8_t cert[1024];
    size_t cert_size = 0;
    const atcacert_def_t* cert_def = NULL;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t cert_public_key[ATCA_ECCP256_PUBKEY_SIZE];

    ret = tng_atcacert_max_device_cert_size(&cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = tng_atcacert_read_device_cert(cert, &cert_size, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = (int)tng_get_device_cert_def(&cert_def);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_get_subj_public_key(
        cert_def,
        cert,
        cert_size,
        cert_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = tng_atcacert_device_public_key(public_key, cert);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(cert_public_key, public_key, sizeof(public_key));
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info tng_atcacert_client_unit_test_info[] =
{
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_root_public_key),            DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_root_cert),                  DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_max_signer_cert_size),       DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_read_signer_cert),           DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_signer_public_key_no_cert),  DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_signer_public_key_cert),     DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_max_device_cert_size),       DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_read_device_cert_no_signer), DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_read_device_cert_signer),    DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_device_public_key_no_cert),  DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(tng_atcacert_client, tng_atcacert_device_public_key_cert),     DEVICE_MASK(ATECC608)},
    { (fp_test_case)NULL,                                                               (uint8_t)0 },
};
// *INDENT-ON*
