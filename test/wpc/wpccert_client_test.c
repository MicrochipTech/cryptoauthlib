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
#include "app/wpc/wpccert_client.h"
#include "app/wpc/zcust_def_1_signer.h"
#include "app/wpc/zcust_def_2_device.h"
#include "atcacert/atcacert_def.h"

TEST_GROUP(wpccert_client);

TEST_SETUP(wpccert_client)
{
    atcab_init(gCfg);
    test_assert_data_is_locked();
}

TEST_TEAR_DOWN(wpccert_client)
{
    atcab_release();
}

TEST(wpccert_client, wpccert_read_mfg_cert)
{
    int ret;
    uint8_t cert[512];
    size_t cert_size = 0;
    ATCADevice device = atcab_get_device();

    ret = wpccert_read_mfg_cert(device, cert, &cert_size, 0);
    TEST_ASSERT_SUCCESS(ret);
}

TEST(wpccert_client, wpccert_read_pdu_cert)
{
    int ret;
    uint8_t cert[512];
    size_t cert_size = 0;
    ATCADevice device = atcab_get_device();

    ret = wpccert_read_pdu_cert(device, cert, &cert_size, 0);
    TEST_ASSERT_SUCCESS(ret);
}

TEST(wpccert_client, wpccert_mfg_public_key_no_cert)
{
    int ret;
    uint8_t cert[512];
    size_t cert_size = 0;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t cert_public_key[ATCA_ECCP256_PUBKEY_SIZE];
    const atcacert_def_t* cert_def;
    ATCADevice device = atcab_get_device();

    ret = wpccert_get_slot_info(NULL, &cert_def, 0);
    TEST_ASSERT_SUCCESS(ret);

    ret = wpccert_read_mfg_cert(device, cert, &cert_size, 0);
    TEST_ASSERT_SUCCESS(ret);

    ret = atcacert_get_subj_public_key(
        cert_def,
        cert,
        cert_size,
        cert_public_key);
    TEST_ASSERT_SUCCESS(ret);

    ret = wpccert_public_key(cert_def, public_key, NULL);
    TEST_ASSERT_SUCCESS(ret);
    TEST_ASSERT_EQUAL_MEMORY(cert_public_key, public_key, sizeof(public_key));
}

TEST(wpccert_client, wpccert_mfg_public_key_cert)
{
    int ret;
    uint8_t cert[512];
    size_t cert_size = 0;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t cert_public_key[ATCA_ECCP256_PUBKEY_SIZE];
    const atcacert_def_t* cert_def;
    ATCADevice device = atcab_get_device();

    ret = wpccert_get_slot_info(NULL, &cert_def, 0);
    TEST_ASSERT_SUCCESS(ret);

    ret = wpccert_read_mfg_cert(device, cert, &cert_size, 0);
    TEST_ASSERT_SUCCESS(ret);

    ret = atcacert_get_subj_public_key(
        cert_def->ca_cert_def,
        cert,
        cert_size,
        cert_public_key);
    TEST_ASSERT_SUCCESS(ret);

    ret = wpccert_public_key(cert_def, public_key, cert);
    TEST_ASSERT_SUCCESS(ret);
    TEST_ASSERT_EQUAL_MEMORY(cert_public_key, public_key, sizeof(public_key));
}


TEST(wpccert_client, wpccert_pdu_public_key_no_cert)
{
    int ret;
    uint8_t cert[512];
    size_t cert_size = 0;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t cert_public_key[ATCA_ECCP256_PUBKEY_SIZE];
    const atcacert_def_t* cert_def;
    ATCADevice device = atcab_get_device();

    ret = wpccert_get_slot_info(NULL, &cert_def, 0);
    TEST_ASSERT_SUCCESS(ret);

    ret = wpccert_read_pdu_cert(device, cert, &cert_size, 0);
    TEST_ASSERT_SUCCESS(ret);

    ret = atcacert_get_subj_public_key(
        cert_def,
        cert,
        cert_size,
        cert_public_key);
    TEST_ASSERT_SUCCESS(ret);

    ret = wpccert_public_key(cert_def, public_key, NULL);
    TEST_ASSERT_SUCCESS(ret);
    TEST_ASSERT_EQUAL_MEMORY(cert_public_key, public_key, sizeof(public_key));
}

TEST(wpccert_client, wpccert_pdu_public_key_cert)
{
    int ret;
    uint8_t cert[512];
    size_t cert_size = 0;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t cert_public_key[ATCA_ECCP256_PUBKEY_SIZE];
    const atcacert_def_t* cert_def;
    ATCADevice device = atcab_get_device();

    ret = wpccert_get_slot_info(NULL, &cert_def, 0);
    TEST_ASSERT_SUCCESS(ret);

    ret = wpccert_read_pdu_cert(device, cert, &cert_size, 0);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_get_subj_public_key(
        cert_def,
        cert,
        cert_size,
        cert_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = wpccert_public_key(cert_def, public_key, cert);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(cert_public_key, public_key, sizeof(public_key));
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info wpccert_client_unit_test_info[] =
{
    { REGISTER_TEST_CASE(wpccert_client, wpccert_read_mfg_cert),             DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(wpccert_client, wpccert_read_pdu_cert),             DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(wpccert_client, wpccert_mfg_public_key_no_cert),    DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(wpccert_client, wpccert_mfg_public_key_cert),       DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(wpccert_client, wpccert_pdu_public_key_no_cert),    DEVICE_MASK(ATECC608)},
    { REGISTER_TEST_CASE(wpccert_client, wpccert_pdu_public_key_cert),       DEVICE_MASK(ATECC608)},
    { (fp_test_case)NULL,                                                    (uint8_t)0 },
};
// *INDENT-ON*
