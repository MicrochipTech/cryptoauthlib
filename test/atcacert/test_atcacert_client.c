/**
 * \file
 * \brief cert client tests
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
#ifndef DO_NOT_TEST_CERT

#include "atcacert/atcacert_client.h"
#include "atcacert/atcacert_pem.h"
#include "third_party/unity/unity.h"
#include "third_party/unity/unity_fixture.h"
#include <string.h>
#include "atca_basic.h"
#include "crypto/atca_crypto_sw_sha2.h"
#include "test_cert_def_0_device.h"
#include "test_cert_def_1_signer.h"
#include "test_cert_def_2_device_csr.h"
#include "test_cert_def_4_device.h"
#include "test_cert_def_5_device.h"
#include "test_cert_def_8_signer.h"
#include "test_cert_def_9_device.h"
#include "test_cert_def_10_device.h"

#ifdef ATCA_MBEDTLS
    #include "mbedtls/certs.h"
#endif

extern ATCAIfaceCfg *gCfg;

uint8_t g_signer_ca_public_key[64];
uint8_t g_signer_public_key[64];
uint8_t g_device_public_key[64];

uint8_t g_signer_cert_ref[512];
size_t g_signer_cert_ref_size = 0;

uint8_t g_device_cert_ref[512];
size_t g_device_cert_ref_size = 0;

//Flag to switch to atcacert_write_cert api or use the talib_write_cert api in the tests
#define TALIB_API_WRITE_RSACERT FEATURE_ENABLED

#if ATCACERT_COMPCERT_EN
static void build_and_save_cert(
    const atcacert_def_t*    cert_def,
    uint8_t*                 cert,
    size_t*                  cert_size,
    const uint8_t            ca_public_key[64],
    const uint8_t            public_key[64],
    const uint8_t            signer_id[2],
    const atcacert_tm_utc_t* issue_date,
    const uint8_t *          config,
    uint8_t                  ca_slot)
{
    int ret;
    atcacert_build_state_t build_state;
    uint8_t tbs_digest[32];
    uint8_t signature[64];
    uint8_t comp_cert[72];
    size_t max_cert_size = *cert_size;
    uint16_t config_count = atcab_is_ca2_device(atcab_get_device_type()) ? 16U : 32U;

    atcacert_tm_utc_t expire_date = {
        .tm_year    = issue_date->tm_year + cert_def->expire_years,
        .tm_mon     = issue_date->tm_mon,
        .tm_mday    = issue_date->tm_mday,
        .tm_hour    = issue_date->tm_hour,
        .tm_min     = 0,
        .tm_sec     = 0
    };

    const atcacert_device_loc_t config_dev_loc = {
        .zone   = DEVZONE_CONFIG,
        .offset = 0,
        .count  = config_count
    };

    atcacert_device_loc_t device_locs[4];
    size_t device_locs_count = 0;
    size_t i;

    if (cert_def->expire_years == 0)
    {
        ret = atcacert_date_get_max_date(cert_def->expire_date_format, &expire_date);
        TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    }

    ret = atcacert_cert_build_start(atcab_get_device(),&build_state, cert_def, cert, cert_size, ca_public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_set_subj_public_key(build_state.cert_def, build_state.cert, *build_state.cert_size, public_key);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    ret = atcacert_set_issue_date(build_state.cert_def, build_state.cert, *build_state.cert_size, issue_date);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    ret = atcacert_set_expire_date(build_state.cert_def, build_state.cert, *build_state.cert_size, &expire_date);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    ret = atcacert_set_signer_id(build_state.cert_def, build_state.cert, *build_state.cert_size, signer_id);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    ret = atcacert_get_comp_cert(build_state.cert_def, build_state.cert, *build_state.cert_size, comp_cert);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_cert_build_process(&build_state, &config_dev_loc, config);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_cert_build_process(&build_state, &cert_def->comp_cert_dev_loc, comp_cert);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_cert_build_finish(&build_state);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_get_tbs_digest(build_state.cert_def, build_state.cert, *build_state.cert_size, tbs_digest);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcab_sign(ca_slot, tbs_digest, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcacert_set_signature(cert_def, cert, cert_size, max_cert_size, signature);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_get_device_locs(atcab_get_device(),cert_def, device_locs, &device_locs_count, sizeof(device_locs) / sizeof(device_locs[0]), 32);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    for (i = 0; i < device_locs_count; i++)
    {
        size_t end_block;
        size_t start_block;
        uint8_t data[96];
        uint8_t block;

        if (device_locs[i].zone == DEVZONE_CONFIG)
        {
            continue;
        }
        if (device_locs[i].zone == DEVZONE_DATA && device_locs[i].is_genkey)
        {
            continue;
        }

        TEST_ASSERT(sizeof(data) >= device_locs[i].count);

        ret = atcacert_get_device_data(cert_def, cert, *cert_size, &device_locs[i], data);
        TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

        start_block = device_locs[i].offset / 32;
        end_block = (device_locs[i].offset + device_locs[i].count) / 32;
        for (block = (uint8_t)start_block; block < end_block; block++)
        {
            ret = atcab_write_zone(device_locs[i].zone, device_locs[i].slot, block, 0, &data[(block - start_block) * 32], 32);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
        }
    }
}
#endif

TEST_GROUP(atcacert_client);

TEST_SETUP(atcacert_client)
{
    int ret = 0;
    bool lockstate = 0;
    bool is_ca_device = false;

    ret = atcab_init(gCfg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    is_ca_device = atcab_is_ca_device(atcab_get_device_type());
    if(false == is_ca_device)
    {
        TEST_IGNORE_MESSAGE("This Test group can be run on Ca devices only");
    }

    ret = atcab_is_config_locked(&lockstate);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    if (!lockstate)
    {
        TEST_IGNORE_MESSAGE("Config zone must be locked for this test.");
    }

    ret = atcab_is_data_locked(&lockstate);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    if (!lockstate)
    {
        TEST_IGNORE_MESSAGE("Data zone must be locked for this test.");
    }
}

TEST_TEAR_DOWN(atcacert_client)
{
    ATCA_STATUS status;

    status = atcab_wakeup();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_sleep();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_release();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

#if ATCACERT_COMPCERT_EN
//! #warning "For demonstration purposes, we're storing the Root private key and Signer private key inside a protected part of the device.
//!           However, for production setup, these secure keys should not be kept in the device,
//!           and the process to create a verification certificate should be performed off-chip."
TEST(atcacert_client, init)
{
    int ret = 0;

    static const uint8_t signer_ca_private_key_slot = 7;
    static const uint8_t signer_private_key_slot = 2;
    uint8_t signer_id[2] = { 0xC4, 0x8B };
    const atcacert_tm_utc_t signer_issue_date = {
        .tm_year    = 2014 - 1900,
        .tm_mon     = 8 - 1,
        .tm_mday    = 2,
        .tm_hour    = 20,
        .tm_min     = 0,
        .tm_sec     = 0
    };
    static const uint8_t device_private_key_slot = 0;
    const atcacert_tm_utc_t device_issue_date = {
        .tm_year    = 2015 - 1900,
        .tm_mon     = 9 - 1,
        .tm_mday    = 3,
        .tm_hour    = 21,
        .tm_min     = 0,
        .tm_sec     = 0
    };
    uint8_t config32[32];
    char disp_str[1500];
    size_t disp_size = sizeof(disp_str);

    ret = atcab_read_zone(ATCA_ZONE_CONFIG, 0, 0, 0, config32, 32);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atca_test_genkey(signer_ca_private_key_slot, g_signer_ca_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_signer_ca_public_key, ATCA_ECCP256_PUBKEY_SIZE, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Signer CA Public Key:\r\n%s\r\n", disp_str);

    ret = atca_test_genkey(signer_private_key_slot, g_signer_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_signer_public_key, ATCA_ECCP256_PUBKEY_SIZE, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Signer Public Key:\r\n%s\r\n", disp_str);

    ret = atca_test_genkey(device_private_key_slot, g_device_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_device_public_key, ATCA_ECCP256_PUBKEY_SIZE, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Device Public Key:\r\n%s\r\n", disp_str);

    // Build signer cert
    g_signer_cert_ref_size = sizeof(g_signer_cert_ref);
    build_and_save_cert(
        &g_test_cert_def_1_signer,
        g_signer_cert_ref,
        &g_signer_cert_ref_size,
        g_signer_ca_public_key,
        g_signer_public_key,
        signer_id,
        &signer_issue_date,
        config32,
        signer_ca_private_key_slot);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_signer_cert_ref, g_signer_cert_ref_size, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Signer Certificate:\r\n%s\r\n", disp_str);

    g_device_cert_ref_size = sizeof(g_device_cert_ref);
    build_and_save_cert(
        &g_test_cert_def_0_device,
        g_device_cert_ref,
        &g_device_cert_ref_size,
        g_signer_public_key,
        g_device_public_key,
        signer_id,
        &device_issue_date,
        config32,
        signer_private_key_slot);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_device_cert_ref, g_device_cert_ref_size, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Device Certificate:\r\n%s\r\n", disp_str);
}

TEST(atcacert_client, atcacert_read_device_loc_gen_key)
{
    int ret;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t data[sizeof(public_key)];

    atcacert_device_loc_t device_loc = { DEVZONE_DATA, 0, TRUE, 0, 64 };

    ret = atcab_get_pubkey(device_loc.slot, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcacert_read_device_loc(&device_loc, data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(&public_key[device_loc.offset], data, device_loc.count);
}

TEST(atcacert_client, atcacert_read_device_loc_gen_key_partial)
{
    int ret;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t data[sizeof(public_key)];
    atcacert_device_loc_t device_loc = { DEVZONE_DATA, 0, TRUE, 5, 55 };

    ret = atcab_get_pubkey(device_loc.slot, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcacert_read_device_loc(&device_loc, data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(&public_key[device_loc.offset], data, device_loc.count);
}

TEST(atcacert_client, atcacert_read_device_loc_data_partial)
{
    int ret;
    uint8_t data_full[72];
    uint8_t data[sizeof(data_full)];
    atcacert_device_loc_t device_loc = { DEVZONE_DATA, 12, FALSE, 5, 55 };

    ret = atcab_read_bytes_zone(device_loc.zone, device_loc.slot, 0, data_full, 72);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcacert_read_device_loc(&device_loc, data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(&data_full[device_loc.offset], data, device_loc.count);
}

TEST(atcacert_client, atcacert_read_cert_signer)
{
    int ret = 0;
    uint8_t cert[512];
    size_t cert_size = sizeof(cert);

    ret = atcacert_read_cert(&g_test_cert_def_1_signer, g_signer_ca_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL(g_signer_cert_ref_size, cert_size);
    TEST_ASSERT_EQUAL_MEMORY(g_signer_cert_ref, cert, cert_size);
}

TEST(atcacert_client, atcacert_read_cert_device)
{
    int ret = 0;
    uint8_t cert[512];
    size_t cert_size = sizeof(cert);

    ret = atcacert_read_cert(&g_test_cert_def_0_device, g_signer_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL(g_device_cert_ref_size, cert_size);
    TEST_ASSERT_EQUAL_MEMORY(g_device_cert_ref, cert, cert_size);
}

TEST(atcacert_client, atcacert_read_subj_key_id)
{
    int ret = 0;
    uint8_t cert[512];
    size_t cert_size = sizeof(cert);
    uint8_t key_id_ref[20];
    uint8_t key_id[20];

    ret = atcacert_read_cert(&g_test_cert_def_1_signer, g_signer_ca_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL(g_signer_cert_ref_size, cert_size);
    TEST_ASSERT_EQUAL_MEMORY(g_signer_cert_ref, cert, cert_size);

    ret = atcacert_get_subj_key_id(&g_test_cert_def_1_signer, cert, cert_size, key_id_ref);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_read_subj_key_id(&g_test_cert_def_1_signer, key_id);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(key_id_ref, key_id, sizeof(key_id));
}

TEST(atcacert_client, atcacert_read_cert_small_buf)
{
    int ret = 0;
    uint8_t cert[512];
    size_t cert_size = sizeof(cert);

    // Getting the actual buffer size needed for the certificate
    ret = atcacert_read_cert(&g_test_cert_def_0_device, g_signer_public_key, NULL, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    // Read the device certificate
    ret = atcacert_read_cert(&g_test_cert_def_0_device, g_signer_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL(g_device_cert_ref_size, cert_size);
    TEST_ASSERT_EQUAL_MEMORY(g_device_cert_ref, cert, cert_size);

    // Decrease the size of the buffer needed for device certificate
    cert_size -= 1;
    ret = atcacert_read_cert(&g_test_cert_def_0_device, g_signer_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BUFFER_TOO_SMALL, ret);
}

TEST(atcacert_client, atcacert_read_cert_bad_params)
{
    int ret = 0;
    uint8_t cert[128];
    size_t cert_size = sizeof(cert);

    ret = atcacert_read_cert(NULL, g_signer_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, NULL, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, g_signer_public_key, NULL, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, NULL, NULL, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(&g_test_cert_def_0_device, g_signer_public_key, cert, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, g_signer_public_key, cert, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(&g_test_cert_def_0_device, NULL, cert, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, NULL, cert, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(&g_test_cert_def_0_device, g_signer_public_key, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, g_signer_public_key, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(&g_test_cert_def_0_device, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
}

TEST(atcacert_client, atcacert_get_response_bad_params)
{
    int ret = 0;
    uint8_t response[64];
    const uint8_t challenge[32] = {
        0x0c, 0xa6, 0x34, 0xc8, 0x37, 0x2f, 0x87, 0x99, 0x99, 0x7e, 0x9e, 0xe9, 0xd5, 0xbc, 0x72, 0x71,
        0x84, 0xd1, 0x97, 0x0a, 0xea, 0xfe, 0xac, 0x60, 0x7e, 0xd1, 0x3e, 0x12, 0xb7, 0x32, 0x25, 0xf1
    };

    ret = atcacert_get_response(16, challenge, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(0, NULL, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(16, NULL, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(0, challenge, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(16, challenge, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(0, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(16, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
}

#if (ATCA_ECC_SUPPORT)
TEST(atcacert_client, atcacert_get_response)
{
    int ret = 0;
    uint8_t response[64];
    bool is_verified = false;
    const uint8_t challenge[32] = {
        0x0c, 0xa6, 0x34, 0xc8, 0x37, 0x2f, 0x87, 0x99, 0x99, 0x7e, 0x9e, 0xe9, 0xd5, 0xbc, 0x72, 0x71,
        0x84, 0xd1, 0x97, 0x0a, 0xea, 0xfe, 0xac, 0x60, 0x7e, 0xd1, 0x3e, 0x12, 0xb7, 0x32, 0x25, 0xf1
    };
    char disp_str[256];
    size_t disp_size = sizeof(disp_str);

    ret = atcacert_get_response(0, challenge, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcab_verify_extern(challenge, response, g_device_public_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT(is_verified);

    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(challenge, sizeof(challenge), disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Challenge:\r\n%s\r\n", disp_str);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(response, sizeof(response), disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Response:\r\n%s\r\n", disp_str);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_device_public_key, sizeof(g_device_public_key), disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Public Key:\r\n%s\r\n", disp_str);
}

TEST(atcacert_client, atcacert_generate_device_csr)
{
    uint8_t csr_der_buffer[512];
    uint8_t signature[64];
    uint8_t pub_key[64];
    size_t csr_der_buffer_length = 0;
    bool is_verified = false;
    uint8_t csr_digest[ATCA_SHA256_DIGEST_SIZE];
    char disp_str[1024];
    size_t disp_size = sizeof(disp_str);
    const atcacert_cert_loc_t* pub_loc = NULL;
    int ret = 0;

    memset(csr_der_buffer, 0, sizeof(csr_der_buffer));

    // Generate the device CSR
    csr_der_buffer_length = sizeof(csr_der_buffer);
    ret = atcacert_create_csr(&g_csr_def_2_device, csr_der_buffer, &csr_der_buffer_length);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcab_bin2hex(csr_der_buffer, csr_der_buffer_length, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    printf("Device CSR:\r\n%s\r\n", disp_str);

    // Get the public key from CSR
    pub_loc =  &(g_csr_def_2_device.std_cert_elements[STDCERT_PUBLIC_KEY]);
    ret = atcacert_get_cert_element(&g_csr_def_2_device, pub_loc, csr_der_buffer, csr_der_buffer_length, pub_key, ATCA_ECCP256_PUBKEY_SIZE);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    // Get the digest of the CSR
    ret = atcacert_get_tbs_digest(&g_csr_def_2_device, csr_der_buffer, csr_der_buffer_length, csr_digest);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    //Get the signature from the CSR
    ret = atcacert_get_signature(&g_csr_def_2_device, csr_der_buffer, csr_der_buffer_length, signature);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcab_verify_extern(csr_digest, signature, pub_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(is_verified);

}


TEST(atcacert_client, atcacert_generate_device_csr_pem)
{
    uint8_t csr_der_buffer[512];
    char csr_pem_buffer[512];
    uint8_t signature[64];
    uint8_t pub_key[64];
    size_t csr_der_buffer_length = 0;
    size_t csr_pem_buffer_length = 0;
    bool is_verified = false;
    uint8_t csr_digest[ATCA_SHA256_DIGEST_SIZE] = { 0 };
    const atcacert_cert_loc_t* pub_loc = NULL;
    int ret = 0;

    memset(csr_pem_buffer, 0, sizeof(csr_pem_buffer));
    memset(csr_der_buffer, 0, sizeof(csr_der_buffer));

    //Generate the CSR certificate in PEM
    csr_pem_buffer_length = sizeof(csr_pem_buffer);
    ret = atcacert_create_csr_pem(&g_csr_def_2_device, (char*)&csr_pem_buffer, &csr_pem_buffer_length);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    printf("Device CSR :\r\n%s", csr_pem_buffer);

    // Convert the CSR certificate to DER
    csr_der_buffer_length = sizeof(csr_der_buffer);
    ret = atcacert_decode_pem_csr(csr_pem_buffer, csr_pem_buffer_length, csr_der_buffer, &csr_der_buffer_length);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    // Get the public key from CSR
    pub_loc =  &(g_csr_def_2_device.std_cert_elements[STDCERT_PUBLIC_KEY]);
    ret = atcacert_get_cert_element(&g_csr_def_2_device, pub_loc, csr_der_buffer, csr_der_buffer_length, pub_key, ATCA_ECCP256_PUBKEY_SIZE);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    // Get the digest of the CSR
    ret = atcacert_get_tbs_digest(&g_csr_def_2_device, csr_der_buffer, csr_der_buffer_length, csr_digest);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    //Get the signature from the CSR
    ret = atcacert_get_signature(&g_csr_def_2_device, csr_der_buffer, csr_der_buffer_length, signature);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcab_verify_extern(csr_digest, signature, pub_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT(is_verified);
}
#endif
#endif

#if ATCACERT_INTEGRATION_EN

//For ECC608
#ifdef ATCA_ATECC608_SUPPORT
uint8_t test_ecc608_configdata_full_cert_test[ATCA_ECC_CONFIG_SIZE] = {
    0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x04, 0x05, 0x06, 0x07, 0xEE, 0x01, 0x01, 0x00,  //15
    0xC0, 0x00, 0xA1, 0x00, 0xAF, 0x2F, 0xC4, 0x44, 0x87, 0x20, 0xC4, 0xF4, 0x8F, 0x0F, 0x0F, 0x0F,  //31,
    0x9F, 0x8F, 0x83, 0x64, 0x04, 0x04, 0xC4, 0x64, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,  //47
    0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,  //63
    0x00, 0x00, 0x00, 0x00, 0xFF, 0x84, 0x03, 0xBC, 0x09, 0x69, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00,  //79
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x0E, 0x40, 0x00, 0x00, 0x00, 0x00,  //95
    0x33, 0x00, 0x1C, 0x00, 0x13, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x3A, 0x10, 0x1C, 0x00, 0x33, 0x00,  //111
    0x1C, 0x00, 0x1C, 0x00, 0x38, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x32, 0x00, 0x30, 0x00   //127
};
#endif

#if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
const uint8_t test_ecc_configdata_full_cert_test[ATCA_ECC_CONFIG_SIZE] = {
    0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x04, 0x05, 0x06, 0x07, 0xEE, 0x00, 0x01, 0x00, //15
    0xC0, 0x00, 0x55, 0x00, 0x8F, 0x2F, 0xC4, 0x44, 0x87, 0x20, 0xC4, 0xF4, 0x8F, 0x0F, 0x8F, 0x8F, //31,
    0x9F, 0x8F, 0x83, 0x64, 0x04, 0x04, 0xC4, 0x64, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, //47
    0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, //63
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //79
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //95
    0x33, 0x00, 0x1C, 0x00, 0x13, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x1C, 0x00, 0x1C, 0x00, 0x33, 0x00, //111
    0x1C, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x32, 0x00, 0x30, 0x00  //127
};
#endif

TEST(atcacert_client, atcacert_get_subj)
{
    ATCA_STATUS status;
    uint8_t cert_buffer[800] = { 0x00 };
    uint8_t public_key[64] = { 0x00 };
    uint8_t subject_data[256] = { 0x00 };
    cal_buffer subject_data_buf = CAL_BUF_INIT(sizeof(subject_data), subject_data);
    size_t cert_sz = 0x00;
    ATCADeviceType dev_type = atca_test_get_device_type();
    if (atcab_is_ca_device(dev_type))
    {
#if ATCA_CA_SUPPORT
        // Skip test if data zone is locked
        test_assert_data_is_unlocked();

        // Skip test if config zone is locked
        test_assert_config_is_unlocked();

        #if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
            status = atcab_write_config_zone(test_ecc_configdata_full_cert_test);

        #elif defined(ATCA_ATECC608_SUPPORT)
            status = atcab_write_config_zone(test_ecc608_configdata_full_cert_test);
        #endif
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        cert_sz = sizeof(g_test_ecc256_ca_cert_ecc608);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_5_device, g_test_ecc256_ca_cert_ecc608, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = (sizeof(g_test_ecc256_ca_cert_ecc608) - 3);
        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_5_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_subject(&g_test_cert_def_5_device, cert_buffer, cert_sz, &subject_data_buf);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        status = ATCA_NO_DEVICES;
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        ta_element_attributes_t data_attr;
        uint16_t signer_cert_handle = 0x8800;
        status = talib_handle_init_data(&data_attr, sizeof(g_test_ecc256_ca_cert));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Creating data handle for storing the complete signer certificate */
        status = talib_create_element_with_handle(atcab_get_device(), signer_cert_handle, &data_attr);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = sizeof(g_test_ecc256_ca_cert);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_4_device, g_test_ecc256_ca_cert, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_4_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_subject(&g_test_cert_def_4_device, cert_buffer, cert_sz, &subject_data_buf);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_cert_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
    }

}

TEST(atcacert_client, atcacert_get_subj_pbkey)
{
    ATCA_STATUS status;
    uint8_t cert_buffer[800] = { 0x00 };
    uint8_t public_key[64] = { 0x00 };
    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();
    size_t cert_sz = 0x00;
    ATCADeviceType dev_type = atca_test_get_device_type();
    uint8_t ref_pubkey[64] = { 0x00 };

    if (atcab_is_ca_device(dev_type))
    {
#if ATCA_CA_SUPPORT
        // Skip test if data zone is locked
        test_assert_data_is_unlocked();

        // Skip test if config zone is locked
        test_assert_config_is_unlocked();

        #if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
            status = atcab_write_config_zone(test_ecc_configdata_full_cert_test);

        #elif defined(ATCA_ATECC608_SUPPORT)
            status = atcab_write_config_zone(test_ecc608_configdata_full_cert_test);
        #endif
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        uint8_t ref_pubkey_ecc[64] = {0x6B,0xD8,0xEC,0x15,0x0F,0xD5,0xB6,0x44,0xE4,0xC1,0xB4,0x41,0x23,0xA0,0xE3,0x9E,0x6E,0xFD,0x88,0x83,0x07,0xAE,0xCC,0x0B,0x81,0x54,0x51,0x2C,0x5E,0x7F,0x71,0xFB,0x8E,0xE5,0x7B,0x15,0x61,0xB1,0xB5,0x8E,0x93,0x65,0x7A,0x02,0x68,0xA4,0x1F,0x00,0xE5,0x0B,0x02,0x5D,0x12,0xD1,0x39,0x4C,0x84,0xAC,0x94,0xC7,0x51,0x51,0xD3,0x1F};
        memcpy(ref_pubkey, ref_pubkey_ecc, 64);
        cert_sz = sizeof(g_test_ecc256_ca_cert_ecc608);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_5_device, g_test_ecc256_ca_cert_ecc608, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = (sizeof(g_test_ecc256_ca_cert_ecc608)-3);
        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_5_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_subj_public_key(&g_test_cert_def_5_device, cert_buffer, cert_sz, public_key);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        status = ATCA_NO_DEVICES;
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT

        uint8_t ref_pubkey_ta[64] = { 0x62, 0xB4, 0xC4, 0xF9, 0x4E, 0xD0, 0xDB, 0x36, 0xFE, 0xEC, 0x9A, 0x4E, 0xC8, 0x2A, 0x93, 0x96, 0x47, 0x1D, 0x01, 0x0A, 0xA9, 0x37, 0x91, 0x98, 0xB4, 0xBD, 0xDB, 0x7E, 0xEB, 0xD3, 0x32, 0x65, 0x88, 0xAA, 0xA5, 0x53, 0xC1, 0x61, 0x63, 0x92, 0xC9, 0xE4, 0x2D, 0xD1, 0x88, 0x56, 0x9F, 0x9A, 0xC2, 0x54, 0x85, 0x4A, 0xAA, 0xF4, 0xEC, 0xB8, 0x12, 0xBC, 0x66, 0x5D, 0x76, 0xE2, 0x22, 0xC8 };
        memcpy(ref_pubkey, ref_pubkey_ta, 64);
        cert_sz = sizeof(g_test_ecc256_ca_cert);
        ta_element_attributes_t data_attr;
        uint16_t signer_cert_handle = 0x8800;
        status = talib_handle_init_data(&data_attr, sizeof(g_test_ecc256_ca_cert));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Creating data handle for storing the complete signer certificate */
        status = talib_create_element_with_handle(atcab_get_device(), signer_cert_handle, &data_attr);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_4_device, g_test_ecc256_ca_cert, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_4_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_subj_public_key(&g_test_cert_def_4_device, cert_buffer, cert_sz, public_key);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_cert_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
    }
    TEST_ASSERT_EQUAL(0, memcmp(ref_pubkey, public_key, sizeof(ref_pubkey)));
}

TEST(atcacert_client, atcacert_get_subj_pbkey_id)
{
    ATCA_STATUS status;
    uint8_t cert_buffer[800] = { 0x00 };
    uint8_t public_key[64] = { 0x00 };
    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();
    uint8_t key_id[20] = { 0x00 };
    uint8_t ref_key_id[20] = { 0x00 };
    uint8_t key_id_sz = sizeof(ref_key_id);
    ATCADeviceType dev_type = atca_test_get_device_type();
    size_t cert_sz = 0x00;

    if (atcab_is_ca_device(dev_type))
    {
#if ATCA_CA_SUPPORT
        // Skip test if data zone is locked
        test_assert_data_is_unlocked();

        // Skip test if config zone is locked
        test_assert_config_is_unlocked();

        #if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
            status = atcab_write_config_zone(test_ecc_configdata_full_cert_test);

        #elif defined(ATCA_ATECC608_SUPPORT)
            status = atcab_write_config_zone(test_ecc608_configdata_full_cert_test);
        #endif
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        uint8_t ref_key_id_ecc[20] = { 0x52,0xCB,0xBF,0x0D,0xA6,0xA5,0xE2,0x72,0x67,0x61,0x39,0x87,0xE5,0x24,0xAE,0xC3,0x7D,0x74,0xE2,0x3F };
        memcpy(ref_key_id, ref_key_id_ecc, sizeof(ref_key_id_ecc));
        cert_sz = sizeof(g_test_ecc256_ca_cert_ecc608);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_5_device, g_test_ecc256_ca_cert_ecc608, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = (sizeof(g_test_ecc256_ca_cert_ecc608) - 3);
        status = atcacert_read_cert(&g_test_cert_def_5_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_subj_key_id(&g_test_cert_def_5_device, cert_buffer, cert_sz, key_id);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        status = ATCA_NO_DEVICES;
#endif

    }
    else
    {
#if ATCA_TA_SUPPORT
        uint8_t ref_key_id_ta[20] = { 0x00, 0xD8, 0xDE, 0xEC, 0x59, 0x5C, 0xE6, 0x3E, 0x43, 0x44, 0x77, 0xEA, 0xDA, 0x57, 0xE4, 0xEB, 0x6C, 0x22, 0xD6, 0x15 };
        memcpy(ref_key_id, ref_key_id_ta, sizeof(ref_key_id_ta));
        cert_sz = sizeof(g_test_ecc256_ca_cert);
        ta_element_attributes_t data_attr;
        uint16_t signer_cert_handle = 0x8800;
        status = talib_handle_init_data(&data_attr, sizeof(g_test_ecc256_ca_cert));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Creating data handle for storing the complete signer certificate */
        status = talib_create_element_with_handle(atcab_get_device(), signer_cert_handle, &data_attr);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_4_device, g_test_ecc256_ca_cert, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_4_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_subj_key_id(&g_test_cert_def_4_device, cert_buffer, cert_sz, key_id);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_cert_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
    }
    TEST_ASSERT_EQUAL(0, memcmp(ref_key_id, key_id, key_id_sz));
}

TEST(atcacert_client, atcacert_get_issue_date_test)
{
    ATCA_STATUS status;
    uint8_t cert_buffer[800] = { 0x00 };
    uint8_t public_key[64] = { 0x00 };
    atcacert_tm_utc_t issue_date = {
            .tm_year = 0,
            .tm_mon = 0, //Actual month as per the test certificate (g_test_ecc256_ca_cert) is December. CAL takes 0 as Jan and Dec as 11
            .tm_mday = 0,
            .tm_hour = 0,
            .tm_min = 0,
            .tm_sec = 0
    };
    size_t cert_sz = 0x00;
    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();

    atcacert_tm_utc_t issue_date_ref = {
            .tm_year = 0,
            .tm_mon = 0, //Actual month as per the test certificate (g_test_ecc256_ca_cert) is December. CAL takes 0 as Jan and Dec as 11
            .tm_mday = 0,
            .tm_hour = 0,
            .tm_min = 0,
            .tm_sec = 0
    };

    ATCADeviceType dev_type = atca_test_get_device_type();

    if (atcab_is_ca_device(dev_type))
    {
#if ATCA_CA_SUPPORT
        // Skip test if data zone is locked
        test_assert_data_is_unlocked();

        // Skip test if config zone is locked
        test_assert_config_is_unlocked();

        #if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
            status = atcab_write_config_zone(test_ecc_configdata_full_cert_test);

        #elif defined(ATCA_ATECC608_SUPPORT)
            status = atcab_write_config_zone(test_ecc608_configdata_full_cert_test);
        #endif
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        static const atcacert_tm_utc_t issue_date_ref_ecc = {
            .tm_year = 121,
            .tm_mon = 11, //Actual month as per the test certificate (g_test_ecc256_ca_cert) is December. CAL takes 0 as Jan and Dec as 11
            .tm_mday = 30,
            .tm_hour = 15,
            .tm_min = 33,
            .tm_sec = 32
        };
        memcpy(&issue_date_ref, &issue_date_ref_ecc, sizeof(issue_date_ref_ecc));
        cert_sz = sizeof(g_test_ecc256_ca_cert_ecc608);

        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_5_device, g_test_ecc256_ca_cert_ecc608, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = (sizeof(g_test_ecc256_ca_cert_ecc608) - 3);
        status = atcacert_read_cert(&g_test_cert_def_5_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Not Before : Dec 24 18 : 26 : 04 2022 GMT
        //221224182604Z (from asn1 editor)
        status = atcacert_get_issue_date(&g_test_cert_def_5_device, cert_buffer, cert_sz, &issue_date);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        status = ATCA_NO_DEVICES;
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        static const atcacert_tm_utc_t issue_date_ref_ta = {
            .tm_year = 122,
            .tm_mon = 11, //Actual month as per the test certificate (g_test_ecc256_ca_cert) is December. CAL takes 0 as Jan and Dec as 11
            .tm_mday = 24,
            .tm_hour = 18,
            .tm_min = 26,
            .tm_sec = 04
        };
        memcpy(&issue_date_ref, &issue_date_ref_ta, sizeof(issue_date_ref_ta));
        ta_element_attributes_t data_attr;
        uint16_t signer_cert_handle = 0x8800;
        status = talib_handle_init_data(&data_attr, sizeof(g_test_ecc256_ca_cert));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = sizeof(g_test_ecc256_ca_cert);
        /* Creating data handle for storing the complete signer certificate */
        status = talib_create_element_with_handle(atcab_get_device(), signer_cert_handle, &data_attr);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_4_device, g_test_ecc256_ca_cert, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_4_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Not Before : Dec 24 18 : 26 : 04 2022 GMT
        //221224182604Z (from asn1 editor)
        status = atcacert_get_issue_date(&g_test_cert_def_4_device, cert_buffer, cert_sz, &issue_date);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_cert_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
    }
    TEST_ASSERT_EQUAL(0, memcmp(&issue_date_ref, &issue_date, sizeof(atcacert_tm_utc_t)));
}

TEST(atcacert_client, atcacert_get_expiry_date)
{
    ATCA_STATUS status;
    uint8_t cert_buffer[800] = { 0x00 };
    uint8_t public_key[64] = { 0x00 };
    atcacert_tm_utc_t expiry_date = {
        .tm_year = 0,
        .tm_mon = 0,
        .tm_mday = 0,
        .tm_hour = 0,
        .tm_min = 0,
        .tm_sec = 0,
    };

    size_t cert_sz = 0x00;

    atcacert_tm_utc_t expiry_date_ref = {
        .tm_year = 0,
        .tm_mon = 0,
        .tm_mday = 0,
        .tm_hour = 0,
        .tm_min = 0,
        .tm_sec = 0,
    };
    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();
    ATCADeviceType dev_type = atca_test_get_device_type();

    if (atcab_is_ca_device(dev_type))
    {
#if ATCA_CA_SUPPORT
        // Skip test if data zone is locked
        test_assert_data_is_unlocked();

        // Skip test if config zone is locked
        test_assert_config_is_unlocked();

        #if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
            status = atcab_write_config_zone(test_ecc_configdata_full_cert_test);

        #elif defined(ATCA_ATECC608_SUPPORT)
            status = atcab_write_config_zone(test_ecc608_configdata_full_cert_test);
        #endif
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        static const atcacert_tm_utc_t expiry_date_ref_ecc = {
            .tm_year = 131,
            .tm_mon = 11,
            .tm_mday = 28,
            .tm_hour = 15,
            .tm_min = 33,
            .tm_sec = 32,
        };
        memcpy(&expiry_date_ref, &expiry_date_ref_ecc, sizeof(expiry_date_ref_ecc));
        cert_sz = sizeof(g_test_ecc256_ca_cert_ecc608);

        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_5_device, g_test_ecc256_ca_cert_ecc608, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = (sizeof(g_test_ecc256_ca_cert_ecc608) - 3);
        status = atcacert_read_cert(&g_test_cert_def_5_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_expire_date(&g_test_cert_def_5_device, cert_buffer, cert_sz, &expiry_date);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        status = ATCA_NO_DEVICES;
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        static const atcacert_tm_utc_t expiry_date_ref_ta = {
            .tm_year = 123,
            .tm_mon = 11,
            .tm_mday = 24,
            .tm_hour = 18,
            .tm_min = 26,
            .tm_sec = 04,
        };
        memcpy(&expiry_date_ref, &expiry_date_ref_ta, sizeof(expiry_date_ref_ta));
        ta_element_attributes_t data_attr;
        uint16_t signer_cert_handle = 0x8800;
        status = talib_handle_init_data(&data_attr, sizeof(g_test_ecc256_ca_cert));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Creating data handle for storing the complete signer certificate */
        status = talib_create_element_with_handle(atcab_get_device(), signer_cert_handle, &data_attr);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = sizeof(g_test_ecc256_ca_cert);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_4_device, g_test_ecc256_ca_cert, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_4_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_expire_date(&g_test_cert_def_4_device, cert_buffer, cert_sz, &expiry_date);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_cert_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
    }

    TEST_ASSERT_EQUAL(0, memcmp(&expiry_date_ref, &expiry_date, sizeof(atcacert_tm_utc_t)));
}

TEST(atcacert_client, atcacert_get_serial_num)
{
    ATCA_STATUS status;
    uint8_t cert_buffer[800] = { 0x00 };
    uint8_t public_key[64] = { 0x00 };
    uint8_t ref_cert_sn[32] = {0x00};
    uint8_t cert_sn[32] = { 0x00 };
    size_t cert_sn_size = sizeof(cert_sn);
    size_t cert_sz = 0x00;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();

    ATCADeviceType dev_type = atca_test_get_device_type();

    if (atcab_is_ca_device(dev_type))
    {
#if ATCA_CA_SUPPORT
        // Skip test if data zone is locked
        test_assert_data_is_unlocked();

        // Skip test if config zone is locked
        test_assert_config_is_unlocked();

        #if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
            status = atcab_write_config_zone(test_ecc_configdata_full_cert_test);

        #elif defined(ATCA_ATECC608_SUPPORT)
            status = atcab_write_config_zone(test_ecc608_configdata_full_cert_test);
        #endif
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        uint8_t ref_cert_sn_ecc[32] = {0x51 , 0xd7 , 0x42 , 0x1c , 0xdd , 0xd2 , 0xed , 0xed , 0xd0 , 0x3d , 0x59 , 0xa4 , 0x15 , 0xec , 0xf0 , 0xd1 , 0xcc , 0xaa , 0xce , 0xcb};
        cert_sz = sizeof(g_test_ecc256_ca_cert_ecc608);

        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_5_device, g_test_ecc256_ca_cert_ecc608, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = (sizeof(g_test_ecc256_ca_cert_ecc608) - 3);

        status = atcacert_read_cert(&g_test_cert_def_5_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        memcpy(ref_cert_sn, ref_cert_sn_ecc, sizeof(ref_cert_sn_ecc));
        status = atcacert_get_cert_sn(&g_test_cert_def_5_device, cert_buffer, cert_sz, cert_sn, &cert_sn_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        status = ATCA_NO_DEVICES;
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        uint8_t ref_cert_sn_ta[32] = { 0x01 };
        memcpy(ref_cert_sn, ref_cert_sn_ta, sizeof(ref_cert_sn_ta));
        cert_sz = sizeof(g_test_ecc256_ca_cert);
        ta_element_attributes_t data_attr;
        uint16_t signer_cert_handle = 0x8800;
        status = talib_handle_init_data(&data_attr, sizeof(g_test_ecc256_ca_cert));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Creating data handle for storing the complete signer certificate */
        status = talib_create_element_with_handle(atcab_get_device(), signer_cert_handle, &data_attr);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_4_device, g_test_ecc256_ca_cert, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_4_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_cert_sn(&g_test_cert_def_4_device, cert_buffer, cert_sz, cert_sn, &cert_sn_size);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_cert_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
    }
    TEST_ASSERT_EQUAL(0, memcmp(ref_cert_sn, cert_sn, cert_sn_size));
}

TEST(atcacert_client, atcacert_get_auth_key_id_test)
{
    ATCA_STATUS status;
    uint8_t cert_buffer[800] = { 0x00 };
    size_t cert_sz = 0x00;
    uint8_t ref_auth_key_id[20] = {0x00};
    uint8_t auth_key_id[20] = { 0x00 };
    uint8_t public_key[64] = { 0x00 };

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();

    ATCADeviceType dev_type = atca_test_get_device_type();

    if (atcab_is_ca_device(dev_type))
    {
#if ATCA_CA_SUPPORT
        // Skip test if data zone is locked
        test_assert_data_is_unlocked();

        // Skip test if config zone is locked
        test_assert_config_is_unlocked();

        #if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
            status = atcab_write_config_zone(test_ecc_configdata_full_cert_test);

        #elif defined(ATCA_ATECC608_SUPPORT)
            status = atcab_write_config_zone(test_ecc608_configdata_full_cert_test);
        #endif
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        uint8_t ref_authkey_id_ecc[20] = { 0x99,0x9C,0xA4,0x4C,0xC7,0x23,0x40,0xD9,0xA9,0xC6,0x85,0xAF,0x76,0x76,0x04,0x34,0x13,0x81,0x72,0xB8 };
        memcpy(ref_auth_key_id, ref_authkey_id_ecc, sizeof(ref_authkey_id_ecc));
        cert_sz = sizeof(g_test_ecc256_ca_cert_ecc608);

        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_5_device, g_test_ecc256_ca_cert_ecc608, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = (sizeof(g_test_ecc256_ca_cert_ecc608) - 3);

        status = atcacert_read_cert(&g_test_cert_def_5_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_auth_key_id(&g_test_cert_def_5_device, cert_buffer, cert_sz, auth_key_id);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        status = ATCA_NO_DEVICES;
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        uint8_t ref_auth_key_id_ta[20] = { 0xA8,0xC1,0x09,0x1C,0x2C,0x82,0xF6,0xE7,0x36,0xB9,0x40,0x2D,0xAB,0x7B,0x27,0xC8,0x08,0x5D,0x18,0xBF };
        memcpy(ref_auth_key_id, ref_auth_key_id_ta, sizeof(ref_auth_key_id_ta));
        cert_sz = sizeof(g_test_ecc256_ca_cert);
        ta_element_attributes_t data_attr;
        uint16_t signer_cert_handle = 0x8800;
        status = talib_handle_init_data(&data_attr, sizeof(g_test_ecc256_ca_cert));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Creating data handle for storing the complete signer certificate */
        status = talib_create_element_with_handle(atcab_get_device(), signer_cert_handle, &data_attr);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_4_device, g_test_ecc256_ca_cert, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_4_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_auth_key_id(&g_test_cert_def_4_device, cert_buffer, cert_sz, auth_key_id);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_cert_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
    }
    TEST_ASSERT_EQUAL(0, memcmp(ref_auth_key_id, auth_key_id, sizeof(ref_auth_key_id)));
}


TEST(atcacert_client, atcacert_get_issuer_test)
{
    ATCA_STATUS status;
    uint8_t cert_buffer[800] = { 0x00 };
    uint8_t public_key[64] = { 0x00 };
    uint8_t issuer_data[256] = { 0x00 };
    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();
    size_t cert_sz = 0x00;
    ATCADeviceType dev_type = atca_test_get_device_type();

    if (atcab_is_ca_device(dev_type))
    {
#if ATCA_CA_SUPPORT
        // Skip test if data zone is locked
        test_assert_data_is_unlocked();

        // Skip test if config zone is locked
        test_assert_config_is_unlocked();

        #if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
            status = atcab_write_config_zone(test_ecc_configdata_full_cert_test);

        #elif defined(ATCA_ATECC608_SUPPORT)
            status = atcab_write_config_zone(test_ecc608_configdata_full_cert_test);
        #endif
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        cert_sz = sizeof(g_test_ecc256_ca_cert_ecc608);

        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_5_device, g_test_ecc256_ca_cert_ecc608, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        cert_sz = (sizeof(g_test_ecc256_ca_cert_ecc608) - 3);

        status = atcacert_read_cert(&g_test_cert_def_5_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_issuer(&g_test_cert_def_5_device, cert_buffer, cert_sz, issuer_data);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#else
        status = ATCA_NO_DEVICES;
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        cert_sz = sizeof(g_test_ecc256_ca_cert);
        ta_element_attributes_t data_attr;
        uint16_t signer_cert_handle = 0x8800;
        status = talib_handle_init_data(&data_attr, sizeof(g_test_ecc256_ca_cert));
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        /* Creating data handle for storing the complete signer certificate */
        status = talib_create_element_with_handle(atcab_get_device(), signer_cert_handle, &data_attr);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = (ATCA_STATUS)atcacert_write_cert(&g_test_cert_def_4_device, g_test_ecc256_ca_cert, cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Read cert to check the asn1 parse der api works fine
        status = atcacert_read_cert(&g_test_cert_def_4_device, public_key, cert_buffer, &cert_sz);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = atcacert_get_issuer(&g_test_cert_def_4_device, cert_buffer, cert_sz, issuer_data);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        status = talib_delete_handle(atcab_get_device(), (uint32_t)signer_cert_handle);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#endif
    }
}

/** \brief Execute write and read command to create handle for large certificate element on shared data memory of odd size
 */
#if ATCA_TA_SUPPORT

TEST(atcacert_client, atcacert_write_rsa_signed_cert)
{
    ATCA_STATUS status;
    ta_element_attributes_t attr_crt_handle_attr;

    // Skip test if data zone isn't locked
    test_assert_data_is_locked();

    // Skip test if config zone isn't locked
    test_assert_config_is_locked();

    uint16_t cert_handle;
    status = atca_test_config_get_id(TEST_TYPE_RSA3072_CERT, &cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    uint16_t cert_size = (sizeof(g_test_cert_rsa3072)+1u);

    uint8_t cert_rd[1431] = {0x00};
    size_t cert_rd_sz = 0x00;

//Flag to select which api to use for writing the certificate in the atcacert_write_rsa_signed_cert test
#if TALIB_API_WRITE_RSACERT == FEATURE_ENABLED
    cal_buffer cert_data_buf = CAL_BUF_INIT(sizeof(g_test_cert_rsa3072), g_test_cert_rsa3072);
    status = talib_write_X509_cert(atcab_get_device(), cert_handle, &cert_data_buf);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    cal_buffer cert_rddata_buf = CAL_BUF_INIT(cert_rd_sz, NULL);
    //Read cert get the length of the certificate stored; pass null output buffer
    status = talib_read_X509_cert(atcab_get_device(), cert_handle, &cert_rddata_buf);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status); 
    TEST_ASSERT_EQUAL(cert_rddata_buf.len, g_test_cert_def_10_device.cert_template_size);
    //Read full certificate stored
    cert_rddata_buf.buf = cert_rd;
    status = talib_read_X509_cert(atcab_get_device(), cert_handle, &cert_rddata_buf);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status); 

#else
    status = atcacert_write_cert(&g_test_cert_def_10_device, g_test_cert_rsa3072, g_test_cert_def_10_device.cert_template_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    //Read cert get the length of the certificate stored; pass null output buffer
    status = atcacert_read_cert(&g_test_cert_def_10_device, NULL, NULL, &cert_rd_sz);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status); 
    TEST_ASSERT_EQUAL(cert_rd_sz, g_test_cert_def_10_device.cert_template_size);
    //Read cert to check the asn1 parse der api works fine
    status = atcacert_read_cert(&g_test_cert_def_10_device, NULL, cert_rd, &cert_rd_sz);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(cert_rd_sz, g_test_cert_def_10_device.cert_template_size);    
#endif
    TEST_ASSERT_EQUAL_MEMORY(&g_test_cert_rsa3072, cert_rd, g_test_cert_def_10_device.cert_template_size);
    status = talib_delete_handle(atcab_get_device(), (uint32_t)cert_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}
#endif

#endif

#if ATCA_CA2_CERT_SUPPORT
TEST_GROUP(atcacert_client_ca2);

TEST_SETUP(atcacert_client_ca2)
{
    int ret = 0;
    bool lockstate = 0;
    bool is_ca2_device = false;

    ret = atcab_init(gCfg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    is_ca2_device = atcab_is_ca2_device(atcab_get_device_type());
    if(false == is_ca2_device)
    {
        TEST_IGNORE_MESSAGE("This Test group can be run on Ecc204/ta010 devices only");
    }

    ret = atcab_is_config_locked(&lockstate);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    if (!lockstate)
    {
        TEST_IGNORE_MESSAGE("Config zone must be locked for this test.");
    }
}

TEST_TEAR_DOWN(atcacert_client_ca2)
{
    ATCA_STATUS status;

    status = atcab_release();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

//! #warning "For demonstration purposes, we're storing the Root private key and Signer private key inside a protected part of the device.
//!           However, for production setup, these secure keys should not be kept in the device,
//!           and the process to create a verification certificate should be performed off-chip."
TEST(atcacert_client_ca2, init)
{
    int ret = 0;
    static const uint8_t signer_ca_private_key_slot = 0;
    static const uint8_t signer_private_key_slot = 0;
    uint8_t signer_id[2] = { 0xC4, 0x8B };
    const atcacert_tm_utc_t signer_issue_date = {
        .tm_year    = 2014 - 1900,
        .tm_mon     = 8 - 1,
        .tm_mday    = 2,
        .tm_hour    = 20,
        .tm_min     = 0,
        .tm_sec     = 0
    };
    static const uint8_t device_private_key_slot = 0;
    const atcacert_tm_utc_t device_issue_date = {
        .tm_year    = 2015 - 1900,
        .tm_mon     = 9 - 1,
        .tm_mday    = 3,
        .tm_hour    = 21,
        .tm_min     = 0,
        .tm_sec     = 0
    };
    uint8_t config[16];
    char disp_str[1500];
    size_t disp_size = sizeof(disp_str);

    ret = atcab_read_zone(ATCA_ZONE_CONFIG, 0, 0, 0, config, 16);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    //! Generate Device private key and Device public key
    ret = atca_test_genkey(device_private_key_slot, g_device_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_device_public_key, ATCA_ECCP256_PUBKEY_SIZE, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Device Public Key:\r\n%s\r\n", disp_str);

    ret = atcab_write_bytes_zone(ATCA_ZONE_DATA, 1, 8, g_device_public_key, ATCA_ECCP256_PUBKEY_SIZE);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    //! Generate Signer private key and Signer public key
    ret = atca_test_genkey(signer_private_key_slot, g_signer_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_signer_public_key, ATCA_ECCP256_PUBKEY_SIZE, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Signer Public Key:\r\n%s\r\n", disp_str);

    ret = atcab_write_bytes_zone(ATCA_ZONE_DATA, 1, 6, g_signer_public_key, ATCA_ECCP256_PUBKEY_SIZE);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    g_device_cert_ref_size = sizeof(g_device_cert_ref);
    build_and_save_cert(
        &g_test_cert_def_9_device,
        g_device_cert_ref,
        &g_device_cert_ref_size,
        g_signer_public_key,
        g_device_public_key,
        signer_id,
        &device_issue_date,
        config,
        signer_private_key_slot);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_device_cert_ref, g_device_cert_ref_size, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Device Certificate:\r\n%s\r\n", disp_str);

    //! Generate Signer CA Private key and Signer CA public key
    ret = atca_test_genkey(signer_ca_private_key_slot, g_signer_ca_public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_signer_ca_public_key, ATCA_ECCP256_PUBKEY_SIZE, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Signer CA Public Key:\r\n%s\r\n", disp_str);

    // Build signer cert
    g_signer_cert_ref_size = sizeof(g_signer_cert_ref);
    build_and_save_cert(
        &g_test_cert_def_8_signer,
        g_signer_cert_ref,
        &g_signer_cert_ref_size,
        g_signer_ca_public_key,
        g_signer_public_key,
        signer_id,
        &signer_issue_date,
        config,
        signer_ca_private_key_slot);
    disp_size = sizeof(disp_str);
    ret = atcab_bin2hex(g_signer_cert_ref, g_signer_cert_ref_size, disp_str, &disp_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    printf("Signer Certificate:\r\n%s\r\n", disp_str);
    printf("\n");
}

TEST(atcacert_client_ca2, atcacert_read_device_loc_pub_key)
{
    int ret;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t data[sizeof(public_key)];

    atcacert_device_loc_t device_loc = { DEVZONE_DATA, 1, FALSE, 256, 64 };

    ret = atcacert_read_device_loc(&device_loc, data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(&g_device_public_key[0], data, device_loc.count);
}

TEST(atcacert_client_ca2, atcacert_read_device_loc_pub_key_partial)
{
    int ret;
    uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE];
    uint8_t data[sizeof(public_key)];
    atcacert_device_loc_t device_loc = { DEVZONE_DATA, 1, FALSE, 261, 55 };

    ret = atcacert_read_device_loc(&device_loc, data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(&g_device_public_key[5], data, device_loc.count);
}

TEST(atcacert_client_ca2, atcacert_read_device_loc_data_partial)
{
    int ret;
    uint8_t data_full[72];
    uint8_t data[sizeof(data_full)];
    atcacert_device_loc_t device_loc = { DEVZONE_DATA, 1, FALSE, 5, 55 };

    ret = atcab_read_bytes_zone(device_loc.zone, device_loc.slot, 0, data_full, 72);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);

    ret = atcacert_read_device_loc(&device_loc, data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(&data_full[device_loc.offset], data, device_loc.count);
}

TEST(atcacert_client_ca2, atcacert_read_cert_signer)
{
    int ret = 0;
    uint8_t cert[512];
    size_t cert_size = sizeof(cert);

    ret = atcacert_read_cert(&g_test_cert_def_8_signer, g_signer_ca_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL(g_signer_cert_ref_size, cert_size);
    TEST_ASSERT_EQUAL_MEMORY(g_signer_cert_ref, cert, cert_size);
}

TEST(atcacert_client_ca2, atcacert_read_cert_device)
{
    int ret = 0;
    uint8_t cert[512];
    size_t cert_size = sizeof(cert);

    ret = atcacert_read_cert(&g_test_cert_def_9_device, g_signer_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL(g_device_cert_ref_size, cert_size);
    TEST_ASSERT_EQUAL_MEMORY(g_device_cert_ref, cert, cert_size);
}

TEST(atcacert_client_ca2, atcacert_read_subj_key_id)
{
    int ret = 0;
    uint8_t cert[512];
    size_t cert_size = sizeof(cert);
    uint8_t key_id_ref[20];
    uint8_t key_id[20];

    ret = atcacert_read_cert(&g_test_cert_def_8_signer, g_signer_ca_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL(g_signer_cert_ref_size, cert_size);
    TEST_ASSERT_EQUAL_MEMORY(g_signer_cert_ref, cert, cert_size);

    ret = atcacert_get_subj_key_id(&g_test_cert_def_8_signer, cert, cert_size, key_id_ref);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    ret = atcacert_read_subj_key_id(&g_test_cert_def_8_signer, key_id);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL_MEMORY(key_id_ref, key_id, sizeof(key_id));
}

TEST(atcacert_client_ca2, atcacert_read_cert_small_buf)
{
    int ret = 0;
    uint8_t cert[512];
    size_t cert_size = sizeof(cert);

    // Getting the actual buffer size needed for the certificate
    ret = atcacert_read_cert(&g_test_cert_def_9_device, g_signer_public_key, NULL, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);

    // Read the device certificate
    ret = atcacert_read_cert(&g_test_cert_def_9_device, g_signer_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_SUCCESS, ret);
    TEST_ASSERT_EQUAL(g_device_cert_ref_size, cert_size);
    TEST_ASSERT_EQUAL_MEMORY(g_device_cert_ref, cert, cert_size);

    // Decrease the size of the buffer needed for device certificate
    cert_size -= 1;
    ret = atcacert_read_cert(&g_test_cert_def_9_device, g_signer_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BUFFER_TOO_SMALL, ret);
}

TEST(atcacert_client_ca2, atcacert_read_cert_bad_params)
{
    int ret = 0;
    uint8_t cert[128];
    size_t cert_size = sizeof(cert);

    ret = atcacert_read_cert(NULL, g_signer_public_key, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, NULL, cert, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, g_signer_public_key, NULL, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, NULL, NULL, &cert_size);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(&g_test_cert_def_9_device, g_signer_public_key, cert, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, g_signer_public_key, cert, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(&g_test_cert_def_9_device, NULL, cert, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, NULL, cert, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(&g_test_cert_def_9_device, g_signer_public_key, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, g_signer_public_key, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(&g_test_cert_def_9_device, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_read_cert(NULL, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
}

TEST(atcacert_client_ca2, atcacert_get_response_bad_params)
{
    int ret = 0;
    uint8_t response[64];
    const uint8_t challenge[32] = {
        0x0c, 0xa6, 0x34, 0xc8, 0x37, 0x2f, 0x87, 0x99, 0x99, 0x7e, 0x9e, 0xe9, 0xd5, 0xbc, 0x72, 0x71,
        0x84, 0xd1, 0x97, 0x0a, 0xea, 0xfe, 0xac, 0x60, 0x7e, 0xd1, 0x3e, 0x12, 0xb7, 0x32, 0x25, 0xf1
    };

    ret = atcacert_get_response(16, challenge, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(0, NULL, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(16, NULL, response);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(0, challenge, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(16, challenge, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(0, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);

    ret = atcacert_get_response(16, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCACERT_E_BAD_PARAMS, ret);
}
#endif
#endif
