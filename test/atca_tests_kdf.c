/**
 * \file
 * \brief Unity tests for the cryptoauthlib KDF Command
 *
 * \copyright (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
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
#include "basic/atca_basic.h"
#include "host/atca_host.h"
#include "test/atca_tests.h"
#include "atca_execution.h"

#define AES_CONFIG_ENABLE_BIT_MASK   (uint8_t)0x01

TEST(atca_cmd_unit_test, kdf)
{

    ATCA_STATUS status = ATCA_GEN_FAIL;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    uint8_t data_input_32[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    unit_test_assert_data_is_locked();

    // build read command
    packet.param1 = ATCA_ZONE_CONFIG;
    packet.param2 = 0x0003;

    status = atRead(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    if ((packet.data[2] & AES_CONFIG_ENABLE_BIT_MASK) == 0)  //packet.data[2] contains the AES enable bit
    {
        TEST_IGNORE_MESSAGE("Ignoring the test, AES is not enabled in Configuration zone");
    }

    //32 bytes key in Alternate key buffer ,32 bytes data in and 32 byte data out in tempkey
    packet.param1 = NONCE_MODE_PASSTHROUGH | NONCE_MODE_TARGET_ALTKEYBUF;
    packet.param2 = 0x0000;
    memcpy(packet.data, nonce, 32);    // a 32-byte nonce

    status = atNonce(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(NONCE_COUNT_LONG, packet.txsize);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(NONCE_RSP_SIZE_SHORT, packet.data[ATCA_COUNT_IDX]);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, packet.data[1]);

    packet.param1 = KDF_MODE_ALG_AES | KDF_MODE_SOURCE_ALTKEYBUF | KDF_MODE_TARGET_TEMPKEY;
    packet.param2 = 0x0000;
    memset(packet.data, 0x00, 4);                  // a 4 byte details related to AES
    memcpy(&packet.data[4], data_input_32, 32);    // a 32 byte input data to AES KDF
    packet.txsize = ATCA_CMD_SIZE_MIN + KDF_DETAILS_SIZE + AES_DATA_SIZE;
    status = atKDF(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}


TEST(atca_cmd_basic_test, kdf_prf_output)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t out_kdf_prf[64];
    uint8_t data_input_16[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t data_input_32[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t expected_kdf_prf[] = { 0x1E, 0xBC, 0xBE, 0x62, 0x00, 0x5A, 0xB9, 0x48, 0xFD, 0xFF, 0xE1, 0xC4, 0x02, 0xAA, 0xBA, 0x35, 0x4E, 0xC6, 0x76, 0x05, 0x0C, 0x9B, 0xC1, 0xAA, 0xE1, 0xFF, 0x5B, 0x15, 0x09, 0xA4, 0xA0, 0x4A,
                                   0x44, 0x25, 0x46, 0x64, 0xC2, 0xA4, 0x80, 0xF5, 0xB7, 0x7E, 0xA2, 0xD1, 0x02, 0x0C, 0x7B, 0xA4, 0xB3, 0x64, 0x0C, 0x4A, 0xC7, 0x93, 0x32, 0x4C, 0x26, 0xD6, 0xFD, 0xDF, 0xDB, 0x1F, 0x01, 0x1A };

    test_assert_data_is_locked();


    // 32 bytes key in tempkey, 16 bytes data in, and 64 byte data out in output buffer

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_PRF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT,
        0x1234,
        KDF_DETAILS_PRF_KEY_LEN_32 | KDF_DETAILS_PRF_TARGET_LEN_64 | KDF_DETAILS_PRF_AEAD_MODE0 | ((uint32_t)sizeof(data_input_16) << 24),
        data_input_16,
        out_kdf_prf,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(expected_kdf_prf, out_kdf_prf, 64);


    // 32 bytes key in Alternate key buffer, 32 bytes message, and 32 byte data out in tempkey

    status = atcab_nonce_load(NONCE_MODE_TARGET_ALTKEYBUF, nonce, sizeof(nonce));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_PRF | KDF_MODE_SOURCE_ALTKEYBUF | KDF_MODE_TARGET_TEMPKEY,
        0x1234,
        KDF_DETAILS_PRF_KEY_LEN_32 | KDF_DETAILS_PRF_TARGET_LEN_32 | KDF_DETAILS_PRF_AEAD_MODE0 | ((uint32_t)sizeof(data_input_32) << 24),
        data_input_32,
        NULL,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //32 bytes key in tempkey ,32 bytes data in and 32 byte data out in key slot

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_PRF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_SLOT,
        0x0500,
        KDF_DETAILS_PRF_KEY_LEN_32 | KDF_DETAILS_PRF_TARGET_LEN_32 | KDF_DETAILS_PRF_AEAD_MODE0 | ((uint32_t)sizeof(data_input_32) << 24),
        data_input_32,
        NULL,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_basic_test, kdf_prf_output_encrypted)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t out_nonce[32];
    uint8_t out_kdf_prf[64];
    uint8_t out_kdf_prf_encrypted[64];
    atca_io_decrypt_in_out_t io_dec_params;


    uint8_t data_input_16[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    test_assert_data_is_locked();

    //32 bytes data in tempkey, 16 bytes data, and 64 byte data out in output buffer

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_PRF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT,
        0x1234,
        KDF_DETAILS_PRF_KEY_LEN_32 | KDF_DETAILS_PRF_TARGET_LEN_64 | KDF_DETAILS_PRF_AEAD_MODE0 | ((uint32_t)sizeof(data_input_16) << 24),
        data_input_16,
        out_kdf_prf,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    // 32 bytes data in tempkey, 16 bytes data in, 64 byte encrypted data out in output buffer and 32 bytes nonce.

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_PRF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT_ENC,
        0x1234,
        KDF_DETAILS_PRF_KEY_LEN_32 | KDF_DETAILS_PRF_TARGET_LEN_64 | KDF_DETAILS_PRF_AEAD_MODE0 | ((uint32_t)sizeof(data_input_16) << 24),
        data_input_16,
        out_kdf_prf_encrypted,
        out_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = g_slot4_key;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_prf_encrypted;
    io_dec_params.data_size = 64;
    status = atcah_io_decrypt(&io_dec_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(out_kdf_prf, out_kdf_prf_encrypted, 64);        //Comparing the Clear KDF key with decrypted KDF key
}


TEST(atca_cmd_basic_test, kdf_aes_output)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t out_kdf_aes[32];

    uint8_t data_input_16[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };


    uint8_t expected_kdf_aes[] = { 0x0A, 0x94, 0x0B, 0xB5, 0x41, 0x6E, 0xF0, 0x45, 0xF1, 0xC3, 0x94, 0x58, 0xC6, 0x53, 0xEA, 0x5A,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


    //32 bytes data in tempkey ,16 bytes data and 32 byte data out in output buffer

    test_assert_data_is_locked();
    check_config_aes_enable();      //Checking the AES enable bit in configuration zone,if not set it skips the test

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_AES | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT,
        0x1234,
        0,
        data_input_16,
        out_kdf_aes,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(expected_kdf_aes, out_kdf_aes, 32);


    //32 bytes key in Alternate key buffer ,16 bytes data in and 32 byte data out in tempkey

    status = atcab_nonce_load(NONCE_MODE_TARGET_ALTKEYBUF, nonce, sizeof(nonce));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_AES | KDF_MODE_SOURCE_ALTKEYBUF | KDF_MODE_TARGET_TEMPKEY,
        0x1234,
        0,
        data_input_16,
        NULL,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //32 bytes key in tempkey ,16 bytes data in and 32 byte data out in key slot

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_AES | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_SLOT,
        0x0500,
        0,
        data_input_16,
        NULL,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}



TEST(atca_cmd_basic_test, kdf_aes_output_encrypted)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t out_nonce[32];
    uint8_t out_kdf_aes[32];
    uint8_t out_kdf_aes_encrypted[32];
    atca_io_decrypt_in_out_t io_dec_params;


    uint8_t data_input_16[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };





    if (gCfg->devtype != ATECC608A)
    {
        TEST_IGNORE();
    }

    test_assert_data_is_locked();
    check_config_aes_enable();      //Checking the AES enable bit in configuration zone,if not set it skips the test

    //32 bytes data in tempkey ,16 bytes data and 32 byte data out in output buffer

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_AES | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT,
        0x1234,
        0,
        data_input_16,
        out_kdf_aes,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //32 bytes data in tempkey ,16 bytes data in,32 byte encrypted data out in output buffer and 32 bytes nonce.

    status = atcab_kdf(
        KDF_MODE_ALG_AES | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT_ENC,
        0x1234,
        0,
        data_input_16,
        out_kdf_aes_encrypted,
        out_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = g_slot4_key;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_aes_encrypted;
    io_dec_params.data_size = 32;
    status = atcah_io_decrypt(&io_dec_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(out_kdf_aes, out_kdf_aes_encrypted, 32);  //Comparing the Clear KDF key with decrypted KDF key
}



TEST(atca_cmd_basic_test, kdf_hkdf_output)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t out_kdf_hkdf[32];
    uint8_t data_input_16[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t data_input_32[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t data_input_iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x69, 0x76, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    test_assert_data_is_locked();

    //32 bytes key in tempkey  ,16 bytes data in and 32 byte data out in output buffer

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_HKDF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT,
        0x0000,
        KDF_DETAILS_HKDF_MSG_LOC_INPUT | ((uint32_t)sizeof(data_input_16) << 24),
        data_input_16,
        out_kdf_hkdf,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //32 bytes key in Alternate key buffer  ,32 bytes data in and 32 byte data out in tempkey

    status = atcab_nonce_load(NONCE_MODE_TARGET_ALTKEYBUF, nonce, sizeof(nonce));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_HKDF | KDF_MODE_SOURCE_ALTKEYBUF | KDF_MODE_TARGET_TEMPKEY,
        0x0000,
        KDF_DETAILS_HKDF_MSG_LOC_INPUT | ((uint32_t)sizeof(data_input_32) << 24),
        data_input_32,
        NULL,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //32 bytes key in tempkey ,32 bytes data in and 32 byte data out in key slot

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_HKDF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_SLOT,
        0x0500,
        KDF_DETAILS_HKDF_MSG_LOC_INPUT | ((uint32_t)sizeof(data_input_32) << 24),
        data_input_32,
        NULL,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //32 bytes key in tempkey ,32 bytes data in and 32 byte data out in key slot mode (Special KDF Initialization Vector function)

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_HKDF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_SLOT,
        0x0500,
        KDF_DETAILS_HKDF_MSG_LOC_IV | ((uint32_t)sizeof(data_input_iv) << 24),
        data_input_iv,
        NULL,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}


TEST(atca_cmd_basic_test, kdf_hkdf_output_encrypted)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t out_nonce[32];
    uint8_t out_kdf_hkdf[32];
    uint8_t out_kdf_hkdf_encrypted[32];
    atca_io_decrypt_in_out_t io_dec_params;


    uint8_t data_input_16[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    test_assert_data_is_locked();


    //32 bytes data in tempkey ,16 bytes data and 32 byte data out in output buffer

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_HKDF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT,
        0x1234,
        KDF_DETAILS_HKDF_MSG_LOC_INPUT | ((uint32_t)sizeof(data_input_16) << 24),
        data_input_16,
        out_kdf_hkdf,
        NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //32 bytes data in tempkey ,16 bytes data in,32 byte encrypted data out in output buffer and 32 bytes nonce.

    status = atcab_nonce(nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_kdf(
        KDF_MODE_ALG_HKDF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT_ENC,
        0x1234,
        KDF_DETAILS_HKDF_MSG_LOC_INPUT | ((uint32_t)sizeof(data_input_16) << 24),
        data_input_16,
        out_kdf_hkdf_encrypted,
        out_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Decrypt the KDF result
    memset(&io_dec_params, 0, sizeof(io_dec_params));
    io_dec_params.io_key = g_slot4_key;
    io_dec_params.out_nonce = out_nonce;
    io_dec_params.data = out_kdf_hkdf_encrypted;
    io_dec_params.data_size = 32;
    status = atcah_io_decrypt(&io_dec_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(out_kdf_hkdf, out_kdf_hkdf_encrypted, 32);  //Comparing the Clear KDF key with decrypted KDF key
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info kdf_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_prf_output),            DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_prf_output_encrypted),  DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_aes_output),            DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_aes_output_encrypted),  DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_hkdf_output),           DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, kdf_hkdf_output_encrypted), DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },               /* Array Termination element*/
};

t_test_case_info kdf_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, kdf), DEVICE_MASK(ATECC608A), },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

