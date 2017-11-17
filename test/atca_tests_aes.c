/**
 * \file
 * \brief Unity tests for the cryptoauthlib Basic API
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */
#include <stdlib.h>
#include "atca_test.h"
#include "basic/atca_basic.h"
#include "host/atca_host.h"
#include "test/atca_tests.h"

TEST(atca_cmd_unit_test, aes)
{

    ATCA_STATUS status;
    ATCAPacket packet;
    uint8_t encrypted_data_out[16];
    uint8_t decrypted_data_out[16];


    const uint8_t tempkey[32] = {
        0xC5, 0xA6, 0x62, 0x71, 0xD5, 0x44, 0x6D, 0xF9, 0X6F, 0x7D, 0x9A, 0x4A, 0xD1, 0x73, 0xB4, 0xAE,
        0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63
    };
    uint8_t expected_encrypt_data_out[] = {
        0x86, 0xB0, 0xF5, 0x3C, 0x87, 0x37, 0x6C, 0x7B, 0X84, 0x7D, 0x05, 0x70, 0x0C, 0x30, 0xCA, 0xD3
    };

    uint8_t data_input_encrypt[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    uint8_t data_input_decrypt[] = {
        0x86, 0xB0, 0xF5, 0x3C, 0x87, 0x37, 0x6C, 0x7B, 0X84, 0x7D, 0x05, 0x70, 0x0C, 0x30, 0xCA, 0xD3
    };


    uint8_t expected_decrypt_data_out[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // build read command
    packet.param1 = ATCA_ZONE_CONFIG;
    packet.param2 = 0x0003;

    status = atRead(gCommandObj, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = send_command(gCommandObj, gIface, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    if ((packet.data[2] & AES_CONFIG_ENABLE_BIT_MASK) == 0) //packet.data[2] contains the AES enable bit
    {
        TEST_IGNORE_MESSAGE("Ignoring the test ,AES is not enabled in Configuration zone");
    }


    //build a nonce command (pass through mode) to store the aes key in tempkey
    packet.param1 = NONCE_MODE_PASSTHROUGH;
    packet.param2 = 0x0000;
    memcpy(packet.data, tempkey, ATCA_KEY_SIZE);    // a 32-byte nonce

    status = atNonce(gCommandObj, &packet);
    TEST_ASSERT_EQUAL_INT(NONCE_COUNT_LONG, packet.txsize);
    TEST_ASSERT_EQUAL_INT(NONCE_RSP_SIZE_SHORT, packet.rxsize);
    status = send_command(gCommandObj, gIface, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // check for nonce response for pass through mode
    TEST_ASSERT_EQUAL_INT8(ATCA_SUCCESS, packet.data[1]);


    packet.param1 = AES_MODE_ENCRYPT;                       //selects encrypt mode and use first 16 byte data in tempkey as key
    packet.param2 = 0xFFFF;
    memcpy(packet.data, data_input_encrypt, AES_DATA_SIZE); // a 16-byte data to be encrypted

    status = atAES(gCommandObj, &packet);
    status = send_command(gCommandObj, gIface, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    memcpy(encrypted_data_out, &(packet.data[1]), AES_DATA_SIZE);    // a 16-byte encrypted data

    TEST_ASSERT_EQUAL_MEMORY(expected_encrypt_data_out, encrypted_data_out, AES_DATA_SIZE);



    packet.param1 = AES_MODE_DECRYPT;                       //selects decrypt mode and use first 16 byte data in tempkey as key
    packet.param2 = 0xFFFF;
    memcpy(packet.data, data_input_decrypt, AES_DATA_SIZE); // a 16-byte data to be encrypted

    status = atAES(gCommandObj, &packet);
    status = send_command(gCommandObj, gIface, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    memcpy(decrypted_data_out, &(packet.data[1]), AES_DATA_SIZE);    // a 16-byte decrypted data

    TEST_ASSERT_EQUAL_MEMORY(decrypted_data_out, expected_decrypt_data_out, AES_DATA_SIZE);


}



TEST(atca_cmd_basic_test, aes_encrypt_key_tempkey_short)
{
    ATCA_STATUS status;
    uint8_t encrypted_data_out[16];
    const uint8_t tempkey[32] = {
        0xC5, 0xA6, 0x62, 0x71, 0xD5, 0x44, 0x6D, 0xF9, 0X6F, 0x7D, 0x9A, 0x4A, 0xD1, 0x73, 0xB4, 0xAE,
        0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63
    };
    uint8_t expected_data_out0[] = {
        0x86, 0xB0, 0xF5, 0x3C, 0x87, 0x37, 0x6C, 0x7B, 0X84, 0x7D, 0x05, 0x70, 0x0C, 0x30, 0xCA, 0xD3
    };

    uint8_t expected_data_out1[] = {
        0xE9, 0x3E, 0x13, 0x59, 0x02, 0xD6, 0xA2, 0xF5, 0X88, 0x4A, 0xF9, 0xB3, 0x8A, 0x67, 0xDB, 0xA2
    };


    uint8_t data_in[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };






    check_config_aes_enable();      //Checking the AES enable bit in configuration zone,if not set it skips the test

    status = atcab_nonce(tempkey);  //Loading AES key to tempkey
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, 0, data_in, encrypted_data_out);//Encrypting data with first 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_data_out0, encrypted_data_out, AES_DATA_SIZE);

    status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, 1, data_in, encrypted_data_out);//Encrypting data with second 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_data_out1, encrypted_data_out, AES_DATA_SIZE);

}

TEST(atca_cmd_basic_test, aes_encrypt_key_tempkey_long)
{
    ATCA_STATUS status;
    uint8_t encrypted_data_out[16];

    const uint8_t tempkey[64] = {
        0xC5, 0xA6, 0x62, 0x71, 0xD5, 0x44, 0x6D, 0xF9, 0X6F, 0x7D, 0x9A, 0x4A, 0xD1, 0x73, 0xB4, 0xAE,
        0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    uint8_t expected_data_out0[] = {
        0x86, 0xB0, 0xF5, 0x3C, 0x87, 0x37, 0x6C, 0x7B, 0X84, 0x7D, 0x05, 0x70, 0x0C, 0x30, 0xCA, 0xD3
    };

    uint8_t expected_data_out1[] = {
        0xE9, 0x3E, 0x13, 0x59, 0x02, 0xD6, 0xA2, 0xF5, 0X88, 0x4A, 0xF9, 0xB3, 0x8A, 0x67, 0xDB, 0xA2
    };

    uint8_t expected_data_out2[] = {
        0x0A, 0x94, 0x0B, 0xB5, 0x41, 0x6E, 0xF0, 0x45, 0XF1, 0xC3, 0x94, 0x58, 0xC6, 0x53, 0xEA, 0x5A
    };

    uint8_t expected_data_out3[] = {
        0x0A, 0x94, 0x0B, 0xB5, 0x41, 0x6E, 0xF0, 0x45, 0XF1, 0xC3, 0x94, 0x58, 0xC6, 0x53, 0xEA, 0x5A
    };


    uint8_t data_in[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    check_config_aes_enable();                                                                     //Checking the AES enable bit in configuration zone,if not set it skips the test

    status = atcab_nonce_base(NONCE_MODE_PASSTHROUGH | NONCE_MODE_INPUT_LEN_64, 0, tempkey, NULL); //Loading AES key to tempkey
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, 0, data_in, encrypted_data_out);//Encrypting data with first 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_data_out0, encrypted_data_out, AES_DATA_SIZE);

    status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, 1, data_in, encrypted_data_out);//Encrypting data with second 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_data_out1, encrypted_data_out, AES_DATA_SIZE);

    status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, 2, data_in, encrypted_data_out);//Encrypting data with third 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_data_out2, encrypted_data_out, AES_DATA_SIZE);

    status = atcab_aes_encrypt(ATCA_TEMPKEY_KEYID, 3, data_in, encrypted_data_out);//Encrypting data with fourth 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_data_out3, encrypted_data_out, AES_DATA_SIZE);

}


TEST(atca_cmd_basic_test, aes_decrypt_key_tempkey_short)
{
    ATCA_STATUS status;
    uint8_t decrypted_data_out[16];

    const uint8_t tempkey[32] = {
        0xC5, 0xA6, 0x62, 0x71, 0xD5, 0x44, 0x6D, 0xF9, 0X6F, 0x7D, 0x9A, 0x4A, 0xD1, 0x73, 0xB4, 0xAE,
        0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63
    };
    uint8_t data_input0[] = {
        0x86, 0xB0, 0xF5, 0x3C, 0x87, 0x37, 0x6C, 0x7B, 0X84, 0x7D, 0x05, 0x70, 0x0C, 0x30, 0xCA, 0xD3
    };

    uint8_t data_input1[] = {
        0xE9, 0x3E, 0x13, 0x59, 0x02, 0xD6, 0xA2, 0xF5, 0X88, 0x4A, 0xF9, 0xB3, 0x8A, 0x67, 0xDB, 0xA2
    };


    uint8_t expected_output[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    check_config_aes_enable();      //Checking the AES enable bit in configuration zone,if not set it skips the test

    status = atcab_nonce(tempkey);  //Loading AES key to tempkey
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_decrypt(ATCA_TEMPKEY_KEYID, 0, data_input0, decrypted_data_out);//Decrypting data with first 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_output, decrypted_data_out, AES_DATA_SIZE);

    status = atcab_aes_decrypt(ATCA_TEMPKEY_KEYID, 1, data_input1, decrypted_data_out);//Decrypting data with second 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_output, decrypted_data_out, AES_DATA_SIZE);

}


TEST(atca_cmd_basic_test, aes_decrypt_key_tempkey_long)
{
    ATCA_STATUS status;
    uint8_t decrypted_data_out[16];

    const uint8_t tempkey[64] = {
        0xC5, 0xA6, 0x62, 0x71, 0xD5, 0x44, 0x6D, 0xF9, 0X6F, 0x7D, 0x9A, 0x4A, 0xD1, 0x73, 0xB4, 0xAE,
        0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    uint8_t data_input0[] = {
        0x86, 0xB0, 0xF5, 0x3C, 0x87, 0x37, 0x6C, 0x7B, 0X84, 0x7D, 0x05, 0x70, 0x0C, 0x30, 0xCA, 0xD3
    };

    uint8_t data_input1[] = {
        0xE9, 0x3E, 0x13, 0x59, 0x02, 0xD6, 0xA2, 0xF5, 0X88, 0x4A, 0xF9, 0xB3, 0x8A, 0x67, 0xDB, 0xA2
    };

    uint8_t data_input2[] = {
        0x0A, 0x94, 0x0B, 0xB5, 0x41, 0x6E, 0xF0, 0x45, 0XF1, 0xC3, 0x94, 0x58, 0xC6, 0x53, 0xEA, 0x5A
    };

    uint8_t data_input3[] = {
        0x0A, 0x94, 0x0B, 0xB5, 0x41, 0x6E, 0xF0, 0x45, 0XF1, 0xC3, 0x94, 0x58, 0xC6, 0x53, 0xEA, 0x5A
    };


    uint8_t expected_output[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    check_config_aes_enable();                                                                     //Checking the AES enable bit in configuration zone,if not set it skips the test

    status = atcab_nonce_base(NONCE_MODE_PASSTHROUGH | NONCE_MODE_INPUT_LEN_64, 0, tempkey, NULL); //Loading AES key to tempkey
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_decrypt(ATCA_TEMPKEY_KEYID, 0, data_input0, decrypted_data_out);//Decrypting data with first 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(expected_output, decrypted_data_out, AES_DATA_SIZE);

    status = atcab_aes_decrypt(ATCA_TEMPKEY_KEYID, 1, data_input1, decrypted_data_out);//Decrypting data with second 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(expected_output, decrypted_data_out, AES_DATA_SIZE);

    status = atcab_aes_decrypt(ATCA_TEMPKEY_KEYID, 2, data_input2, decrypted_data_out);//Decrypting data with third 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(expected_output, decrypted_data_out, AES_DATA_SIZE);

    status = atcab_aes_decrypt(ATCA_TEMPKEY_KEYID, 3, data_input3, decrypted_data_out);//Decrypting data with fourth 16 bytes in tempkey as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(expected_output, decrypted_data_out, AES_DATA_SIZE);

}



TEST(atca_cmd_basic_test, aes_encrypt_key_slot)
{
    ATCA_STATUS status;
    uint8_t encrypted_data_out[16];
    uint8_t key_slot = 10;
    bool persistent_latch_state;
    const uint8_t aes_key[32] = {
        0xC5, 0xA6, 0x62, 0x71, 0xD5, 0x44, 0x6D, 0xF9, 0X6F, 0x7D, 0x9A, 0x4A, 0xD1, 0x73, 0xB4, 0xAE,
        0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63
    };
    uint8_t expected_encrypted_data0[] = {
        0x86, 0xB0, 0xF5, 0x3C, 0x87, 0x37, 0x6C, 0x7B, 0X84, 0x7D, 0x05, 0x70, 0x0C, 0x30, 0xCA, 0xD3
    };

    uint8_t expected_encrypted_data1[] = {
        0xE9, 0x3E, 0x13, 0x59, 0x02, 0xD6, 0xA2, 0xF5, 0X88, 0x4A, 0xF9, 0xB3, 0x8A, 0x67, 0xDB, 0xA2
    };


    uint8_t data_in[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    test_assert_data_is_locked();

    check_config_aes_enable();                              //Checking the AES enable bit in configuration zone,if not set it skips the test

    status = atcab_info_get_latch(&persistent_latch_state); //Get the State of the persistent latch
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (!persistent_latch_state)
    {
        TEST_IGNORE_MESSAGE("Ignoring the test, persistent latch should be set");
    }


    //Loading AES key to slot 10
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, aes_key, sizeof(aes_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_encrypt(key_slot, 0, data_in, encrypted_data_out);//Encrypting data with first 16 bytes in slot 10 as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_encrypted_data0, encrypted_data_out, 16);

    status = atcab_aes_encrypt(key_slot, 1, data_in, encrypted_data_out);//Encrypting data with second 16 bytes in slot 10 as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_encrypted_data1, encrypted_data_out, 16);

}



TEST(atca_cmd_basic_test, aes_decrypt_key_slot)
{
    ATCA_STATUS status;
    uint8_t key_slot = 10;
    uint8_t decrypted_data_out[16];
    bool persistent_latch_state;

    const uint8_t aes_key[32] = {
        0xC5, 0xA6, 0x62, 0x71, 0xD5, 0x44, 0x6D, 0xF9, 0X6F, 0x7D, 0x9A, 0x4A, 0xD1, 0x73, 0xB4, 0xAE,
        0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63
    };
    uint8_t data_input0[] = {
        0x86, 0xB0, 0xF5, 0x3C, 0x87, 0x37, 0x6C, 0x7B, 0X84, 0x7D, 0x05, 0x70, 0x0C, 0x30, 0xCA, 0xD3
    };

    uint8_t data_input1[] = {
        0xE9, 0x3E, 0x13, 0x59, 0x02, 0xD6, 0xA2, 0xF5, 0X88, 0x4A, 0xF9, 0xB3, 0x8A, 0x67, 0xDB, 0xA2
    };


    uint8_t expected_decrypted_data[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };


    test_assert_data_is_locked();

    check_config_aes_enable();                              //Checking the AES enable bit in configuration zone,if not set it skips the test

    status = atcab_info_get_latch(&persistent_latch_state); //Get the State of the persistent latch
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (!persistent_latch_state)
    {
        TEST_IGNORE_MESSAGE("Ignoring the test, persistent latch should be set");
    }

    //Loading AES key to slot 10
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, aes_key, sizeof(aes_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_decrypt(key_slot, 0, data_input0, decrypted_data_out);//Encrypting data with first 16 bytes in slot 10 as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_decrypted_data, decrypted_data_out, 16);

    status = atcab_aes_decrypt(key_slot, 1, data_input1, decrypted_data_out);//Encrypting data with second 16 bytes in slot 10 as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(expected_decrypted_data, decrypted_data_out, 16);

}

TEST(atca_cmd_basic_test, aes_gfm)
{
    ATCA_STATUS status;
    uint8_t gfm_data[16];
    const uint8_t h[] = {
        0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0X88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E
    };
    const uint8_t input[] = {
        0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 0XF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE, 0x78
    };
    const uint8_t expected_gfm_data[16] = {
        0x5E, 0x2E, 0xC7, 0x46, 0x91, 0x70, 0x62, 0x88, 0X2C, 0x85, 0xB0, 0x68, 0x53, 0x53, 0xDE, 0xB7
    };

    //Calculating GFM for the input data data_input
    status = atcab_aes_gfm(h, input, gfm_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(expected_gfm_data, gfm_data, 16);
}

TEST(atca_cmd_basic_test, volatile_key_permit)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint16_t key_id = 0x0004;
    uint8_t response[MAC_SIZE];
    uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];
    atca_temp_key_t temp_key;
    uint8_t num_in[NONCE_NUMIN_SIZE];
    uint8_t rand_out[RANDOM_NUM_SIZE];
    atca_nonce_in_out_t nonce_params;
    uint8_t sn[ATCA_SERIAL_NUM_SIZE];
    atca_check_mac_in_out_t checkmac_params;
    size_t i;
    uint8_t encrypted_data_out[16];
    uint8_t key_slot = 10;
    bool persistent_latch_state;
    const uint8_t aes_key[32] = {
        0xC5, 0xA6, 0x62, 0x71, 0xD5, 0x44, 0x6D, 0xF9, 0X6F, 0x7D, 0x9A, 0x4A, 0xD1, 0x73, 0xB4, 0xAE,
        0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63
    };

    uint8_t data_in[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0X08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    test_assert_data_is_locked();

    status = atcab_info_get_latch(&persistent_latch_state); //Get the State of the persistent latch
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (persistent_latch_state)
    {
        TEST_IGNORE_MESSAGE("Ignoring the test, persistent latch already set");
    }

    check_config_aes_enable();                   //Checking the AES enable bit in configuration zone,if not set it skips the test

    //Loading AES key to slot 10
    status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_slot, 0, aes_key, sizeof(aes_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_aes_encrypt(key_slot, 0, data_in, encrypted_data_out); //Encrypting data with first 16 bytes in slot 10 as key

    TEST_ASSERT_EQUAL(ATCA_EXECUTION_ERROR, status);                      //Encryption fails as the persistent latch is not set


    // Read SN
    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform random nonce
    memset(&temp_key, 0, sizeof(temp_key));
    memset(num_in, 0, sizeof(num_in));
    memset(&nonce_params, 0, sizeof(nonce_params));
    nonce_params.mode = NONCE_MODE_SEED_UPDATE;
    nonce_params.zero = 0;
    nonce_params.num_in = num_in;
    nonce_params.rand_out = rand_out;
    nonce_params.temp_key = &temp_key;
    status = atcab_nonce_rand(nonce_params.num_in, rand_out);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate nonce value
    status = atcah_nonce(&nonce_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Calculate response
    for (i = 0; i < sizeof(other_data); i++)
    {
        other_data[i] = (uint8_t)(i + 0xF0);
    }
    checkmac_params.mode = CHECKMAC_MODE_BLOCK2_TEMPKEY;
    checkmac_params.key_id = key_id;
    checkmac_params.client_chal = NULL;
    checkmac_params.client_resp = response;
    checkmac_params.other_data = other_data;
    checkmac_params.sn = sn;
    checkmac_params.otp = NULL;
    checkmac_params.slot_key = g_slot4_key;
    checkmac_params.target_key = NULL;
    checkmac_params.temp_key = &temp_key;
    status = atcah_check_mac(&checkmac_params);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Perform CheckMac
    status = atcab_checkmac(
        checkmac_params.mode,
        checkmac_params.key_id,
        checkmac_params.client_chal,
        checkmac_params.client_resp,
        checkmac_params.other_data);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_info_set_latch(true); //persistent latch is set
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    status = atcab_aes_encrypt(key_slot, 0, data_in, encrypted_data_out); //Encrypting data with first 16 bytes in slot 10 as key
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);                              //Encryption should pass as persistent latch is set

}
t_test_case_info aes_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, volatile_key_permit),           DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_encrypt_key_tempkey_short), DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_encrypt_key_tempkey_long),  DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_decrypt_key_tempkey_short), DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_decrypt_key_tempkey_long),  DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_encrypt_key_slot),          DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_decrypt_key_slot),          DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, aes_gfm),                       DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },                   /* Array Termination element*/
};

t_test_case_info aes_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, aes), DEVICE_MASK(ATECC608A)  },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};


