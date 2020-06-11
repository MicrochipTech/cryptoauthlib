
#include "atca_config.h"
#include "cryptoauthlib.h"
#include "atca_test.h"

#if ATCA_TA_SUPPORT

uint8_t cmac_key[] = { 0x28, 0x97, 0xcc, 0x89, 0x57, 0x0f, 0x8b, 0xa8, 0xe4, 0x92, 0x1f, 0xea, 0x9d, 0xe3, 0x44, 0xd5 };
uint8_t cmac_i_nonce[] = { 40, 1, 45, 15, 180, 250, 79, 185, 217, 134, 94, 116, 72, 138, 202, 85 };
uint8_t cmac_r_nonce[] = { 198, 170, 177, 175, 106, 96, 66, 21, 229, 116, 215, 229, 255, 167, 55, 103 };

uint8_t gcm_key[] = { 0x69, 0x71, 0xf9, 0x3b, 0x99, 0xd1, 0xdb, 0x92, 0x67, 0xb9, 0xd0, 0xe8, 0x0c, 0x96, 0xaa, 0x7e };
uint8_t gcm_i_nonce[] = { 0x01, 0x5f, 0x68, 0xd3, 0x21, 0x4d, 0xb0, 0x13, 0x07, 0xa1, 0xc7, 0x97, 0x3d, 0x19, 0x09, 0x00 };
uint8_t gcm_r_nonce[] = { 0x24, 0x75, 0x84, 0x05, 0x06, 0xa3, 0x20, 0x63, 0x36, 0x5e, 0x3c, 0x2b, 0xdb, 0x69, 0x8b, 0x36 };

uint8_t hmac_key[] = { 0xa2, 0x26, 0xe1, 0x65, 0x69, 0x01, 0x80, 0xeb, 0x1a, 0x0c, 0x9c, 0x5b, 0x64, 0x5e, 0x42, 0x02,
                       0xfa, 0x2f, 0x4f, 0xfd, 0x68, 0x75 };
uint8_t hmac_i_nonce[] = { 0xd4, 0xe4, 0x9a, 0x02, 0x9f, 0xf2, 0xca, 0xff, 0x5e, 0x7c, 0xda, 0x2f, 0x13, 0x07, 0xa8, 0xb6 };
uint8_t hmac_r_nonce[] = { 0xad, 0x23, 0x38, 0x09, 0x4e, 0xd3, 0xbf, 0xc3, 0x89, 0xc6, 0xf6, 0x35, 0xb6, 0xcf, 0xcf, 0xf0 };


TEST(atca_cmd_basic_test, auth_test_hmac)
{
    ATCA_STATUS status;
    uint8_t key_buf[32] = { 0 };
    uint16_t key_id;
    uint8_t revision[8] = { 0 };
    uint16_t auth_id = 0x4100;

    memcpy(key_buf, hmac_key, sizeof(hmac_key));

    status = atca_test_config_get_id(TEST_TYPE_AUTH_HMAC, &key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_auth_generate_nonce(_gDevice, auth_id, 0, hmac_i_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_auth_startup(_gDevice, key_id, TA_AUTH_ALG_ID_HMAC, 2, 32, key_buf, hmac_i_nonce, hmac_r_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
#ifdef ATCA_PRINTF
    printf("\nkeyMat: ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key_buf[i]);
    }
    printf("\n");
#endif

    /* Execute a nested command */
    status = talib_info(_gDevice, revision);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_auth_terminate(_gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_basic_test, auth_test_cmac)
{
    ATCA_STATUS status;
    uint8_t key_buf[32] = { 0 };
    uint16_t key_id;
    uint8_t revision[8] = { 0 };
    uint16_t auth_id = 0x4100;

    memcpy(key_buf, cmac_key, sizeof(cmac_key));

    status = atca_test_config_get_id(TEST_TYPE_AUTH_CMAC, &key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_write_element(_gDevice, key_id, sizeof(cmac_key), cmac_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_auth_generate_nonce(_gDevice, auth_id, 0, cmac_i_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_auth_startup(_gDevice, key_id, TA_AUTH_ALG_ID_CMAC, 2, 16, key_buf, cmac_i_nonce, cmac_r_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    printf("\nkeyMat: ");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", key_buf[i]);
    }
    printf("\n");
#endif

    status = talib_info(_gDevice, revision);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_auth_terminate(_gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_basic_test, auth_test_gcm)
{
    ATCA_STATUS status;
    uint8_t key_buf[32] = { 0 };
    uint16_t key_id;
    uint8_t revision[8] = { 0 };

    memcpy(key_buf, gcm_key, sizeof(gcm_key));

    status = atca_test_config_get_id(TEST_TYPE_AUTH_GCM, &key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_write_element(_gDevice, key_id, sizeof(gcm_key), gcm_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_auth_generate_nonce(_gDevice, 0x4100, 0, gcm_i_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_auth_startup(_gDevice, key_id, TA_AUTH_ALG_ID_GCM, 2, 16, key_buf, gcm_i_nonce, gcm_r_nonce);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    printf("\nkeyMat: ");
    for (int i = 0; i < _gDevice->session_key_len; i++)
    {
        printf("%02x", key_buf[i]);
    }
    printf("\n");
#endif

    status = talib_info(_gDevice, revision);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_auth_terminate(_gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

t_test_case_info talib_auth_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, auth_test_hmac), DEVICE_MASK(TA100) },
#ifdef ATCA_TA100_AES_AUTH_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, auth_test_cmac), DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, auth_test_gcm), DEVICE_MASK(TA100) },
#endif
    /* Array Termination element*/
    { (fp_test_case)NULL,                    (uint8_t)0 },
};

t_test_case_info* talib_auth_tests[] = {
    talib_auth_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
