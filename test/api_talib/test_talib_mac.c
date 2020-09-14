
#include "atca_config.h"
#include "cryptoauthlib.h"
#include "atca_test.h"
#include "vectors/aes_cmac_nist_vectors.h"

#if ATCA_TA_SUPPORT

/** \brief  This test cases load an AES key, performs CMAC operation and verifies it.
 *          .
 */
TEST(atca_cmd_basic_test, mac_test_cmac)
{
    ATCA_STATUS status;
    uint8_t key_block;
    size_t msg_index;
    uint8_t cmac[ATCA_AES128_KEY_SIZE];
    uint16_t key_id;

    // Skip test if AES is not enabled
    check_config_aes_enable();

    status = atca_test_config_get_id(TEST_TYPE_AES, &key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    for (key_block = 0; key_block < 4; key_block++)
    {
        // Load AES keys into slot
        status = atcab_write_bytes_zone(ATCA_ZONE_DATA, key_id, 0, &g_aes_keys[key_block][0], 16);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Skippping the first test case as the message size is zero
        for (msg_index = 1; msg_index < sizeof(g_cmac_msg_sizes) / sizeof(g_cmac_msg_sizes[0]); msg_index++)
        {

            status = talib_cmac(atcab_get_device(), key_id, 0,
                                g_plaintext, g_cmac_msg_sizes[msg_index], cmac);
            TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

            TEST_ASSERT_EQUAL_MEMORY(g_cmacs[key_block][msg_index], cmac, sizeof(cmac));
        }
    }
}



t_test_case_info talib_mac_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, mac_test_cmac), DEVICE_MASK(TA100)      },
    /* Array Termination element*/
    { (fp_test_case)NULL,                     (uint8_t)0 },
};

t_test_case_info* talib_mac_tests[] = {
    talib_mac_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
