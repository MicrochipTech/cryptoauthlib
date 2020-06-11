
#include "atca_config.h"
#include "cryptoauthlib.h"
#include "atca_test.h"

#if ATCA_TA_SUPPORT

/** \brief  It performs the self test of most of the cryptographic algorithms in the device.
 *
 */
TEST(atca_cmd_basic_test, self_test)
{
    ATCA_STATUS status;
    uint32_t self_test_result;

    status = talib_selftest(atcab_get_device(), TA_SELFTEST_MODE_USEMAP, SELFTEST_MAP_ALL, &self_test_result);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL(self_test_result, 0);

}

t_test_case_info talib_selftest_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, self_test), DEVICE_MASK(TA100)    },
    /* Array Termination element*/
    { (fp_test_case)NULL,                     (uint8_t)0 },
};

t_test_case_info* talib_selftest_tests[] = {
    talib_selftest_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
