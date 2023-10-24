/**
 * \file
 * \brief Tests for the cryptoauthlib Basic API
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
#include "test_atcab.h"

static t_test_case_info* basic_tests[] =
{
    /* Basic chip Tests */
    startup_basic_test_info,
    info_basic_test_info,
    random_basic_test_info,
    write_basic_test_info,
    read_basic_test_info,
    lock_basic_test_info,

    /* ECC Key Tests */
    genkey_basic_test_info,
    privwrite_basic_test_info,
    verify_basic_test_info,
    sign_basic_test_info,
    ecdh_basic_test_info,

    /* Hashing and MAC tests */
    sha_basic_test_info,
    hmac_basic_test_info,
    mac_basic_test_info,
    derivekey_basic_test_info,

    /* Chip and Key Features */
    gendig_basic_test_info,
    nonce_basic_test_info,
    updateextra_basic_test_info,
    counter_basic_test_info,

    /* Advanced part test */
    kdf_basic_test_info,
    sboot_basic_test_info,
    selftest_basic_test_info,
    aes_basic_test_info,
    aes_cbc_basic_test_info,
    aes_cmac_basic_test_info,
    aes_ctr_basic_test_info,
    aes_cbcmac_basic_test_info,
    aes_gcm_basic_test_info,
    aes_ccm_basic_test_info,
    (t_test_case_info*)NULL, /* Array Termination element*/
};

void RunAllBasicTests(void)
{
    RunAllTests(basic_tests);
}

int run_basic_tests(int argc, char* argv[])
{
#ifdef ATCA_ATECC608_SUPPORT
    if (ATECC608 == (gCfg->devtype))
    {
        check_clock_divider(argc, argv);
    }
#endif
    if (gCfg->devtype < ATCA_DEV_UNKNOWN)
    {
        return run_test(argc, argv, RunAllBasicTests);
    }
    else
    {
        printf("Device is NOT Selected... Select device before running tests!");
        return -1;
    }
}

const char* ATCA_TEST_HELPER_FILE = "In helper: " __FILE__;
const char* TEST_GROUP_atca_cmd_basic_test = "atca_cmd_basic_test";

TEST_SETUP(atca_cmd_basic_test)
{
    UnityMalloc_StartTest();

    ATCA_STATUS status = atcab_init(gCfg);
    TEST_ASSERT_SUCCESS_MSG(status, ATCA_TEST_HELPER_FILE);
}

TEST_TEAR_DOWN(atca_cmd_basic_test)
{
    ATCA_STATUS status;
    bool test_failed = atca_test_already_exiting();
    bool comm_failed = atca_test_unresponsive();

    if (comm_failed)
    {
        /* Assume if there are comm failures there isn't a point trying to
           continue to fail here */
        status = atcab_wakeup();
        if (!test_failed)
        {
            TEST_ASSERT_SUCCESS_MSG(status, ATCA_TEST_HELPER_FILE);
        }

        status = atcab_sleep();
        if (!test_failed)
        {
            TEST_ASSERT_SUCCESS_MSG(status, ATCA_TEST_HELPER_FILE);
        }
    }

    status = atcab_release();
    if (!test_failed && !comm_failed)
    {
        /* Don't override the existing failure location or the global
            status return value */
        TEST_ASSERT_SUCCESS_MSG(status, ATCA_TEST_HELPER_FILE);
    }

    UnityMalloc_EndTest();
}
