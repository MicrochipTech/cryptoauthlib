/**
 * \file
 * \brief Tests for the cryptoauthlib talib API
 *
 * \copyright (c) 2015-2023 Microchip Technology Inc. and its subsidiaries.
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
#include "test_hal.h"

extern t_test_case_info hal_basic_tests[];

/* Tests are ordered based on successive capability used by commands. If a command
 * is used in a test then it is tested ahead of the other. E.g. verify is tested
 * using verify
 */
static t_test_case_info* hal_test_list[] =
{
    hal_basic_tests,
    /* Array Termination element*/
    (t_test_case_info*)NULL,
};

void run_hal_tests(void)
{
    RunAllTests(hal_test_list);
}

int hal_tests(int argc, char* argv[])
{
    return run_test(argc, argv, run_hal_tests);
}

const char* HAL_HELPER_FILE = "In helper: " __FILE__;
const char* TEST_GROUP_hal = "hal";

TEST_SETUP(hal)
{
#ifdef ATCA_PRINTF
    printf("\n");
    fflush(stdout);
    fflush(stderr);
#endif

    UnityMalloc_StartTest();

    ATCA_STATUS status = atcab_init(gCfg);
    TEST_ASSERT_SUCCESS_MSG(status, HAL_HELPER_FILE);
}

TEST_TEAR_DOWN(hal)
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
            TEST_ASSERT_SUCCESS_MSG(status, HAL_HELPER_FILE);
        }

        status = atcab_sleep();
        if (!test_failed)
        {
            TEST_ASSERT_SUCCESS_MSG(status, HAL_HELPER_FILE);
        }
    }

    status = atcab_release();
    if (!test_failed && !comm_failed)
    {
        /* Don't override the existing failure location or the global
            status return value */
        TEST_ASSERT_SUCCESS_MSG(status, HAL_HELPER_FILE);
    }

    UnityMalloc_EndTest();
}
