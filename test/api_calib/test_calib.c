/**
 * \file
 * \brief Tests for the cryptoauthlib calib API
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
#include "test_calib.h"

//extern t_test_case_info calib_commands_info[];
//extern t_test_case_info calib_packet_info[];
extern t_test_case_info calib_info_tests[];
extern t_test_case_info calib_delete_tests[];

static t_test_case_info* calib_test_list[] =
{
    /* Basic tests that should pass for all parts */
    calib_info_tests,

    /* Chip and Key Features */
    calib_delete_tests,

    /* Array Termination element*/
    (t_test_case_info*)NULL,
};

void run_all_calib_tests(void)
{
    RunAllTests(calib_test_list);
}

int run_calib_tests(int argc, char* argv[])
{
    return run_test(argc, argv, run_all_calib_tests);
}

const char* CALIB_HELPER_FILE = "In helper: " __FILE__;
const char* TEST_GROUP_calib = "calib";

TEST_SETUP(calib)
{
    UnityMalloc_StartTest();

    ATCA_STATUS status = atcab_init(gCfg);
    TEST_ASSERT_SUCCESS_MSG(status, CALIB_HELPER_FILE);
}

TEST_TEAR_DOWN(calib)
{
    ATCA_STATUS status;
    bool test_failed = atca_test_already_exiting();
    bool comm_failed = atca_test_unresponsive();

    status = atcab_release();
    if (!test_failed && !comm_failed)
    {
        /* Don't override the existing failure location or the global
            status return value */
        TEST_ASSERT_SUCCESS_MSG(status, CALIB_HELPER_FILE);
    }

    UnityMalloc_EndTest();
}
