/**
 * \file
 * \brief Unity tests for the cryptoauthlib Verify Command
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


TEST(atca_cmd_unit_test, info)
{
    ATCA_STATUS status;
    ATCAPacket packet;

    uint32_t devrev = 0;
    uint32_t devrev_min = 0;
    uint32_t devrev_max = 0;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build an info command
    packet.param1 = INFO_MODE_REVISION;   // these tests are for communication testing mainly,
                                          // but if testing the entire chip, would need to go through all the modes.
                                          // this tests version mode only
    status = atInfo(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(ATCA_RSP_SIZE_4, packet.data[ATCA_COUNT_IDX]);

    switch (gCfg->devtype)
    {
    case ATSHA204A:
        devrev_min = 0x00020008;
        devrev_max = 0x000200FF;
        break;
    case ATECC108A:
        devrev_min = 0x00001002;
        devrev_max = 0x000010FF;
        break;
    case ATECC508A:
        devrev_min = 0x00005000;
        devrev_max = 0x000050FF;
        break;
    case ATECC608A:
        devrev_min = 0x00006000;
        devrev_max = 0x000060FF;
        break;
    default:
        TEST_FAIL_MESSAGE("Unknown device type");
        break;
    }

    devrev = ((uint32_t)packet.data[1] << 24) |
             ((uint32_t)packet.data[2] << 16) |
             ((uint32_t)packet.data[3] << 8) |
             ((uint32_t)packet.data[4] << 0);

    if (devrev < devrev_min || devrev > devrev_max)
    {
        TEST_FAIL_MESSAGE("Unexpected DevRev");
    }
}

TEST(atca_cmd_basic_test, info)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t revision[4];

    status = atcab_info(revision);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}


// *INDENT-OFF* - Preserve formatting
t_test_case_info info_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },/* Array Termination element*/
};

t_test_case_info info_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, info), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

