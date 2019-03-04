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

TEST(atca_cmd_unit_test, wake_sleep)
{
    ATCA_STATUS status;

    status = atwake(_gDevice->mIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atsleep(_gDevice->mIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_unit_test, wake_idle)
{
    ATCA_STATUS status;

    status = atwake(_gDevice->mIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atidle(_gDevice->mIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST(atca_cmd_unit_test, crcerror)
{
    ATCA_STATUS status;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    if (_gDevice->mIface->mIfaceCFG->iface_type == ATCA_HID_IFACE)
    {
        TEST_IGNORE_MESSAGE("Kit protocol corrects CRC errors.");
    }
    if (_gDevice->mIface->mIfaceCFG->iface_type == ATCA_UART_IFACE)
    {
        TEST_IGNORE_MESSAGE("Kit protocol corrects CRC errors.");
    }

    // build an info command
    packet.param1 = INFO_MODE_REVISION;   // these tests are for communication testing mainly,
                                          // but if testing the entire chip, would need to go through all the modes.
                                          // this tests version mode only
    status = atInfo(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    // simulate the packet so CRC is broken
    packet.data[0] = 0xff;
    packet.data[1] = 0xff;
    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_STATUS_CRC, status);

    // test to make sure CRC error is in the packet
    TEST_ASSERT_EQUAL_INT8_MESSAGE(0x04, packet.data[0], "Failed error response length test");
    TEST_ASSERT_EQUAL_INT8_MESSAGE(0xff, packet.data[1], "Failed bad CRC test");
}

TEST(atca_cmd_basic_test, version)
{
    char ver_str[20];
    ATCA_STATUS status = ATCA_GEN_FAIL;

    ver_str[0] = '\0';
    status = atcab_version(ver_str);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(8, strlen(ver_str));
}

TEST(atca_cmd_basic_test, init)
{
    TEST_ASSERT_NOT_EQUAL(NULL, _gDevice);
}


TEST(atca_cmd_basic_test, doubleinit)
{
    uint8_t rev[4];
    ATCA_STATUS status = ATCA_GEN_FAIL;

    TEST_ASSERT_NOT_EQUAL(NULL, _gDevice);

    // Make sure communication works initially
    status = atcab_info(rev);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // a double init should be benign
    status = atcab_init(gCfg);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_NOT_EQUAL(NULL, _gDevice);

    // Make sure communication still works
    status = atcab_info(rev);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info startup_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, version),    DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, init),       DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, doubleinit), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },/* Array Termination element*/
};

t_test_case_info startup_unit_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_unit_test, wake_sleep), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, wake_idle),  DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { REGISTER_TEST_CASE(atca_cmd_unit_test, crcerror),   DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608A) },
    { (fp_test_case)NULL,                    (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

