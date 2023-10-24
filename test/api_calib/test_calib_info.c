/**
 * \file
 * \brief calib info tests
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
#include <stdlib.h>
#include "test_calib.h"

TEST(calib, info)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t revision[4];

    status = atcab_info(revision);
    TEST_ASSERT_SUCCESS(status);
    if (atcab_is_ca_device(gCfg->devtype))
    {
#if ATCA_CA_SUPPORT
        ATCADeviceType devtype = calib_get_devicetype(revision);
        if (gCfg->devtype != devtype)
        {
            g_test_abort = true;
        }
        TEST_ASSERT_EQUAL_MESSAGE(gCfg->devtype, devtype, "Device Type Mismatch");
#endif
    }
}

#if ATCA_CA2_SUPPORT
TEST(calib, info_lock_status)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t is_locked, slot = 1;
    uint16_t param2;

    // lockstatus of Config subzone
    param2 = ATCA_ZONE_CA2_CONFIG | (slot << 1);

    // is_locked = 0x00 means unlocked
    // is_locked = 0x01 means locked
    status = calib_info_lock_status(atcab_get_device(), param2, &is_locked);
    TEST_ASSERT_SUCCESS(status);

    // lockstatus of Data zone
    param2 = ATCA_ZONE_CA2_DATA | (slot << 1);

    // is_locked = 0x00 means unlocked
    // is_locked = 0x01 means locked
    status = calib_info_lock_status(atcab_get_device(), param2, &is_locked);
    TEST_ASSERT_SUCCESS(status);
}

TEST(calib, info_chip_status)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t chip_status[4];

    // chip_status[0] = 0x00 means No Deletion
    // chip_status[0] = 0xFF means Deletion has completed
    status = calib_info_chip_status(atcab_get_device(), chip_status);
    TEST_ASSERT_SUCCESS(status);
}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info calib_info_tests[] =
{
    { REGISTER_TEST_CASE(calib, info),              NULL},
#if ATCA_CA2_SUPPORT
    { REGISTER_TEST_CASE(calib, info_lock_status),  atca_test_cond_ca2},
    { REGISTER_TEST_CASE(calib, info_chip_status),  atca_test_cond_ca2},
#endif

    /* Array Termination element*/
    { (fp_test_case)NULL, NULL },
};
// *INDENT-ON*
