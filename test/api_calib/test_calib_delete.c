/**
 * \file
 * \brief Unity tests for the cryptoauthlib Delete Command
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

#ifndef TEST_CALIB_DELETE_EN
#define TEST_CALIB_DELETE_EN      (CALIB_DELETE_EN && ATCA_CA2_SUPPORT)
#endif

#if defined(ATCA_TEST_DELETE_ENABLE) && TEST_CALIB_DELETE_EN

TEST(calib, delete_test)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t chip_status[4];
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
                                         0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20 };

    // CSZ0 and CSZ1 should be locked
    test_assert_config_is_locked();

    // Get chip_status
    status = atcab_info_chip_status(chip_status);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (0x00 == chip_status[0])
    {
        // Perform delete
        status = calib_delete(atcab_get_device(), num_in, g_slot4_key);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        // Read chip_status to ensure delete is successful
        status = atcab_info_chip_status(chip_status);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL(0xFF, chip_status[0]);
    }
}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info calib_delete_tests[] =
{
#if defined(ATCA_TEST_DELETE_ENABLE) && TEST_CALIB_DELETE_EN
    { REGISTER_TEST_CASE(calib, delete_test),   atca_test_cond_ca2 },
#endif
    /* Array Termination element*/
    { (fp_test_case)NULL, NULL },
};
// *INDENT-ON*
