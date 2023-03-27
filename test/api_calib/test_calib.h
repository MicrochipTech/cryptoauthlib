/**
 * \file
 * \brief Tests for the Cryptoauthlib API (cablib)
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

#ifndef TEST_CALIB_H_
#define TEST_CALIB_H_

#include "atca_test.h"

#ifdef __cplusplus
extern "C" {
#endif

ATCA_STATUS calib_config_get_slot_by_test(uint8_t test_type, uint16_t* handle);
ATCA_STATUS calib_config_get_ecc204_slot_by_test(uint8_t test_type, uint16_t* handle);
ATCA_STATUS calib_config_get_sha10x_slot_by_test(uint8_t test_type, uint16_t* handle);

/* Test Commands */
int run_calib_tests(int argc, char* argv[]);

/* Common test setup/teardown */
extern const char* TEST_GROUP_calib;
void TEST_calib_SETUP(void);
void TEST_calib_TEAR_DOWN(void);

#ifdef __cplusplus
}
#endif

#endif /* TEST_CALIB_H_*/
