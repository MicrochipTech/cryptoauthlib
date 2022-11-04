/**
 * \file
 * \brief Unity tests for the cryptoauthlib Basic API
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

#ifndef TEST_ATCAB_H
#define TEST_ATCAB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "atca_test.h"

extern t_test_case_info startup_basic_test_info[];
extern t_test_case_info info_basic_test_info[];
extern t_test_case_info aes_basic_test_info[];
extern t_test_case_info aes_cbc_basic_test_info[];
extern t_test_case_info aes_cmac_basic_test_info[];
extern t_test_case_info aes_ctr_basic_test_info[];
extern t_test_case_info aes_cbcmac_basic_test_info[];
extern t_test_case_info aes_gcm_basic_test_info[];
extern t_test_case_info aes_ccm_basic_test_info[];
extern t_test_case_info verify_basic_test_info[];
extern t_test_case_info derivekey_basic_test_info[];
extern t_test_case_info sha_basic_test_info[];
extern t_test_case_info hmac_basic_test_info[];
extern t_test_case_info sign_basic_test_info[];
extern t_test_case_info mac_basic_test_info[];
extern t_test_case_info ecdh_basic_test_info[];
extern t_test_case_info write_basic_test_info[];
extern t_test_case_info read_basic_test_info[];
extern t_test_case_info genkey_basic_test_info[];
extern t_test_case_info privwrite_basic_test_info[];
extern t_test_case_info lock_basic_test_info[];
extern t_test_case_info kdf_basic_test_info[];
extern t_test_case_info selftest_basic_test_info[];
extern t_test_case_info gendig_basic_test_info[];
extern t_test_case_info random_basic_test_info[];
extern t_test_case_info nonce_basic_test_info[];
extern t_test_case_info pause_basic_test_info[];
extern t_test_case_info updateextra_basic_test_info[];
extern t_test_case_info counter_basic_test_info[];
extern t_test_case_info sboot_basic_test_info[];

/* Atcab unity tests */
void RunAllBasicTests(void);

/* Console function */
int run_basic_tests(int argc, char* argv[]);

/* Common test setup/teardown */
extern const char* TEST_GROUP_atca_cmd_basic_test;
void TEST_atca_cmd_basic_test_SETUP(void);
void TEST_atca_cmd_basic_test_TEAR_DOWN(void);

#ifdef __cplusplus
}
#endif

#endif
