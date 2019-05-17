/**
 * \file
 * \brief Tests for the Cryptoauthlib Basic API
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

#ifndef ATCA_TEST_H_
#define ATCA_TEST_H_

#include "test/unity.h"
#include "test/unity_fixture.h"
#include "cryptoauthlib.h"

#define TEST_ASSERT_SUCCESS(x)  TEST_ASSERT_EQUAL(ATCA_SUCCESS, x)

extern ATCAIfaceCfg *gCfg;
extern const uint8_t g_slot4_key[];

#define AES_CONFIG_ENABLE_BIT_MASK   (uint8_t)0x01


typedef void (*fp_test_case)(void);

typedef struct
{
    fp_test_case fp_test;
    uint8_t      support_device_mask;
}t_test_case_info;

#define DEVICE_MASK(device) \
    ((uint8_t)1 << device)
#define REGISTER_TEST_CASE(group, name) \
    TEST_ ## group ## _ ## name ## _run

void RunAllTests(t_test_case_info** tests_list);

extern t_test_case_info startup_basic_test_info[];
extern t_test_case_info info_basic_test_info[];
extern t_test_case_info aes_basic_test_info[];
extern t_test_case_info aes_cbc_basic_test_info[];
extern t_test_case_info aes_cmac_basic_test_info[];
extern t_test_case_info aes_ctr_basic_test_info[];
extern t_test_case_info aes_gcm_basic_test_info[];
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

extern t_test_case_info helper_basic_test_info[];
extern t_test_case_info otpzero_basic_test_info[];

extern t_test_case_info startup_unit_test_info[];
extern t_test_case_info info_unit_test_info[];
extern t_test_case_info aes_unit_test_info[];
extern t_test_case_info verify_unit_test_info[];
extern t_test_case_info derivekey_unit_test_info[];
extern t_test_case_info sha_unit_test_info[];
extern t_test_case_info hmac_unit_test_info[];
extern t_test_case_info sign_unit_test_info[];
extern t_test_case_info mac_unit_test_info[];
extern t_test_case_info ecdh_unit_test_info[];
extern t_test_case_info write_unit_test_info[];
extern t_test_case_info read_unit_test_info[];
extern t_test_case_info genkey_unit_test_info[];
extern t_test_case_info privwrite_unit_test_info[];
extern t_test_case_info lock_unit_test_info[];
extern t_test_case_info kdf_unit_test_info[];
extern t_test_case_info selftest_unit_test_info[];
extern t_test_case_info gendig_unit_test_info[];
extern t_test_case_info random_unit_test_info[];
extern t_test_case_info nonce_unit_test_info[];
extern t_test_case_info pause_unit_test_info[];
extern t_test_case_info updateextra_unit_test_info[];
extern t_test_case_info counter_unit_test_info[];
extern t_test_case_info sboot_unit_test_info[];
extern t_test_case_info jwt_unit_test_info[];
extern t_test_case_info tng_atca_unit_test_info[];
extern t_test_case_info tng_atcacert_client_unit_test_info[];

void test_assert_interface_init(void);
void test_assert_interface_deinit(void);

extern uint8_t test_ecc608_configdata[ATCA_ECC_CONFIG_SIZE];
extern const uint8_t test_ecc_configdata[ATCA_ECC_CONFIG_SIZE];
extern const uint8_t sha204_default_config[ATCA_SHA_CONFIG_SIZE];

void unit_test_assert_config_is_locked(void);
void unit_test_assert_config_is_unlocked(void);
void unit_test_assert_data_is_locked(void);
void unit_test_assert_data_is_unlocked(void);

void test_assert_config_is_unlocked(void);
void test_assert_config_is_locked(void);
void test_assert_data_is_unlocked(void);
void test_assert_data_is_locked(void);
void check_config_aes_enable(void);

// Helper tests
void RunAllHelperTests(void);
void RunBasicOtpZero(void);
void RunAllBasicTests(void);
void RunAllFeatureTests(void);
void RunTNG22Tests(void);
void RunTNGTNTests(void);

#ifdef _WIN32
void hex_to_data(const char* hex_str, uint8_t* data, size_t data_size);
#endif
#endif /* ATCA_TEST_H_ */
