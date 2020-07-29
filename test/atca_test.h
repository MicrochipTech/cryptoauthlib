/**
 * \file
 * \brief Tests for the Cryptoauthlib Basic API
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

#ifndef ATCA_TEST_H_
#define ATCA_TEST_H_

#include "third_party/unity/unity.h"
#include "third_party/unity/unity_fixture.h"
#include "cryptoauthlib.h"

#define TEST_ASSERT_SUCCESS(x)  TEST_ASSERT_EQUAL(ATCA_SUCCESS, x)

extern ATCAIfaceCfg *gCfg;
extern const uint8_t g_slot4_key[];

#define AES_CONFIG_ENABLE_BIT_MASK   (uint8_t)0x01


typedef void (*fp_test_case)(void);

typedef struct
{
    fp_test_case fp_test;
    uint32_t     support_device_mask;
}t_test_case_info;

#define DEVICE_MASK(device)                 ((uint8_t)1 << device)
#define REGISTER_TEST_CASE(group, name)     TEST_ ## group ## _ ## name ## _run

#define DEVICE_MASK_ECC                     (DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) | DEVICE_MASK(ATECC608))


#if !defined(ATCA_ECC_SUPPORT) && !defined(DO_NOT_TEST_CERT)
#define DO_NOT_TEST_CERT
#endif

#if ATCA_CA_SUPPORT
#include "host/atca_host.h"
#endif

#if ATCA_TA_SUPPORT
#include "api_talib/test_talib.h"
#endif

extern bool g_atca_test_quiet_mode;

void RunAllTests(t_test_case_info** tests_list);
int run_test(int argc, char* argv[], void* fptest);
void run_all_talib_tests(void);

extern const char* TEST_GROUP_atca_cmd_basic_test;
void TEST_atca_cmd_basic_test_SETUP(void);
void TEST_atca_cmd_basic_test_TEAR_DOWN(void);

extern const char* TEST_GROUP_atca_cmd_unit_test;
void TEST_atca_cmd_unit_test_SETUP(void);
void TEST_atca_cmd_unit_test_TEAR_DOWN(void);


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

extern t_test_case_info jwt_unit_test_info[];
extern t_test_case_info tng_atca_unit_test_info[];
extern t_test_case_info tng_atcacert_client_unit_test_info[];

void test_assert_interface_init(void);
void test_assert_interface_deinit(void);

#if ATCA_CA_SUPPORT
extern uint8_t test_ecc608_configdata[ATCA_ECC_CONFIG_SIZE];
extern const uint8_t test_ecc_configdata[ATCA_ECC_CONFIG_SIZE];
extern const uint8_t sha204_default_config[ATCA_SHA_CONFIG_SIZE];
#endif
#if ATCA_TA_SUPPORT
const uint8_t test_ta100_configdata[TA_CONFIG_SIZE];
#endif

void atca_test_assert_config_is_unlocked(UNITY_LINE_TYPE from_line);
void atca_test_assert_config_is_locked(UNITY_LINE_TYPE from_line);
void atca_test_assert_data_is_unlocked(UNITY_LINE_TYPE from_line);
void atca_test_assert_data_is_locked(UNITY_LINE_TYPE from_line);
void atca_test_assert_aes_enabled(UNITY_LINE_TYPE from_line);

#define unit_test_assert_config_is_locked()     atca_test_assert_config_is_locked(__LINE__)
#define unit_test_assert_config_is_unlocked()   atca_test_assert_config_is_unlocked(__LINE__)
#define unit_test_assert_data_is_locked()       atca_test_assert_data_is_locked(__LINE__)
#define unit_test_assert_data_is_unlocked()     atca_test_assert_data_is_unlocked(__LINE__)

#define test_assert_config_is_unlocked()        atca_test_assert_config_is_unlocked(__LINE__)
#define test_assert_config_is_locked()          atca_test_assert_config_is_locked(__LINE__)
#define test_assert_data_is_unlocked()          atca_test_assert_data_is_unlocked(__LINE__)
#define test_assert_data_is_locked()            atca_test_assert_data_is_locked(__LINE__)

#define check_config_aes_enable()               atca_test_assert_aes_enabled(__LINE__)


#define TEST_TYPE_ECC_SIGN          (1)
#define TEST_TYPE_ECC_VERIFY        (2)
#define TEST_TYPE_ECC_GENKEY        (3)
#define TEST_TYPE_AES               (4)
#define TEST_TYPE_DATA              (5)
#define TEST_TYPE_HMAC              (6)
#define TEST_TYPE_ECDH              (7)
#define TEST_TYPE_AUTH_HMAC         (8)
#define TEST_TYPE_AUTH_CMAC         (9)
#define TEST_TYPE_AUTH_GCM          (10)
#define TEST_TYPE_ECC_ROOT_KEY      (11)

typedef struct
{
    uint8_t  test_type;
    uint16_t handle;
    void*    attributes;
} device_object_meta_t;

/* Configuration */
ATCA_STATUS atca_test_config_get_id(uint8_t test_type, uint16_t* handle);

// Helper tests
void RunAllHelperTests(void);
void RunBasicOtpZero(void);
void RunAllBasicTests(void);
void RunAllFeatureTests(void);
void RunTNGTests(void);

/* Setup & Configuration */
void atca_test_config_set_ifacecfg(ATCAIfaceCfg * ifacecfg);

/* Commands */
int process_options(int argc, char* argv[]);

int select_204(int argc, char* argv[]);
int select_206(int argc, char* argv[]);
int select_108(int argc, char* argv[]);
int select_508(int argc, char* argv[]);
int select_608(int argc, char* argv[]);
int select_ta100(int argc, char* argv[]);

int certdata_unit_tests(int argc, char* argv[]);
int certio_unit_tests(int argc, char* argv[]);
ATCA_STATUS is_config_locked(bool* isLocked);
ATCA_STATUS is_data_locked(bool* isLocked);
int lock_status(int argc, char* argv[]);
int lock_config_zone(int argc, char* argv[]);
int lock_data_zone(int argc, char* argv[]);
ATCA_STATUS get_info(uint8_t* revision);
ATCA_STATUS get_serial_no(uint8_t* sernum);
int do_randoms(int argc, char* argv[]);
int read_config(int argc, char* argv[]);
int lock_config(int argc, char* argv[]);
int lock_data(int argc, char* argv[]);
int info(int argc, char* argv[]);
int read_sernum(int argc, char* argv[]);
int discover(int argc, char* argv[]);

int run_basic_tests(int argc, char* argv[]);
int run_unit_tests(int argc, char* argv[]);
int run_otpzero_tests(int argc, char* argv[]);
int run_helper_tests(int argc, char* argv[]);
int run_all_tests(int argc, char* argv[]);
ATCA_STATUS set_chip_mode(uint8_t i2c_user_extra_add, uint8_t ttl_enable, uint8_t watchdog, uint8_t clock_divider);
void update_chip_mode(uint8_t* chip_mode, uint8_t i2c_user_extra_add, uint8_t ttl_enable, uint8_t watchdog, uint8_t clock_divider);
int set_clock_divider_m0(int argc, char* argv[]);
int set_clock_divider_m1(int argc, char* argv[]);
int set_clock_divider_m2(int argc, char* argv[]);
int run_tng_tests(int argc, char* argv[]);
ATCA_STATUS check_clock_divider(int argc, char* argv[]);

#ifdef _WIN32
void hex_to_data(const char* hex_str, uint8_t* data, size_t data_size);
#endif

void atca_test_task(void);

#endif /* ATCA_TEST_H_ */
