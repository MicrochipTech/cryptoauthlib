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

extern bool g_test_abort;
extern ATCA_STATUS g_last_status;
#define TEST_ASSERT_SUCCESS(x)          TEST_ASSERT_EQUAL(ATCA_SUCCESS, g_last_status = x)
#define TEST_ASSERT_SUCCESS_MSG(x, m)    TEST_ASSERT_EQUAL_MESSAGE(ATCA_SUCCESS, g_last_status = x, m)

extern ATCAIfaceCfg *gCfg;
extern const uint8_t g_slot4_key[];

#define AES_CONFIG_ENABLE_BIT_MASK          (uint8_t)0x01

#define CMD_PROCESSOR_MAX_ARGS  16

typedef void (*fp_test_case)(void);
typedef bool (*fp_test_condition)(void);

typedef struct
{
    fp_test_case      fp_test;
    fp_test_condition fp_condition;
}t_test_case_info;

typedef int (*fp_menu_handler)(int argc, char* argv[]);

typedef struct
{
    const char*     menu_cmd;
    fp_menu_handler fp_handler;
} t_menu_info_simple;
#define MENU_ITEM_SIMPLE(c, f)   { c, f }

#ifdef ATCA_TEST_SIMPLE_MENU
typedef t_menu_info_simple t_menu_info
#define MENU_ITEM   MENU_ITEM_SIMPLE
#else
typedef struct
{
    const char*     menu_cmd;
    const char*     menu_cmd_description;
    fp_menu_handler fp_handler;
} t_menu_info;
#define MENU_ITEM(c, d, f)   { c, d, f }
#endif

#define REGISTER_TEST_CASE(group, name)         TEST_ ## group ## _ ## name ## _run
#define REGISTER_TEST_CONDITION(group, name)    TEST_ ## group ## _ ## name ## _cond

#define TEST_CONDITION(group, name)             bool TEST_ ## group ## _ ## name ## _cond(void)

#if !defined(ATCA_ECC_SUPPORT) && !defined(DO_NOT_TEST_CERT)
#define DO_NOT_TEST_CERT
#endif

#ifndef DO_NOT_TEST_CERT
#include "atcacert/atcacert_check_config.h"
#endif

#if ATCA_CA_SUPPORT
#include "host/atca_host.h"
#endif

#if ATCA_TA_SUPPORT
#include "api_talib/test_talib.h"
#endif

#ifdef ATCA_HAL_KIT_SUPPORT
    extern ATCA_STATUS hal_kit_bridge_connect(ATCAIfaceCfg * cfg);
#endif

    extern bool g_atca_test_quiet_mode;

/* Cryptoauthlib Test Api */
void RunAllTests(t_test_case_info** tests_list);
int run_test(int argc, char* argv[], void (*fptest)(void));
void run_all_talib_tests(void);

extern t_test_case_info buffer_test_info[];
extern t_test_case_info helper_basic_test_info[];
extern t_test_case_info otpzero_basic_test_info[];

extern t_test_case_info tng_atca_unit_test_info[];
extern t_test_case_info tng_atcacert_client_unit_test_info[];

extern t_test_case_info wpccert_client_unit_test_info[];
extern t_test_case_info wpc_apis_unit_test_info[];

extern t_test_case_info test_crypto_pbkdf2_info[];

void test_assert_interface_init(void);
void test_assert_interface_deinit(void);

#if ATCA_CA_SUPPORT
extern uint8_t test_ecc608_configdata[ATCA_ECC_CONFIG_SIZE];
#endif
#if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT)
extern const uint8_t test_ecc_configdata[ATCA_ECC_CONFIG_SIZE];
#endif
#ifdef ATCA_ATSHA204A_SUPPORT
extern const uint8_t sha204_default_config[ATCA_SHA_CONFIG_SIZE];
#endif
#if defined(ATCA_ECC204_SUPPORT) || defined(ATCA_TA010_SUPPORT)
extern const uint8_t test_ecc204_configdata[ATCA_CA2_CONFIG_SIZE];
#endif
#ifdef ATCA_SHA104_SUPPORT
extern const uint8_t test_sha104_configdata[ATCA_CA2_CONFIG_SIZE];
#endif
#ifdef ATCA_SHA105_SUPPORT
extern const uint8_t test_sha105_configdata[ATCA_CA2_CONFIG_SIZE];
#endif
#if ATCA_TA_SUPPORT
extern const uint8_t test_ta10x_configdata[TA_CONFIG_SIZE];
#endif

bool atca_test_already_exiting(void);
bool atca_test_unresponsive(void);

void atca_test_assert_config_is_unlocked(UNITY_LINE_TYPE from_line);
void atca_test_assert_config_is_locked(UNITY_LINE_TYPE from_line);
void atca_test_assert_data_is_unlocked(UNITY_LINE_TYPE from_line);
void atca_test_assert_data_is_locked(UNITY_LINE_TYPE from_line);
void atca_test_assert_random_buffer(UNITY_LINE_TYPE from_line, uint8_t * buf, size_t buflen);
void atca_test_assert_aes_enabled(UNITY_LINE_TYPE from_line);
#if ATCA_TA_SUPPORT
void atca_test_assert_ta_sboot_enabled(UNITY_LINE_TYPE from_line, uint8_t mode);
void atca_test_assert_ta_sboot_preboot_enabled(UNITY_LINE_TYPE from_line);
#endif

#define unit_test_assert_config_is_locked()     atca_test_assert_config_is_locked(__LINE__)
#define unit_test_assert_config_is_unlocked()   atca_test_assert_config_is_unlocked(__LINE__)
#define unit_test_assert_data_is_locked()       atca_test_assert_data_is_locked(__LINE__)
#define unit_test_assert_data_is_unlocked()     atca_test_assert_data_is_unlocked(__LINE__)

#define test_assert_config_is_unlocked()        atca_test_assert_config_is_unlocked(__LINE__)
#define test_assert_config_is_locked()          atca_test_assert_config_is_locked(__LINE__)
#define test_assert_data_is_unlocked()          atca_test_assert_data_is_unlocked(__LINE__)
#define test_assert_data_is_locked()            atca_test_assert_data_is_locked(__LINE__)
#define test_assert_random_buffer(buf, len)     atca_test_assert_random_buffer(__LINE__, buf, len)

#define check_config_aes_enable()               atca_test_assert_aes_enabled(__LINE__)
#define check_config_ta_sboot_enable(mode)      atca_test_assert_ta_sboot_enabled(__LINE__, mode)
#define check_config_ta_sboot_preboot_enable()  atca_test_assert_ta_sboot_preboot_enabled(__LINE__)


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
#define TEST_TYPE_TEMPLATE_DATA     (12)

typedef struct
{
    uint8_t  test_type;
    uint16_t handle;
    void*    attributes;
} device_object_meta_t;

/* Configuration */
ATCA_STATUS atca_test_config_get_id(uint8_t test_type, uint16_t* handle);

// Helper tests
int run_tests(int test);
void RunAllHelperTests(void);
void RunBasicOtpZero(void);
void RunTNGTests(void);
void RunWPCTests(void);
void RunPbkdf2Tests(void);

/* Setup & Configuration */
void atca_test_config_set_ifacecfg(ATCAIfaceCfg * ifacecfg);
#if defined(ATCA_ECC_SUPPORT) || defined(ATCA_ECC204_SUPPORT) || defined(ATCA_TA010_SUPPORT) || ATCA_TA_SUPPORT
ATCA_STATUS atca_test_genkey(uint16_t key_id, uint8_t *public_key);
#endif
ATCADeviceType atca_test_get_device_type(void);
bool atca_test_cond_p256_all(void);
bool atca_test_cond_p256_sign(void);
bool atca_test_cond_p256_sign_verify(void);
bool atca_test_cond_aes128_ecb(void);
bool atca_test_cond_ecc608(void);
bool atca_test_cond_ta100(void);
bool atca_test_cond_ca2(void);

/* Commands */
int process_options(int argc, char* argv[]);
int select_device(int argc, char* argv[]);

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

int run_otpzero_tests(int argc, char* argv[]);
int run_helper_tests(int argc, char* argv[]);
int run_all_tests(int argc, char* argv[]);

ATCA_STATUS set_chip_mode(uint8_t i2c_user_extra_add, uint8_t ttl_enable, uint8_t watchdog, uint8_t clock_divider);
void update_chip_mode(uint8_t* chip_mode, uint8_t i2c_user_extra_add, uint8_t ttl_enable, uint8_t watchdog, uint8_t clock_divider);
int set_clock_divider_m0(int argc, char* argv[]);
int set_clock_divider_m1(int argc, char* argv[]);
int set_clock_divider_m2(int argc, char* argv[]);
int run_tng_tests(int argc, char* argv[]);
int run_wpc_tests(int argc, char* argv[]);

ATCA_STATUS check_clock_divider(int argc, char* argv[]);

#if defined(_WIN32) || defined(__linux__)
void hex_to_data(const char* hex_str, uint8_t* data, size_t data_size);
#endif

void atca_test_task(void);

#endif /* ATCA_TEST_H_ */
