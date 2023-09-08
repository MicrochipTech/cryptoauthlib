/**
 * \file
 * \brief  Cryptoauthlib Testing: Common Resources & Functions
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
#include "cryptoauthlib.h"
#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
#include "app/tng/tng_atca.h"
#define ATCA_TEST_TNG
#endif
#if defined(ATCA_WPC_SUPPORT)
#include "app/wpc/wpc_apis.h"
#define ATCA_TEST_WPC
#endif
#if ATCA_CA_SUPPORT
#include "api_calib/test_calib.h"
#endif
#if ATCA_TA_SUPPORT
#include "api_talib/test_talib.h"
#endif

/* Access to test runner internal details */
extern struct UNITY_STORAGE_T Unity;

/* Track the last status code for the last command run (early abort) */
ATCA_STATUS g_last_status;

/* Terminate all testing immediately */
bool g_test_abort;

/* Answer yes to prompts in the next command run */
bool g_atca_test_quiet_mode = false;

#ifdef ATCA_ATSHA204A_SUPPORT
const uint8_t sha204_default_config[ATCA_SHA_CONFIG_SIZE] = {
    // block 0
    // Not Written: First 16 bytes are not written
    0x01, 0x23, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xEE, 0x55, 0x00, 0x00,
    // I2C, CheckMacConfig, OtpMode, SelectorMode
    0xC8, 0x00, 0x55, 0x00,
    // SlotConfig
    0x8F, 0x80, 0x80, 0xA1,
    0x82, 0xE0, 0xC4, 0xF4,
    0x84, 0x00, 0xA0, 0x85,
    // block 1
    0x86, 0x40, 0x87, 0x07,
    0x0F, 0x00, 0xC4, 0x64,
    0x8A, 0x7A, 0x0B, 0x8B,
    0x0C, 0x4C, 0xDD, 0x4D,
    0xC2, 0x42, 0xAF, 0x8F,
    // Use Flags
    0xFF, 0x00, 0xFF, 0x00,
    0xFF, 0x00, 0xFF, 0x00,
    0xFF, 0x00, 0xFF, 0x00,
    // block 2
    0xFF, 0x00, 0xFF, 0x00,
    // Last Key Use
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    // Not Written: UserExtra, Selector, LockData, LockConfig (word offset = 5)
    0x00, 0x00, 0x55, 0x55,
};
#endif

// These keys are chosen specifically to test the CMAC subkey generation code.
// When the keys are used to encrypt an all-zero block we need all bit
// combinations of the uppermost 2 bits (0b00, 0b01, 0b10, 0b11)
// 2B7E151628AED2A6ABF7158809CF4F3C AESEnc(0)=7DF76B0C1AB899B33E42F047B91B546F 7D=0b01 111101
// 6BE163D42B623E70D164FA145DB1D463 AESEnc(0)=EEA8C3FD920AC8D3D3A424E473C56B4A EE=0b11 101110
// 7058710B58E1E665D3D2F5B465176403 AESEnc(0)=38AE4CF5CAB844CF6D1463044C8749AE 38=0b00 111000
// 114443FA8E9614845EC7296CD13BC9DC AESEnc(0)=863496604DDD579049A63908D49853D5 86=0b10 000110
// The first key is one commonly used by NIST for some AES test vectors
const uint8_t g_aes_keys[4][16] = {
    { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C },
    { 0x6B, 0xE1, 0x63, 0xD4, 0x2B, 0x62, 0x3E, 0x70, 0xD1, 0x64, 0xFA, 0x14, 0x5D, 0xB1, 0xD4, 0x63 },
    { 0x70, 0x58, 0x71, 0x0B, 0x58, 0xE1, 0xE6, 0x65, 0xD3, 0xD2, 0xF5, 0xB4, 0x65, 0x17, 0x64, 0x03 },
    { 0x11, 0x44, 0x43, 0xFA, 0x8E, 0x96, 0x14, 0x84, 0x5E, 0xC7, 0x29, 0x6C, 0xD1, 0x3B, 0xC9, 0xDC }
};

// Input plaintext for testing.
// This input test data is commonly used by NIST for some AES test vectors
const uint8_t g_plaintext[64] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

t_test_case_info* otpzero_tests[] =
{
    otpzero_basic_test_info,
    (t_test_case_info*)NULL, /* Array Termination element*/
};

t_test_case_info* helper_tests[] =
{
    helper_basic_test_info,
    buffer_test_info,
    (t_test_case_info*)NULL, /* Array Termination element*/
};

t_test_case_info* tng_tests[] =
{
#ifdef ATCA_TEST_TNG
    tng_atca_unit_test_info,
#ifndef DO_NOT_TEST_CERT
    tng_atcacert_client_unit_test_info,
#endif
#endif
    (t_test_case_info*)NULL, /* Array Termination element*/
};

t_test_case_info* wpc_tests[] =
{
#ifdef ATCA_TEST_WPC
    wpc_apis_unit_test_info,
#ifndef DO_NOT_TEST_CERT
    wpccert_client_unit_test_info,
#endif
#endif
    (t_test_case_info*)NULL, /* Array Termination element*/
};

/** \brief Runs a test suite or individual test - the function is expected to call
 * unity test operations
 */
int run_test(int argc, char* argv[], void (*fptest)(void))
{
    int ret;

    if (CMD_PROCESSOR_MAX_ARGS > argc)
    {
        argv[argc++] = "-v";
    }

    /* Reset the last status result */
    g_last_status = ATCA_SUCCESS;

    /* Reset the abort */
    g_test_abort = false;

    /* Launch the unity test framework */
    ret = UnityMain(argc, (const char**)argv, fptest);

    if (!ret && !Unity.NumberOfTests)
    {
        /* The assumption is that tests were supposed to have been run so if
           non were executed the assumption is there is a configuration problem.
           If a test suite has no tests for a given configuration don't run it */
        printf("No tests were run for this configuration\n");
        ret = -1;
    }
    return ret;
}

void RunAllTests(t_test_case_info** tests_list)
{
    t_test_case_info* sp_current_test;

    /*Loop through all the commands test info*/
    while ((*tests_list != NULL) && !atca_test_unresponsive())
    {
        /*Get current command test info*/
        sp_current_test = *tests_list;

        /*Loop through till last test in the test info*/
        while (sp_current_test->fp_test != NULL)
        {
            bool run_test = (NULL != sp_current_test->fp_condition) ? sp_current_test->fp_condition() : true;

            if (run_test)
            {
                /*Execute current test case*/
                sp_current_test->fp_test();
            }

            if (atca_test_unresponsive())
            {
                /* Early return on communication failures */
                break;
            }

            /*Move to next test*/
            sp_current_test++;
        }

        /*Move to next command*/
        tests_list++;
    }
}

void RunBasicOtpZero(void)
{
    RunAllTests(otpzero_tests);
}

void RunAllHelperTests(void)
{
    RunAllTests(helper_tests);
}

void RunTNGTests(void)
{
    RunAllTests(tng_tests);
}

void RunWPCTests(void)
{
    RunAllTests(wpc_tests);
}

#ifdef ATCA_NO_HEAP
ATCA_DLL ATCADevice g_atcab_device_ptr;
ATCA_DLL struct atca_device g_atcab_device;
ATCA_DLL struct atca_command g_atcab_command;
ATCA_DLL struct atca_iface g_atcab_iface;
#endif

bool atca_test_unresponsive(void)
{
    return g_test_abort || (ATCA_COMM_FAIL == g_last_status) || (ATCA_WAKE_FAILED == g_last_status);
}

bool atca_test_already_exiting(void)
{
    return Unity.CurrentTestFailed || Unity.CurrentTestIgnored;
}

void atca_test_assert_config_is_unlocked(UNITY_LINE_TYPE from_line)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_config_locked(&is_locked);

    UNITY_TEST_ASSERT_EQUAL_INT(ATCA_SUCCESS, status, from_line, NULL);

    if (is_locked)
    {
        TEST_IGNORE_MESSAGE("Config zone must be unlocked for this test.");
    }
}

void atca_test_assert_config_is_locked(UNITY_LINE_TYPE from_line)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_config_locked(&is_locked);

    UNITY_TEST_ASSERT_EQUAL_INT(ATCA_SUCCESS, status, from_line, NULL);

    if (!is_locked)
    {
        TEST_IGNORE_MESSAGE("Config zone must be locked for this test.");
    }
}

void atca_test_assert_data_is_unlocked(UNITY_LINE_TYPE from_line)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_data_locked(&is_locked);

    UNITY_TEST_ASSERT_EQUAL_INT(ATCA_SUCCESS, status, from_line, NULL);

    if (is_locked)
    {
        TEST_IGNORE_MESSAGE("Data zone must be unlocked for this test.");
    }
}

void atca_test_assert_data_is_locked(UNITY_LINE_TYPE from_line)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_data_locked(&is_locked);

    UNITY_TEST_ASSERT_EQUAL_INT(ATCA_SUCCESS, status, from_line, NULL);

    if (!is_locked)
    {
        TEST_IGNORE_MESSAGE("Data zone must be locked for this test.");
    }
}

/** \brief Check to ensure that not too many instances of the same value appear in the
 * buffer to make sure something came through the API. This is not an actual randomness
 * qualification test but should catch most invalid conditions such as buffer misalignment,
 * failing to copy, etc.
 */
void atca_test_assert_random_buffer(UNITY_LINE_TYPE from_line, uint8_t * buf, size_t buflen)
{
    uint8_t hg[256];
    size_t i;

    (void)memset(hg, 0, sizeof(hg));

    UNITY_TEST_ASSERT_NOT_NULL(buf, from_line, NULL);

    for (i = 0; i < buflen; i++)
    {
        hg[buf[i]]++;
    }

#ifdef ATCA_PRINTF
    size_t printed = 0;
    printf("\n");
    for (i = 0; i < sizeof(hg); i++)
    {
        if (0 < hg[i])
        {
            printf("%3d: %d, ", i, hg[i]);
            printed++;
            if (0 == printed % 8)
            {
                printf("\n");
            }
        }
    }
    printf("\n");
#endif

    for (i = 0; i < sizeof(hg); i++)
    {
        UNITY_TEST_ASSERT_SMALLER_OR_EQUAL_INT(buflen / 4 ? buflen / 4 : 1, hg[i], from_line,
                                               "Buffer has a significant count of the same value");
    }
}

//The Function checks the AES_ENABLE byte in configuration zone , if it is not set, it skips the test
void atca_test_assert_aes_enabled(UNITY_LINE_TYPE from_line)
{
    if (!atcab_is_ta_device(gCfg->devtype))
    {
        ATCA_STATUS status;
        uint8_t aes_enable;

        // Byte 13 of the config zone contains the AES enable bit
        status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 13, &aes_enable, 1);
        UNITY_TEST_ASSERT_EQUAL_INT(ATCA_SUCCESS, status, from_line, NULL);

        if ((aes_enable & AES_CONFIG_ENABLE_BIT_MASK) == 0)
        {
            TEST_IGNORE_MESSAGE("Ignoring the test, AES is not enabled in config zone");
        }
    }
}

#if ATCA_TA_SUPPORT
//The Function checks the Secureboot mode byte in configuration zone , if it is not set, it skips the test
void atca_test_assert_ta_sboot_enabled(UNITY_LINE_TYPE from_line, uint8_t mode)
{
    if (atcab_is_ta_device(gCfg->devtype))
    {
        ATCA_STATUS status;
        uint8_t check_config_sboot_enable[8];
        uint16_t config_size = sizeof(check_config_sboot_enable);
        cal_buffer check_config_sboot_enable_buf = CAL_BUF_INIT(config_size, check_config_sboot_enable);

        // Bytes 32 of the config zone contains the Secure boot config bit
        status = talib_read_partial_element(atcab_get_device(), TA_HANDLE_CONFIG_MEMORY, 32, &check_config_sboot_enable_buf);
        UNITY_TEST_ASSERT_EQUAL_INT(ATCA_SUCCESS, status, from_line, NULL);

        if ((check_config_sboot_enable[0] & TA_SECUREBOOT_CONFIG_MODE_MASK) != mode)
        {
            TEST_IGNORE_MESSAGE("Ignoring the test, Secureboot mode is not configured");
        }
    }
}

//The Function checks the Secureboot preboot mode byte in configuration zone , if it is not set, it skips the test
void atca_test_assert_ta_sboot_preboot_enabled(UNITY_LINE_TYPE from_line)
{
    if (atcab_is_ta_device(gCfg->devtype))
    {
        ATCA_STATUS status;
        uint8_t check_config_sboot_enable[8];
        uint16_t config_size = sizeof(check_config_sboot_enable);
        cal_buffer check_config_sboot_enable_buf = CAL_BUF_INIT(config_size, check_config_sboot_enable);

        // Bytes 32 of the config zone contains the Secure boot config bit
        status = talib_read_partial_element(atcab_get_device(), TA_HANDLE_CONFIG_MEMORY, 32, &check_config_sboot_enable_buf);
        UNITY_TEST_ASSERT_EQUAL_INT(ATCA_SUCCESS, status, from_line, NULL);

        if ((check_config_sboot_enable[1] & TA_SECUREBOOT_CONFIG_PREBOOT_ENABLE_MASK)
            != TA_SECUREBOOT_CONFIG_PREBOOT_ENABLE_MASK)
        {
            TEST_IGNORE_MESSAGE("Ignoring the test, Secureboot preboot is not configured");
        }
    }
}
#endif

ATCA_STATUS atca_test_config_get_id(uint8_t test_type, uint16_t* handle)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (test_type && handle)
    {
        switch (gCfg->devtype)
        {
#if ATCA_CA_SUPPORT
        case ATSHA204A:
        /* fallthrough */
        case ATECC108A:
        /* fallthrough */
        case ATECC508A:
        /* fallthrough */
        case ATECC608:
            status = calib_config_get_slot_by_test(test_type, handle);
            break;
#endif
#if defined(ATCA_TA010_SUPPORT) || defined(ATCA_ECC204_SUPPORT)
        case TA010:
        /* fallthrough */
        case ECC204:
            status = calib_config_get_ecc204_slot_by_test(test_type, handle);
            break;
#endif
#if defined(ATCA_SHA104_SUPPORT) || defined(ATCA_SHA105_SUPPORT)
        case SHA104:
        /* fallthrough */
        case SHA105:
            status = calib_config_get_sha10x_slot_by_test(test_type, handle);
            break;
#endif
#if ATCA_TA_SUPPORT
        case TA100:
            status = talib_config_get_handle_by_test(test_type, handle);
            break;
#endif
        default:
            status = ATCA_UNIMPLEMENTED;
            break;
        }
    }

    if (ATCA_UNIMPLEMENTED == status)
    {
        TEST_IGNORE_MESSAGE("Device Configuration does not support this test");
    }

    return status;
}

/* Helper function to execute genkey and retry if there are failures since there is
   a chance that the genkey will fail to produce a valid keypair and a retry is nearly
   always successful */
#if defined(ATCA_ECC_SUPPORT) || defined(ATCA_ECC204_SUPPORT) || defined(ATCA_TA010_SUPPORT) || ATCA_TA_SUPPORT
ATCA_STATUS atca_test_genkey(uint16_t key_id, uint8_t *public_key)
{
    int attempts = 2;
    ATCA_STATUS status;

    do
    {
        status = atcab_genkey(key_id, public_key);
    }
    while (status && --attempts);
    return status;
}
#endif
