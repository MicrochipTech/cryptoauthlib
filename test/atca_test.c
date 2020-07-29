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
#if ATCA_CA_SUPPORT
#include "api_calib/test_calib.h"
#endif
#if ATCA_TA_SUPPORT
#include "api_talib/test_talib.h"
#endif

const char* ATCA_TEST_HELPER_FILE = "In helper: " __FILE__;

const char* TEST_GROUP_atca_cmd_basic_test = "atca_cmd_basic_test";
const char* TEST_GROUP_atca_cmd_unit_test = "atca_cmd_unit_test";

bool g_atca_test_quiet_mode = false;

#ifdef ATCA_SHA_SUPPORT

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

t_test_case_info* basic_tests[] =
{
    startup_basic_test_info,
    info_basic_test_info,
    aes_basic_test_info,
    aes_cbc_basic_test_info,
    aes_cmac_basic_test_info,
    aes_ctr_basic_test_info,
    aes_gcm_basic_test_info,
    verify_basic_test_info,
    derivekey_basic_test_info,
    sha_basic_test_info,
    hmac_basic_test_info,
    sign_basic_test_info,
    mac_basic_test_info,
    ecdh_basic_test_info,
    write_basic_test_info,
    read_basic_test_info,
    genkey_basic_test_info,
    privwrite_basic_test_info,
    lock_basic_test_info,
    kdf_basic_test_info,
    sboot_basic_test_info,
    selftest_basic_test_info,
    gendig_basic_test_info,
    random_basic_test_info,
    nonce_basic_test_info,
    updateextra_basic_test_info,
    counter_basic_test_info,
    (t_test_case_info*)NULL, /* Array Termination element*/
};

#if ATCA_CA_SUPPORT
t_test_case_info* unit_tests[] =
{
    calib_commands_info,
    calib_packet_info,
    (t_test_case_info*)NULL, /* Array Termination element*/
};
#endif

t_test_case_info* otpzero_tests[] =
{
    otpzero_basic_test_info,
    (t_test_case_info*)NULL, /* Array Termination element*/
};

t_test_case_info* helper_tests[] =
{
    helper_basic_test_info,
    jwt_unit_test_info,
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


void RunAllTests(t_test_case_info** tests_list)
{
    t_test_case_info* sp_current_test;
    uint32_t support_device_mask;

    /*Loop through all the commands test info*/
    while (*tests_list != NULL)
    {
        /*Get current command test info*/
        sp_current_test = *tests_list;

        /*Loop through till last test in the test info*/
        while (sp_current_test->fp_test != NULL)
        {
            /*Get current device mask*/
            support_device_mask = DEVICE_MASK(gCfg->devtype);

            /*check if current test mask contains current device mask*/
            if ((sp_current_test->support_device_mask & support_device_mask) == support_device_mask)
            {
                /*Execute current test case*/
                sp_current_test->fp_test();
            }

            /*Move to next test*/
            sp_current_test++;
        }

        /*Move to next command*/
        tests_list++;
    }
}

void RunAllBasicTests(void)
{
    RunAllTests(basic_tests);
};

void RunAllFeatureTests(void)
{
#if ATCA_CA_SUPPORT
    RunAllTests(unit_tests);
#endif
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

#if 0 // ATCA_CA_SUPPORT
static bool atcau_is_locked(uint8_t zone)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;

    // build an read command
    packet.param1 = 0x00;
    packet.param2 = 0x15;
    status = atRead(ca_cmd, &packet);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atca_execute_command(&packet, _gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    switch (zone)
    {
    case LOCK_ZONE_DATA:
        return packet.data[ATCA_RSP_DATA_IDX + 2] == 0;
        break;
    case LOCK_ZONE_CONFIG:
        return packet.data[ATCA_RSP_DATA_IDX + 3] == 0;
        break;
    default:
        TEST_FAIL_MESSAGE("Invalid lock zone");
        break;
    }
    return false;
}
#endif

#ifdef ATCA_NO_HEAP
ATCA_DLL ATCADevice _gDevice;
ATCA_DLL struct atca_device g_atcab_device;
ATCA_DLL struct atca_command g_atcab_command;
ATCA_DLL struct atca_iface g_atcab_iface;
#endif

/**
 * \brief Initialize the interface and check it was successful
 */
void test_assert_interface_init()
{
#ifdef ATCA_NO_HEAP
    ATCA_STATUS status;
#endif

    // If the device is still connected - disconnect it
    if (_gDevice)
    {
#ifdef ATCA_NO_HEAP
        status = releaseATCADevice(_gDevice);
        _gDevice = NULL;
#else
        deleteATCADevice(&_gDevice);
        TEST_ASSERT_NULL_MESSAGE(_gDevice, ATCA_TEST_HELPER_FILE);
#endif
    }

    // Get the device
#ifdef ATCA_NO_HEAP
    g_atcab_device.mCommands = &g_atcab_command;
    g_atcab_device.mIface    = &g_atcab_iface;
    status = initATCADevice(gCfg, &g_atcab_device);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    _gDevice = &g_atcab_device;
#else
    _gDevice = newATCADevice(gCfg);
    TEST_ASSERT_NOT_NULL_MESSAGE(_gDevice, ATCA_TEST_HELPER_FILE);
#endif

#ifdef ATCA_ATECC608_SUPPORT
    if (ATECC608 == (_gDevice->mCommands->dt))
    {
        // Set the clock divider, which should be the same value as the test config
        _gDevice->mCommands->clock_divider = test_ecc608_configdata[ATCA_CHIPMODE_OFFSET] & ATCA_CHIPMODE_CLOCK_DIV_MASK;
    }
#endif
}

/**
 * \brief Clean up the allocated interface
 */
void test_assert_interface_deinit(void)
{
    ATCA_STATUS status;

    TEST_ASSERT((_gDevice != NULL) && (_gDevice->mIface != NULL));

    status = atwake(_gDevice->mIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atsleep(_gDevice->mIface);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_NO_HEAP
    status = releaseATCADevice(_gDevice);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    _gDevice = NULL;
#else
    deleteATCADevice(&_gDevice);
    TEST_ASSERT_NULL(_gDevice);
#endif
}

void atca_test_assert_config_is_unlocked(UNITY_LINE_TYPE from_line)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_config_locked(&is_locked);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (is_locked)
    {
        TEST_IGNORE_MESSAGE("Config zone must be unlocked for this test.");
    }
}

void atca_test_assert_config_is_locked(UNITY_LINE_TYPE from_line)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_config_locked(&is_locked);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (!is_locked)
    {
        TEST_IGNORE_MESSAGE("Config zone must be locked for this test.");
    }
}

void atca_test_assert_data_is_unlocked(UNITY_LINE_TYPE from_line)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_data_locked(&is_locked);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

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


//The Function checks the AES_ENABLE byte in configuration zone , if it is not set, it skips the test
void atca_test_assert_aes_enabled(UNITY_LINE_TYPE from_line)
{
    if (TA100 != gCfg->devtype)
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
#if ATCA_TA_SUPPORT
        case TA100:
            status = talib_config_get_handle_by_test(test_type, handle);
            break;
#endif
        default:
            break;
        }
    }

    if (ATCA_UNIMPLEMENTED == status)
    {
        TEST_IGNORE_MESSAGE("Device Configuration does not support this test");
    }

    return status;
}

TEST_SETUP(atca_cmd_basic_test)
{
    UnityMalloc_StartTest();

    ATCA_STATUS status = atcab_init(gCfg);

    TEST_ASSERT_EQUAL_INT_MESSAGE(ATCA_SUCCESS, status, ATCA_TEST_HELPER_FILE);
}

TEST_TEAR_DOWN(atca_cmd_basic_test)
{
    ATCA_STATUS status;

    status = atcab_wakeup();
    TEST_ASSERT_EQUAL_INT_MESSAGE(ATCA_SUCCESS, status, ATCA_TEST_HELPER_FILE);

    status = atcab_sleep();
    TEST_ASSERT_EQUAL_INT_MESSAGE(ATCA_SUCCESS, status, ATCA_TEST_HELPER_FILE);

    status = atcab_release();
    TEST_ASSERT_EQUAL_INT_MESSAGE(ATCA_SUCCESS, status, ATCA_TEST_HELPER_FILE);

    UnityMalloc_EndTest();
}

TEST_SETUP(atca_cmd_unit_test)
{
    test_assert_interface_init();
}

TEST_TEAR_DOWN(atca_cmd_unit_test)
{
    test_assert_interface_deinit();
}
