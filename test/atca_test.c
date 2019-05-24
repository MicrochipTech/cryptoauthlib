/**
 * \file
 * \brief  Cryptoauthlib Testing: Common Resources & Functions
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
#include "atca_test.h"
#include "atca_execution.h"
#include "app/tng/tng_atca.h"

extern tng_type_t g_tng_test_type;

// gCfg must point to one of the cfg_ structures for any unit test to work.  this allows
// the command console to switch device types at runtime.
ATCAIfaceCfg g_iface_config = {
    .iface_type        = ATCA_UNKNOWN_IFACE,
    .devtype           = ATCA_DEV_UNKNOWN,
    .atcai2c           = {
        .slave_address = 0xC0,
        .bus           = 2,
        .baud          = 400000,
    },
    .wake_delay        = 1500,
    .rx_retries        = 20
};

ATCAIfaceCfg *gCfg = &g_iface_config;

const uint8_t g_slot4_key[] = {
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
    0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
    0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0d, 0xb1, 0xe3
};

uint8_t test_ecc608_configdata[ATCA_ECC_CONFIG_SIZE] = {
    0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x04, 0x05, 0x06, 0x07, 0xEE, 0x01, 0x01, 0x00,  //15
    0xC0, 0x00, 0xA1, 0x00, 0xAF, 0x2F, 0xC4, 0x44, 0x87, 0x20, 0xC4, 0xF4, 0x8F, 0x0F, 0x0F, 0x0F,  //31, 5
    0x9F, 0x8F, 0x83, 0x64, 0xC4, 0x44, 0xC4, 0x64, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,  //47
    0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,  //63
    0x00, 0x00, 0x00, 0x00, 0xFF, 0x84, 0x03, 0xBC, 0x09, 0x69, 0x76, 0x00, 0x00, 0x00, 0x00, 0x00,  //79
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x0E, 0x40, 0x00, 0x00, 0x00, 0x00,  //95
    0x33, 0x00, 0x1C, 0x00, 0x13, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x3E, 0x00, 0x1C, 0x00, 0x33, 0x00,  //111
    0x1C, 0x00, 0x1C, 0x00, 0x38, 0x10, 0x30, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x32, 0x00, 0x30, 0x00   //127
};

const uint8_t test_ecc_configdata[ATCA_ECC_CONFIG_SIZE] = {
    0x01, 0x23, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x04, 0x05, 0x06, 0x07, 0xEE, 0x00, 0x01, 0x00, //15
    0xC0, 0x00, 0x55, 0x00, 0x8F, 0x2F, 0xC4, 0x44, 0x87, 0x20, 0xC4, 0xF4, 0x8F, 0x0F, 0x8F, 0x8F, //31, 5
    0x9F, 0x8F, 0x83, 0x64, 0xC4, 0x44, 0xC4, 0x64, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, //47
    0x0F, 0x0F, 0x0F, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, //63
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //79
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //95
    0x33, 0x00, 0x1C, 0x00, 0x13, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x1C, 0x00, 0x1C, 0x00, 0x33, 0x00, //111
    0x1C, 0x00, 0x1C, 0x00, 0x3C, 0x00, 0x30, 0x00, 0x3C, 0x00, 0x3C, 0x00, 0x32, 0x00, 0x30, 0x00  //127
};

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
    pause_basic_test_info,
    updateextra_basic_test_info,
    counter_basic_test_info,
    (t_test_case_info*)NULL, /* Array Termination element*/
};

t_test_case_info* unit_tests[] =
{
    startup_unit_test_info,
    info_unit_test_info,
    aes_unit_test_info,
    verify_unit_test_info,
    derivekey_unit_test_info,
    sha_unit_test_info,
    hmac_unit_test_info,
    sign_unit_test_info,
    mac_unit_test_info,
    ecdh_unit_test_info,
    write_unit_test_info,
    read_unit_test_info,
    genkey_unit_test_info,
    privwrite_unit_test_info,
    lock_unit_test_info,
    kdf_unit_test_info,
    sboot_unit_test_info,
    selftest_unit_test_info,
    gendig_unit_test_info,
    random_unit_test_info,
    nonce_unit_test_info,
    pause_unit_test_info,
    updateextra_unit_test_info,
    counter_unit_test_info,
    (t_test_case_info*)NULL, /* Array Termination element*/
};

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
    tng_atca_unit_test_info,
#ifndef DO_NOT_TEST_CERT
    tng_atcacert_client_unit_test_info,
#endif
    (t_test_case_info*)NULL, /* Array Termination element*/
};


void RunAllTests(t_test_case_info** tests_list)
{
    t_test_case_info* sp_current_test;
    uint8_t support_device_mask;

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
    RunAllTests(unit_tests);
}

void RunBasicOtpZero(void)
{
    RunAllTests(otpzero_tests);
}

void RunAllHelperTests(void)
{
    RunAllTests(helper_tests);
}

void RunTNG22Tests(void)
{
    g_tng_test_type = TNGTYPE_22;
    RunAllTests(tng_tests);
}

void RunTNGTNTests(void)
{
    g_tng_test_type = TNGTYPE_TN;
    RunAllTests(tng_tests);
}


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

#ifdef ATCA_NO_HEAP
extern struct atca_device g_atcab_device;
extern struct atca_command g_atcab_command;
extern struct atca_iface g_atcab_iface;
#endif

/**
 * \brief Initialize the interface and check it was successful
 */
void test_assert_interface_init(void)
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
        TEST_ASSERT_NULL(_gDevice);
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
    TEST_ASSERT_NOT_NULL(_gDevice);
#endif

    if (_gDevice->mCommands->dt == ATECC608A)
    {
        // Set the clock divider, which should be the same value as the test config
        _gDevice->mCommands->clock_divider = test_ecc608_configdata[ATCA_CHIPMODE_OFFSET] & ATCA_CHIPMODE_CLOCK_DIV_MASK;
    }
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

void test_assert_config_is_unlocked(void)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_locked(LOCK_ZONE_CONFIG, &is_locked);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (is_locked)
    {
        TEST_IGNORE_MESSAGE("Config zone must be unlocked for this test.");
    }
}

void test_assert_config_is_locked(void)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_locked(LOCK_ZONE_CONFIG, &is_locked);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (!is_locked)
    {
        TEST_IGNORE_MESSAGE("Config zone must be locked for this test.");
    }
}

void test_assert_data_is_unlocked(void)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_locked(LOCK_ZONE_DATA, &is_locked);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (is_locked)
    {
        TEST_IGNORE_MESSAGE("Data zone must be unlocked for this test.");
    }
}

void test_assert_data_is_locked(void)
{
    bool is_locked = false;
    ATCA_STATUS status = atcab_is_locked(LOCK_ZONE_DATA, &is_locked);

    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if (!is_locked)
    {
        TEST_IGNORE_MESSAGE("Data zone must be locked for this test.");
    }
}


//The Function checks the AES_ENABLE byte in configuration zone , if it is not set, it skips the test
void check_config_aes_enable(void)
{
    ATCA_STATUS status;
    uint8_t aes_enable;

    // Byte 13 of the config zone contains the AES enable bit
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 13, &aes_enable, 1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    if ((aes_enable & AES_CONFIG_ENABLE_BIT_MASK) == 0)
    {
        TEST_IGNORE_MESSAGE("Ignoring the test, AES is not enabled in config zone");
    }
}

void unit_test_assert_config_is_locked(void)
{
    if (!atcau_is_locked(LOCK_ZONE_CONFIG))
    {
        TEST_IGNORE_MESSAGE("Config zone must be locked for this test.");
    }
}
void unit_test_assert_config_is_unlocked(void)
{
    if (atcau_is_locked(LOCK_ZONE_CONFIG))
    {
        TEST_IGNORE_MESSAGE("Config zone must be unlocked for this test.");
    }
}

void unit_test_assert_data_is_locked(void)
{
    if (!atcau_is_locked(LOCK_ZONE_DATA))
    {
        TEST_IGNORE_MESSAGE("Data zone must be locked for this test.");
    }
}

void unit_test_assert_data_is_unlocked(void)
{
    if (atcau_is_locked(LOCK_ZONE_DATA))
    {
        TEST_IGNORE_MESSAGE("Data zone must be unlocked for this test.");
    }
}


