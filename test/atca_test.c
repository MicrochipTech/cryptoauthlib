/**
 * \file
 * \brief  Cryptoauthlib Testing: Common Resources & Functions
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */
#include "atca_test.h"
#include "atca_execution.h"

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

t_test_case_info* basic_tests[] =
{
    startup_basic_test_info,
    info_basic_test_info,
    aes_basic_test_info,
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

static int atcau_get_addr(uint8_t zone, uint8_t slot, uint8_t block, uint8_t offset, uint16_t* addr)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if (addr == NULL)
    {
        return ATCA_BAD_PARAM;
    }
    if (zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_DATA && zone != ATCA_ZONE_OTP)
    {
        return ATCA_BAD_PARAM;;
    }
    *addr = 0;
    offset = offset & (uint8_t)0x07;

    if ((zone == ATCA_ZONE_CONFIG) || (zone == ATCA_ZONE_OTP))
    {
        *addr = block << 3;
        *addr |= offset;
    }
    else if (zone == ATCA_ZONE_DATA)
    {
        *addr = slot << 3;
        *addr |= offset;
        *addr |= block << 8;
    }
    else
    {
        status = ATCA_BAD_PARAM;
    }
    return status;
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

/**
 * \brief Initialize the interface and check it was successful
 */
void test_assert_interface_init(void)
{
    /* If the device is still connected - disconnect it */
    if (_gDevice)
    {
        deleteATCADevice(&_gDevice);
        TEST_ASSERT_NULL(_gDevice);
    }

    /* Get the device */
    _gDevice = newATCADevice(gCfg);
    TEST_ASSERT_NOT_NULL(_gDevice);

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

    deleteATCADevice(&_gDevice);
    TEST_ASSERT_NULL(_gDevice);
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


