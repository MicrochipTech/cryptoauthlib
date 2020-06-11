/**
 * \file
 * \brief Basic test for Info command api - TA100
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
#include "test_talib.h"

#if ATCA_TA_SUPPORT

/** \brief This test case read device revision number
 */
TEST(atca_cmd_basic_test, ta_info)
{
    ATCA_STATUS status;
    uint8_t info[TA_REVISION_NUMBER_SIZE];

    status = talib_info(atcab_get_device(), info);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief This test case read device serial number
 */
TEST(atca_cmd_basic_test, info_sernum)
{
    ATCA_STATUS status;
    uint8_t sernum[TA_SERIAL_NUMBER_SIZE];

    status = talib_info_serial_number(atcab_get_device(), sernum);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief This test case gives how much non volatile memory is remaining
 */ 
TEST(atca_cmd_basic_test, info_nv_remain)
{
    ATCA_STATUS status;
    uint32_t nv_remain;

    status = talib_info_get_nv_remain(atcab_get_device(), &nv_remain);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief This test case get the dedicated memory of 16 byte
 */
TEST(atca_cmd_basic_test, info_dedicated_memory)
{
    ATCA_STATUS status;
    uint8_t dedicated_memory[TA_DEDICATED_MEMORY_SIZE];

    status = talib_info_get_dedicated_memory(atcab_get_device(), dedicated_memory);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief This test case get the device chip status (config zone, setup lock and vcc latch)
 */
TEST(atca_cmd_basic_test, info_chip_status)
{
    ATCA_STATUS status;
    uint8_t chip_status[TA_CHIP_STATUS_SIZE];

    status = talib_info_get_chip_status(atcab_get_device(), chip_status);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief This test case check whether the given volatile register id is created or not (valid or not)
 */ 
TEST(atca_cmd_basic_test, info_volreg_status)
{
    ATCA_STATUS status;
    ta_element_attributes_t attr_aes_handle;
    const uint16_t aes_handle = TA_HANDLE_VOLATILE_REGISTER2;
    uint8_t volreg_id;
    uint8_t is_valid;

    status = talib_handle_init_symmetric_key(&attr_aes_handle, TA_KEY_TYPE_AES128, TA_PROP_SYMM_KEY_USAGE_ANY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_hmac_element_with_handle(atcab_get_device(), TA_KEY_TYPE_AES128_SIZE, aes_handle, 
                                                  &attr_aes_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Get the last byte of volatile register id
    volreg_id = aes_handle & 0x000F;

    status = talib_is_volatile_register_valid(atcab_get_device(), volreg_id, &is_valid);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(1, is_valid);
}

/** \brief This test case check whether given handle is valid or not
 */
TEST(atca_cmd_basic_test, info_handle_valid)
{
    ATCA_STATUS status;
    uint16_t handle;
    uint8_t is_valid;

    status = atca_test_config_get_id(TEST_TYPE_ECC_SIGN, &handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_is_handle_valid(atcab_get_device(), handle, &is_valid);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(1, is_valid);
}

/** \brief This test case get the device ROM ID
 */
TEST(atca_cmd_basic_test, info_rom_id)
{
    ATCA_STATUS status;
    uint16_t rom_id;

    status = talib_info_get_rom_id(atcab_get_device(), &rom_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief This test case get the data handle size and verify it.
 */
TEST(atca_cmd_basic_test, info_handle_size)
{
    ATCA_STATUS status;
    size_t handle_size;
    uint16_t handle;
    size_t expected_handle_size = 0x0048;  // Decimal value 72

    status = atca_test_config_get_id(TEST_TYPE_DATA, &handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_info_get_handle_size(atcab_get_device(), (uint32_t)handle, &handle_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(expected_handle_size, handle_size);
}

/** \brief This test case get the given handle - handle info and verify its attributes
 */
TEST(atca_cmd_basic_test, info_handle_attributes)
{
    ATCA_STATUS status;
    ta_element_attributes_t rw_data_attr = { 3, 72, 0, 0, 0, 0x54, 0 };
    uint8_t handle_info[TA_HANDLE_INFO_SIZE];
    uint16_t handle;

    status = atca_test_config_get_id(TEST_TYPE_DATA, &handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_info_get_handle_info(atcab_get_device(), (uint32_t)handle, handle_info);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(handle_info, (uint8_t*)&rw_data_attr, 8);
}

/** \brief This test case check the given auth id is valid or not
 */
TEST(atca_cmd_basic_test, info_auth_status)
{
    ATCA_STATUS status;
    uint8_t is_valid;

    status = talib_is_auth_session_valid(atcab_get_device(), 1, &is_valid);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(false, is_valid);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_info_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ta_info),                       DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_sernum),                   DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_nv_remain),                DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_auth_status),              DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_dedicated_memory),         DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_chip_status),              DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_volreg_status),            DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_handle_valid),             DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_handle_size),              DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_handle_attributes),        DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, info_rom_id),                   DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_info_tests[] = {
    talib_info_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
