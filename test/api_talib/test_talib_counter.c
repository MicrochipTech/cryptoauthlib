/**
 * \file
 * \brief Basic test for Counter command api - TA100
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

/** \brief This test cases read and incremnet the COUNTER 1 value.
 *         i)   Execute counter command in read mode to read the initial value
 *         ii)  Manually incremnent the read value by 1
 *         iii) Execute counter command in increment mode and read the counter value after increment
 *         iv)  verify both value (incremented by device and incremnted by user)
 */  
TEST(atca_cmd_basic_test, ta_counter_test)
{
    ATCA_STATUS status;
    uint32_t counter_value1;
    uint32_t counter_value2;

    // Read current counter value
    status = talib_counter_read(atcab_get_device(), TA_HANDLE_COUNTER1, &counter_value1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Increment counter and make sure new value is 1 higher
    status = talib_counter_increment(atcab_get_device(), TA_HANDLE_COUNTER1, &counter_value2);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(counter_value1 + 1, counter_value2);

    // Increment again with NULL
    status = talib_counter_increment(atcab_get_device(), TA_HANDLE_COUNTER1, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Re-read counter value to double check
    status = talib_counter_read(atcab_get_device(), TA_HANDLE_COUNTER1, &counter_value1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(counter_value2 + 1, counter_value1);

    // Check bad counter ID
    status = talib_counter_increment(atcab_get_device(), 3, NULL);
    TEST_ASSERT_EQUAL(TA_BAD_HANDLE, status);
}

/** \brief This test case assign counter2 to private key handle and counter value will be incremented for each 
 *         use of the key and also this test cases verify counter increment is happening for every single use 
 *         of the key.
 */
TEST(atca_cmd_basic_test, ta_counter_match)
{
    ATCA_STATUS status;
    uint32_t counter2_value;
    uint32_t counter_match;
    uint16_t private_key_handle;
    ta_element_attributes_t attr_private_key_handle;
    uint8_t message[TA_SIGN_P256_MSG_SIZE];
    uint8_t signature[TA_SIGN_P256_SIG_SIZE];
    uint8_t pub_key[TA_ECC256_PUB_KEY_SIZE];
    bool is_verified = false;

    status = talib_counter_read(atcab_get_device(), TA_HANDLE_COUNTER2, &counter2_value);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    counter_match = counter2_value;

    status = talib_handle_init_private_key(&attr_private_key_handle, TA_KEY_TYPE_ECCP256, 
                                          TA_ALG_MODE_ECC_ECDSA, TA_PROP_SIGN_INT_EXT_DIGEST,
                                          TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    attr_private_key_handle.byte7_settings |= 0x02; // Tied counter2 to private key handle

    status = talib_create_element(atcab_get_device(), &attr_private_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_genkey((uint32_t)private_key_handle, pub_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_random(message);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_sign(private_key_handle, message, signature);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_counter_read(atcab_get_device(), TA_HANDLE_COUNTER2, &counter2_value);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(counter_match + 1, counter2_value); // Counter should now equal the counter match value

    status = atcab_verify_extern(message, signature, pub_key, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_counter_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ta_counter_test),           DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ta_counter_match),          DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_counter_tests[] = {
    talib_counter_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
