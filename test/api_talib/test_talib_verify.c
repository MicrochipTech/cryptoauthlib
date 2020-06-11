/**
 * \file
 * \brief Basic test for Verify command api - TA100
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

/** \brief Execute an verify command to find an Y value of public key using known X value of public key
 */ 
TEST(atca_cmd_basic_test, verify_point_exp)
{
    ATCA_STATUS status;
    const uint8_t eccp256_pub_key[TA_ECC256_PUB_KEY_SIZE] = {
        0x8F, 0x8D, 0x18, 0x2B, 0xD8, 0x19, 0x04, 0x85, 0x82, 0xA9, 0x92, 0x7E, 0xA0, 0xC5, 0x6D, 0xEF,
        0xB4, 0x15, 0x95, 0x48, 0xE1, 0x1C, 0xA5, 0xF7, 0xAB, 0xAC, 0x45, 0xBB, 0xCE, 0x76, 0x81, 0x5B,
        0xE5, 0xC6, 0x4F, 0xCD, 0x2F, 0xD1, 0x26, 0x98, 0x54, 0x4D, 0xE0, 0x37, 0x95, 0x17, 0x26, 0x66,
        0x60, 0x73, 0x04, 0x61, 0x19, 0xAD, 0x5E, 0x11, 0xA9, 0x0A, 0xA4, 0x97, 0x73, 0xAE, 0xAC, 0x86
    };
    uint8_t x_known_val[TA_VERIFY_X_VAL_MAX_SIZE];
    uint8_t y_value[TA_VERIFY_Y_VAL_MAX_SIZE];

    // Copy the x value
    memcpy(x_known_val, eccp256_pub_key, TA_VERIFY_X_VAL_MAX_SIZE);

    status = talib_verify_point_exp(atcab_get_device(), TA_VERIFY_Y_IS_EVEN, x_known_val, y_value);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(y_value, &eccp256_pub_key[32], sizeof(y_value));
}

/** \brief Execute verify operation to verify the signature using ECCP384 public key stored in shared data.
 */ 
TEST(atca_cmd_basic_test, verify_p384pubkey_stored)
{
    ATCA_STATUS status;
    uint16_t private_key_handle;
    uint16_t public_key_handle;
    ta_element_attributes_t attr_priv_key_handle;
    ta_element_attributes_t attr_pub_key_handle;
    uint8_t pub_key[TA_ECC384_PUB_KEY_SIZE];
    size_t pub_key_len = sizeof(pub_key);
    uint8_t message[TA_SIGN_P384_MSG_SIZE];
    const uint16_t message_len = sizeof(message);
    uint8_t signature[TA_SIGN_P384_SIG_SIZE];
    uint16_t sign_size = sizeof(signature);
    bool is_verified = false;

    status = talib_handle_init_private_key(&attr_priv_key_handle, TA_KEY_TYPE_ECCP384, TA_ALG_MODE_ECC_ECDSA, 
                                           TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_NO_KEY_AGREEMENT);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_priv_key_handle, &private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)private_key_handle, 
                               pub_key, &pub_key_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_handle_init_public_key(&attr_pub_key_handle, TA_KEY_TYPE_ECCP384, TA_ALG_MODE_ECC_ECDSA,
                                          TA_PROP_VAL_NO_SECURE_BOOT_SIGN, TA_PROP_ROOT_PUB_KEY_VERIFY);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_create_element(atcab_get_device(), &attr_pub_key_handle, &public_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_write_element(atcab_get_device(), public_key_handle, TA_ECC384_PUB_KEY_SIZE, pub_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_random(atcab_get_device(), NULL, message, message_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sign_external(atcab_get_device(), TA_KEY_TYPE_ECCP384, private_key_handle, 
                                 TA_HANDLE_INPUT_BUFFER, message, (uint16_t)sizeof(message), signature, 
                                 &sign_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_verify(atcab_get_device(), TA_KEY_TYPE_ECCP384, TA_HANDLE_INPUT_BUFFER, public_key_handle,
                          signature, sign_size, message, message_len, NULL, 0, &is_verified);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT(is_verified);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)private_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)public_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_verify_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_point_exp),           DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, verify_p384pubkey_stored),   DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_verify_tests[] = {
    talib_verify_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
