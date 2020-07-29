/**
 * \file
 * \brief Basic test for ECDH command api - TA100
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

/** \brief Execute ECDH command to generate premaster secret for ECCP224 key and receive premaster secret in io buffer.
 */
TEST(atca_cmd_basic_test, ecdh_p224_io_buffer)
{
    ATCA_STATUS status;
    uint16_t alice_priv_key_handle;
    uint16_t bob_priv_key_handle;
    ta_element_attributes_t alice_priv_key_attributes;
    ta_element_attributes_t bob_priv_key_attributes;
    uint8_t alice_pubkey[TA_ECC224_PUB_KEY_SIZE];
    size_t pubkey_len = sizeof(alice_pubkey);
    uint8_t bob_pubkey[TA_ECC224_PUB_KEY_SIZE];
    uint8_t alice_pms[TA_ECDH_ECCP224_PMS_SIZE];
    uint8_t bob_pms[TA_ECDH_ECCP224_PMS_SIZE];

#ifdef ATCA_PRINTF
    char displaystr[400];
    size_t displen = sizeof(displaystr);
#endif

    // Skip if setup is not locked
    test_assert_data_is_locked();

    // Generate Alice's private key handle attributes
    status = talib_handle_init_private_key(&alice_priv_key_attributes, TA_KEY_TYPE_ECCP224,
                                           TA_ALG_MODE_ECC_ECDH, TA_PROP_NO_SIGN_GENERATION,
                                           TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create Alice's private key handle
    status = talib_create_element(atcab_get_device(), &alice_priv_key_attributes, &alice_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Bob's private key handle attributes
    status = talib_handle_init_private_key(&bob_priv_key_attributes, TA_KEY_TYPE_ECCP224,
                                           TA_ALG_MODE_ECC_ECDH, TA_PROP_NO_SIGN_GENERATION,
                                           TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create Bob's private key handle
    status = talib_create_element(atcab_get_device(), &bob_priv_key_attributes, &bob_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Alice's ECCP224 private key and public key
    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)alice_priv_key_handle,
                               alice_pubkey, &pubkey_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Bob's ECCP224 private key and public key
    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)bob_priv_key_handle,
                               bob_pubkey, &pubkey_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Alice's pre master secret (only X) and get it in io buffer
    status = talib_ecdh_io_buffer(atcab_get_device(), alice_priv_key_handle, bob_pubkey, pubkey_len, alice_pms);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(alice_pms, TA_ECDH_ECCP224_PMS_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);
#endif

    // Generate Bob's pre master secret (only X) and get it in io buffer
    status = talib_ecdh_io_buffer(atcab_get_device(), bob_priv_key_handle, alice_pubkey, pubkey_len, bob_pms);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(bob_pms, TA_ECDH_ECCP224_PMS_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);
#endif

    // Verify Alice's pms and Bob's pms
    TEST_ASSERT_EQUAL_MEMORY(alice_pms, bob_pms, sizeof(alice_pms));

    // Delete Alice's private key handle
    status = talib_delete_handle(atcab_get_device(), (uint32_t)alice_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Delete Bob's private key handle
    status = talib_delete_handle(atcab_get_device(), (uint32_t)bob_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute ECDH operation to generate premaster secret and load it in volatile register.
 */
TEST(atca_cmd_basic_test, ecdh_to_vol_reg)
{
    ATCA_STATUS status;
    const uint16_t details = TA_CREATE_DETAILS_VOLATILE_DESTINATION | TA_CREATE_DETAILS_HMAC_KEY_LENGTH(32);
    const uint16_t dev_handle = TA_HANDLE_VOLATILE_REGISTER3;
    ta_element_attributes_t attr_dev_priv_key_handle;
    const uint8_t host_pub_key[TA_ECC256_PUB_KEY_SIZE] = {
        0x8F, 0x8D, 0x18, 0x2B, 0xD8, 0x19, 0x04, 0x85, 0x82, 0xA9, 0x92, 0x7E, 0xA0, 0xC5, 0x6D, 0xEF,
        0xB4, 0x15, 0x95, 0x48, 0xE1, 0x1C, 0xA5, 0xF7, 0xAB, 0xAC, 0x45, 0xBB, 0xCE, 0x76, 0x81, 0x5B,
        0xE5, 0xC6, 0x4F, 0xCD, 0x2F, 0xD1, 0x26, 0x98, 0x54, 0x4D, 0xE0, 0x37, 0x95, 0x17, 0x26, 0x66,
        0x60, 0x73, 0x04, 0x61, 0x19, 0xAD, 0x5E, 0x11, 0xA9, 0x0A, 0xA4, 0x97, 0x73, 0xAE, 0xAC, 0x86
    };
    uint8_t dev_pub_key[TA_ECC256_PUB_KEY_SIZE];

    // Skip test if setup isn't locked
    test_assert_data_is_locked();

    status = talib_handle_init_symmetric_key(&attr_dev_priv_key_handle, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_MAC);

    status = talib_create_ephemeral_element_with_handle(atcab_get_device(), details, dev_handle,
                                                        &attr_dev_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_genkey((uint32_t)dev_handle, dev_pub_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_ecdh_to_handle(atcab_get_device(), dev_handle, dev_handle, host_pub_key, sizeof(host_pub_key));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_delete_handle(atcab_get_device(), (uint32_t)dev_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute ECDH command to generate premaster secret for ECCP224 key and
 *         store premaster secret x followed by y in shared data.
 */
TEST(atca_cmd_basic_test, ecdh_to_shared_data)
{
    ATCA_STATUS status;
    uint16_t alice_priv_key_handle;
    uint16_t bob_priv_key_handle;
    uint16_t alice_pms_handle;
    ta_element_attributes_t alice_priv_key_attributes;
    ta_element_attributes_t bob_priv_key_attributes;
    ta_element_attributes_t alice_pms_attributes;
    uint8_t alice_pubkey[TA_ECC224_PUB_KEY_SIZE];
    size_t pubkey_len = sizeof(alice_pubkey);
    uint8_t bob_pubkey[TA_ECC224_PUB_KEY_SIZE];
    uint8_t alice_pms[TA_ECDH_ECCP224_XY_PMS_SIZE];
    uint16_t pms_size = sizeof(alice_pms);
    uint8_t bob_pms[TA_ECDH_ECCP224_XY_PMS_SIZE];

#ifdef ATCA_PRINTF
    char displaystr[512];
    size_t displen = sizeof(displaystr);
#endif

    // Skip if setup is not locked
    test_assert_data_is_locked();

    // Generate Alice's private key handle attributes
    status = talib_handle_init_private_key(&alice_priv_key_attributes, TA_KEY_TYPE_ECCP224,
                                           TA_ALG_MODE_ECC_ECDH, TA_PROP_NO_SIGN_GENERATION,
                                           TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create Alice's private key handle
    status = talib_create_element(atcab_get_device(), &alice_priv_key_attributes, &alice_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Bob's private key handle attributes
    status = talib_handle_init_private_key(&bob_priv_key_attributes, TA_KEY_TYPE_ECCP224,
                                           TA_ALG_MODE_ECC_ECDH, TA_PROP_NO_SIGN_GENERATION,
                                           TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create Bob's private key handle
    status = talib_create_element(atcab_get_device(), &bob_priv_key_attributes, &bob_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Alice's pre master secret key handle attributes
    status = talib_handle_init_symmetric_key(&alice_pms_attributes, TA_KEY_TYPE_HMAC,
                                             TA_PROP_SYMM_KEY_USAGE_ANY);

    // Create handle to store Alice pre master secret in shared data
    status = talib_create_hmac_element(atcab_get_device(), pms_size, &alice_pms_attributes, &alice_pms_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Alice's ECCP224 private and public key
    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)alice_priv_key_handle,
                               alice_pubkey, &pubkey_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Bob's ECCP224 private and public key
    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)bob_priv_key_handle,
                               bob_pubkey, &pubkey_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate pre master secret x followed by y and store it in Alice pms handle
    status = talib_ecdh_xy_to_handle(atcab_get_device(), alice_priv_key_handle, alice_pms_handle, bob_pubkey,
                                     sizeof(bob_pubkey));
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Read the Alice pre master secret to verify against Bob's pre master secret
    status = talib_read_element(atcab_get_device(), alice_pms_handle, &pms_size, alice_pms);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(alice_pms, TA_ECDH_ECCP224_XY_PMS_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);
#endif

    // Generate Bob's pre master secret (x followed by y) and get it in io buffer
    status = talib_ecdh_xy_in_io_buffer(atcab_get_device(), bob_priv_key_handle, alice_pubkey,
                                        pubkey_len, bob_pms);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(bob_pms, TA_ECDH_ECCP224_XY_PMS_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);
#endif

    // Verify the Alice's pms and Bob's pms
    TEST_ASSERT_EQUAL_MEMORY(alice_pms, bob_pms, sizeof(alice_pms));

    // Delete Alice's private key handle
    status = talib_delete_handle(atcab_get_device(), (uint32_t)alice_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Delete Bob's private key handle
    status = talib_delete_handle(atcab_get_device(), (uint32_t)bob_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Delete Alice's pms handle
    status = talib_delete_handle(atcab_get_device(), (uint32_t)alice_pms_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

/** \brief Execute ECDH command to generate premaster secret for ECCP384 key and
 *         get premaster secret x followed by y in io buffer.
 */
TEST(atca_cmd_basic_test, ecdh_p384_xy_io_buffer)
{
    ATCA_STATUS status;
    uint16_t alice_priv_key_handle;
    uint16_t bob_priv_key_handle;
    ta_element_attributes_t alice_priv_key_attributes;
    ta_element_attributes_t bob_priv_key_attributes;
    uint8_t alice_pubkey[TA_ECC384_PUB_KEY_SIZE];
    size_t pubkey_len = sizeof(alice_pubkey);
    uint8_t bob_pubkey[TA_ECC384_PUB_KEY_SIZE];
    uint8_t alice_pms[TA_ECDH_ECCP384_XY_PMS_SIZE];
    uint8_t bob_pms[TA_ECDH_ECCP384_XY_PMS_SIZE];

#ifdef ATCA_PRINTF
    char displaystr[512];
    size_t displen = sizeof(displaystr);
#endif

    // Skip if setup is not locked
    test_assert_data_is_locked();

    // Generate Alice's private key handle attributes
    status = talib_handle_init_private_key(&alice_priv_key_attributes, TA_KEY_TYPE_ECCP384,
                                           TA_ALG_MODE_ECC_ECDH, TA_PROP_NO_SIGN_GENERATION,
                                           TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create Alice's private key handle
    status = talib_create_element(atcab_get_device(), &alice_priv_key_attributes, &alice_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Bob's private key handle attributes
    status = talib_handle_init_private_key(&bob_priv_key_attributes, TA_KEY_TYPE_ECCP384,
                                           TA_ALG_MODE_ECC_ECDH, TA_PROP_NO_SIGN_GENERATION,
                                           TA_PROP_KEY_AGREEMENT_OUT_BUFF);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Create Bob's private key handle
    status = talib_create_element(atcab_get_device(), &bob_priv_key_attributes, &bob_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Alice's ECCP384 private key and public key
    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)alice_priv_key_handle,
                               alice_pubkey, &pubkey_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Bob's ECCP384 private key and public key
    status = talib_genkey_base(atcab_get_device(), TA_KEYGEN_MODE_NEWKEY, (uint32_t)bob_priv_key_handle,
                               bob_pubkey, &pubkey_len);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Generate Alice's pre master secret x followed by y and get in io buffer
    status = talib_ecdh_xy_in_io_buffer(atcab_get_device(), alice_priv_key_handle, bob_pubkey, pubkey_len,
                                        alice_pms);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(alice_pms, TA_ECDH_ECCP384_XY_PMS_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);
#endif

    // Generate Bob's pre master secret x followed by y and get in io buffer
    status = talib_ecdh_xy_in_io_buffer(atcab_get_device(), bob_priv_key_handle, alice_pubkey, pubkey_len,
                                        bob_pms);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

#ifdef ATCA_PRINTF
    displen = sizeof(displaystr);
    status = atcab_bin2hex(bob_pms, TA_ECDH_ECCP384_XY_PMS_SIZE, displaystr, &displen);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    printf("alice's pms:\r\n%s\r\n", displaystr);
#endif

    // Verify Alice's pms and Bob's pms
    TEST_ASSERT_EQUAL_MEMORY(alice_pms, bob_pms, sizeof(alice_pms));

    // Delete Alice's private key handle
    status = talib_delete_handle(atcab_get_device(), (uint32_t)alice_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Delete Bob's private key handle
    status = talib_delete_handle(atcab_get_device(), (uint32_t)bob_priv_key_handle);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_ecdh_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ecdh_p224_io_buffer),            DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ecdh_p384_xy_io_buffer),         DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ecdh_to_vol_reg),                DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, ecdh_to_shared_data),            DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_ecdh_tests[] = {
    talib_ecdh_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
