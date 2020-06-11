/**
 * \file
 * \brief Unity tests for the cryptoauthlib Verify Command
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
#include <stdlib.h>
#include "atca_test.h"

#ifdef ATCA_ECC_SUPPORT

TEST(atca_cmd_basic_test, priv_write_unencrypted)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    static const uint8_t private_key[36] = {
        0x00, 0x00, 0x00, 0x00,
        0x87, 0x8F, 0x0A, 0xB6,0xA5,  0x26,  0xD7,  0x11,  0x1C,  0x26,  0xE6,  0x17,  0x08,  0x10,  0x79,  0x6E,
        0x7B, 0x33, 0x00, 0x7F,0x83,  0x2B,  0x8D,  0x64,  0x46,  0x7E,  0xD6,  0xF8,  0x70,  0x53,  0x7A,  0x19
    };
    static const uint8_t public_key_ref[64] = {
        0x8F, 0x8D, 0x18, 0x2B, 0xD8, 0x19, 0x04, 0x85, 0x82, 0xA9, 0x92, 0x7E, 0xA0, 0xC5, 0x6D, 0xEF,
        0xB4, 0x15, 0x95, 0x48, 0xE1, 0x1C, 0xA5, 0xF7, 0xAB, 0xAC, 0x45, 0xBB, 0xCE, 0x76, 0x81, 0x5B,
        0xE5, 0xC6, 0x4F, 0xCD, 0x2F, 0xD1, 0x26, 0x98, 0x54, 0x4D, 0xE0, 0x37, 0x95, 0x17, 0x26, 0x66,
        0x60, 0x73, 0x04, 0x61, 0x19, 0xAD, 0x5E, 0x11, 0xA9, 0x0A, 0xA4, 0x97, 0x73, 0xAE, 0xAC, 0x86
    };
    uint8_t public_key[64];
    uint8_t host_num_in[NONCE_NUMIN_SIZE] = { 0 };

    test_assert_config_is_locked();
    test_assert_data_is_unlocked();

#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
    status = atcab_priv_write(0, private_key, 0, NULL);
#else
    status = atcab_priv_write(0, private_key, 0, NULL, host_num_in);
#endif
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_get_pubkey(0, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(public_key_ref, public_key, sizeof(public_key_ref));
}

// This test can be worked using only a root module configuration of provisioning project without pointing authkey
TEST(atca_cmd_basic_test, priv_write_encrypted)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t write_key_id = 0x04;
    uint8_t public_key[64];
    static const uint8_t private_key[36] = {
        0x00, 0x00, 0x00, 0x00,
        0x87, 0x8F, 0x0A, 0xB6,0xA5,  0x26,  0xD7,  0x11,  0x1C,  0x26,  0xE6,  0x17,  0x08,  0x10,  0x79,  0x6E,
        0x7B, 0x33, 0x00, 0x7F,0x83,  0x2B,  0x8D,  0x64,  0x46,  0x7E,  0xD6,  0xF8,  0x70,  0x53,  0x7A,  0x19
    };
    static const uint8_t public_key_ref[64] = {
        0x8F, 0x8D, 0x18, 0x2B, 0xD8, 0x19, 0x04, 0x85, 0x82, 0xA9, 0x92, 0x7E, 0xA0, 0xC5, 0x6D, 0xEF,
        0xB4, 0x15, 0x95, 0x48, 0xE1, 0x1C, 0xA5, 0xF7, 0xAB, 0xAC, 0x45, 0xBB, 0xCE, 0x76, 0x81, 0x5B,
        0xE5, 0xC6, 0x4F, 0xCD, 0x2F, 0xD1, 0x26, 0x98, 0x54, 0x4D, 0xE0, 0x37, 0x95, 0x17, 0x26, 0x66,
        0x60, 0x73, 0x04, 0x61, 0x19, 0xAD, 0x5E, 0x11, 0xA9, 0x0A, 0xA4, 0x97, 0x73, 0xAE, 0xAC, 0x86
    };
    uint8_t host_num_in[NONCE_NUMIN_SIZE] = { 0 };

    test_assert_data_is_locked();

#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
    status = atcab_priv_write(0x07, private_key, write_key_id, g_slot4_key);
#else
    status = atcab_priv_write(0x07, private_key, write_key_id, g_slot4_key, host_num_in);
#endif
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_get_pubkey(0x07, public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(public_key_ref, public_key, sizeof(public_key_ref));
}
#endif

// *INDENT-OFF* - Preserve formatting
t_test_case_info privwrite_basic_test_info[] =
{
#ifdef ATCA_ECC_SUPPORT
    { REGISTER_TEST_CASE(atca_cmd_basic_test, priv_write_unencrypted), DEVICE_MASK_ECC                      },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, priv_write_encrypted),   DEVICE_MASK_ECC                      },
#endif
    { (fp_test_case)NULL,                     (uint8_t)0 },            /* Array Termination element*/
};
// *INDENT-ON*

