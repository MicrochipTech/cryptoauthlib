/**
 * \file
 * \copyright (c) 2015-2019 Microchip Technology Inc. and its subsidiaries.
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

#include "test/unity_fixture.h"
#include "test/atca_test.h"
#include "app/tng/tng_atca.h"

tng_type_t g_tng_test_type;

TEST_GROUP(tng_atca);

TEST_SETUP(tng_atca)
{
}

TEST_TEAR_DOWN(tng_atca)
{
}

TEST(tng_atca, tng_get_type)
{
    ATCA_STATUS status;
    tng_type_t type;

    status = tng_get_type(&type);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL(g_tng_test_type, type);
}

TEST(tng_atca, tng_get_device_pubkey)
{
    ATCA_STATUS status;
    uint8_t public_key[ATCA_PUB_KEY_SIZE];
    size_t i;
    bool is_all_zero;

    memset(public_key, 0, sizeof(public_key));

    status = tng_get_device_pubkey(public_key);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    // Make sure we got something back
    is_all_zero = true;
    for (i = 0; i < sizeof(public_key); i++)
    {
        if (public_key[i] != 0)
        {
            is_all_zero = false;
            break;
        }
    }
    TEST_ASSERT(!is_all_zero);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info tng_atca_unit_test_info[] =
{
    { REGISTER_TEST_CASE(tng_atca, tng_get_type),          DEVICE_MASK(ATECC608A)},
    { REGISTER_TEST_CASE(tng_atca, tng_get_device_pubkey), DEVICE_MASK(ATECC608A)},
    { (fp_test_case)NULL,                                  (uint8_t)0 },
};
// *INDENT-ON*