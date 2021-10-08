/**
 * \file
 * \brief Tests for the CryptoAuthLib software crypto API.
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
#include "vectors/pbkdf2_sha256_vectors.h"

TEST_GROUP(atca_crypto_pbkdf2_sw);

TEST_SETUP(atca_crypto_pbkdf2_sw)
{
}

TEST_TEAR_DOWN(atca_crypto_pbkdf2_sw)
{
}

TEST(atca_crypto_pbkdf2_sw, vectors)
{
    ATCA_STATUS status;
    const pbkdf2_sha256_test_vector * pVector = pbkdf2_sha256_test_vectors;
    size_t i;
    uint8_t result[128];

    for (i = 0; i < pbkdf2_sha256_test_vectors_count; i++, pVector++)
    {
        status = atcac_pbkdf2_sha256(pVector->c, (uint8_t*)pVector->p, pVector->plen, (uint8_t*)pVector->s,
                                     pVector->slen, result, pVector->dklen);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(pVector->dk, result, pVector->dklen);
    }
}

TEST(atca_cmd_basic_test, pdkdf2_hw_vectors)
{
    ATCA_STATUS status;
    const pbkdf2_sha256_fixed_size_test_vector* pVector = pbkdf2_sha256_fixed_size_test_vectors;
    size_t i;
    uint8_t result[ATCA_SHA256_DIGEST_SIZE];
    uint16_t key_id = 6;

    status = atca_test_config_get_id(TEST_TYPE_HMAC, &key_id);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    for (i = 0; i < pbkdf2_sha256_fixed_size_test_vectors_count; i++, pVector++)
    {
        status = atcab_pbkdf2_sha256(pVector->c, key_id, (uint8_t*)pVector->s, pVector->slen, result, ATCA_SHA256_DIGEST_SIZE);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
        TEST_ASSERT_EQUAL_MEMORY(pVector->dk, result, ATCA_SHA256_DIGEST_SIZE);
    }
}

t_test_case_info test_crypto_pbkdf2_info[] =
{
    { REGISTER_TEST_CASE(atca_crypto_pbkdf2_sw, vectors),             DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC | DEVICE_MASK(TA100)                     },
    { REGISTER_TEST_CASE(atca_cmd_basic_test,   pdkdf2_hw_vectors),   DEVICE_MASK(ATSHA204A) | DEVICE_MASK_ECC | DEVICE_MASK(TA100)                     },
    /* Array Termination element*/
    { (fp_test_case)NULL,                       (uint8_t)0 },
};
