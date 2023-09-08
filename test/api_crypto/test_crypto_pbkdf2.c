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

#ifndef TEST_ATCAC_PBKDF2_EN
#define TEST_ATCAC_PBKDF2_EN      ATCAC_PBKDF2_SHA256_EN
#endif

#ifndef TEST_ATCAB_PBKDF2_EN
#define TEST_ATCAB_PBKDF2_EN      ATCAB_PBKDF2_SHA256_EN
#endif

#if TEST_ATCAC_PBKDF2_EN
TEST_GROUP(atcac_pbkdf2);

TEST_SETUP(atcac_pbkdf2)
{
    UnityMalloc_StartTest();
}

TEST_TEAR_DOWN(atcac_pbkdf2)
{
    UnityMalloc_EndTest();
}

TEST(atcac_pbkdf2, vectors)
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
#endif /* TEST_ATCAC_PBKDF2_EN */

#if TEST_ATCAB_PBKDF2_EN
TEST_GROUP(atcab_pbkdf2);

TEST_SETUP(atcab_pbkdf2)
{
    UnityMalloc_StartTest();

    TEST_IGNORE_MESSAGE("Skipping because a device is NOT selected");

    ATCA_STATUS status = atcab_init(gCfg);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
}

TEST_TEAR_DOWN(atcab_pbkdf2)
{
    ATCA_STATUS status;

    status = atcab_wakeup();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_sleep();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_release();
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    UnityMalloc_EndTest();
}

TEST_CONDITION(atcab_pbkdf2, vectors)
{
    ATCADeviceType dev_type = atca_test_get_device_type();

    return atcab_is_ta_device(dev_type) || dev_type == ATSHA204A || dev_type == ATECC608A;
}

TEST(atcab_pbkdf2, vectors)
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
#endif /* TEST_ATCAB_PBKDF2_EN */

t_test_case_info atcac_pbkdf2_test_info[] =
{
#if TEST_ATCAC_PBKDF2_EN
    { REGISTER_TEST_CASE(atcac_pbkdf2, vectors), NULL     },
#endif
#if TEST_ATCAB_PBKDF2_EN
    { REGISTER_TEST_CASE(atcab_pbkdf2, vectors), REGISTER_TEST_CONDITION(atcab_pbkdf2, vectors)},
#endif
    /* Array Termination element*/
    { (fp_test_case)NULL,              NULL },
};
