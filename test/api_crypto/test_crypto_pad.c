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
#include "vectors/pkcs7_pad_vectors.h"

#ifndef TEST_ATCAC_PKCS7_EN
#define TEST_ATCAC_PKCS7_EN      ATCAC_PKCS7_PAD_EN
#endif

#if TEST_ATCAC_PKCS7_EN
TEST_GROUP(atcac_pkcs7);

TEST_SETUP(atcac_pkcs7)
{
    UnityMalloc_StartTest();
}

TEST_TEAR_DOWN(atcac_pkcs7)
{
    UnityMalloc_EndTest();
}

TEST(atcac_pkcs7, pad_success)
{
    ATCA_STATUS status;
    const pkcs7_pad_test_vector * pVector = pkcs7_pad_test_vectors;
    size_t i;
    uint8_t buffer[130];
    size_t length1;
    size_t length2;

    for (i = 0; i < pkcs7_pad_test_vectors_count; i++, pVector++)
    {
        length1 = sizeof(buffer) / 2;
        status = atcab_hex2bin(pVector->in, strlen(pVector->in), &buffer[sizeof(buffer) / 2], &length1);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        length2 = sizeof(buffer) / 2;
        status = atcac_pkcs7_pad(&buffer[sizeof(buffer) / 2], &length2, length1, pVector->blocksize);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        length1 = sizeof(buffer);
        status = atcab_bin2hex_(&buffer[sizeof(buffer) / 2], length2, (char*)buffer, &length1, false, false, true);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        TEST_ASSERT_EQUAL_MEMORY(pVector->out, buffer, length1);
    }
}

TEST(atcac_pkcs7, unpad_success)
{
    ATCA_STATUS status;
    const pkcs7_pad_test_vector * pVector = pkcs7_pad_test_vectors;
    size_t i;
    uint8_t buffer[130];
    size_t length1;
    size_t length2;

    for (i = 0; i < pkcs7_pad_test_vectors_count; i++, pVector++)
    {
        length1 = sizeof(buffer) / 2;
        status = atcab_hex2bin(pVector->out, strlen(pVector->out), &buffer[sizeof(buffer) / 2], &length1);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcac_pkcs7_unpad(&buffer[sizeof(buffer) / 2], &length1, pVector->blocksize);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        length2 = sizeof(buffer);
        status = atcab_bin2hex_(&buffer[sizeof(buffer) / 2], length1, (char*)buffer, &length2, false, false, true);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        TEST_ASSERT_EQUAL_MEMORY(pVector->in, buffer, length2);
    }
}

TEST(atcac_pkcs7, unpad_invalid)
{
    ATCA_STATUS status;
    const pkcs7_pad_test_vector * pVector = pkcs7_unpad_test_vectors;
    size_t i;
    uint8_t buffer[65];
    size_t length1;

    for (i = 0; i < pkcs7_unpad_test_vectors_count; i++, pVector++)
    {
        length1 = sizeof(buffer);
        status = atcab_hex2bin(pVector->in, strlen(pVector->in), buffer, &length1);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcac_pkcs7_unpad(buffer, &length1, pVector->blocksize);
        TEST_ASSERT_NOT_EQUAL(ATCA_SUCCESS, status);
    }
}

#endif /* TEST_ATCAC_PBKDF2_EN */


t_test_case_info atcac_pad_test_info[] =
{
#if TEST_ATCAC_PKCS7_EN
    { REGISTER_TEST_CASE(atcac_pkcs7, pad_success),   NULL },
    { REGISTER_TEST_CASE(atcac_pkcs7, unpad_success), NULL },
    { REGISTER_TEST_CASE(atcac_pkcs7, unpad_invalid), NULL },
#endif
    /* Array Termination element*/
    { (fp_test_case)NULL,             NULL },
};
