/**
 * \file
 * \brief Basic test for SHA command api - TA100
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

/** \brief Execute SHA command with start, update and end mode and verify the final digest with Entire 
 *         message mode output
 */
TEST(atca_cmd_basic_test, sha_with_handle)
{
    ATCA_STATUS status;
    const uint8_t nist_hash_msg1[] = "abc";
    uint8_t digest1[ATCA_SHA2_256_DIGEST_SIZE];
    uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE];

    status = talib_sha_start_with_handle(atcab_get_device(), TA_HANDLE_SHA_CONTEXT1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sha_update_with_handle(atcab_get_device(), TA_HANDLE_SHA_CONTEXT1, (uint16_t)
                                         (sizeof(nist_hash_msg1) - 1), nist_hash_msg1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sha_end_with_handle(atcab_get_device(), TA_HANDLE_SHA_CONTEXT1, digest);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sha_with_handle(atcab_get_device(), TA_HANDLE_SHA_CONTEXT1, (uint16_t)
                                   (sizeof(nist_hash_msg1) - 1), nist_hash_msg1, digest1);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    TEST_ASSERT_EQUAL_MEMORY(digest1, digest, sizeof(digest1));
}

/** \brief This test case performs i)    Start SHA operation
 *                                 ii)   Update context handle with input message
 *                                 iii)  Read the context from context handle
 *                                 iv)   Perform SHA (END mode) and get the digest1
 *                                 v)    Perfrom SHA operation with different input
 *                                 vi)   Write the read context (step iii)) into same context handle
 *                                 vii)  Perform SHA (END mode) and get the digest2
 *                                 viii) Verify the digest1 and digest2
 */
TEST(atca_cmd_basic_test, sha_context_with_handle)
{
    ATCA_STATUS status;
    uint16_t data_out_size = 0;
    uint16_t context_size;
    uint8_t context[SHA_CONTEXT_MAX_SIZE];
    uint8_t digest[ATCA_SHA256_DIGEST_SIZE];
    uint8_t digest1[ATCA_SHA256_DIGEST_SIZE];
    uint8_t digest2[ATCA_SHA256_DIGEST_SIZE];
    uint8_t message[ATCA_SHA256_BLOCK_SIZE];

    uint8_t data_input[] = {
        0x01, 0x02, 0x03, 0x04, 0x05
    };

    // Skip test if setup isn't locked
    test_assert_data_is_locked();

    //Calculating the digest for message data_input and reading the context
    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_START, 0, TA_HANDLE_SHA_CONTEXT1, NULL,
                            NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_UPDATE, (uint16_t)sizeof(data_input), 
                            TA_HANDLE_SHA_CONTEXT1, data_input, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    context_size = sizeof(context);
    status = talib_sha_read_context_with_handle(atcab_get_device(), TA_HANDLE_SHA_CONTEXT1, context,
                                                &context_size); //Reading the context to use it later
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_UPDATE, (uint16_t)sizeof(data_input), 
                            TA_HANDLE_SHA_CONTEXT1, data_input, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    data_out_size = sizeof(digest1);
    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_END, 0, TA_HANDLE_SHA_CONTEXT1, NULL, 
                            digest1, &data_out_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


    //Calculating the digest for another message
    memset(message, 0x5A, sizeof(message));
    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_START, 0, TA_HANDLE_SHA_CONTEXT1, NULL,
                            NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_UPDATE, ATCA_SHA256_BLOCK_SIZE, TA_HANDLE_SHA_CONTEXT1,
                            message, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_UPDATE, ATCA_SHA256_BLOCK_SIZE, TA_HANDLE_SHA_CONTEXT1,
                            message, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_UPDATE, ATCA_SHA256_BLOCK_SIZE, TA_HANDLE_SHA_CONTEXT1,
                            message, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    data_out_size = sizeof(digest);
    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_END, 0, TA_HANDLE_SHA_CONTEXT1, NULL, digest, 
                            &data_out_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);



    //Write context the data, read from read context and comparing both the digest.
    status = talib_sha_write_context_with_handle(atcab_get_device(), TA_HANDLE_SHA_CONTEXT1, context,
                                                 context_size); 
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    //Calculating the digest using the write context
    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_UPDATE, (uint16_t)sizeof(data_input), 
                            TA_HANDLE_SHA_CONTEXT1, data_input, NULL, NULL);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    data_out_size = sizeof(digest2);
    status = talib_sha_base(atcab_get_device(), TA_SHA_MODE_END, 0, TA_HANDLE_SHA_CONTEXT1, NULL, 
                            digest2, &data_out_size);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);
    TEST_ASSERT_EQUAL_MEMORY(digest1, digest2, ATCA_SHA256_DIGEST_SIZE);
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info talib_sha_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sha_with_handle),             DEVICE_MASK(TA100) },
    { REGISTER_TEST_CASE(atca_cmd_basic_test, sha_context_with_handle),     DEVICE_MASK(TA100) },
    { (fp_test_case)NULL,                     (uint8_t)0 },   /* Array Termination element*/
};
// *INDENT-OFN*

t_test_case_info* talib_sha_tests[] = {
    talib_sha_basic_test_info,
    /* Array Termination element*/
    (t_test_case_info*)NULL
};

#endif
