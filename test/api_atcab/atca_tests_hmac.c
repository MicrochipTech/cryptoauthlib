/**
 * \file
 * \brief Unity tests for the cryptoauthlib Basic API
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

#if ATCA_CA_SUPPORT

TEST(atca_cmd_basic_test, hmac)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t sn[ATCA_SERIAL_NUM_SIZE];
    uint8_t otp[ATCA_OTP_SIZE];
    uint8_t num_in[20];
    struct atca_temp_key temp_key;
    atca_nonce_in_out_t nonce_params;
    uint8_t rand_out[32];
    uint8_t hmac_digest[32];
    struct atca_hmac_in_out hmac_params;
    uint8_t hmac_digest_host[32];
    uint8_t modes[] = {
        HMAC_MODE_FLAG_TK_RAND,
        HMAC_MODE_FLAG_TK_RAND | HMAC_MODE_FLAG_OTP88,
        HMAC_MODE_FLAG_TK_RAND | HMAC_MODE_FLAG_OTP88 | HMAC_MODE_FLAG_OTP64,
        HMAC_MODE_FLAG_TK_RAND | HMAC_MODE_FLAG_OTP88 | HMAC_MODE_FLAG_OTP64 | HMAC_MODE_FLAG_FULLSN,
        HMAC_MODE_FLAG_TK_RAND | HMAC_MODE_FLAG_OTP88 | HMAC_MODE_FLAG_FULLSN,
        HMAC_MODE_FLAG_TK_RAND | HMAC_MODE_FLAG_OTP64,
        HMAC_MODE_FLAG_TK_RAND | HMAC_MODE_FLAG_OTP64 | HMAC_MODE_FLAG_FULLSN,
        HMAC_MODE_FLAG_TK_RAND | HMAC_MODE_FLAG_FULLSN,
    };
    size_t i = 0;


    test_assert_data_is_locked();

    status = atcab_read_serial_number(sn);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    status = atcab_read_bytes_zone(ATCA_ZONE_OTP, 0, 0, otp, ATCA_OTP_SIZE);
    TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

    for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
    {
        if (gCfg->devtype == ATECC508A && (modes[i] & HMAC_MODE_FLAG_OTP88 || modes[i] & HMAC_MODE_FLAG_OTP64))
        {
            continue;  // ATECC508A doesn't support OTP mode bits

        }
        //Calculate hmac using chip
        memset(&temp_key, 0, sizeof(temp_key));
        memset(num_in, 0, sizeof(num_in));
        memset(&nonce_params, 0, sizeof(nonce_params));
        nonce_params.mode = NONCE_MODE_SEED_UPDATE;
        nonce_params.zero = 0;
        nonce_params.num_in = num_in;
        nonce_params.temp_key = &temp_key;
        nonce_params.rand_out = rand_out;
        status = atcab_nonce_rand(nonce_params.num_in, rand_out);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcah_nonce(&nonce_params);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        hmac_params.mode = modes[i];
        hmac_params.key_id = 4;
        hmac_params.key = g_slot4_key;
        hmac_params.otp = otp;
        hmac_params.sn = sn;
        hmac_params.response = hmac_digest_host;
        hmac_params.temp_key = &temp_key;
        status = atcab_hmac(hmac_params.mode, hmac_params.key_id, hmac_digest);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);


        //Calculate hmac on host
        status = atcah_nonce(&nonce_params);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        status = atcah_hmac(&hmac_params);
        TEST_ASSERT_EQUAL(ATCA_SUCCESS, status);

        //Compare Chip and Host calculations
        TEST_ASSERT_EQUAL_MEMORY(hmac_digest, hmac_params.response, sizeof(hmac_digest));
    }
}

// *INDENT-OFF* - Preserve formatting
t_test_case_info hmac_basic_test_info[] =
{
    { REGISTER_TEST_CASE(atca_cmd_basic_test, hmac), DEVICE_MASK(ATSHA204A) | DEVICE_MASK(ATECC108A) | DEVICE_MASK(ATECC508A) },
    { (fp_test_case)NULL,                     (uint8_t)0 },/* Array Termination element*/
};
// *INDENT-ON*

#else
t_test_case_info hmac_basic_test_info[] =
{
    { (fp_test_case)NULL, (uint8_t)0 },
};
#endif