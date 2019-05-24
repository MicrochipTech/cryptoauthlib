/**
 * \file
 *
 * \copyright (c) 2015-2018 Microchip Technology Inc. and its subsidiaries.
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

#include "test/unity.h"
#include "test/unity_fixture.h"

#ifdef __GNUC__
// Unity macros trigger this warning
#pragma GCC diagnostic ignored "-Wnested-externs"
#endif

TEST_GROUP_RUNNER(atcacert_der_enc_integer)
{
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_min);
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_1byte);
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_multi_byte);
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_large);
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_trim_1_pos);
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_trim_multi_pos);
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_trim_all_pos);
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_trim_1_neg);
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_trim_multi_neg);
    RUN_TEST_CASE(atcacert_der_enc_integer, signed_trim_all_neg);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_min);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_min_pad);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_multi_byte);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_multi_byte_pad);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_large);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_large_pad);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_trim_1_pos);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_trim_multi_pos);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_trim_all_pos);
    RUN_TEST_CASE(atcacert_der_enc_integer, unsigned_trim_neg_pad);
    RUN_TEST_CASE(atcacert_der_enc_integer, small_buf);
    RUN_TEST_CASE(atcacert_der_enc_integer, bad_params);
}

TEST_GROUP_RUNNER(atcacert_der_dec_integer)
{
    RUN_TEST_CASE(atcacert_der_dec_integer, good);
    RUN_TEST_CASE(atcacert_der_dec_integer, good_large);
    RUN_TEST_CASE(atcacert_der_dec_integer, zero_size);
    RUN_TEST_CASE(atcacert_der_dec_integer, not_enough_data);
    RUN_TEST_CASE(atcacert_der_dec_integer, small_buf);
    RUN_TEST_CASE(atcacert_der_dec_integer, bad_params);
}