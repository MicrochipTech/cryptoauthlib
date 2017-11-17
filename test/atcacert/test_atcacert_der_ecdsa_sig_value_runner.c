/**
 * \file
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */

#include "test/unity.h"
#include "test/unity_fixture.h"

#ifdef __GNUC__
// Unity macros trigger this warning
#pragma GCC diagnostic ignored "-Wnested-externs"
#endif

TEST_GROUP_RUNNER(atcacert_der_enc_ecdsa_sig_value)
{
    RUN_TEST_CASE(atcacert_der_enc_ecdsa_sig_value, no_padding);
    RUN_TEST_CASE(atcacert_der_enc_ecdsa_sig_value, r_padding);
    RUN_TEST_CASE(atcacert_der_enc_ecdsa_sig_value, s_padding);
    RUN_TEST_CASE(atcacert_der_enc_ecdsa_sig_value, rs_padding);
    RUN_TEST_CASE(atcacert_der_enc_ecdsa_sig_value, trim);
    RUN_TEST_CASE(atcacert_der_enc_ecdsa_sig_value, trim_all);
    RUN_TEST_CASE(atcacert_der_enc_ecdsa_sig_value, small_buf);
    RUN_TEST_CASE(atcacert_der_enc_ecdsa_sig_value, bad_params);
}

TEST_GROUP_RUNNER(atcacert_der_dec_ecdsa_sig_value)
{
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, no_padding);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, r_padding);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, s_padding);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, rs_padding);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, trim);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, trim_all);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_bs_tag);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_bs_length_low);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_bs_length_high);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_bs_extra_data);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_bs_spare_bits);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_seq_tag);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_seq_length_low);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_seq_length_high);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_seq_extra_data);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_rint_tag);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_rint_length_low);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_rint_length_high);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_sint_tag);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_sint_length_low);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_sint_length_high);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_rint_too_large);
    RUN_TEST_CASE(atcacert_der_dec_ecdsa_sig_value, bad_sint_too_large);
}