/**
 * \file
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
#ifndef DO_NOT_TEST_CERT

#ifdef __GNUC__
// Unity macros trigger this warning
#pragma GCC diagnostic ignored "-Wnested-externs"
#endif

#undef min
#undef max

TEST_GROUP_RUNNER(atcacert_date_enc_iso8601_sep)
{
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, good);
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, min);
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, max);
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, bad_year);
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, bad_month);
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, bad_day);
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, bad_hour);
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, bad_min);
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, bad_sec);
    RUN_TEST_CASE(atcacert_date_enc_iso8601_sep, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_rfc5280_utc)
{
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, good);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, min);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, max);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, y2k);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, bad_year);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, bad_month);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, bad_day);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, bad_hour);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, bad_min);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, bad_sec);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_utc, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_posix_uint32_be)
{
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, good);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, min);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, large);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, max);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, bad_low);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, bad_high);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_be, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_posix_uint32_le)
{
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, good);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, min);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, large);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, max);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, bad_low);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, bad_high);
    RUN_TEST_CASE(atcacert_date_enc_posix_uint32_le, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_rfc5280_gen)
{
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, good);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, min);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, max);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, bad_year);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, bad_month);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, bad_day);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, bad_hour);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, bad_min);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, bad_sec);
    RUN_TEST_CASE(atcacert_date_enc_rfc5280_gen, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc_compcert)
{
    RUN_TEST_CASE(atcacert_date_enc_compcert, good);
    RUN_TEST_CASE(atcacert_date_enc_compcert, min);
    RUN_TEST_CASE(atcacert_date_enc_compcert, max);
    RUN_TEST_CASE(atcacert_date_enc_compcert, bad_year);
    RUN_TEST_CASE(atcacert_date_enc_compcert, bad_month);
    RUN_TEST_CASE(atcacert_date_enc_compcert, bad_day);
    RUN_TEST_CASE(atcacert_date_enc_compcert, bad_hour);
    RUN_TEST_CASE(atcacert_date_enc_compcert, bad_expire);
    RUN_TEST_CASE(atcacert_date_enc_compcert, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_enc)
{
    RUN_TEST_CASE(atcacert_date_enc, iso8601_sep);
    RUN_TEST_CASE(atcacert_date_enc, rfc5280_utc);
    RUN_TEST_CASE(atcacert_date_enc, posix_uint32_be);
    RUN_TEST_CASE(atcacert_date_enc, posix_uint32_le);
    RUN_TEST_CASE(atcacert_date_enc, rfc5280_gen);
    RUN_TEST_CASE(atcacert_date_enc, small_buf);
    RUN_TEST_CASE(atcacert_date_enc, bad_format);
    RUN_TEST_CASE(atcacert_date_enc, bad_params);
}


TEST_GROUP_RUNNER(atcacert_date_dec_iso8601_sep)
{
    RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, good);
    RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, min);
    RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, max);
    RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, bad_int);
    RUN_TEST_CASE(atcacert_date_dec_iso8601_sep, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_rfc5280_utc)
{
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, good);
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, min);
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, max);
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, y2k);
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, bad_int);
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_utc, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_posix_uint32_be)
{
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, good);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, min);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, int32_max);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, large);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, max);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_be, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_posix_uint32_le)
{
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, good);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, min);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, int32_max);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, large);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, max);
    RUN_TEST_CASE(atcacert_date_dec_posix_uint32_le, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_rfc5280_gen)
{
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, good);
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, min);
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, max);
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, bad_int);
    RUN_TEST_CASE(atcacert_date_dec_rfc5280_gen, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_get_max_date)
{
    RUN_TEST_CASE(atcacert_date_get_max_date, iso8601_sep);
    RUN_TEST_CASE(atcacert_date_get_max_date, rfc5280_utc);
    RUN_TEST_CASE(atcacert_date_get_max_date, posix_uint32_be);
    RUN_TEST_CASE(atcacert_date_get_max_date, posix_uint32_le);
    RUN_TEST_CASE(atcacert_date_get_max_date, rfc5280_gen);
    RUN_TEST_CASE(atcacert_date_get_max_date, new_format);
    RUN_TEST_CASE(atcacert_date_get_max_date, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec_compcert)
{
    RUN_TEST_CASE(atcacert_date_dec_compcert, good);
    RUN_TEST_CASE(atcacert_date_dec_compcert, min);
    RUN_TEST_CASE(atcacert_date_dec_compcert, max);
    RUN_TEST_CASE(atcacert_date_dec_compcert, posix_uint32_be);
    RUN_TEST_CASE(atcacert_date_dec_compcert, bad_params);
}

TEST_GROUP_RUNNER(atcacert_date_dec)
{
    RUN_TEST_CASE(atcacert_date_dec, iso8601_sep);
    RUN_TEST_CASE(atcacert_date_dec, rfc5280_utc);
    RUN_TEST_CASE(atcacert_date_dec, posix_uint32_be);
    RUN_TEST_CASE(atcacert_date_dec, posix_uint32_le);
    RUN_TEST_CASE(atcacert_date_dec, rfc5280_gen);
    RUN_TEST_CASE(atcacert_date_dec, small_buf);
    RUN_TEST_CASE(atcacert_date_dec, bad_format);
    RUN_TEST_CASE(atcacert_date_dec, bad_params);
}

#endif
