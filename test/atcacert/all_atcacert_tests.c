/**
 * \file
 * \copyright Copyright (c) 2017 Microchip Technology Inc. and its subsidiaries (Microchip). All rights reserved.
 *
 * \page License
 *
 * You are permitted to use this software and its derivatives with Microchip
 * products. Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Microchip may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with a
 *    Microchip integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL MICROCHIP BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "test/unity_fixture.h"

#ifdef __GNUC__
// Unity macros trigger this warning
#pragma GCC diagnostic ignored "-Wnested-externs"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#endif

void RunAllCertDataTests(void)
{
    RUN_TEST_GROUP(atcacert_der_enc_length);
    RUN_TEST_GROUP(atcacert_der_dec_length);

    RUN_TEST_GROUP(atcacert_der_enc_integer);
    RUN_TEST_GROUP(atcacert_der_dec_integer);

    RUN_TEST_GROUP(atcacert_der_enc_ecdsa_sig_value);
    RUN_TEST_GROUP(atcacert_der_dec_ecdsa_sig_value);

    RUN_TEST_GROUP(atcacert_date_enc_iso8601_sep);
    RUN_TEST_GROUP(atcacert_date_enc_rfc5280_utc);
    RUN_TEST_GROUP(atcacert_date_enc_posix_uint32_be);
    RUN_TEST_GROUP(atcacert_date_enc_posix_uint32_le);
    RUN_TEST_GROUP(atcacert_date_enc_rfc5280_gen);
    RUN_TEST_GROUP(atcacert_date_enc_compcert);
    RUN_TEST_GROUP(atcacert_date_enc);

    RUN_TEST_GROUP(atcacert_date_dec_iso8601_sep);
    RUN_TEST_GROUP(atcacert_date_dec_rfc5280_utc);
    RUN_TEST_GROUP(atcacert_date_dec_posix_uint32_be);
    RUN_TEST_GROUP(atcacert_date_dec_posix_uint32_le);
    RUN_TEST_GROUP(atcacert_date_dec_rfc5280_gen);
    RUN_TEST_GROUP(atcacert_date_get_max_date);
    RUN_TEST_GROUP(atcacert_date_dec_compcert);
    RUN_TEST_GROUP(atcacert_date_dec);

    RUN_TEST_GROUP(atcacert_get_key_id);
    RUN_TEST_GROUP(atcacert_set_cert_element);
    RUN_TEST_GROUP(atcacert_get_cert_element);
    RUN_TEST_GROUP(atcacert_public_key_add_padding);
    RUN_TEST_GROUP(atcacert_public_key_remove_padding);
    RUN_TEST_GROUP(atcacert_set_subj_public_key);
    RUN_TEST_GROUP(atcacert_get_subj_public_key);
    RUN_TEST_GROUP(atcacert_get_subj_key_id);
    RUN_TEST_GROUP(atcacert_set_signature);
    RUN_TEST_GROUP(atcacert_get_signature);
    RUN_TEST_GROUP(atcacert_set_issue_date);
    RUN_TEST_GROUP(atcacert_get_issue_date);
    RUN_TEST_GROUP(atcacert_set_expire_date);
    RUN_TEST_GROUP(atcacert_get_expire_date);
    RUN_TEST_GROUP(atcacert_set_signer_id);
    RUN_TEST_GROUP(atcacert_get_signer_id);
    RUN_TEST_GROUP(atcacert_set_cert_sn);
    RUN_TEST_GROUP(atcacert_gen_cert_sn);
    RUN_TEST_GROUP(atcacert_get_cert_sn);
    RUN_TEST_GROUP(atcacert_set_auth_key_id);
    RUN_TEST_GROUP(atcacert_get_auth_key_id);
    RUN_TEST_GROUP(atcacert_set_comp_cert);
    RUN_TEST_GROUP(atcacert_get_comp_cert);
    RUN_TEST_GROUP(atcacert_get_tbs);
    RUN_TEST_GROUP(atcacert_get_tbs_digest);
    RUN_TEST_GROUP(atcacert_merge_device_loc);
    RUN_TEST_GROUP(atcacert_get_device_locs);
    RUN_TEST_GROUP(atcacert_cert_build);
    RUN_TEST_GROUP(atcacert_is_device_loc_overlap);
    RUN_TEST_GROUP(atcacert_get_device_data);
}

void RunAllCertIOTests(void)
{
    RUN_TEST_GROUP(atcacert_client);
    RUN_TEST_GROUP(atcacert_host_hw);
}
