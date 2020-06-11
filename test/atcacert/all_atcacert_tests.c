/**
 * \file
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
    
#endif
