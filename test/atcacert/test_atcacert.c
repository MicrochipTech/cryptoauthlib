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

extern t_test_case_info atcacert_der_enc_length_tests[];
extern t_test_case_info atcacert_der_dec_length_tests[];

extern t_test_case_info atcacert_der_enc_integer_tests[];
extern t_test_case_info atcacert_der_dec_integer_tests[];

extern t_test_case_info atcacert_der_enc_ecdsa_sig_value_tests[];
extern t_test_case_info atcacert_der_dec_ecdsa_sig_value_tests[];

extern t_test_case_info atcacert_date_enc_iso8601_sep_tests[];
extern t_test_case_info atcacert_date_enc_rfc5280_utc_tests[];
extern t_test_case_info atcacert_date_enc_posix_uint32_be_tests[];
extern t_test_case_info atcacert_date_enc_posix_uint32_le_tests[];
extern t_test_case_info atcacert_date_enc_rfc5280_gen_tests[];
extern t_test_case_info atcacert_date_enc_compcert_tests[];
extern t_test_case_info atcacert_date_enc_tests[];

extern t_test_case_info atcacert_date_dec_iso8601_sep_tests[];
extern t_test_case_info atcacert_date_dec_rfc5280_utc_tests[];
extern t_test_case_info atcacert_date_dec_posix_uint32_be_tests[];
extern t_test_case_info atcacert_date_dec_posix_uint32_le_tests[];
extern t_test_case_info atcacert_date_dec_rfc5280_gen_tests[];
extern t_test_case_info atcacert_date_get_max_date_tests[];
extern t_test_case_info atcacert_date_dec_compcert_tests[];
extern t_test_case_info atcacert_date_dec_tests[];

extern t_test_case_info atcacert_get_key_id_tests[];
extern t_test_case_info atcacert_set_cert_element_tests[];
extern t_test_case_info atcacert_get_cert_element_tests[];
extern t_test_case_info atcacert_public_key_add_padding_tests[];
extern t_test_case_info atcacert_public_key_remove_padding_tests[];
extern t_test_case_info atcacert_set_subj_public_key_tests[];
extern t_test_case_info atcacert_get_subj_public_key_tests[];
extern t_test_case_info atcacert_get_subj_key_id_tests[];
extern t_test_case_info atcacert_set_signature_tests[];
extern t_test_case_info atcacert_get_signature_tests[];
extern t_test_case_info atcacert_set_issue_date_tests[];
extern t_test_case_info atcacert_get_issue_date_tests[];
extern t_test_case_info atcacert_set_expire_date_tests[];
extern t_test_case_info atcacert_get_expire_date_tests[];
extern t_test_case_info atcacert_set_signer_id_tests[];
extern t_test_case_info atcacert_get_signer_id_tests[];
extern t_test_case_info atcacert_set_cert_sn_tests[];
extern t_test_case_info atcacert_gen_cert_sn_tests[];
extern t_test_case_info atcacert_generate_sn_tests[];
extern t_test_case_info atcacert_get_cert_sn_tests[];
extern t_test_case_info atcacert_set_auth_key_id_tests[];
extern t_test_case_info atcacert_get_auth_key_id_tests[];
extern t_test_case_info atcacert_set_comp_cert_tests[];
extern t_test_case_info atcacert_get_comp_cert_tests[];
extern t_test_case_info atcacert_get_tbs_tests[];
extern t_test_case_info atcacert_get_tbs_digest_tests[];
extern t_test_case_info atcacert_merge_device_loc_tests[];
extern t_test_case_info atcacert_get_device_locs_tests[];
extern t_test_case_info atcacert_cert_build_tests[];
extern t_test_case_info atcacert_is_device_loc_overlap_tests[];
extern t_test_case_info atcacert_get_device_data_tests[];

extern t_test_case_info atcacert_client_tests[];
extern t_test_case_info atcacert_host_hw_tests[];
extern t_test_case_info atcacert_client_ca2_tests[];
extern t_test_case_info atcacert_client_ta_tests[];
extern t_test_case_info atcacert_host_hw_ta_tests[];
extern t_test_case_info atcacert_host_sw_tests[];

t_test_case_info* atcacert_data_test_list[] = {
#if ATCACERT_COMPCERT_EN
    atcacert_der_enc_length_tests,
    atcacert_der_dec_length_tests,

    atcacert_der_enc_integer_tests,
    atcacert_der_dec_integer_tests,

    atcacert_der_enc_ecdsa_sig_value_tests,
    atcacert_der_dec_ecdsa_sig_value_tests,

#if ATCACERT_DATEFMT_ISO_EN
    atcacert_date_enc_iso8601_sep_tests,
#endif
    atcacert_date_enc_rfc5280_utc_tests,
#if ATCACERT_DATEFMT_POSIX_EN
    atcacert_date_enc_posix_uint32_be_tests,
    atcacert_date_enc_posix_uint32_le_tests,
#endif
    atcacert_date_enc_rfc5280_gen_tests,
    atcacert_date_enc_compcert_tests,
    atcacert_date_enc_tests,

#if ATCACERT_DATEFMT_ISO_EN
    atcacert_date_dec_iso8601_sep_tests,
#endif
    atcacert_date_dec_rfc5280_utc_tests,
#if ATCACERT_DATEFMT_POSIX_EN
    atcacert_date_dec_posix_uint32_be_tests,
    atcacert_date_dec_posix_uint32_le_tests,
#endif
    atcacert_date_dec_rfc5280_gen_tests,
    atcacert_date_get_max_date_tests,
    atcacert_date_dec_compcert_tests,
    atcacert_date_dec_tests,

    atcacert_get_key_id_tests,
    atcacert_set_cert_element_tests,
    atcacert_get_cert_element_tests,
    atcacert_public_key_add_padding_tests,
    atcacert_public_key_remove_padding_tests,
    atcacert_set_subj_public_key_tests,
    atcacert_get_subj_public_key_tests,
    atcacert_get_subj_key_id_tests,
    atcacert_set_signature_tests,
    atcacert_get_signature_tests,
    atcacert_set_issue_date_tests,
    atcacert_get_issue_date_tests,
    atcacert_set_expire_date_tests,
    atcacert_get_expire_date_tests,
    atcacert_set_signer_id_tests,
    atcacert_get_signer_id_tests,
    atcacert_set_cert_sn_tests,
    atcacert_gen_cert_sn_tests,
    atcacert_generate_sn_tests,
    atcacert_get_cert_sn_tests,
    atcacert_set_auth_key_id_tests,
    atcacert_get_auth_key_id_tests,
    atcacert_set_comp_cert_tests,
    atcacert_get_comp_cert_tests,
    atcacert_get_tbs_tests,
    atcacert_get_tbs_digest_tests,
    atcacert_merge_device_loc_tests,
    atcacert_get_device_locs_tests,
    atcacert_cert_build_tests,
    atcacert_is_device_loc_overlap_tests,
    atcacert_get_device_data_tests,
#endif
    /* Array Termination element*/
    (t_test_case_info*)NULL,
};

t_test_case_info* atcacert_io_test_list[] = {
    atcacert_client_tests,
#if ATCACERT_COMPCERT_EN
    atcacert_host_hw_tests, 
    atcacert_client_ca2_tests,
#endif
#if ATCA_TA_SUPPORT
    atcacert_client_ta_tests,
#if ATCACERT_COMPCERT_EN
    atcacert_host_hw_ta_tests, 
#endif
#endif
    atcacert_host_sw_tests,
    /* Array Termination element*/
    (t_test_case_info*)NULL,
};

#endif
