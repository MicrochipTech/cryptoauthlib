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

TEST_GROUP_RUNNER(atcacert_get_key_id)
{
    RUN_TEST_CASE(atcacert_get_key_id, good);
    RUN_TEST_CASE(atcacert_get_key_id, bad_params);
}

TEST_GROUP_RUNNER(atcacert_set_cert_element)
{
    RUN_TEST_CASE(atcacert_set_cert_element, good);
    RUN_TEST_CASE(atcacert_set_cert_element, edge);
    RUN_TEST_CASE(atcacert_set_cert_element, missing);
    RUN_TEST_CASE(atcacert_set_cert_element, unexpected_size);
    RUN_TEST_CASE(atcacert_set_cert_element, out_of_bounds);
    RUN_TEST_CASE(atcacert_set_cert_element, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_cert_element)
{
    RUN_TEST_CASE(atcacert_get_cert_element, good);
    RUN_TEST_CASE(atcacert_get_cert_element, missing);
    RUN_TEST_CASE(atcacert_get_cert_element, unexpected_size);
    RUN_TEST_CASE(atcacert_get_cert_element, out_of_bounds);
    RUN_TEST_CASE(atcacert_get_cert_element, bad_params);
}

TEST_GROUP_RUNNER(atcacert_public_key_add_padding)
{
    RUN_TEST_CASE(atcacert_public_key_add_padding, separate);
    RUN_TEST_CASE(atcacert_public_key_add_padding, in_place);
}

TEST_GROUP_RUNNER(atcacert_public_key_remove_padding)
{
    RUN_TEST_CASE(atcacert_public_key_remove_padding, separate);
    RUN_TEST_CASE(atcacert_public_key_remove_padding, in_place);
}

TEST_GROUP_RUNNER(atcacert_set_subj_public_key)
{
    RUN_TEST_CASE(atcacert_set_subj_public_key, good);
    RUN_TEST_CASE(atcacert_set_subj_public_key, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_subj_public_key)
{
    RUN_TEST_CASE(atcacert_get_subj_public_key, good);
    RUN_TEST_CASE(atcacert_get_subj_public_key, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_subj_key_id)
{
    RUN_TEST_CASE(atcacert_get_subj_key_id, good);
    RUN_TEST_CASE(atcacert_get_subj_key_id, bad_params);
}

TEST_GROUP_RUNNER(atcacert_set_signature)
{
    RUN_TEST_CASE(atcacert_set_signature, non_x509);
    RUN_TEST_CASE(atcacert_set_signature, x509_same_size);
    RUN_TEST_CASE(atcacert_set_signature, x509_bigger);
    RUN_TEST_CASE(atcacert_set_signature, x509_smaller);
    RUN_TEST_CASE(atcacert_set_signature, x509_smallest);
    RUN_TEST_CASE(atcacert_set_signature, x509_out_of_bounds);
    RUN_TEST_CASE(atcacert_set_signature, x509_small_buf);
    RUN_TEST_CASE(atcacert_set_signature, x509_bad_cert_length);
    RUN_TEST_CASE(atcacert_set_signature, x509_cert_length_change);
    RUN_TEST_CASE(atcacert_set_signature, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_signature)
{
    RUN_TEST_CASE(atcacert_get_signature, non_x509);
    RUN_TEST_CASE(atcacert_get_signature, x509_no_padding);
    RUN_TEST_CASE(atcacert_get_signature, x509_r_padding);
    RUN_TEST_CASE(atcacert_get_signature, x509_rs_padding);
    RUN_TEST_CASE(atcacert_get_signature, x509_bad_sig);
    RUN_TEST_CASE(atcacert_get_signature, x509_out_of_bounds);
    RUN_TEST_CASE(atcacert_get_signature, x509_bad_params);
}

TEST_GROUP_RUNNER(atcacert_set_issue_date)
{
    RUN_TEST_CASE(atcacert_set_issue_date, good);
    RUN_TEST_CASE(atcacert_set_issue_date, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_issue_date)
{
    RUN_TEST_CASE(atcacert_get_issue_date, good);
    RUN_TEST_CASE(atcacert_get_issue_date, bad_params);
}

TEST_GROUP_RUNNER(atcacert_set_expire_date)
{
    RUN_TEST_CASE(atcacert_set_expire_date, good);
    RUN_TEST_CASE(atcacert_set_expire_date, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_expire_date)
{
    RUN_TEST_CASE(atcacert_get_expire_date, good);
    RUN_TEST_CASE(atcacert_get_expire_date, bad_params);
}

TEST_GROUP_RUNNER(atcacert_set_signer_id)
{
    RUN_TEST_CASE(atcacert_set_signer_id, good);
    RUN_TEST_CASE(atcacert_set_signer_id, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_signer_id)
{
    RUN_TEST_CASE(atcacert_get_signer_id, uppercase);
    RUN_TEST_CASE(atcacert_get_signer_id, lowercase);
    RUN_TEST_CASE(atcacert_get_signer_id, invalid);
    RUN_TEST_CASE(atcacert_get_signer_id, bad_params);
}

TEST_GROUP_RUNNER(atcacert_set_cert_sn)
{
    RUN_TEST_CASE(atcacert_set_cert_sn, good);
    RUN_TEST_CASE(atcacert_set_cert_sn, unexpected_size);
    RUN_TEST_CASE(atcacert_set_cert_sn, bad_params);
}

TEST_GROUP_RUNNER(atcacert_gen_cert_sn)
{
    RUN_TEST_CASE(atcacert_gen_cert_sn, stored);
    RUN_TEST_CASE(atcacert_gen_cert_sn, stored_bad_params);
    RUN_TEST_CASE(atcacert_gen_cert_sn, device_sn);
    RUN_TEST_CASE(atcacert_gen_cert_sn, device_sn_unexpected_size);
    RUN_TEST_CASE(atcacert_gen_cert_sn, device_sn_bad_params);
    RUN_TEST_CASE(atcacert_gen_cert_sn, signer_id);
    RUN_TEST_CASE(atcacert_gen_cert_sn, signer_id_unexpected_size);
    RUN_TEST_CASE(atcacert_gen_cert_sn, signer_id_bad_signer_id);
    RUN_TEST_CASE(atcacert_gen_cert_sn, signer_id_bad_params);
    RUN_TEST_CASE(atcacert_gen_cert_sn, pub_key_hash);
    RUN_TEST_CASE(atcacert_gen_cert_sn, pub_key_hash_pos);
    RUN_TEST_CASE(atcacert_gen_cert_sn, pub_key_hash_raw);
    RUN_TEST_CASE(atcacert_gen_cert_sn, pub_key_hash_unexpected_size);
    RUN_TEST_CASE(atcacert_gen_cert_sn, pub_key_hash_bad_public_key);
    RUN_TEST_CASE(atcacert_gen_cert_sn, pub_key_hash_bad_issue_date);
    RUN_TEST_CASE(atcacert_gen_cert_sn, pub_key_hash_bad_params);
    RUN_TEST_CASE(atcacert_gen_cert_sn, device_sn_hash);
    RUN_TEST_CASE(atcacert_gen_cert_sn, device_sn_hash_pos);
    RUN_TEST_CASE(atcacert_gen_cert_sn, device_sn_hash_raw);
    RUN_TEST_CASE(atcacert_gen_cert_sn, device_sn_hash_unexpected_size);
    RUN_TEST_CASE(atcacert_gen_cert_sn, device_sn_hash_bad_issue_date);
    RUN_TEST_CASE(atcacert_gen_cert_sn, device_sn_hash_bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_cert_sn)
{
    RUN_TEST_CASE(atcacert_get_cert_sn, good);
    RUN_TEST_CASE(atcacert_get_cert_sn, bad_params);
}

TEST_GROUP_RUNNER(atcacert_set_auth_key_id)
{
    RUN_TEST_CASE(atcacert_set_auth_key_id, good);
    RUN_TEST_CASE(atcacert_set_auth_key_id, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_auth_key_id)
{
    RUN_TEST_CASE(atcacert_get_auth_key_id, good);
    RUN_TEST_CASE(atcacert_get_auth_key_id, bad_params);
}

TEST_GROUP_RUNNER(atcacert_set_comp_cert)
{
    RUN_TEST_CASE(atcacert_set_comp_cert, same_size);
    RUN_TEST_CASE(atcacert_set_comp_cert, bigger);
    RUN_TEST_CASE(atcacert_set_comp_cert, bad_format);
    RUN_TEST_CASE(atcacert_set_comp_cert, bad_template_id);
    RUN_TEST_CASE(atcacert_set_comp_cert, bad_chain_id);
    RUN_TEST_CASE(atcacert_set_comp_cert, bad_sn_source);
    RUN_TEST_CASE(atcacert_set_comp_cert, bad_enc_dates);
    RUN_TEST_CASE(atcacert_set_comp_cert, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_comp_cert)
{
    RUN_TEST_CASE(atcacert_get_comp_cert, good);
    RUN_TEST_CASE(atcacert_get_comp_cert, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_tbs)
{
    RUN_TEST_CASE(atcacert_get_tbs, good);
    RUN_TEST_CASE(atcacert_get_tbs, bad_cert);
    RUN_TEST_CASE(atcacert_get_tbs, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_tbs_digest)
{
    RUN_TEST_CASE(atcacert_get_tbs_digest, good);
    RUN_TEST_CASE(atcacert_get_tbs_digest, bad_params);
}

TEST_GROUP_RUNNER(atcacert_merge_device_loc)
{
    RUN_TEST_CASE(atcacert_merge_device_loc, empty_list);
    RUN_TEST_CASE(atcacert_merge_device_loc, devzone_none);
    RUN_TEST_CASE(atcacert_merge_device_loc, count0);
    RUN_TEST_CASE(atcacert_merge_device_loc, align1);
    RUN_TEST_CASE(atcacert_merge_device_loc, align2);
    RUN_TEST_CASE(atcacert_merge_device_loc, align3);
    RUN_TEST_CASE(atcacert_merge_device_loc, align4);
    RUN_TEST_CASE(atcacert_merge_device_loc, align5);
    RUN_TEST_CASE(atcacert_merge_device_loc, align6);
    RUN_TEST_CASE(atcacert_merge_device_loc, align7);
    RUN_TEST_CASE(atcacert_merge_device_loc, align8);
    RUN_TEST_CASE(atcacert_merge_device_loc, align9);
    RUN_TEST_CASE(atcacert_merge_device_loc, align10);
    RUN_TEST_CASE(atcacert_merge_device_loc, align11);
    RUN_TEST_CASE(atcacert_merge_device_loc, 32block_no_change);
    RUN_TEST_CASE(atcacert_merge_device_loc, 32block_round_down);
    RUN_TEST_CASE(atcacert_merge_device_loc, 32block_round_up);
    RUN_TEST_CASE(atcacert_merge_device_loc, 32block_round_both);
    RUN_TEST_CASE(atcacert_merge_device_loc, 32block_round_down_merge);
    RUN_TEST_CASE(atcacert_merge_device_loc, 32block_round_up_merge);
    RUN_TEST_CASE(atcacert_merge_device_loc, data_diff_slot);
    RUN_TEST_CASE(atcacert_merge_device_loc, data_diff_genkey);
    RUN_TEST_CASE(atcacert_merge_device_loc, config);
    RUN_TEST_CASE(atcacert_merge_device_loc, otp);
    RUN_TEST_CASE(atcacert_merge_device_loc, first);
    RUN_TEST_CASE(atcacert_merge_device_loc, mid);
    RUN_TEST_CASE(atcacert_merge_device_loc, last);
    RUN_TEST_CASE(atcacert_merge_device_loc, add);
    RUN_TEST_CASE(atcacert_merge_device_loc, small_buf);
    RUN_TEST_CASE(atcacert_merge_device_loc, bad_params);
}

TEST_GROUP_RUNNER(atcacert_get_device_locs)
{
    RUN_TEST_CASE(atcacert_get_device_locs, device);
    RUN_TEST_CASE(atcacert_get_device_locs, signer_device);
    RUN_TEST_CASE(atcacert_get_device_locs, 32block_signer_device);
    RUN_TEST_CASE(atcacert_get_device_locs, small_buf);
    RUN_TEST_CASE(atcacert_get_device_locs, bad_params);
}

TEST_GROUP_RUNNER(atcacert_cert_build)
{
    RUN_TEST_CASE(atcacert_cert_build, start_signer);
    RUN_TEST_CASE(atcacert_cert_build, process_signer_public_key);
    RUN_TEST_CASE(atcacert_cert_build, process_signer_comp_cert);
    RUN_TEST_CASE(atcacert_cert_build, finish_signer);

    RUN_TEST_CASE(atcacert_cert_build, start_signer_no_ca_key);
    RUN_TEST_CASE(atcacert_cert_build, process_signer_auth_key_id);

    RUN_TEST_CASE(atcacert_cert_build, start_device);
    RUN_TEST_CASE(atcacert_cert_build, process_device_public_key);
    RUN_TEST_CASE(atcacert_cert_build, process_device_comp_cert);
    RUN_TEST_CASE(atcacert_cert_build, process_device_comp_cert_new_expire);
    RUN_TEST_CASE(atcacert_cert_build, finish_device);
    RUN_TEST_CASE(atcacert_cert_build, transform);

    RUN_TEST_CASE(atcacert_cert_build, start_small_buf);
    RUN_TEST_CASE(atcacert_cert_build, start_bad_params);
    RUN_TEST_CASE(atcacert_cert_build, process_bad_params);
    RUN_TEST_CASE(atcacert_cert_build, finish_missing_device_sn);
    RUN_TEST_CASE(atcacert_cert_build, finish_bad_params);

    RUN_TEST_CASE(atcacert_cert_build, max_cert_size_x509);
    RUN_TEST_CASE(atcacert_cert_build, max_cert_size_x509_dynamic_sn);
    RUN_TEST_CASE(atcacert_cert_build, max_cert_size_x509_dynamic_sn_bad_size);
    RUN_TEST_CASE(atcacert_cert_build, max_cert_size_custom);
    RUN_TEST_CASE(atcacert_cert_build, max_cert_size_bad_params);
}

TEST_GROUP_RUNNER(atcacert_is_device_loc_overlap)
{
    RUN_TEST_CASE(atcacert_is_device_loc_overlap, align1);
    RUN_TEST_CASE(atcacert_is_device_loc_overlap, align2);
    RUN_TEST_CASE(atcacert_is_device_loc_overlap, align3);
    RUN_TEST_CASE(atcacert_is_device_loc_overlap, align4);
    RUN_TEST_CASE(atcacert_is_device_loc_overlap, align5);
    RUN_TEST_CASE(atcacert_is_device_loc_overlap, align6);
    RUN_TEST_CASE(atcacert_is_device_loc_overlap, align7);
    RUN_TEST_CASE(atcacert_is_device_loc_overlap, align8);
}

TEST_GROUP_RUNNER(atcacert_get_device_data)
{
    RUN_TEST_CASE(atcacert_get_device_data, flow);
}
