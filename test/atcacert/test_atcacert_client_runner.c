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

TEST_GROUP_RUNNER(atcacert_client)
{
    // Load certificate data onto the device
    RUN_TEST_CASE(atcacert_client, init);

    RUN_TEST_CASE(atcacert_client, atcacert_read_device_loc_gen_key);
    RUN_TEST_CASE(atcacert_client, atcacert_read_device_loc_gen_key_partial);
    RUN_TEST_CASE(atcacert_client, atcacert_read_device_loc_data_partial);

    RUN_TEST_CASE(atcacert_client, atcacert_read_cert_signer);
    RUN_TEST_CASE(atcacert_client, atcacert_read_cert_device);
    RUN_TEST_CASE(atcacert_client, atcacert_read_subj_key_id);
    RUN_TEST_CASE(atcacert_client, atcacert_read_cert_small_buf);
    RUN_TEST_CASE(atcacert_client, atcacert_read_cert_bad_params);
    RUN_TEST_CASE(atcacert_client, atcacert_generate_device_csr);
    RUN_TEST_CASE(atcacert_client, atcacert_generate_device_csr_pem);

    RUN_TEST_CASE(atcacert_client, atcacert_get_response);
    RUN_TEST_CASE(atcacert_client, atcacert_get_response_bad_params);
}
#endif
