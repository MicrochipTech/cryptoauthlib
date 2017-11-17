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


#ifndef ATCA_TLS_TESTS_H_
#define ATCA_TLS_TESTS_H_


#include "test/unity.h"

void atcatls_test_runner(ATCAIfaceCfg* pCfg);

// TLS API Init/finish
void test_atcatls_config_default(void);
void test_atcatls_init_finish(void);

// Core TLS definitions
void test_atcatls_create_key(void);
void test_atcatls_sign(void);
void test_atcatls_verify(void);
void test_atcatls_ecdh(void);
void test_atcatls_ecdhe(void);
void test_atcatls_calc_pubkey(void);
void test_atcatls_read_pubkey(void);
void test_atcatls_random(void);
void test_atcatls_get_sn(void);

// Certificate Handling
void test_atcatls_verify_cert_chain(void);
void test_atcatls_verify_default_certs(void);
void test_atcatls_ca_pubkey_write_read(void);
void test_atcatls_get_ca_cert(void);
void test_atcatls_create_csr(void);

// Encrypted Read/Write
void test_atcatls_init_enc_key(void);
void test_atcatls_enc_write_read(void);
void test_atcatls_enc_rsakey_write_read(void);


#endif /* ATCA_TLS_TESTS_H_ */