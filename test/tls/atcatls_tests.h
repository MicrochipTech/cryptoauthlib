/**
 * \file
 *
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