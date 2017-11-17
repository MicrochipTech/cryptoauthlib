/**
 * \file
 * \brief Unity tests for the CryptoAuthLib software crypto API.
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

#ifndef ATCA_CRYPTO_TESTS_H_
#define ATCA_CRYPTO_TESTS_H_

#include "unity.h"

int atca_crypto_sw_tests(void);

void test_atcac_sw_sha1_nist1(void);
void test_atcac_sw_sha1_nist2(void);
void test_atcac_sw_sha1_nist3(void);
void test_atcac_sw_sha1_nist_short(void);
void test_atcac_sw_sha1_nist_long(void);
void test_atcac_sw_sha1_nist_monte(void);
void test_atcac_sw_sha2_256_nist1(void);
void test_atcac_sw_sha2_256_nist2(void);
void test_atcac_sw_sha2_256_nist3(void);
void test_atcac_sw_sha2_256_nist_short(void);
void test_atcac_sw_sha2_256_nist_long(void);
void test_atcac_sw_sha2_256_nist_monte(void);


#endif