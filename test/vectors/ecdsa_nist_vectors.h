/**
 * \file
 * \brief Embedded NIST vectors for the ECDSA algorithm
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

#ifndef ECDSA_NIST_VECTORS_H
#define ECDSA_NIST_VECTORS_H

#include "vectors_config_check.h"
#include "atca_compiler.h"

/* See https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures */

#ifndef ATCA_NO_PRAGMA_PACK
#pragma pack(push, 1)
#endif

#if TEST_VECTOR_EC_P224_EN
typedef struct ATCA_PACKED
{
    uint8_t Msg[128];
    uint8_t Qx[28];
    uint8_t Qy[28];
    uint8_t R[28];
    uint8_t S[28];
    bool    Result;
    char*   ResultText;
} ecdsa_p224_test_vector;

extern const ecdsa_p224_test_vector ecdsa_p224_test_vectors[];
extern const size_t ecdsa_p224_test_vectors_count;
#endif

#if TEST_VECTOR_EC_P256_EN
typedef struct ATCA_PACKED
{
    uint8_t Msg[128];
    uint8_t Qx[32];
    uint8_t Qy[32];
    uint8_t R[32];
    uint8_t S[32];
    bool    Result;
    char*   ResultText;
} ecdsa_p256_test_vector;

extern const ecdsa_p256_test_vector ecdsa_p256_test_vectors[];
extern const size_t ecdsa_p256_test_vectors_count;
#endif

#if TEST_VECTOR_EC_P384_EN
typedef struct ATCA_PACKED
{
    uint8_t Msg[128];
    uint8_t Qx[48];
    uint8_t Qy[48];
    uint8_t R[48];
    uint8_t S[48];
    bool    Result;
    char*   ResultText;
} ecdsa_p384_test_vector;

#ifdef ATCA_TA100_SUPPORT
extern const ecdsa_p384_test_vector ecdsa_p384_s256_test_vectors[];
extern const size_t ecdsa_p384_s256_test_vectors_count;
#endif
#endif /* TEST_VECTOR_EC_P384_EN */

#if TEST_VECTOR_EC_P521_EN
typedef struct ATCA_PACKED
{
    uint8_t Msg[128];
    uint8_t Qx[66];
    uint8_t Qy[66];
    uint8_t R[66];
    uint8_t S[66];
    bool    Result;
    char*   ResultText;
} ecdsa_p521_test_vector;

extern const ecdsa_p521_test_vector ecdsa_p521_test_vectors[];
extern const size_t ecdsa_p521_test_vectors_count;
#endif

#ifndef ATCA_NO_PRAGMA_PACK
#pragma pack(pop)
#endif

#endif /* ECDSA_NIST_VECTORS_H */
