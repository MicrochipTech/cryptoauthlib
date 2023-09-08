/**
 * \file
 * \brief Common Utilities for working with NIST Vector Files
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

#ifndef NIST_VECTOR_UTILS_H
#define NIST_VECTOR_UTILS_H

#include "vectors_config_check.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) || defined(__linux__)

#include <stdio.h>
#include <stdlib.h>

#include "atca_status.h"

/* General Utilities */
ATCA_STATUS read_rsp_hex_value(FILE* file, const char* name, uint8_t* data, size_t data_size);
ATCA_STATUS read_rsp_int_value(FILE* file, const char* name, char * found, int* value);
ATCA_STATUS read_rsp_match_value(FILE* file, const char* name, const char* match);

ATCA_STATUS open_vectors_file(const char * path);
void close_vectors_file(void);

void free_vector(void * ptr);

/* ------------- CMAC Vector Support ------------- */

typedef struct
{
    int       count;
    int       klen;
    int       mlen;
    int       tlen;
    uint8_t * key;
    uint8_t * msg;
    uint8_t * mac;
} cmac_vector_info;

typedef struct
{
    cmac_vector_info meta;
    uint8_t          data[];
} cmac_vector;

ATCA_STATUS load_cmac_vector(cmac_vector ** vector);

/* ------------- HMAC Vector Support ------------- */

typedef struct
{
    int       count;
    int       klen;
    int       tlen;
    int       mlen;
    uint8_t * key;
    uint8_t * msg;
    uint8_t * mac;
} hmac_vector_info;

typedef struct
{
    hmac_vector_info meta;
    uint8_t          data[];
} hmac_vector;

ATCA_STATUS load_hmac_vector(hmac_vector ** vector);

/* ------------- SHA Vector Support ------------- */

typedef struct
{
    int       len;
    uint8_t * msg;
    uint8_t * digest;
} sha_vector_info;

typedef struct
{
    sha_vector_info meta;
    uint8_t         data[];
} sha_vector;

ATCA_STATUS load_sha_vector(sha_vector ** vector, size_t digest_size);



/* ------------- AES-GCM Vector Support ------------- */

typedef struct
{
    int       count;
    int       klen;
    int       ivlen;
    int       ptlen;
    int       ctlen;
    int       aadlen;
    int       taglen;
    uint8_t * key;
    uint8_t * iv;
    uint8_t * pt;
    uint8_t * ct;
    uint8_t * aad;
    uint8_t * tag;
} aes_gcm_vector_info;

typedef struct
{
    aes_gcm_vector_info meta;
    uint8_t             data[];
} aes_gcm_vector;

ATCA_STATUS load_aes_gcm_vector(aes_gcm_vector ** vector);


/* ------------- RSA Vector Support ------------- */

typedef struct
{

    uint8_t * n;
    int       e;            // Expected to be 0x03 or 0x10001
    int       mlen;
    uint8_t * msg;
    uint8_t * sig;
} rsa_vector_info;

typedef struct
{
    rsa_vector_info meta;
    uint8_t         data[];
} rsa_vector;

ATCA_STATUS load_rsa_vector(rsa_vector ** vector, size_t mod, char * hash_alg);


#endif

#ifdef __cplusplus
}
#endif

#endif /* NIST_VECTOR_UTILS_H */
