/**
 * \file
 * \brief WolfSSL Integration Support
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

#ifndef ATCA_WOLFSSL_INTERFACE_H
#define ATCA_WOLFSSL_INTERFACE_H

#ifdef ATCA_WOLFSSL

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __COVERITY__
#pragma coverity compliance block(include) \
    (fp "CERT DCL37-C" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Directive 4.10" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 3.1" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 7.3" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 8.2" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 20.13" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 21.1" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 21.2" "Ignoring violations from third party libraries")
#endif

#include "wolfssl/wolfcrypt/types.h"
#ifndef WOLFSSL_CMAC
#define WOLFSSL_CMAC
#endif
#ifndef HAVE_AESGCM
#define HAVE_AESGCM
#endif
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/sha.h"
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/error-crypt.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/random.h"

typedef struct atcac_aes_gcm_ctx
{
    Aes      aes;
    uint8_t  iv[AES_BLOCK_SIZE];
    uint16_t iv_len;
} atcac_aes_gcm_ctx_t;

typedef struct atcac_sha1_ctx
{
    wc_Sha sha;
} atcac_sha1_ctx_t;

typedef struct atcac_sha2_256_ctx
{
    wc_Sha256 sha;
} atcac_sha2_256_ctx_t;

typedef struct atcac_sha2_384_ctx
{
    wc_Sha384 sha;
} atcac_sha2_384_ctx_t;

typedef struct atcac_sha2_512_ctx
{
    wc_Sha512 sha;
} atcac_sha2_512_ctx_t;

typedef struct atcac_aes_cmac_ctx
{
    Cmac cmac;
} atcac_aes_cmac_ctx_t;

typedef struct atcac_hmac_ctx
{
    Hmac hmac;
} atcac_hmac_ctx_t;

typedef struct atcac_pk_ctx
{
    void*   ptr;
    uint8_t key_type;
} atcac_pk_ctx_t;

/* Some configurations end up with a circular definition the above have to be defined before include ecc.h (since ecc.h can call cryptoauthlib functions) */
#include "wolfssl/wolfcrypt/ecc.h"

#ifdef __COVERITY__
#pragma coverity compliance end_block(include) \
    "CERT DCL37-C" \
    "MISRA C-2012 Directive 4.10" \
    "MISRA C-2012 Rule 3.1" \
    "MISRA C-2012 Rule 7.3" \
    "MISRA C-2012 Rule 8.2" \
    "MISRA C-2012 Rule 20.13" \
    "MISRA C-2012 Rule 21.1" \
    "MISRA C-2012 Rule 21.2"
#endif

#ifdef __cplusplus
}
#endif

#endif /* ATCA_WOLFSSL */

#endif /* ATCA_WOLFSSL_INTERFACE_H */
