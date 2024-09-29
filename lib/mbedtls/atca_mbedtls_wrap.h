/**
 * \brief mbedTLS Interface Functions that enable mbedtls objects to use
 * cryptoauthlib functions
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

#ifndef ATCA_MBEDTLS_WRAP_H
#define ATCA_MBEDTLS_WRAP_H

#ifdef ATCA_MBEDTLS

#ifdef __COVERITY__
#pragma coverity compliance block(include) \
    (fp "CERT INT30-C" "Ignoring violations from third party libraries") \
    (fp "CERT INT31-C" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 3.1" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 5.1" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 8.2" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 10.4" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 11.9" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 14.4" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 15.6" "Ignoring violations from third party libraries") \
    (fp "MISRA C-2012 Rule 21.1" "Ignoring violations from third party libraries")
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#ifndef MBEDTLS_CMAC_C
#define MBEDTLS_CMAC_C
#endif

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>

typedef struct atcac_sha1_ctx
{
    mbedtls_md_context_t mctx;
} atcac_sha1_ctx_t;

#if ATCAC_SHA256_EN
typedef struct atcac_sha2_256_ctx
{
    mbedtls_md_context_t mctx;
} atcac_sha2_256_ctx_t;
#endif

#if ATCAC_SHA384_EN
typedef struct atcac_sha2_384_ctx
{
    mbedtls_md_context_t mctx;
} atcac_sha2_384_ctx_t;
#endif

#if ATCAC_SHA512_EN
typedef struct atcac_sha2_512_ctx
{
    mbedtls_md_context_t mctx;
} atcac_sha2_512_ctx_t;
#endif

typedef struct atcac_hmac_ctx
{
    mbedtls_md_context_t* mctx;
} atcac_hmac_ctx_t;

typedef struct atcac_aes_gcm_ctx
{
    mbedtls_cipher_context_t mctx;
} atcac_aes_gcm_ctx_t;

typedef struct atcac_aes_cmac_ctx
{
    mbedtls_cipher_context_t mctx;
} atcac_aes_cmac_ctx_t;

typedef struct atcac_pk_ctx
{
    mbedtls_pk_context mctx;
} atcac_pk_ctx_t;

#ifdef __COVERITY__
#pragma coverity compliance end_block(include) \
    "CERT INT30-C" \
    "CERT INT31-C" \
    "MISRA C-2012 Rule 3.1" \
    "MISRA C-2012 Rule 5.1" \
    "MISRA C-2012 Rule 8.2" \
    "MISRA C-2012 Rule 10.4" \
    "MISRA C-2012 Rule 11.9" \
    "MISRA C-2012 Rule 14.4" \
    "MISRA C-2012 Rule 15.6" \
    "MISRA C-2012 Rule 21.1"
#endif


/** \defgroup atca_mbedtls_ mbedTLS Wrapper methods (atca_mbedtls_)
 *
 * \brief
 * These methods are for interfacing cryptoauthlib to mbedtls
 *
   @{ */

#include "atca_device.h"

#include "mbedtls/bignum.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mbedtls_pk_context;
struct mbedtls_x509_crt;
struct atcacert_def_s;

/** Structure to hold metadata - is written into the mbedtls pk structure as the private key
    bignum value 'd' which otherwise would be unused. Bignums can be any arbitrary length of
    bytes    */
typedef struct atca_mbedtls_eckey_s
{
    ATCADevice device;
    uint16_t   handle;
} atca_mbedtls_eckey_t;

/* Integration Helper */
int atca_mbedtls_ecdsa_sign(const mbedtls_mpi* d, mbedtls_mpi* r, mbedtls_mpi* s,
                            const unsigned char* buf, size_t buf_len);

/* Wrapper Functions */
int atca_mbedtls_pk_init_ext(ATCADevice device, mbedtls_pk_context* pkey, const uint16_t slotid);
int atca_mbedtls_pk_init(mbedtls_pk_context* pkey, const uint16_t slotid);
int atca_mbedtls_cert_add(struct mbedtls_x509_crt * cert, const struct atcacert_def_s * cert_def);

/* Application Callback definitions */

/** \brief ECDH Callback to obtain the "slot" used in ECDH operations from the
 * application
 * \return Slot Number
 */
int atca_mbedtls_ecdh_slot_cb(void);

/** \brief ECDH Callback to obtain the IO Protection secret from the application
 * \param[out] secret 32 byte array used to store the secret
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atca_mbedtls_ecdh_ioprot_cb(uint8_t secret[32]);

struct mbedtls_x509_crt* atcac_mbedtls_new(void);
struct atcac_x509_ctx* atcac_x509_ctx_new(void);
void atcac_x509_ctx_free(struct atcac_x509_ctx* ctx);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* ATCA_MBEDTLS */

#endif /* _ATCA_MBEDTLS_WRAP_H_ */
