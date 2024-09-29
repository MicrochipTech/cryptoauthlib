/**
 * \file
 * \brief OpenSSL Integration Support
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

#ifndef ATCA_OPENSSL_INTERFACE_H
#define ATCA_OPENSSL_INTERFACE_H

#include "atca_config_check.h"

#ifdef ATCA_OPENSSL

#ifdef __cplusplus
extern "C" {
#endif

/** \def ATCAC_SHA1_EN
 * Indicates if this module is a provider of a SHA1 implementation
 */
#ifndef ATCAC_SHA1_EN
#define ATCAC_SHA1_EN                       (DEFAULT_ENABLED)
#endif /* ATCAC_SHA1_EN */

/** \def ATCAC_SHA256_EN
 * Indicates if this module is a provider of a SHA256 implementation
 */
#ifndef ATCAC_SHA256_EN
#define ATCAC_SHA256_EN                      (FEATURE_ENABLED)
#endif /* ATCAC_SHA256_EN */

/** \def ATCAC_SHA384_EN
 * Indicates if this module is a provider of a SHA384 implementation
 *
 * Disabled by default. Use FEATURE_ENABLED to use SHA384
 */
#ifndef ATCAC_SHA384_EN
#define ATCAC_SHA384_EN                      (FEATURE_DISABLED)
#endif /* ATCAC_SHA384_EN */

/** \def ATCAC_SHA512_EN
 * Indicates if this module is a provider of a SHA512 implementation
 *
 * Disabled by default. Use FEATURE_ENABLED to use SHA512
 */
#ifndef ATCAC_SHA512_EN
#define ATCAC_SHA512_EN                      (FEATURE_DISABLED)
#endif /* ATCAC_SHA512_EN */

/** \def ATCAC_AES_CMAC_EN
 * Indicates if this module is a provider of an AES-CMAC implementation
 */
#ifndef ATCAC_AES_CMAC_EN
#define ATCAC_AES_CMAC_EN                   (DEFAULT_ENABLED)
#endif /* ATCAC_AES_CMAC_EN */

/** \def ATCAC_AES_GCM_EN
 * Indicates if this module is a provider of an AES-GCM implementation
 */
#ifndef ATCAC_AES_GCM_EN
#define ATCAC_AES_GCM_EN                    (DEFAULT_ENABLED)
#endif /* ATCAC_AES_GCM_EN */

/** \def ATCAC_PKEY_EN
 * Indicates if this module is a provider of a generic asymmetric cryptography
 * implementation */
#ifndef ATCAC_PKEY_EN
#define ATCAC_PKEY_EN                       (DEFAULT_ENABLED)
#endif

/** \def HOSTLIB_CERT_EN
 * Indicates if this module is a provider of x509 certificate handling
 */
#ifndef HOSTLIB_CERT_EN
#define HOSTLIB_CERT_EN                     (DEFAULT_ENABLED)
#endif

#if ATCAC_AES_GCM_EN
typedef struct atcac_aes_gcm_ctx
{
    void* ptr;
} atcac_aes_gcm_ctx_t;
#endif

typedef struct atcac_sha1_ctx
{
    void* ptr;
} atcac_sha1_ctx_t;

typedef struct atcac_sha2_256_ctx
{
    void* ptr;
} atcac_sha2_256_ctx_t;

typedef struct atcac_sha2_384_ctx
{
    void* ptr;
} atcac_sha2_384_ctx_t;

typedef struct atcac_sha2_512_ctx
{
    void* ptr;
} atcac_sha2_512_ctx_t;

typedef struct atcac_aes_cmac_ctx
{
    void* ptr;
} atcac_aes_cmac_ctx_t;

typedef struct atcac_hmac_ctx
{
    void* ptr;
} atcac_hmac_ctx_t;

typedef struct atcac_pk_ctx
{
    void* ptr;
} atcac_pk_ctx_t;

typedef struct atcac_x509_ctx
{
    void* ptr;
} atcac_x509_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* ATCA_OPENSSL */

#endif /* ATCA_OPENSSL_INTERFACE_H */
