/**
 * \file
 * \brief Configuration Check for MbedTLS Integration Support
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

#ifndef ATCA_MBEDTLS_INTERFACE_H
#define ATCA_MBEDTLS_INTERFACE_H

#include "atca_config_check.h"

#ifdef ATCA_MBEDTLS

#if !defined(ATCA_BUILD_SHARED_LIBS) && defined(ATCA_NO_HEAP)
#include "atca_mbedtls_wrap.h"
#endif

/** \def ATCAC_SHA1_EN
 * Indicates if this module is a provider of a SHA1 implementation
 */
#ifndef ATCAC_SHA1_EN
#if defined(MBEDTLS_CONFIG_H) && !defined(MBEDTLS_SHA1_C)
#define ATCAC_SHA1_EN                       (DEFAULT_DISABLED)
#else
#define ATCAC_SHA1_EN                       (DEFAULT_ENABLED)
#endif
#endif /* ATCAC_SHA1_EN */

/** \def ATCAC_SHA256_EN
 * Indicates if this module is a provider of a SHA256 implementation
 */
#ifndef ATCAC_SHA256_EN
#if defined(MBEDTLS_CONFIG_H) && !defined(MBEDTLS_SHA256_C)
#define ATCAC_SHA256_EN                      (DEFAULT_DISABLED)
#else
#define ATCAC_SHA256_EN                      (FEATURE_ENABLED)
#endif
#endif /* ATCAC_SHA256_EN */

/** \def ATCAC_SHA384_EN
 * Indicates if this module is a provider of a SHA384 implementation
 *
 * Disabled by default. Use FEATURE_ENABLED to use SHA384
 */
#ifndef ATCAC_SHA384_EN
#if defined(MBEDTLS_CONFIG_H) && !defined(MBEDTLS_SHA384_C)
#define ATCAC_SHA384_EN                      (DEFAULT_DISABLED)
#else
#define ATCAC_SHA384_EN                      (FEATURE_DISABLED)
#endif
#endif /* ATCAC_SHA384_EN */

/** \def ATCAC_SHA512_EN
 * Indicates if this module is a provider of a SHA512 implementation
 *
 * Disabled by default. Use FEATURE_ENABLED to use SHA512
 */
#ifndef ATCAC_SHA512_EN
#if defined(MBEDTLS_CONFIG_H) && !defined(MBEDTLS_SHA512_C)
#define ATCAC_SHA512_EN                      (DEFAULT_DISABLED)
#else
#define ATCAC_SHA512_EN                      (FEATURE_DISABLED)
#endif
#endif /* ATCAC_SHA512_EN */

/** \def ATCAC_AES_CMAC_EN
 * Indicates if this module is a provider of an AES-CMAC implementation
 */
#ifndef ATCAC_AES_CMAC_EN
#if defined(MBEDTLS_CONFIG_H) && !defined(MBEDTLS_CMAC_C)
#define ATCAC_AES_CMAC_EN                   (DEFAULT_DISABLED)
#else
#define ATCAC_AES_CMAC_EN                   (DEFAULT_ENABLED)
#endif
#endif /* ATCAC_AES_CMAC_EN */

/** \def ATCAC_AES_GCM_EN
 * Indicates if this module is a provider of an AES-GCM implementation
 */
#ifndef ATCAC_AES_GCM_EN
#if defined(MBEDTLS_CONFIG_H) && !defined(MBEDTLS_GCM_C)
#define ATCAC_AES_GCM_EN                    (DEFAULT_DISABLED)
#else
#define ATCAC_AES_GCM_EN                    (DEFAULT_ENABLED)
#endif
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

typedef struct atcac_x509_ctx
{
    void* ptr;
} atcac_x509_ctx_t;

#endif /* ATCA_MBEDTLS */

#endif /* ATCA_MBEDTLS_INTERFACE_H */
