/**
 * \file
 * \brief Consistency checks for configuration options
 *
 * \copyright (c) 2015-2021 Microchip Technology Inc. and its subsidiaries.
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

#ifndef CRYPTO_CONFIG_CHECK_H
#define CRYPTO_CONFIG_CHECK_H

#include "atca_config_check.h"

#if ATCA_HOSTLIB_EN
#if defined(ATCA_MBEDTLS)
#include "mbedtls/atca_mbedtls_interface.h"
#elif defined(ATCA_WOLFSSL)
#include "wolfssl/atca_wolfssl_interface.h"
#elif defined(ATCA_OPENSSL)
#include "openssl/atca_openssl_interface.h"
#endif
#endif

/* Host side Cryptographic functionality required by the library */

/** \def ATCAC_SHA1_EN
 *
 * Enable ATCAC_SHA1_EN to enable sha1 host side api
 *
 * Supported API's: atcab_write
 **/
#ifndef ATCAC_SHA1_EN
#define ATCAC_SHA1_EN                       (DEFAULT_ENABLED)
#endif

/** \def ATCAC_SHA256_EN
 *
 * Enable ATCAC_SHA256_EN to enable sha256 host side api
 *
 * Supported API's: atcab_write
 **/
#ifndef ATCAC_SHA256_EN
#define ATCAC_SHA256_EN                     (DEFAULT_ENABLED)
#endif

/** \def ATCAC_SHA256_HMAC
 *
 * Requires: ATCAC_SHA256_HMAC
 *           ATCAC_SW_SHA2_256
 *
 * Enable ATCAC_SHA256_HMAC to initialize context for performing HMAC (sha256) in software
 *
 * Supported API's: atcac_sha256_hmac_init, atcac_sha256_hmac_update, atcac_sha256_hmac_finish
 **/
#ifndef ATCAC_SHA256_HMAC_EN
#define ATCAC_SHA256_HMAC_EN                ATCAC_SHA256_EN
#endif

/** \def ATCAC_SHA256_HMAC_COUNTER
 *
 * Requires: ATCAC_SHA256_HMAC_COUNTER
 *           ATCAC_SHA256_HMAC
 *           ATCAC_SW_SHA2_256
 *
 * Enable ATCAC_SHA256_HMAC_COUNTER to implement SHA256 HMAC-Counter per NIST SP 800-108 used for
 * KDF like operations
 *
 * Supported API's: atcac_sha256_hmac_counter
 **/
#ifndef ATCAC_SHA256_HMAC_CTR_EN
#define ATCAC_SHA256_HMAC_CTR_EN            ATCAC_SHA256_HMAC_EN
#endif

/** \def ATCAC_RANDOM_EN
 *
 * Requires: ATCA_HOSTLIB_EN
 *
 * Enable ATCAC_RANDOM_EN get random numbers from the host's
 * implementation - generally assumed to come from the host's
 * cryptographic library or peripheral driver
 *
 */
#ifndef ATCAC_RANDOM_EN
#define ATCAC_RANDOM_EN                     ATCA_HOSTLIB_EN
#endif

/** \def ATCAC_VERIFY_EN
 *
 * Requires: ATCA_HOSTLIB_EN
 *
 * Enable ATCAC_VERIFY_EN to use the host's verify functions. Generally assumed
 * to come from the host's cryptographic library or peripheral driver.
 */
#ifndef ATCAC_VERIFY_EN
#define ATCAC_VERIFY_EN                     ATCA_HOSTLIB_EN
#endif

/** \def ATCAC_SIGN_EN
 *
 * Requires: ATCA_HOSTLIB_EN
 *
 * Enable ATCAC_SIGN_EN to use the host's sign functions. Generally assumed
 * to come from the host's cryptographic library or peripheral driver.
 */
#ifndef ATCAC_SIGN_EN
#define ATCAC_SIGN_EN                       ATCA_HOSTLIB_EN
#endif

/** \def ATCA_CRYPTO_SHA1_EN
 *
 * Enable ATCAC_SHA1_EN to enable sha1 host side api
 *
 * Supported API's: atcab_write
 **/
#ifndef ATCA_CRYPTO_SHA1_EN
#define ATCA_CRYPTO_SHA1_EN                 (ATCAC_SHA1_EN && !ATCA_HOSTLIB_EN)
#endif

/** \def ATCAC_SHA256_EN
 *
 * Enable ATCAC_SHA256_EN to enable sha256 host side api
 *
 * Supported API's: atcab_write
 **/
#ifndef ATCA_CRYPTO_SHA2_EN
#define ATCA_CRYPTO_SHA2_EN                 (ATCAC_SHA256_EN && !ATCA_HOSTLIB_EN)
#endif

/** \def ATCA_CRYPTO_SHA2_HMAC_EN
 *
 * Requires: ATCAC_SHA256_EN
 *
 * Enable ATCAC_SHA256_HMAC to initialize context for performing HMAC (sha256) in software
 *
 * Supported API's: atcac_sha256_hmac_init, atcac_sha256_hmac_update, atcac_sha256_hmac_finish
 **/
#ifndef ATCA_CRYPTO_SHA2_HMAC_EN
#define ATCA_CRYPTO_SHA2_HMAC_EN            (ATCAC_SHA256_HMAC_EN && !ATCA_HOSTLIB_EN)
#endif

/** \def ATCA_CRYPTO_SHA2_HMAC_CTR_EN
 *
 * Requires: ATCAC_SHA256_HMAC_EN
 *
 * Enable ATCAC_SHA256_HMAC_COUNTER to implement SHA256 HMAC-Counter per NIST SP 800-108 used for
 * KDF like operations
 *
 * Supported API's: atcac_sha256_hmac_counter
 **/
#ifndef ATCA_CRYPTO_SHA2_HMAC_CTR_EN
#define ATCA_CRYPTO_SHA2_HMAC_CTR_EN        ATCAC_SHA256_HMAC_CTR_EN
#endif

/****** ATCA_CRYPTO_PBKDF2 ******/

/** \def  ATCAC_PBKDF2_SHA256_EN
 *
 * Requires: ATCAC_SHA256_EN
 *           ATCAC_SHA256_HMAC_EN
 *
 * Enable ATCAC_PBKDF2_SHA256_EN to calculate a PBKDF2 hash of a given password and salt
 *
 * Supported API's: atcac_pbkdf2_256
 **/
#ifndef ATCAC_PBKDF2_SHA256_EN
#define ATCAC_PBKDF2_SHA256_EN      ATCAC_SHA256_HMAC_EN
#endif

/** \def  ATCAB_PBKDF2_SHA256_EN
 *
 * Requires: CALIB_SHA_HMAC_EN
 *
 * Enable ATCAB_PBKDF2_SHA256_EN to calculate a PBKDF2 password hash using a stored key inside a
 * device. The key length is determined by the device being used. ECCx08: 32 bytes, TA100: 16-64 bytes
 *
 * Supported API's: atcab_pbkdf2_256, atcab_pbkdf2_256_ext
 **/
#ifndef ATCAB_PBKDF2_SHA256_EN
#define ATCAB_PBKDF2_SHA256_EN      (CALIB_SHA_HMAC_EN || TALIB_SHA_HMAC_EN)
#endif

#endif /* CRYPTO_CONFIG_CHECK_H */
