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

#ifndef ATCA_CONFIG_CHECK_H
#define ATCA_CONFIG_CHECK_H

#define FEATURE_ENABLED     (1)
#define FEATURE_DISABLED    (0)

#define DEFAULT_ENABLED     FEATURE_ENABLED
#define DEFAULT_DISABLED    FEATURE_DISABLED

/** Library Configuration File - All build attributes should be included in
    atca_config.h */
#if defined(LIBRARY_BUILD_EN)
    #define LIBRARY_BUILD_EN_CHECK 1
#else
    #define LIBRARY_BUILD_EN_CHECK 0
    #include "atca_config.h"
#endif

#if defined(LIBRARY_USAGE_EN)
    #define LIBRARY_USAGE_EN_CHECK 1
#else
    #define LIBRARY_USAGE_EN_CHECK 0
#endif

/* Configuration Macros to detect device classes */
#if defined(ATCA_ATSHA204A_SUPPORT) || defined(ATCA_ATSHA206A_SUPPORT) || defined(ATCA_SHA104_SUPPORT) || defined(ATCA_SHA105_SUPPORT)
#define ATCA_SHA_SUPPORT    1
#endif

/* Make sure all configuration options work */
#if defined(ATCA_ATECC608A_SUPPORT) && !defined(ATCA_ATECC608_SUPPORT)
#define ATCA_ATECC608_SUPPORT
#endif

/* Support for fully featured ECC devices */
#if defined(ATCA_ATECC108A_SUPPORT) || defined(ATCA_ATECC508A_SUPPORT) \
    || defined(ATCA_ATECC608_SUPPORT)
#define ATCA_ECC_SUPPORT    DEFAULT_ENABLED
#else
#define ATCA_ECC_SUPPORT    DEFAULT_DISABLED
#endif

/* Support for a second generation of cryptoauth parts */
#if defined(ATCA_ECC204_SUPPORT) || defined(ATCA_TA010_SUPPORT) || defined(ATCA_SHA104_SUPPORT) || defined(ATCA_SHA105_SUPPORT)
#define ATCA_CA2_SUPPORT    DEFAULT_ENABLED
#else
#define ATCA_CA2_SUPPORT    DEFAULT_DISABLED
#endif

/* Support for cert feature in second generation of cryptoauth parts */
#if defined(ATCA_ECC204_SUPPORT) || defined(ATCA_TA010_SUPPORT)
#define ATCA_CA2_CERT_SUPPORT    DEFAULT_ENABLED
#else
#define ATCA_CA2_CERT_SUPPORT    DEFAULT_DISABLED
#endif

/* Classic Cryptoauth Devices */
#if defined(ATCA_SHA_SUPPORT) || ATCA_ECC_SUPPORT || ATCA_CA2_SUPPORT
#define ATCA_CA_SUPPORT     DEFAULT_ENABLED
#else
#define ATCA_CA_SUPPORT     DEFAULT_DISABLED
#endif

/* New Trust Anchor Devices */
#ifndef ATCA_TA_SUPPORT
#if defined(ATCA_TA100_SUPPORT) || defined(ATCA_TA101_SUPPORT)
#define ATCA_TA_SUPPORT     DEFAULT_ENABLED
#else
#define ATCA_TA_SUPPORT     DEFAULT_DISABLED
#endif
#endif /* ATCA_TA_SUPPORT */

/* Check for external crypto libraries for host side operations */
#ifndef ATCA_HOSTLIB_EN
#if defined(ATCA_MBEDTLS) || defined(ATCA_OPENSSL) || defined(ATCA_WOLFSSL)
#define ATCA_HOSTLIB_EN    DEFAULT_ENABLED
#else
#define ATCA_HOSTLIB_EN    DEFAULT_DISABLED
#endif
#endif

/** Does the atcab_ API layer need to be instantiated (adds a layer of abstraction) */
#ifndef ATCA_USE_ATCAB_FUNCTIONS
#if (ATCA_TA_SUPPORT && ATCA_CA_SUPPORT)
#define ATCA_USE_ATCAB_FUNCTIONS
#endif
#endif

#ifndef ATCA_CHECK_PARAMS_EN
#define ATCA_CHECK_PARAMS_EN    DEFAULT_ENABLED
#endif

#if ATCA_CHECK_PARAMS_EN
/** Emits message and returns the status code when the condition is true */
#define ATCA_CHECK_INVALID_MSG(c, s, m)     if (c) { return ATCA_TRACE(s, m); }
/* Continues when the condition is true - emits message if the condition is false */
#define ATCA_CHECK_VALID_MSG(c, m)          if (!ATCA_TRACE(!(c), m))
#else
#define ATCA_CHECK_INVALID_MSG(c, s, m)     
#define ATCA_CHECK_VALID_MSG(c, m)          if (1)
#endif

#define ATCA_CHECK_INVALID(c, s)    ATCA_CHECK_INVALID_MSG(c, s, "")
#define ATCA_CHECK_VALID(c)         ATCA_CHECK_VALID_MSG(c, "")

/** \def MULTIPART_BUF_EN
 * Enables multipart buffer handling (generally for small memory model platforms)
 */
#ifndef MULTIPART_BUF_EN
#define MULTIPART_BUF_EN        (DEFAULT_DISABLED)
#endif

#ifndef ATCA_NO_HEAP
#define ATCA_HEAP
#endif

/** \def ATCA_UNUSED_VAR_CHECK
 * Enables removal of compiler warning due to unused variables
 */
#ifndef ATCA_UNUSED_VAR_CHECK
#define ATCA_UNUSED_VAR_CHECK   (DEFAULT_ENABLED)
#endif

/**** AES command ****/

/** \def ATCAB_AES
 *
 * Enable ATCAB_AES to compute the AES-128 encrypt, decrypt
 *
 * Supported API's: atcab_aes
 **/
#ifndef ATCAB_AES_EN
#if defined(ATCA_ATECC608_SUPPORT) || defined(ATCA_TA_SUPPORT)
#define ATCAB_AES_EN              (DEFAULT_ENABLED)
#else
#define ATCAB_AES_EN              (DEFAULT_DISABLED)
#endif
#endif

/** \def ATCAB_AES_GFM_EN
 *
 * Enable ATCAB_AES_GFM_EN to enabled Galois Field Multiply
 *
 * Supported API's: atcab_aes
 **/
#if !defined(ATCAB_AES_GFM_EN) && ATCAB_AES_EN && defined(ATCA_ATECC608_SUPPORT)
#define ATCAB_AES_GFM_EN          (DEFAULT_ENABLED)
#endif

/** \def ATCAB_AES_GCM
 *
 * Requires: ATCAB_AES_GCM
 *
 * Supported API's: atcab_aes_gcm_init
 *                  atcab_aes_gcm_init_rand
 *                  atcab_aes_gcm_aad_update
 *                  atcab_aes_gcm_encrypt_update
 *                  atcab_aes_gcm_encrypt_finish
 *                  atcab_aes_gcm_decrypt_update
 *                  atcab_aes_gcm_decrypt_finish
 **/
#ifndef ATCAB_AES_GCM_EN
#define ATCAB_AES_GCM_EN          (DEFAULT_ENABLED)
#endif

#if ATCAB_AES_GCM_EN && !ATCAB_AES_GFM_EN && !ATCA_TA_SUPPORT && ATCA_ECC_SUPPORT
#error "AES128-GCM with ECC parts required the GFM (ATCAB_AES_GFM_EN) to be enabled as well"
#endif

/**** CHECKMAC command ****/

/** \def ATCAB_CHECKMAC
 *
 * Requires: ATCAB_CHECKMAC
 *           CALIB_CHECKMAC
 *
 * Enable ATCAB_CHECKMAC to compare a MAC response with input values
 *
 * Supported API's: atcab_checkmac
 **/
#ifndef ATCAB_CHECKMAC_EN
#define ATCAB_CHECKMAC_EN             (DEFAULT_ENABLED)
#endif

/***** COUNTER command *****/

/** \def ATCAB_COUNTER
 *
 * Requires: ATCAB_COUNTER
 *           CALIB_COUNTER
 *
 * Enable ATCAB_COUNTER to compute the counter functions
 *
 * Supported API's: atcab_counter
 **/
#ifndef ATCAB_COUNTER_EN
#define ATCAB_COUNTER_EN                (DEFAULT_ENABLED)
#endif

/*****  DERIVEKEY command ******/

/** \def ATCAB_DERIVEKEY
 *
 * Requires: ATCAB_DERIVEKEY
 *           CALIB_DERIVEKEY
 *
 * Enable ATCAB_DERIVEKEY for deriving a new key from a nonce (TempKey) and an existing key
 *
 * Supported API's: atcab_derivekey
 **/
#ifndef ATCAB_DERIVEKEY_EN
#define ATCAB_DERIVEKEY_EN              (DEFAULT_ENABLED)
#endif

/******* ECDH command *******/

/** \def ATCAB_ECDH
 *
 * Requires: ATCAB_ECDH
 *           CALIB_ECDH
 *
 * Supported API's: atcab_ecdh_base
 *                  atcab_ecdh
 *                  atcab_ecdh_tempkey
 *
 * Enable ATCAB_ECDH for generating premaster secret key using ECDH
 * ECDH command with a private key in a slot/tempkey and the premaster secret is returned in the clear
 **/
#ifndef ATCAB_ECDH_EN
#define ATCAB_ECDH_EN                     (DEFAULT_ENABLED)
#endif

/** \def ATCAB_ECDH_ENC
 *
 *  Requires: ATCAB_ECDH_ENC
 *            CALIB_ECDH_ENC
 *
 *  Supported API's: atcab_ecdh_enc
 *                   atcab_ecdh_ioenc
 *                   atcab_ecdh_tempkey_ioenc
 *
 * ECDH command with a private key in a slot and the premaster secret is read from the next slot
 * ECDH command with a private key in a slot/tempkey and the premaster secret is returned encrypted
 * using the IO protection key
 **/
#ifndef ATCAB_ECDH_ENC_EN
#define ATCAB_ECDH_ENC_EN                 (DEFAULT_ENABLED)
#endif

/******  GENDIG command  ******/

/** \def ATCAB_GENDIG
 *
 * Requires: ATCAB_GENDIG
 *           CALIB_GENDIG
 *
 * Enable ATCAB_GENDIG to perform a SHA256 hash on the source data indicated by zone with  the
 * contents of TempKey
 *
 * Supported API's: atcab_gendig
 **/
#ifndef ATCAB_GENDIG_EN
#define ATCAB_GENDIG_EN                   (DEFAULT_ENABLED)
#endif

/******  GENKEY COMMAND  ******/

/** \def ATCAB_GENKEY_BASE
 *
 * Requires: ATCAB_GENKEY_BASE
 *           CALIB_GENKEY_BASE
 *
 * Enable ATCAB_GENKEY_BASE which can generate a private key, compute a public key, nd/or compute a
 * digest of a public key
 *
 * Supported API's: atcab_genkey_base
 **/
#ifndef ATCAB_GENKEY_EN
#define ATCAB_GENKEY_EN                   (DEFAULT_ENABLED)
#endif

/** \def ATCAB_GENKEY_MAC_EN
 *
 * Requires: ATCAB_GENKEY_EN
 *
 * Enable ATCAB_GENKEY_MAC_EN which provides for a mac with the genkey command
 *
 * Supported API's: atcab_genkey_base
 **/
#ifndef ATCAB_GENKEY_MAC_EN
#define ATCAB_GENKEY_MAC_EN               ATCAB_GENKEY_EN
#endif

/******* HMAC COMMAND *******/

/** \def ATCAB_HMAC
 *
 * Requires: ATCAB_HMAC
 *           ATCAB_HMAC
 *
 * Enable ATCAB_HMAC which computes an HMAC/SHA-256 digest of a key stored in the device, a
 * challenge, and other information on the device
 *
 * Supported API's: atcab_hmac
 **/
#ifndef ATCAB_HMAC_EN
#define ATCAB_HMAC_EN                     (DEFAULT_ENABLED)
#endif

/******* INFO COMMAND ********/

/** \def ATCAB_INFO_LATCH_EN
 *
 * Enable ATCAB_INFO_LATCH_EN which enables control of GPIOs and the
 * persistent latch
 *
 * Supported API's: atcab_info_base
 **/
#ifndef ATCAB_INFO_LATCH_EN
#define ATCAB_INFO_LATCH_EN             (DEFAULT_ENABLED)
#endif

/****** KDF COMMAND ******/

/** \def ATCAB_KDF
 *
 *  Requires: ATCAB_KDF
 *            CALIB_KDF
 *
 * Enable ATCAB_KDF to derive a new key in PRF, AES, or HKDF modes
 *
 * Supported API's: atcab_kdf
 **/
#ifndef ATCAB_KDF_EN
#define ATCAB_KDF_EN                      (DEFAULT_ENABLED)
#endif

/****** LOCK COMMAND ******/

/** \def ATCAB_LOCK
 *
 * Requires: ATCAB_LOCK
 *            CALIB_LOCK
 *
 * Enable ATCAB_LOCK which prevents future modifications of the Configuration and/or Data and OTP zones
 *
 * Supported API's: atcab_lock
 **/
#ifndef ATCAB_LOCK_EN
#define ATCAB_LOCK_EN                       (DEFAULT_ENABLED)
#endif

/******  MAC command  ******/

/** \def ATCAB_MAC
 *
 * Enable ATCAB_MAC to computes a SHA-256 digest of a key stored in the device, a challenge, and
 * other information on the device
 *
 * Supported API's: atcab_mac
 **/
#ifndef ATCAB_MAC_EN
#define ATCAB_MAC_EN                        (DEFAULT_ENABLED)
#endif

/****** NONCE command ******/

/** \def ATCAB_NONCE_BASE
 *
 * Enable ATCAB_NONCE_BASE which loads a random or fixed nonce/data into the device for use by subsequent
 * commands
 *
 * Requires: ATCAB_NONCE_BASE
 *           CALIB_NONCE_BASE
 *
 * Supported API's: atcab_nonce_base
 **/
#ifndef ATCAB_NONCE_EN
#define ATCAB_NONCE_EN                      (DEFAULT_ENABLED)
#endif

/****  PRIVWRITE COMMAND  ****/

/** \def ATCAB_PRIVWRITE
 *
 * Enable ATCAB_PRIVWRITE to write externally generated ECC private keys into the device
 *
 * Requires: ATCAB_PRIVWRITE
 *           CALIB_PRIVWRITE
 *
 * Supported API's: atcab_priv_write
 **/
#ifndef ATCAB_PRIVWRITE_EN
#define ATCAB_PRIVWRITE_EN                   (DEFAULT_ENABLED)
#endif

/***** RANDOM COMMAND *****/

/** \def ATCAB_RANDOM
 *
 * Requires: ATCAB_RANDOM
 *           CALIB_RANDOM
 *
 * Enable ATCAB_RANDOM which generates a 32 byte random number from the CryptoAuth device
 *
 * Supported API's: atcab_random
 *                  atcab_random_ext
 **/
#ifndef ATCAB_RANDOM_EN
#define ATCAB_RANDOM_EN                     (DEFAULT_ENABLED)
#endif

/*****  READ command  *****/

/** \def ATCAB_READ_ZONE
 *
 * Requires: ATCAB_READ_ZONE
 *           CALIB_READ_ZONE
 *
 * Enable ATCAB_READ_ZONE which reads either 4 or 32 bytes of data from a given slot,
 * configuration zone, or the OTP zone
 *
 * Supported API's: atcab_read_zone
 **/
#ifndef ATCAB_READ_EN
#define ATCAB_READ_EN                       (DEFAULT_ENABLED)
#endif

/** \def ATCAB_READ_ENC
 *
 * Requires: ATCAB_READ_ENC
 *           CALIB_READ_ENC
 *
 * Performs Read command on a slot configured for encrypted reads and decrypts the data to return
 * it as plaintext
 *
 * Supported API's: atcab_read_enc
 **/
#ifndef ATCAB_READ_ENC_EN
#define ATCAB_READ_ENC_EN                     ATCAB_READ_EN
#endif

/***** SECUREBOOT command ****/

/** \def ATCAB_SECUREBOOT
 *
 * Enable ATCAB_SECUREBOOT which provides support for secureboot of an external MCU or MPU
 *
 * Requires: ATCAB_SECUREBOOT
 *
 * Supported API's: atcab_secureboot
 **/
#ifndef ATCAB_SECUREBOOT_EN
#define ATCAB_SECUREBOOT_EN                   (DEFAULT_ENABLED)
#endif

/** \def ATCAB_SECUREBOOT_MAC
 *
 * Requires: ATCAB_SECUREBOOT_MAC
 *           CALIB_SECUREBOOT_MAC
 *
 * Performs secureboot command with encrypted digest and validated MAC response using the
 * IO protection key
 *
 * Supported API's: ATCAB_secureboot_mac
 **/
#ifndef ATCAB_SECUREBOOT_MAC_EN
#define ATCAB_SECUREBOOT_MAC_EN               ATCAB_SECUREBOOT_EN
#endif

/**** SELFTEST command ****/

/** \def ATCAB_SELFTEST
 *
 * Enable ATCAB_SELFTEST which performs a test of one or more of the cryptographic engines within
 * the ATECC608 chip
 *
 * Supported API's: atcab_selftest
 **/
#ifndef ATCAB_SELFTEST_EN
#define ATCAB_SELFTEST_EN                     (DEFAULT_ENABLED)
#endif

/****** SHA command ******/

/** \def ATCAB_SHA_BASE
 *
 * Requires: ATCAB_SHA_BASE
 *           CALIB_SHA_BASE
 *
 * Enable ATCAB_SHA_BASE to compute a SHA-256 or HMAC/SHA-256 digest for general purpose use by
 * the host system
 *
 * Supported API's: atcab_sha_base
 **/
#ifndef ATCAB_SHA_EN
#define ATCAB_SHA_EN                        (DEFAULT_ENABLED)
#endif

/** \def ATCAB_SHA_HMAC
 *
 * Requires: ATCAB_SHA_HMAC
 *
 * Use the SHA command to compute an HMAC/SHA-256 operation
 *
 * Supported API's: atcab_sha_hmac, atcab_sha_hmac_init, atcab_sha_hmac_update,
 *                  atcab_sha_hmac_finish, atcab_sha_hmac_ext
 **/
#ifndef ATCAB_SHA_HMAC_EN
#define ATCAB_SHA_HMAC_EN                   ATCAB_SHA_EN
#endif

/** \def ATCAB_SHA_READ_CONTEXT_EN
 *
 * Requires: ATCAB_SHA_EN
 *
 * Use the SHA command to compute an HMAC/SHA-256 operation
 *
 * Supported API's: atcab_sha_read_context, atcab_sha_write_context
 **/
#ifndef ATCAB_SHA_CONTEXT_EN
#define ATCAB_SHA_CONTEXT_EN                ATCAB_SHA_EN
#endif

/****** SIGN command ******/

/** \def ATCAB_SIGN_BASE
 *
 * Requires: ATCAB_SIGN_BASE
 *           CALIB_SIGN_BASE
 *
 * Enable ATCAB_SIGN_BASE to generate a signature using the ECDSA algorithm
 *
 * Supported API's: atcab_sign_base
 **/
#ifndef ATCAB_SIGN_EN
#define ATCAB_SIGN_EN                       (DEFAULT_ENABLED)
#endif

/** \def ATCAB_SIGN_MODE_ENCODING
 *
 * Requires: ATCAB_SIGN
 *
 * Use ATCAB_SIGN_INTERNAL to sign a internally generated message
 *
 * Supported API's: atcab_sign_internal
 **/
#ifndef ATCAB_SIGN_INTERNAL_EN
#define ATCAB_SIGN_INTERNAL_EN              ATCAB_SIGN_EN
#endif

/***** UPDATEEXTRA command ****/

/** \def ATCAB_UPDATEEXTRA
 *
 * Requires: ATCAB_UPDATEEXTRA
 *
 * Enable ATCAB_UPDATEEXTRA to update the values of the two extra bytes within the configuration
 * zone (bytes 84 and 85)
 *
 * Supported API's: atcab_updateextra
 **/
#ifndef ATCAB_UPDATEEXTRA_EN
#define ATCAB_UPDATEEXTRA_EN                (DEFAULT_ENABLED)
#endif

/******** VERIFY command ********/

/** \def ATCAB_VERIFY
 *
 * Requires: ATCAB_VERIFY
 *           CALIB_VERIFY
 *
 * Enable ATCAB_VERIFY which takes an ECDSA [R,S] signature and verifies that it is correctly
 * generated from a given message and public key. In all cases, the signature is an input to the command
 *
 * Supported API's: atcab_verify
 **/
#ifndef ATCAB_VERIFY_EN
#define ATCAB_VERIFY_EN                     (DEFAULT_ENABLED)
#endif

/** \def ATCAB_VERIFY_EXTERN
 *
 * Requires: ATCAB_VERIFY
 *
 * Verifies a signature (ECDSA verify operation) with all components (message, signature, and
 * public key) supplied
 *
 * Supported API's: atcab_verify_extern_ext
 *                  atcab_verify_extern
 **/
#ifndef ATCAB_VERIFY_EXTERN_EN
#define ATCAB_VERIFY_EXTERN_EN              ATCAB_VERIFY_EN
#endif

/** \def ATCAB_VERIFY_MAC_EN
 *
 * Requires: ATCAB_VERIFY
 *
 * Executes verification command with verification MAC for the External or Stored Verify modes
 *
 * Supported API's: atcab_verify_extern_mac, atcab_verify_stored_mac
 **/
#ifndef ATCAB_VERIFY_MAC_EN
#define ATCAB_VERIFY_MAC_EN                 ATCAB_VERIFY_EN
#endif

/** \def ATCAB_VERIFY_STORED
 *
 * Requires: ATCAB_VERIFY
 *
 * Verifies a signature (ECDSA verify operation) with a public key stored in the device
 *
 * Supported API's: atcab_verify_stored_ext
 *                  atcab_verify_stored
 **/
#ifndef ATCAB_VERIFY_STORED_EN
#define ATCAB_VERIFY_STORED_EN              ATCAB_VERIFY_EN
#endif

/** \def ATCAB_VERIFY_VALIDATE
 *
 * Requires: ATCAB_VERIFY_VALIDATE
 *
 * Executes verification command in Validate mode to validate a public key stored in a slot
 *
 * Supported API's: atcab_verify_validate
 **/
#ifndef ATCAB_VERIFY_VALIDATE_EN
#define ATCAB_VERIFY_VALIDATE_EN            ATCAB_VERIFY_EN
#endif

/****** WRITE command ******/

/** \def ATCAB_WRITE
 *
 * Requires: ATCAB_WRITE
 *           CALIB_WRITE
 *
 * Enable ATCAB_WRITE which writes either one four byte word or a 32-byte block to one of the
 * EEPROM zones on the device
 *
 * Supported API's: atcab_write
 **/
#ifndef ATCAB_WRITE_EN
#define ATCAB_WRITE_EN                      (DEFAULT_ENABLED)
#endif

/** \def ATCAB_WRITE_ENC
 *
 * Requires: ATCAB_WRITE_ENC
 *
 * Performs an encrypted write of a 32 byte block into given slot
 *
 * Supported API's: atcab_write_enc
 **/
#ifndef ATCAB_WRITE_ENC_EN
#define ATCAB_WRITE_ENC_EN                  ATCAB_WRITE_EN
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
 **/
#ifndef ATCAC_SHA256_EN
#define ATCAC_SHA256_EN                     (FEATURE_ENABLED)
#endif

/** \def ATCAC_SHA384_EN
 *
 * Enable ATCAC_SHA384_EN to enable sha384 host side api
 *
 * Disabled by default. Enable ATCAC_SHA512_EN to use SHA384
 **/
#ifndef ATCAC_SHA384_EN
#define ATCAC_SHA384_EN                     (FEATURE_DISABLED)
#endif

/** \def ATCAC_SHA512_EN
 *
 * Enable ATCAC_SHA512_EN to enable sha512 host side api
 *
 * Disabled by default. Use FEATURE_ENABLED to enable this feature
 **/
#ifndef ATCAC_SHA512_EN
#define ATCAC_SHA512_EN                     (FEATURE_DISABLED)
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

#endif /* ATCA_CONFIG_CHECK_H */
