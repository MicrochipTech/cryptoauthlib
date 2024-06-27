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

#ifndef CALIB_CONFIG_CHECK_H
#define CALIB_CONFIG_CHECK_H

#include "atca_config_check.h"

/* Device Specific Defaults */
#ifdef ATCA_ATSHA204A_SUPPORT
#define CALIB_SHA204_EN             DEFAULT_ENABLED
#else
#define CALIB_SHA204_EN             DEFAULT_DISABLED
#endif

#ifdef ATCA_ATSHA206A_SUPPORT
#define CALIB_SHA206_EN             DEFAULT_ENABLED
#else
#define CALIB_SHA206_EN             DEFAULT_DISABLED
#endif

#ifdef ATCA_ATECC108A_SUPPORT
#define CALIB_ECC108_EN             DEFAULT_ENABLED
#else
#define CALIB_ECC108_EN             DEFAULT_DISABLED
#endif

#ifdef ATCA_ATECC508A_SUPPORT
#define CALIB_ECC508_EN             DEFAULT_ENABLED
#else
#define CALIB_ECC508_EN             DEFAULT_DISABLED
#endif

#ifdef ATCA_ATECC608_SUPPORT
#define CALIB_ECC608_EN             DEFAULT_ENABLED
#else
#define CALIB_ECC608_EN             DEFAULT_DISABLED
#endif

#ifdef ATCA_ECC204_SUPPORT
#define CALIB_ECC204_EN             DEFAULT_ENABLED
#else
#define CALIB_ECC204_EN             DEFAULT_DISABLED
#endif

#ifdef ATCA_TA010_SUPPORT
#define CALIB_TA010_EN              DEFAULT_ENABLED
#else
#define CALIB_TA010_EN              DEFAULT_DISABLED
#endif

#ifdef ATCA_SHA104_SUPPORT
#define CALIB_SHA104_EN             DEFAULT_ENABLED
#else
#define CALIB_SHA104_EN             DEFAULT_DISABLED
#endif

#ifdef ATCA_SHA105_SUPPORT
#define CALIB_SHA105_EN             DEFAULT_ENABLED
#else
#define CALIB_SHA105_EN             DEFAULT_DISABLED
#endif

/* Helper macros */
#define CALIB_FULL_FEATURE          (CALIB_SHA204_EN || CALIB_ECC108_EN || CALIB_ECC508_EN || CALIB_ECC608_EN)
#define CALIB_ECC_SUPPORT           (CALIB_ECC108_EN || CALIB_ECC508_EN || CALIB_ECC608_EN || CALIB_ECC204_EN || CALIB_TA010_EN)
#define CALIB_CA2_SUPPORT           (CALIB_ECC204_EN || CALIB_TA010_EN || CALIB_SHA104_EN || CALIB_SHA105_EN)
#define CALIB_CA2_CERT_SUPPORT      (CALIB_ECC204_EN || CALIB_TA010_EN)
#define CALIB_SHA206_ONLY           (CALIB_SHA206_EN && !(CALIB_FULL_FEATURE || ATCA_CA2_SUPPORT))


/* Set default maximum packet size that is allowed for CA devices */
#define DEFAULT_CA_MAX_PACKET_SIZE    (198u)

/* Check the user provided maximum packet size and set to default if that exceeds the default configuration */
#if !defined(MAX_PACKET_SIZE) || (MAX_PACKET_SIZE > DEFAULT_CA_MAX_PACKET_SIZE)
#define CA_MAX_PACKET_SIZE            (DEFAULT_CA_MAX_PACKET_SIZE)
#else
#define CA_MAX_PACKET_SIZE            (MAX_PACKET_SIZE)
#endif

/**** AES command ****/

/** \def CALIB_AES
 *
 * Enable CALIB_AES to compute the AES-128 encrypt, decrypt, or GFM calculation
 *
 * Supported API's: calib_aes
 **/
#ifndef CALIB_AES_EN
#define CALIB_AES_EN                  (ATCAB_AES_EN && CALIB_ECC608_EN)
#endif

/**** AES GCM command ****/

/** \def CALIB_AES_GCM
 *
 * Requires: CALIB_AES_GCM
 *           CALIB_AES_MODE_ENCODING
 *           CALIB_AES
 *           CALIB_RANDOM
 *
 * Supported API's: calib_aes_ghash
 *                  calib_aes_gcm_increment
 *                  calib_aes_gcm_init
 *                  calib_aes_gcm_init_rand
 *                  calib_aes_gcm_aad_update
 *                  calib_aes_gcm_update
 *                  calib_aes_gcm_encrypt_update
 *                  calib_aes_gcm_calc_auth_tag
 *                  calib_aes_gcm_encrypt_finish
 *                  calib_aes_gcm_decrypt_update
 *                  calib_aes_gcm_decrypt_finish
 **/
#ifndef CALIB_AES_GCM_EN
#define CALIB_AES_GCM_EN            (ATCAB_AES_GCM_EN && CALIB_AES_EN && CALIB_ECC608_EN)
#endif

/**** CHECKMAC command ****/

/** \def CALIB_CHECKMAC
 *
 * Enable CALIB_CHECKMAC to compare a MAC response with input values
 *
 * Supported API's: calib_checkmac
 **/
#ifndef CALIB_CHECKMAC_EN
#define CALIB_CHECKMAC_EN           (ATCAB_CHECKMAC_EN && (CALIB_FULL_FEATURE || CALIB_SHA105_EN))
#endif

/***** COUNTER command *****/

/** \def CALIB_COUNTER
 *
 * Enable CALIB_COUNTER to compute the counter functions
 *
 * Supported API's: calib_counter
 **/
#ifndef CALIB_COUNTER_EN
#define CALIB_COUNTER_EN            (ATCAB_COUNTER_EN && (CALIB_ECC_SUPPORT || CALIB_SHA104_EN || CALIB_SHA105_EN))
#endif

/***** DELETE command *****/

/** \def CALIB_DELETE
 *
 * Enable CALIB_DELETE to clear all of the Data zone slots and set all bytes of each slot to 0xFF
 *
 * Supported API's: calib_delete
 **/
#ifndef CALIB_DELETE_EN
#define CALIB_DELETE_EN             (DEFAULT_DISABLED)
#endif

/*****  DERIVEKEY command ******/

/** \def CALIB_DERIVEKEY
 *
 * Enable CALIB_DERIVEKEY for deriving a new key from a nonce (TempKey) and an existing key
 *
 * Supported API's: calib_derivekey
 **/
#ifndef CALIB_DERIVEKEY_EN
#define CALIB_DERIVEKEY_EN          (ATCAB_DERIVEKEY_EN && (CALIB_FULL_FEATURE || CALIB_SHA206_EN))
#endif

/******* ECDH command *******/

/** \def CALIB_ECDH
 *
 * Requires: CALIB_ECDH
 *
 * Supported API's: calib_ecdh_base
 *                  calib_ecdh
 *                  calib_ecdh_tempkey
 *
 * Enable CALIB_ECDH for generating premaster secret key using ECDH
 * ECDH command with a private key in a slot/tempkey and the premaster secret is returned in the clear
 **/
#ifndef CALIB_ECDH_EN
#define CALIB_ECDH_EN               (ATCAB_ECDH_EN && (CALIB_ECC508_EN || CALIB_ECC608_EN))
#endif

/** \def CALIB_ECDH_ENC
 *
 *  Requires: CALIB_ECDH_ENC
 *            CALIB_ECDH
 *            CALIB_READ_ZONE
 *            CALIB_READ_ENC
 *            ATCAH_IO_DECRYPT
 *            ATCAC_SW_SHA2_256
 *            CALIB_NONCE_BASE
 *            CALIB_NONCE_MODE_ENCODING
 *            CALIB_GENDIG
 *
 *  Supported API's: calib_ecdh_enc
 *                   calib_ecdh_ioenc
 *                   calib_ecdh_tempkey_ioenc
 *
 * ECDH command with a private key in a slot and the premaster secret is read from the next slot
 * ECDH command with a private key in a slot/tempkey and the premaster secret is returned encrypted
 * using the IO protection key
 **/
#ifndef CALIB_ECDH_ENC_EN
#define CALIB_ECDH_ENC_EN           (ATCAB_ECDH_ENC_EN && (CALIB_ECC508_EN || CALIB_ECC608_EN))
#endif

/******  GENDIG command  ******/

/** \def CALIB_GENDIG
 *
 * Enable CALIB_GENDIG to perform a SHA256 hash on the source data indicated by zone with  the
 * contents of TempKey
 *
 * Supported API's: calib_gendig
 **/
#ifndef CALIB_GENDIG_EN
#define CALIB_GENDIG_EN             (ATCAB_GENDIG_EN && (CALIB_FULL_FEATURE || CALIB_SHA105_EN))
#endif

/******  GENDIVKEY command  ******/

/** \def CALIB_GENDIVKEY
 *
 * Enable CALIB_GENDIVKEY to generate the equivalent diversified key as that programmed into thhe
 * client side device
 *
 * Supported API's: calib_sha105_gendivkey
 **/
#ifndef CALIB_GENDIVKEY_EN
#define CALIB_GENDIVKEY_EN          (ATCAB_GENDIG_EN && CALIB_SHA105_EN)
#endif

/******  GENKEY COMMAND  ******/

/** \def CALIB_GENKEY_BASE
 *
 * Enable CALIB_GENKEY_BASE which can generate a private key, compute a public key, nd/or compute a
 * digest of a public key
 *
 * Supported API's: calib_genkey_base
 **/
#ifndef CALIB_GENKEY_EN
#define CALIB_GENKEY_EN             (ATCAB_GENKEY_EN && CALIB_ECC_SUPPORT)
#endif

/** \def CALIB_GENKEY_MAC
 *
 * Requires: CALIB_GENKEY_MAC
 *
 * Supported API's: calib_genkey_mac
 *
 * Uses Genkey command to calculate SHA256 digest MAC of combining public key and session key
 **/
#ifndef CALIB_GENKEY_MAC_EN
#define CALIB_GENKEY_MAC_EN         (ATCAB_GENKEY_MAC_EN && CALIB_ECC_SUPPORT)
#endif

/******* HMAC COMMAND *******/

/** \def CALIB_HMAC
 *
 * Enable CALIB_HMAC which computes an HMAC/SHA-256 digest of a key stored in the device, a
 * challenge, and other information on the device
 *
 * Supported API's: calib_hmac
 **/
#ifndef CALIB_HMAC_EN
#define CALIB_HMAC_EN               (ATCAB_HMAC_EN && (CALIB_SHA204_EN || CALIB_ECC108_EN || CALIB_ECC508_EN))
#endif

/******* INFO COMMAND ********/

/** \def CALIB_INFO_LATCH_EN
 *
 *  Supported API's:
 *                   calib_info_get_latch
 *                   calib_info_set_latch
 *
 *  ECC204 specific api: calib_info_lock_status
 **/
#ifndef CALIB_INFO_LATCH_EN
#define CALIB_INFO_LATCH_EN         ATCAB_INFO_LATCH_EN
#endif

/****** KDF COMMAND ******/

/** \def CALIB_KDF
 *
 * Enable CALIB_KDF to derive a new key in PRF, AES, or HKDF modes
 *
 * Supported API's: calib_kdf
 **/
#ifndef CALIB_KDF_EN
#define CALIB_KDF_EN                (ATCAB_KDF_EN && CALIB_ECC608_EN)
#endif

/****** LOCK COMMAND ******/

/** \def CALIB_LOCK_EN
 *
 * Enable CALIB_LOCK_EN to enable the lock commands for the classic cryptoauth parts
 *
 * Supported API's: calib_lock
 **/
#ifndef CALIB_LOCK_EN
#define CALIB_LOCK_EN               (ATCAB_LOCK_EN && CALIB_FULL_FEATURE)
#endif

/** \def CALIB_LOCK_CA2_EN
 *
 * Enable CALIB_LOCK_CA2_EN which enables the lock command for the ecc204 and ta010 devices
 *
 * Supported API's: calib_lock
 **/
#ifndef CALIB_LOCK_CA2_EN
#define CALIB_LOCK_CA2_EN         (ATCAB_LOCK_EN && ATCA_CA2_SUPPORT)
#endif

/******  MAC command  ******/

/** \def CALIB_MAC
 *
 * Enable CALIB_MAC to computes a SHA-256 digest of a key stored in the device, a challenge, and
 * other information on the device
 *
 * Supported API's: calib_mac
 **/
#ifndef CALIB_MAC_EN
#define CALIB_MAC_EN                (ATCAB_MAC_EN && (CALIB_FULL_FEATURE || CALIB_SHA206_EN || CALIB_SHA104_EN))
#endif

/****** NONCE command ******/

/** \def CALIB_NONCE_BASE
 *
 * Enable CALIB_NONCE_BASE which loads a random or fixed nonce/data into the device for use by subsequent
 * commands
 *
 * Requires: CALIB_NONCE_BASE
 *
 * Supported API's: calib_nonce_base
 **/
#ifndef CALIB_NONCE_EN
#define CALIB_NONCE_EN              (ATCAB_NONCE_EN && (CALIB_FULL_FEATURE || CALIB_CA2_SUPPORT))
#endif

/****  PRIVWRITE COMMAND  ****/

/** \def CALIB_PRIVWRITE
 *
 * Enable CALIB_PRIVWRITE to write externally generated ECC private keys into the device
 *
 * Requires: CALIB_PRIVWRITE
 *           CALIB_READ_ZONE
 *           CALIB_NONCE_MODE_ENCODING
 *           CALIB_NONCE_BASE
 *           CALIB_GENDIG
 *           ATCAH_GENDIG
 *           ATCAH_PRIVWRITE_AUTH_MAC
 *           ATCAH_NONCE
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: calib_priv_write
 **/
#ifndef CALIB_PRIVWRITE_EN
#define CALIB_PRIVWRITE_EN            (ATCAB_PRIVWRITE_EN && (CALIB_ECC108_EN || CALIB_ECC508_EN || CALIB_ECC608_EN))
#endif

/***** RANDOM COMMAND *****/

/** \def CALIB_RANDOM
 *
 * Enable CALIB_RANDOM which generates a 32 byte random number from the CryptoAuth device
 *
 * Supported API's: calib_random
 **/
#ifndef CALIB_RANDOM_EN
#define CALIB_RANDOM_EN               (ATCAB_RANDOM_EN && CALIB_FULL_FEATURE)
#endif

/*****  READ command  *****/

/** \def CALIB_READ_EN
 *
 * Enable CALIB_READ_EN which enables the read commands
 *
 * Supported API's: calib_read_zone
 *
 **/
#ifndef CALIB_READ_EN
#define CALIB_READ_EN                 (ATCAB_READ_EN && (CALIB_FULL_FEATURE || CALIB_SHA206_EN))
#endif

/** \def CALIB_READ_ZONE
 *
 * Enable CALIB_READ_ZONE which reads either 4 or 32 bytes of data from a given slot,
 * configuration zone, or the OTP zone
 *
 * Supported API's: calib_read_zone
 *
 * Supported ECC204 specific API's: calib_ca2_read_zone
 **/
#ifndef CALIB_READ_CA2_EN
#define CALIB_READ_CA2_EN          (ATCAB_READ_EN && CALIB_CA2_SUPPORT)
#endif

/** \def CALIB_READ_ENC
 *
 * Requires: CALIB_NONCE_BASE
 *           CALIB_NONCE_MODE_ENCODING
 *           CALIB_GENDIG
 *           ATCAH_NONCE
 *           ATCAH_GENDIG
 *           ATCAC_SW_SHA2_256
 *           CALIB_READ_ZONE
 *           CALIB_READ_ENC
 *
 * Performs Read command on a slot configured for encrypted reads and decrypts the data to return
 * it as plaintext
 *
 * Supported API's: calib_read_enc
 **/
#ifndef CALIB_READ_ENC_EN
#define CALIB_READ_ENC_EN             (ATCAB_READ_ENC_EN && CALIB_FULL_FEATURE)
#endif

/***** SECUREBOOT command ****/

/** \def CALIB_SECUREBOOT
 *
 * Enable CALIB_SECUREBOOT which provides support for secureboot of an external MCU or MPU
 *
 * Requires: CALIB_SECUREBOOT
 *
 * Supported API's: calib_secureboot
 *                  calib_secureboot_mac
 **/
#ifndef CALIB_SECUREBOOT_EN
#define CALIB_SECUREBOOT_EN           (ATCAB_SECUREBOOT_EN && CALIB_ECC608_EN)
#endif

/** \def CALIB_SECUREBOOT_MAC
 *
 * Requires: CALIB_NONCE_BASE
 *           CALIB_READ_CONFIG_BYTES_ZONE
 *           CALIB_READ_ZONE
 *           ATCAH_NONCE
 *           ATCAH_SECUREBOOT_ENC
 *           ATCAH_SECUREBOOT_MAC
 *           ATCAC_SW_SHA2_256
 *           CALIB_SECUREBOOT
 *
 * Performs secureboot command with encrypted digest and validated MAC response using the IO protection key
 *
 * Supported API's: calib_secureboot_mac
 **/
#ifndef CALIB_SECUREBOOT_MAC_EN
#define CALIB_SECUREBOOT_MAC_EN       (ATCAB_SECUREBOOT_MAC_EN && CALIB_ECC608_EN)
#endif

/**** SELFTEST command ****/

/** \def CALIB_SELFTEST
 *
 * Enable CALIB_SELFTEST which performs a test of one or more of the cryptographic engines within
 * the ATECC608 chip
 *
 * Supported API's: calib_selftest
 **/
#ifndef CALIB_SELFTEST_EN
#define CALIB_SELFTEST_EN             (ATCAB_SELFTEST_EN && (CALIB_ECC608_EN || CALIB_CA2_SUPPORT))
#endif

/****** SHA command ******/

/** \def CALIB_SHA_EN
 *
 * Enable CALIB_SHA_EN to compute a SHA-256 or HMAC/SHA-256 digest for general purpose use by
 * the host system
 *
 * Supported API's: calib_sha_base
 **/
#ifndef CALIB_SHA_EN
#define CALIB_SHA_EN                  (ATCAB_SHA_EN && (CALIB_FULL_FEATURE || CALIB_CA2_SUPPORT))
#endif

/** \def CALIB_SHA_HMAC_EN
 *
 * Requires: CALIB_SHA_HMAC
 *           CALIB_SHA_BASE
 *
 * Use the SHA command to compute an HMAC/SHA-256 operation
 *
 * Supported API's: calib_sha_hmac,calib_sha_hmac_init, calib_sha_hmac_update, calib_sha_hmac_finish
 **/
#ifndef CALIB_SHA_HMAC_EN
#define CALIB_SHA_HMAC_EN             (ATCAB_SHA_HMAC_EN && CALIB_ECC_SUPPORT)
#endif

/** \def CALIB_SHA_CONTEXT_EN
 *
 * Requires:
 *           CALIB_SHA_BASE
 *
 * Use the SHA command to compute an HMAC/SHA-256 operation
 *
 * Supported API's: calib_sha_read_context
 **/
#ifndef CALIB_SHA_CONTEXT_EN
#define CALIB_SHA_CONTEXT_EN          (ATCAB_SHA_CONTEXT_EN && CALIB_ECC608_EN)
#endif

/****** SIGN command ******/

/** \def CALIB_SIGN_EN
 *
 * Enable CALIB_SIGN_EN to generate a signature using the ECDSA algorithm
 *
 * Supported API's: calib_sign
 *
 **/
#ifndef CALIB_SIGN_EN
#define CALIB_SIGN_EN                 (ATCAB_SIGN_EN && (CALIB_ECC108_EN || CALIB_ECC508_EN || CALIB_ECC608_EN))
#endif

/** \def CALIB_SIGN_CA2_EN
 *
 * Enable CALIB_SIGN_CA2_EN to generate a signature using the ECDSA algorithm
 *
 * Supported API's: calib_sign_base
 *
 **/
#ifndef CALIB_SIGN_CA2_EN
#define CALIB_SIGN_CA2_EN          (ATCAB_SIGN_EN && (CALIB_ECC204_EN || CALIB_TA010_EN))
#endif

/** \def CALIB_SIGN_MODE_ENCODING
 *
 * Requires: CALIB_RANDOM
 *           CALIB_NONCE_MODE_ENCODING
 *           CALIB_NONCE_BASE
 *           CALIB_SIGN_MODE_ENCODING
 *           CALIB_SIGN_BASE
 *
 * Use CALIB_SIGN_MODE_ENCODING to sign a 32-byte external message using the private key in the specified slot.
 *
 * Use CALIB_SIGN_MODE_ENCODING to sign a internally generated message
 *
 * Supported API's: calib_sign , calib_sign_internal
 **/
#ifndef CALIB_SIGN_INTERNAL_EN
#define CALIB_SIGN_INTERNAL_EN        (ATCAB_SIGN_INTERNAL_EN && CALIB_SIGN_EN)
#endif

/***** UPDATEEXTRA command ****/

/** \def CALIB_UPDATEEXTRA_EN
 *
 * Enable CALIB_UPDATEEXTRA_EN to update the values of the two extra bytes within the configuration
 * zone (bytes 84 and 85)
 *
 * Supported API's: calib_updateextra
 **/
#ifndef CALIB_UPDATEEXTRA_EN
#define CALIB_UPDATEEXTRA_EN        (ATCAB_UPDATEEXTRA_EN && CALIB_FULL_FEATURE)
#endif

/******** VERIFY command ********/

/** \def CALIB_VERIFY_EN
 *
 * Enable CALIB_VERIFY_EN which takes an ECDSA [R,S] signature and verifies that it is correctly
 * generated from a given message and public key. In all cases, the signature is an input to the command
 *
 * Supported API's: calib_verify
 **/
#ifndef CALIB_VERIFY_EN
#define CALIB_VERIFY_EN             (ATCAB_VERIFY_EN && (CALIB_ECC108_EN || CALIB_ECC508_EN || CALIB_ECC608_EN))
#endif

/** \def CALIB_VERIFY_MAC_EN
 *
 * Requires: CALIB_NONCE_MODE_ENCODING
 *           CALIB_NONCE_BASE
 *           ATCAH_VERIFY_MAC
 *           ATCAC_SW_SHA2_256
 *           CALIB_VERIFY
 *
 * Executes verification command with verification MAC for the External or Stored Verify modes
 *
 * Supported API's: calib_verify_extern_stored_mac, calib_verify_extern_mac, calib_verify_stored_mac
 **/
#ifndef CALIB_VERIFY_MAC_EN
#define CALIB_VERIFY_MAC_EN         (ATCAB_VERIFY_MAC_EN && CALIB_ECC608_EN)
#endif

/** \def CALIB_VERIFY_EXTERN
 *
 * Requires: CALIB_NONCE_MODE_ENCODING
 *           CALIB_NONCE_BASE
 *           CALIB_VERIFY
 *
 * Verifies a signature (ECDSA verify operation) with all components (message, signature, and
 * public key) supplied
 *
 * Supported API's: calib_verify_extern
 **/
#ifndef CALIB_VERIFY_EXTERN_EN
#define CALIB_VERIFY_EXTERN_EN        (ATCAB_VERIFY_EXTERN_EN && CALIB_VERIFY_EN)
#endif

/** \def CALIB_VERIFY_STORED_EN
 *
 * Requires: CALIB_NONCE_MODE_ENCODING
 *           CALIB_NONCE_BASE
 *           CALIB_VERIFY
 *
 * Verifies a signature (ECDSA verify operation) with a public key stored in the device
 *
 * Supported API's: calib_verify_stored
 **/
#ifndef CALIB_VERIFY_STORED_EN
#define CALIB_VERIFY_STORED_EN        (ATCAB_VERIFY_STORED_EN && CALIB_VERIFY_EN)
#endif

/** \def CALIB_VERIFY_VALIDATE
 *
 * Requires: CALIB_VERIFY
 *           CALIB_VERIFY_VALIDATE
 *
 * Executes verification command in Validate mode to validate a public key stored in a slot
 *
 * Supported API's: calib_verify_validate
 **/
#ifndef CALIB_VERIFY_VALIDATE_EN
#define CALIB_VERIFY_VALIDATE_EN      (ATCAB_VERIFY_VALIDATE_EN && CALIB_VERIFY_EN)
#endif

/****** WRITE command ******/

/** \def ATCAB_WRITE_EN
 *
 * Enable CALIB_WRITE which writes either one four byte word or a 32-byte block to one of the
 * EEPROM zones on the device
 *
 * Supported API's: calib_write
 *
 * Supported ECC204 specific API's: calib_ca2_write
 **/
#ifndef CALIB_WRITE_EN
#define CALIB_WRITE_EN              (ATCAB_WRITE_EN && (CALIB_FULL_FEATURE || CALIB_SHA206_EN))
#endif

/** \def CALIB_WRITE_ENC_EN
 *
 * Requires: CALIB_NONCE_MODE_ENCODING
 *           CALIB_NONCE_BASE
 *           CALIB_READ_ZONE
 *           CALIB_GENDIG
 *           ATCAH_GENDIG
 *           ATCAH_WRITE_AUTH_MAC
 *           ATCAH_NONCE
 *           ATCAC_SW_SHA2_256
 *           CALIB_WRITE
 *           ATCAH_GEN_SESSION_KEY
 *
 * Performs an encrypted write of a 32 byte block into given slot
 *
 * Supported API's: calib_write_enc
 **/
#ifndef CALIB_WRITE_ENC_EN
#define CALIB_WRITE_ENC_EN          (ATCAB_WRITE_ENC_EN && CALIB_FULL_FEATURE)
#endif

/** \def ATCAB_WRITE_EN
 *
 * Enable CALIB_WRITE which writes either one four byte word or a 32-byte block to one of the
 * EEPROM zones on the device
 *
 * Supported API's: calib_write
 *
 * Supported ECC204 specific API's: calib_ca2_write
 **/
#ifndef CALIB_WRITE_CA2_EN
#define CALIB_WRITE_CA2_EN       (ATCAB_WRITE_EN && CALIB_CA2_SUPPORT)
#endif

/* Check host side configuration for missing components */

#include "crypto/crypto_sw_config_check.h"

/* Check for any commands that require a sha implementation */
#if !ATCA_HOSTLIB_EN && !ATCAC_SHA256_EN

#if (CALIB_ECDH_ENC || CALIB_PRIVWRITE_EN || CALIB_READ_ENC_EN || CALIB_WRITE_ENC_EN || CALIB_SECUREBOOT_MAC_EN)
#error "Config Check: a host side sha256 implementation has to be provided to support host side hashing operations"
#endif

#endif

#endif /* CALIB_CONFIG_CHECK_H */
