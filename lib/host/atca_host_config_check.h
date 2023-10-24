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

#ifndef ATCA_HOST_CONFIG_CHECK_H
#define ATCA_HOST_CONFIG_CHECK_H

/** \def ATCAH_INCLUDE_DATA
 *
 * Requires: ATCAH_INCLUDE_DATA
 *
 * Supported API's: atcah_include_data
 *
 * Enable ATCAH_INCLUDE_DATA to copy otp and sn data into a command buffer
 **/
#ifndef ATCAH_INCLUDE_DATA
#define ATCAH_INCLUDE_DATA (DEFAULT_ENABLED)
#endif

/** \def ATCAH_NONCE
 *
 * Requires: ATCAH_NONCE
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_nonce
 *
 * Enable ATCAH_NONCE to calculate host side nonce with the parameters passed
 **/
#ifndef ATCAH_NONCE
#define ATCAH_NONCE (DEFAULT_ENABLED)
#endif

/** \def ATCAH_IO_DECRYPT
 *
 * Requires: ATCAH_IO_DECRYPT
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_io_decrypt
 *
 * Enable ATCAH_IO_DECRYPT to decrypt data that's been encrypted by the IO protection key.The ECDH and KDF commands on the
 * ATECC608 are the only ones that support this operation
 **/
#ifndef ATCAH_IO_DECRYPT
#define ATCAH_IO_DECRYPT (DEFAULT_ENABLED)
#endif

/** \def ATCAH_VERIFY_MAC
 *
 * Requires: ATCAH_VERIFY_MAC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_verify_mac
 *
 * Enable ATCAH_VERIFY_MAC to calculate the expected MAC on the host side for the Verify command
 **/
#ifndef ATCAH_VERIFY_MAC
#define ATCAH_VERIFY_MAC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_SECUREBOOT_ENC
 *
 * Requires: ATCAH_SECUREBOOT_ENC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_secureboot_enc
 *
 * Enable ATCAH_SECUREBOOT_ENC to encrypt the digest for the SecureBoot command when using the encrypted digest / validating mac option
 **/
#ifndef ATCAH_SECUREBOOT_ENC
#define ATCAH_SECUREBOOT_ENC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_SECUREBOOT_MAC
 *
 * Requires: ATCAH_SECUREBOOT_MAC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_secureboot_mac
 *
 * Enable ATCAH_SECUREBOOT_MAC to calculates the expected MAC returned from the SecureBoot command when verification is a success
 **/
#ifndef ATCAH_SECUREBOOT_MAC
#define ATCAH_SECUREBOOT_MAC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_MAC
 *
 * Requires: ATCAH_MAC
 *           ATCAC_SW_SHA2_256
 *           ATCAH_INCLUDE_DATA
 *
 * Supported API's: atcah_mac
 *
 * Enable ATCAH_MAC to generate an SHA-256 digest (MAC) of a key, challenge, and other information
 **/
#ifndef ATCAH_MAC
#define ATCAH_MAC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_CHECK_MAC
 *
 * Requires: ATCAH_CHECK_MAC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_check_mac
 *
 * Enable ATCAH_CHECK_MAC to perform the checkmac operation to generate client response on the host side
 **/
#ifndef ATCAH_CHECK_MAC
#define ATCAH_CHECK_MAC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_GEN_OUTPUT_RESP_MAC
 *
 * Requires: ATCAH_GEN_OUTPUT_RESP_MAC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_gen_output_resp_mac
 *
 * Enable ATCAH_GEN_OUTPUT_RESP_MAC to generate output response mac
 **/
#ifndef ATCAH_GEN_OUTPUT_RESP_MAC
#define ATCAH_GEN_OUTPUT_RESP_MAC   (DEFAULT_ENABLED)
#endif

/** \def ATCAH_HMAC
 *
 * Requires: ATCAH_HMAC
 *           ATCAC_SW_SHA2_256
 *           ATCAH_INCLUDE_DATA
 *
 * Supported API's: atcah_hmac
 *
 * Enable ATCAH_HMAC to generate an HMAC / SHA-256 hash of a key and other information
 **/
#ifndef ATCAH_HMAC
#define ATCAH_HMAC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_GENDIG
 *
 * Requires: ATCAH_GENDIG
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_gen_dig
 *
 * Enable ATCAH_GENDIG to combine the current TempKey with a stored value
 **/
#ifndef ATCAH_GENDIG
#define ATCAH_GENDIG (DEFAULT_ENABLED)
#endif

/** \def ATCAH_GENDIVKEY
 *
 * Requires: ATCAH_GENDIVKEY
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_gendivkey
 *
 * Enable ATCAH_GENDIVKEY to generate the diversified key
 **/
#ifndef ATCAH_GENDIVKEY
#define ATCAH_GENDIVKEY (DEFAULT_ENABLED)
#endif

/** \def ATCAH_GEN_MAC
 *
 * Requires: ATCAH_GEN_MAC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_gen_mac
 *
 * Enable ATCAH_GEN_MAC to generate mac with session key with a plain text
 **/
#ifndef ATCAH_GEN_MAC
#define ATCAH_GEN_MAC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_WRITE_AUTH_MAC
 *
 * Requires: ATCAH_WRITE_AUTH_MAC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_write_auth_mac
 * ECC204 specific API's: atcah_ecc204_write_auth_mac
 *
 * Enable ATCAH_WRITE_AUTH_MAC to calculate the input MAC for the Write command
 **/
#ifndef ATCAH_WRITE_AUTH_MAC
#define ATCAH_WRITE_AUTH_MAC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_PRIVWRITE_AUTH_MAC
 *
 * Requires: ATCAH_PRIVWRITE_AUTH_MAC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_privwrite_auth_mac
 *
 * Enable ATCAH_PRIVWRITE_AUTH_MAC to calculate the input MAC for the PrivWrite command
 **/
#ifndef ATCAH_PRIVWRITE_AUTH_MAC
#define ATCAH_PRIVWRITE_AUTH_MAC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_DERIVE_KEY
 *
 * Requires: ATCAH_DERIVE_KEY
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_derive_key
 *
 * Enable ATCAH_DERIVE_KEY to derive a key with a key and TempKey
 **/
#ifndef ATCAH_DERIVE_KEY
#define ATCAH_DERIVE_KEY (DEFAULT_ENABLED)
#endif

/** \def ATCAH_DERIVE_KEY_MAC
 *
 * Requires: ATCAH_DERIVE_KEY_MAC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_derive_key_mac
 *
 * Enable ATCAH_DERIVE_KEY_MAC to calculate the input MAC for a DeriveKey command
 **/
#ifndef ATCAH_DERIVE_KEY_MAC
#define ATCAH_DERIVE_KEY_MAC (DEFAULT_ENABLED)
#endif

/** \def ATCAH_DECRYPT
 *
 * Requires: ATCAH_DECRYPT
 *
 * Supported API's: atcah_decrypt
 *
 * Enable ATCAH_DECRYPT to decrypt 32-byte encrypted data received with the Read command
 **/
#ifndef ATCAH_DECRYPT
#define ATCAH_DECRYPT (DEFAULT_ENABLED)
#endif

/** \def ATCAH_SHA256
 *
 * Requires: ATCAH_SHA256
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_sha256
 *
 * Enable ATCAH_SHA256 to create a SHA256 digest on a little-endian system
 **/
#ifndef ATCAH_SHA256
#define ATCAH_SHA256 (DEFAULT_ENABLED)
#endif

/** \def ATCAH_GEN_KEY_MSG
 *
 * Requires: ATCAH_SHA256
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_gen_key_msg
 *
 * Enable ATCAH_GEN_KEY_MSG to calculate the PubKey digest created by GenKey and saved to TempKey
 **/
#ifndef ATCAH_GEN_KEY_MSG
#define ATCAH_GEN_KEY_MSG (DEFAULT_ENABLED)
#endif

/** \def ATCAH_CONFIG_TO_SIGN_INTERNAL
 *
 * Requires: ATCAH_CONFIG_TO_SIGN_INTERNAL
 *
 * Supported API's: atcah_config_to_sign_internal
 *
 * Enable ATCAH_CONFIG_TO_SIGN_INTERNAL to populate the slot_config, key_config, and is_slot_locked fields in the
 * atca_sign_internal_in_out structure from the provided config zone
 **/
#ifndef ATCAH_CONFIG_TO_SIGN_INTERNAL
#define ATCAH_CONFIG_TO_SIGN_INTERNAL (DEFAULT_ENABLED)
#endif

/** \def ATCAH_SIGN_INTERNAL_MSG
 *
 * Requires: ATCAH_SIGN_INTERNAL_MSG
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_sign_internal_msg
 *
 * Enable ATCAH_SIGN_INTERNAL_MSG to build the full message that would be signed by the Sign(Internal) command
 **/
#ifndef ATCAH_SIGN_INTERNAL_MSG
#define ATCAH_SIGN_INTERNAL_MSG (DEFAULT_ENABLED)
#endif

/** \def ATCAH_ENCODE_COUNTER_MATCH
 *
 * Requires: ATCAH_ENCODE_COUNTER_MATCH
 *
 * Supported API's: atcah_encode_counter_match
 *
 * Enable ATCAH_ENCODE_COUNTER_MATCH to build the counter match value that needs to be stored in a slot
 **/
#ifndef ATCAH_ENCODE_COUNTER_MATCH
#define ATCAH_ENCODE_COUNTER_MATCH (DEFAULT_ENABLED)
#endif

/** \def ATCAH_GEN_SESSION_KEY
 *
 * Requires: ATCAH_GEN_SESSION_KEY
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_gen_Session_key
 *
 * Enable ATCAH_GEN_SESSION_KEY to calculate the session key for the ECC204
 **/
#ifndef ATCAH_GEN_SESSION_KEY
#define ATCAH_GEN_SESSION_KEY (DEFAULT_ENABLED)
#endif

/** \def ATCAH_DELETE_MAC
 *
 * Requires: ATCAH_DELETE_MAC
 *           ATCAC_SW_SHA2_256
 *
 * Supported API's: atcah_delete_mac
 *
 * Enable ATCAH_DELETE_MAC to calculate the mac
 **/
#ifndef ATCAH_DELETE_MAC
#define ATCAH_DELETE_MAC  (CALIB_DELETE_EN)
#endif

/* ATCA CRYPTO REQUIREMENTS  */

#ifndef ATCAC_SW_SHA2_256
#define ATCAC_SW_SHA2_256 (DEFAULT_ENABLED)
#endif

/* ATCA_HOST_CHECKS */

#if !ATCAC_SW_SHA2_256 && (ATCAH_NONCE || ATCAH_IO_DECRYPT || ATCAH_VERIFY_MAC || ATCAH_SECUREBOOT_ENC ||  \
                           ATCAH_SECUREBOOT_MAC || ATCAH_MAC || ATCAH_CHECK_MAC || ATCAH_HMAC || ATCAH_GENDIG || ATCAH_GEN_MAC || \
                           ATCAH_WRITE_AUTH_MAC || ATCAH_PRIVWRITE_AUTH_MAC || ATCAH_DERIVE_KEY ||  ATCAH_DERIVE_KEY_MAC || \
                           ATCAH_SHA256 || ATCAH_GEN_KEY_MSG || ATCAH_SIGN_INTERNAL_MSG || ATCAH_GEN_SESSION_KEY)
#define ATCAC_SW_SHA2_256 (DEFAULT_ENABLED)
#endif

#if (ATCAH_MAC || ATCAH_HMAC) && !ATCAH_INCLUDE_DATA
#define ATCAH_INCLUDE_DATA (DEFAULT_ENABLED)
#endif

#endif /* ATCA_HOST_CONFIG_CHECK_H */
