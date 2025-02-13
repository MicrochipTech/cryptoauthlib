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

#ifndef CRYPTO_HW_CONFIG_CHECK_H
#define CRYPTO_HW_CONFIG_CHECK_H

#include "atca_config_check.h"

#if ATCA_CA_SUPPORT
#include "calib/calib_config_check.h"
#endif

#if ATCA_TA_SUPPORT && !LIBRARY_USAGE_EN_CHECK
#include "talib/talib_config_check.h"
#endif

/** \def ATCAB_AES_EXTRAS_EN
 *
 * Automatically set base on other configuation options but can be overridden to disable all
 * CBC, CBCMAC, CTR, & CCM modes at once rather than individually
 */
#ifndef ATCAB_AES_EXTRAS_EN
#define ATCAB_AES_EXTRAS_EN         (CALIB_AES_EN || TALIB_AES_EN || LIBRARY_USAGE_EN_CHECK)
#endif

#ifndef ATCAB_AES_RANDOM_IV_EN
#define ATCAB_AES_RANDOM_IV_EN      (ATCA_HOSTLIB_EN || CALIB_RANDOM_EN || TALIB_RANDOM_EN)
#endif

/** \def ATCAB_AES_UPDATE_EN
 * Enable update/finalize APIs for block ciphers
 */
#ifndef ATCAB_AES_UPDATE_EN
#define ATCAB_AES_UPDATE_EN         ATCAB_AES_EXTRAS_EN
#endif

/****** ATCA_CRYPTO_HW_AES_CBC ******/

/** \def  ATCAB_AES_CBC_ENCRYPT_EN
 *
 * Requires: ATCAB_AES_EN
 *
 * Enable ATCAB_AES_CBC_ENCRYPT_EN to encrypt a block of data using CBC mode and a key within the
 * device. atcab_aes_cbc_init() should be called before the first use of this function
 *
 * Supported API's: atcab_aes_cbc_encrypt_block , atcab_aes_cbc_init_ext, atcab_aes_cbc_init
 **/
#ifndef ATCAB_AES_CBC_ENCRYPT_EN
#define ATCAB_AES_CBC_ENCRYPT_EN     ATCAB_AES_EXTRAS_EN
#endif

/** \def  ATCAB_AES_CBC_DECRYPT_EN
 *
 * Requires: ATCAB_AES_EN
 *
 * Enable ATCAB_AES_CBC_DECRYPT to decrypt a block of data using CBC mode and a key within the
 * device. atcab_aes_cbc_init() should be called before the first use of this function
 *
 * Supported API's: atcab_aes_cbc_decrypt_block, atcab_aes_cbc_init_ext, atcab_aes_cbc_init
 **/
#ifndef ATCAB_AES_CBC_DECRYPT_EN
#define ATCAB_AES_CBC_DECRYPT_EN    ATCAB_AES_EXTRAS_EN
#endif

#ifndef ATCAB_AES_CBC_UPDATE_EN
#define ATCAB_AES_CBC_UPDATE_EN     ATCAB_AES_UPDATE_EN
#endif

/****** ATCA_CRYPTO_HW_AES_CBCMAC ******/

/** \def  ATCAB_AES_CBCMAC_EN
 *
 * Requires: ATCAB_AES_CBCMAC
 *           ATCAB_AES_CBC_ENCRYPT
 *           ATCAB_AES_MODE_ENCODING
 *           CALIB_AES_MODE_ENCODING
 *           CALIB_AES
 *
 * Enable ATCAB_AES_CBCMAC to initialize context for AES CBC-MAC operation
 * Enable ATCAB_AES_CBCMAC to calculate AES CBC-MAC with key stored within ECC608 device
 * Enable ATCAB_AES_CBCMAC to finish a CBC-MAC operation returning the CBC-MAC value
 *
 * Supported API's: atcab_aes_cbcmac_init_ext
 *                  atcab_aes_cbcmac_init, atcab_aes_cbcmac_init_update, atcab_aes_cbcmac_finish
 **/
#ifndef ATCAB_AES_CBCMAC_EN
#define ATCAB_AES_CBCMAC_EN         ATCAB_AES_CBC_ENCRYPT_EN
#endif

/****** ATCA_CRYPTO_HW_AES_CTR ******/

/** \def  ATCAB_AES_CTR_EN
 *
 * Requires: ATCAB_AES_EN
 *
 * Enable ATCAB_AES_CTR_EN to support AES-CTR mode
 *
 **/
#ifndef ATCAB_AES_CTR_EN
#define ATCAB_AES_CTR_EN            ATCAB_AES_EXTRAS_EN
#endif

/** \def  ATCAB_AES_CTR_RAND_IV_EN
 *
 * Requires: ATCAB_AES_CTR_EN
 *           ATCAB_RANDOM_EN
 *
 * Enable ATCAB_AES_CTR_RAND_IV_EN to initialize context for AES CTR operation with a random nonce and
 * counter set to 0 as the IV, which is common when starting an encrypt operation
 *
 * Supported API's: atcab_aes_ctr_init_rand_ext, atcab_aes_ctr_init_rand
 **/
#ifndef ATCAB_AES_CTR_RAND_IV_EN
#define ATCAB_AES_CTR_RAND_IV_EN    (ATCAB_AES_CTR_EN && ATCAB_AES_RANDOM_IV_EN)
#endif

/****** ATCA_CRYPTO_HW_AES_CCM ******/

/** \def  ATCAB_AES_CCM_EN
 *
 * Requires: ATCAB_AES_EN
 *           ATCAB_AES_CTR_EN
 *
 * Enable ATCAB_AES_CCM_EN to enable AES CCM operation
 *
 **/
#ifndef ATCAB_AES_CCM_EN
#define ATCAB_AES_CCM_EN            (ATCAB_AES_CBCMAC_EN && ATCAB_AES_CTR_EN)
#endif

/** \def  ATCAB_AES_CCM_INIT_RAND
 *
 * Requires: ATCAB_AES_CCM_INIT_RAND
 *           ATCAB_AES_CCM_INIT
 *           ATCAB_RANDOM
 *           CALIB_RANDOM
 *
 * Enable ATCAB_AES_CCM_INIT_RAND to initialize context for AES CCM operation with a random nonce
 *
 * Supported API's: atcab_aes_ccm_init_rand_ext
 *                  atcab_aes_ccm_init_rand
 **/
#ifndef ATCAB_AES_CCM_RAND_IV_EN
#define ATCAB_AES_CCM_RAND_IV_EN    (ATCAB_AES_CCM_EN && ATCAB_AES_RANDOM_IV_EN)
#endif

/****** ATCA_CRYPTO_HW_AES_CMAC ******/

/** \def  ATCAB_AES_CMAC
 *
 * Requires: ATCAB_AES_CMAC
 *           ATCAB_AES_CBC_ENCRYPT
 *           ATCAB_AES_MODE_ENCODING
 *           CALIB_AES_MODE_ENCODING
 *           CALIB_AES
 *
 * Enable ATCAB_AES_CMAC to initialize a CMAC calculation using an AES-128 key in the device
 * Enable ATCAB_AES_CMAC to add data to an initialized CMAC calculation
 * Enable ATCAB_AES_CMAC to finish a CMAC operation returning the CMAC value
 *
 * Supported API's: atcab_aes_cmac_init_ext, left_shift_one
 *                  atcab_aes_cmac_init, atcab_aes_cmac_init_update, atcab_aes_cmac_finish
 **/
#ifndef ATCAB_AES_CMAC_EN
#define ATCAB_AES_CMAC_EN                   ATCAB_AES_CBC_ENCRYPT_EN
#endif

/****** ATCA_CRYPTO_PKCS7_PADDING ******/
#ifndef ATCAC_PKCS7_PAD_EN
#define ATCAC_PKCS7_PAD_EN          ATCAB_AES_EXTRAS_EN
#endif

#endif /* CRYPTO_HW_CONFIG_CHECK_H */
