/**
 * \file
 * \brief  Wrapper API for software SHA 256 routines
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

#ifndef ATCA_CRYPTO_SW_SHA2_H
#define ATCA_CRYPTO_SW_SHA2_H

#include "atca_crypto_sw.h"
#include <stddef.h>
#include <stdint.h>

/** \defgroup atcac_ Software crypto methods (atcac_)
 *
 * \brief
 * These methods provide a software implementation of various crypto
 * algorithms
 *
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

#if ATCAC_SHA256_EN
ATCA_STATUS atcac_sw_sha2_256(const uint8_t * data, size_t data_size, uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE]);
#endif

ATCA_STATUS atcac_sha256_hmac_ctr_iteration(struct atcac_hmac_ctx* ctx, uint8_t iteration, uint16_t length,
                                            const uint8_t* label, size_t label_len, const uint8_t * data, size_t data_len,
                                            uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE]);

ATCA_STATUS atcac_sha256_hmac_counter(uint8_t * key, size_t key_len, const uint8_t* label, size_t label_len,
                                      const uint8_t* data, size_t data_len, uint8_t* digest, size_t diglen);

#if ATCAC_SHA384_EN
ATCA_STATUS atcac_sw_sha2_384(const uint8_t* data, size_t data_size, uint8_t digest[ATCA_SHA2_384_DIGEST_SIZE]);
#endif

#if ATCAC_SHA512_EN
ATCA_STATUS atcac_sw_sha2_512(const uint8_t* data, size_t data_size, uint8_t digest[ATCA_SHA2_512_DIGEST_SIZE]);
#endif

#ifdef __cplusplus
}
#endif

/** @} */
#endif
