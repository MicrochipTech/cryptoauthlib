/**
 * \file
 * \brief Software implementation of the SHA256, SHA384 and SHA512 algorithm.
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

#ifndef SHA2_ROUTINES_H
#define SHA2_ROUTINES_H

#include <stdint.h>

#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE (32U)
#endif

#ifndef SHA512_DIGEST_SIZE
#define SHA512_DIGEST_SIZE (64U)
#endif

#ifndef SHA384_DIGEST_SIZE
#define SHA384_DIGEST_SIZE (48U)
#endif

#ifndef SHA256_BLOCK_SIZE
#define SHA256_BLOCK_SIZE  (64U)
#endif

#ifndef SHA384_BLOCK_SIZE
#define SHA384_BLOCK_SIZE  (128U)
#endif

#ifndef SHA512_BLOCK_SIZE
#define SHA512_BLOCK_SIZE  (128U)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if ATCA_CRYPTO_SHA256_EN
typedef struct
{
    uint32_t total_msg_size;                //!< Total number of message bytes processed
    uint32_t block_size;                    //!< Number of bytes in current block
    uint8_t  block[SHA256_BLOCK_SIZE * 2];  //!< Unprocessed message storage
    uint32_t hash[8];                       //!< Hash state
} sw_sha256_ctx;
#endif

#if ATCA_CRYPTO_SHA512_EN
typedef struct
{
    uint32_t total_msg_size;                //!< Total number of message bytes processed
    uint32_t block_size;                    //!< Number of bytes in current block
    uint8_t  block[SHA512_BLOCK_SIZE * 2];  //!< Unprocessed message storage
    uint64_t hash[8];                       //!< Hash state
} sw_sha512_ctx;
#endif

#if ATCA_CRYPTO_SHA256_EN
// SHA256
ATCA_STATUS sw_sha256_init(sw_sha256_ctx* ctx);
ATCA_STATUS sw_sha256_update(sw_sha256_ctx* ctx, const uint8_t* msg, uint32_t msg_size);
ATCA_STATUS sw_sha256_final(sw_sha256_ctx* ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
ATCA_STATUS sw_sha256(const uint8_t * message, unsigned int len, uint8_t digest[SHA256_DIGEST_SIZE]);
#endif

#if ATCA_CRYPTO_SHA384_EN
// SHA384
ATCA_STATUS sw_sha384_init(sw_sha512_ctx* ctx);
ATCA_STATUS sw_sha384_update(sw_sha512_ctx* ctx, const uint8_t* msg, uint32_t msg_size);
ATCA_STATUS sw_sha384_final(sw_sha512_ctx * ctx, uint8_t digest[SHA384_DIGEST_SIZE]);
ATCA_STATUS sw_sha384(const uint8_t * message, unsigned int len, uint8_t digest[SHA384_DIGEST_SIZE]);
#endif

#if ATCA_CRYPTO_SHA512_EN
//sha512
ATCA_STATUS sw_sha512_init(sw_sha512_ctx* ctx);
ATCA_STATUS sw_sha512_update(sw_sha512_ctx* ctx, const uint8_t* msg, uint32_t msg_size);
ATCA_STATUS sw_sha512_final(sw_sha512_ctx * ctx, uint8_t digest[SHA512_DIGEST_SIZE]);
ATCA_STATUS sw_sha512(const uint8_t * message, unsigned int len, uint8_t digest[SHA512_DIGEST_SIZE]);
#endif

#ifdef __cplusplus
}
#endif

#endif // SHA2_ROUTINES_H
