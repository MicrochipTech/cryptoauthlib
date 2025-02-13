/**
 * \file
 * \brief Wrapper API for software SHA 256 routines
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

#include "cryptoauthlib.h"
#include "atca_crypto_sw_sha2.h"
#include "cal_internal.h"

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "CERT EXP39-C" "Type casting of pointer is required for using sha_routines") \
    (deviate "MISRA C-2012 Rule 11.3" "Type casting of pointer is required for using sha_routines")
#endif

#if ATCA_CRYPTO_SHA2_EN
#include "hashes/sha2_routines.h"
#endif

#if ATCA_CRYPTO_SHA256_EN
/** \brief initializes the SHA256 software
 * \param[in] ctx  ptr to context data structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_init(struct atcac_sha2_256_ctx* ctx)
{
    return sw_sha256_init((sw_sha256_ctx*)ctx);
}

/** \brief updates the running hash with the next block of data, called iteratively for the entire
    stream of data to be hashed using the SHA256 software
    \param[in] ctx        ptr to SHA context data structure
    \param[in] data       ptr to next block of data to hash
    \param[in] data_size  size amount of data to hash in the given block, in bytes
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_update(struct atcac_sha2_256_ctx* ctx, const uint8_t* data, size_t data_size)
{
    return sw_sha256_update((sw_sha256_ctx*)ctx, data, (uint32_t)(data_size & UINT32_MAX));
}

/** \brief completes the final SHA256 calculation and returns the final digest/hash
 * \param[in]  ctx     ptr to context data structure
 * \param[out] digest  receives the computed digest of the SHA 256
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS atcac_sw_sha2_256_finish(struct atcac_sha2_256_ctx* ctx, uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE])
{
    return sw_sha256_final((sw_sha256_ctx*)ctx, digest);
}
#endif

#if ATCA_CRYPTO_SHA384_EN
/** \brief initializes the SHA384 software
 * \param[in] ctx  ptr to context data structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_384_init(struct atcac_sha2_384_ctx* ctx)
{
    return sw_sha384_init((sw_sha512_ctx*)ctx);
}

/** \brief updates the running hash with the next block of data, called iteratively for the entire
    stream of data to be hashed using the SHA384 software
    \param[in] ctx        ptr to SHA context data structure
    \param[in] data       ptr to next block of data to hash
    \param[in] data_size  size amount of data to hash in the given block, in bytes
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_384_update(struct atcac_sha2_384_ctx* ctx, const uint8_t* data, size_t data_size)
{
    return sw_sha384_update((sw_sha512_ctx*)ctx, data, (uint32_t)(data_size & UINT32_MAX));
}

/** \brief completes the final SHA384 calculation and returns the final digest/hash
 * \param[in]  ctx     ptr to context data structure
 * \param[out] digest  receives the computed digest of the SHA 384
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_384_finish(struct atcac_sha2_384_ctx* ctx, uint8_t digest[ATCA_SHA2_384_DIGEST_SIZE])
{
    return sw_sha384_final((sw_sha512_ctx*)ctx, digest);
}
#endif

#if ATCA_CRYPTO_SHA512_EN
/** \brief initializes the SHA512 software
 * \param[in] ctx  ptr to context data structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_512_init(struct atcac_sha2_512_ctx* ctx)
{
    return sw_sha512_init((sw_sha512_ctx*)ctx);
}

/** \brief updates the running hash with the next block of data, called iteratively for the entire
    stream of data to be hashed using the SHA512 software
    \param[in] ctx        ptr to SHA context data structure
    \param[in] data       ptr to next block of data to hash
    \param[in] data_size  size amount of data to hash in the given block, in bytes
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_512_update(struct atcac_sha2_512_ctx* ctx, const uint8_t* data, size_t data_size)
{
    return sw_sha512_update((sw_sha512_ctx*)ctx, data, (uint32_t)(data_size & UINT32_MAX));
}

/** \brief completes the final SHA512 calculation and returns the final digest/hash
 * \param[in]  ctx     ptr to context data structure
 * \param[out] digest  receives the computed digest of the SHA 512
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_512_finish(struct atcac_sha2_512_ctx* ctx, uint8_t digest[ATCA_SHA2_512_DIGEST_SIZE])
{
    return sw_sha512_final((sw_sha512_ctx*)ctx, digest);
}
#endif

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)

#if ATCA_CRYPTO_SHA256_EN
struct atcac_sha2_256_ctx * atcac_sha256_ctx_new(void)
{
    return (struct atcac_sha2_256_ctx*)hal_malloc(sizeof(atcac_sha2_256_ctx_t));
}
void atcac_sha256_ctx_free(struct atcac_sha2_256_ctx * ctx)
{
    hal_free(ctx);
}
#endif

#if ATCA_CRYPTO_SHA384_EN
struct atcac_sha2_384_ctx * atcac_sha384_ctx_new(void)
{
    return (struct atcac_sha2_384_ctx*)hal_malloc(sizeof(atcac_sha2_384_ctx_t));
}
void atcac_sha384_ctx_free(struct atcac_sha2_384_ctx * ctx)
{
    hal_free(ctx);
}
#endif

#if ATCA_CRYPTO_SHA512_EN
struct atcac_sha2_512_ctx * atcac_sha512_ctx_new(void)
{
    return (struct atcac_sha2_512_ctx*)hal_malloc(sizeof(atcac_sha2_512_ctx_t));
}
void atcac_sha512_ctx_free(struct atcac_sha2_512_ctx * ctx)
{
    hal_free(ctx);
}
#endif /* ATCA_CRYPTO_SHA512_EN*/
#endif /* ATCA_BUILD_SHARED_LIBS || ATCA_HEAP */

#if ATCAC_SHA256_EN
/** \brief single call convenience function which computes Hash of given data using SHA256 software
 * \param[in]  data       pointer to stream of data to hash
 * \param[in]  data_size  size of data stream to hash
 * \param[out] digest     result
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256(const uint8_t* data, size_t data_size, uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE])
{
    ATCA_STATUS ret;
    atcac_sha2_256_ctx_t ctx;

    ret = atcac_sw_sha2_256_init(&ctx);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    ret = atcac_sw_sha2_256_update(&ctx, data, data_size);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    ret = atcac_sw_sha2_256_finish(&ctx, digest);

    return ret;
}
#endif /* ATCAC_SHA256_EN */


#if ATCAC_SHA384_EN
/** \brief single call convenience function which computes Hash of given data using SHA384 software
 * \param[in]  data       pointer to stream of data to hash
 * \param[in]  data_size  size of data stream to hash
 * \param[out] digest     result
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_384(const uint8_t* data, size_t data_size, uint8_t digest[ATCA_SHA2_384_DIGEST_SIZE])
{
    ATCA_STATUS ret;
    atcac_sha2_384_ctx_t ctx;

    ret = atcac_sw_sha2_384_init(&ctx);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    ret = atcac_sw_sha2_384_update(&ctx, data, data_size);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    ret = atcac_sw_sha2_384_finish(&ctx, digest);

    return ret;
}
#endif /* ATCAC_SHA384_EN*/

#if ATCAC_SHA512_EN
/** \brief single call convenience function which computes Hash of given data using SHA512 software
 * \param[in]  data       pointer to stream of data to hash
 * \param[in]  data_size  size of data stream to hash
 * \param[out] digest     result
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_512(const uint8_t* data, size_t data_size, uint8_t digest[ATCA_SHA2_512_DIGEST_SIZE])
{
    ATCA_STATUS ret;
    atcac_sha2_512_ctx_t ctx;

    ret = atcac_sw_sha2_512_init(&ctx);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    ret = atcac_sw_sha2_512_update(&ctx, data, data_size);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    ret = atcac_sw_sha2_512_finish(&ctx, digest);

    return ret;
}
#endif /* ATCAC_SHA512_EN*/

#if ATCA_CRYPTO_SHA2_HMAC_EN
/** \brief Initialize context for performing HMAC (sha256) in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_init(
    struct atcac_hmac_ctx*     ctx,         /**< [in] pointer to a sha256-hmac context */
    struct atcac_sha2_256_ctx* sha256_ctx,  /**< [in] pointer to a sha256 context */
    const uint8_t*             key,         /**< [in] key value to use */
    const uint8_t              key_len      /**< [in] length of the key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    size_t klen = key_len;

    if ((NULL != ctx) && (NULL != sha256_ctx) && (NULL != key) && (0u != key_len))
    {
        ctx->sha256_ctx = sha256_ctx;
        if (klen <= ATCA_SHA2_256_BLOCK_SIZE)
        {
            (void)memcpy(ctx->ipad, key, klen);
            status = ATCA_SUCCESS;
        }
        else
        {
            (void)atcac_sw_sha2_256_init(ctx->sha256_ctx);
            (void)atcac_sw_sha2_256_update(ctx->sha256_ctx, key, klen);
            status = (ATCA_STATUS)atcac_sw_sha2_256_finish(ctx->sha256_ctx, ctx->ipad);
            klen = ATCA_SHA2_256_DIGEST_SIZE;
        }

        if (ATCA_SUCCESS == status)
        {
            unsigned int i;
            if (klen < ATCA_SHA2_256_BLOCK_SIZE)
            {
                (void)memset(&ctx->ipad[klen], 0, ATCA_SHA2_256_BLOCK_SIZE - klen);
            }

            for (i = 0; i < ATCA_SHA2_256_BLOCK_SIZE; i++)
            {
                ctx->opad[i] = (uint8_t)((ctx->ipad[i] ^ 0x5Cu) & UINT8_MAX);
                ctx->ipad[i] ^= 0x36u;
            }

            (void)atcac_sw_sha2_256_init(ctx->sha256_ctx);
            status = (ATCA_STATUS)atcac_sw_sha2_256_update(ctx->sha256_ctx, ctx->ipad, ATCA_SHA2_256_BLOCK_SIZE);
        }

    }

    return status;
}

/** \brief Update HMAC context with input data
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_update(
    struct atcac_hmac_ctx* ctx,          /**< [in] pointer to a sha256-hmac context */
    const uint8_t*         data,         /**< [in] input data */
    size_t                 data_size     /**< [in] length of input data */
    )
{
    return (ATCA_STATUS)atcac_sw_sha2_256_update(ctx->sha256_ctx, data, data_size);
}

/** \brief Finish HMAC calculation and clear the HMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_finish(
    struct atcac_hmac_ctx* ctx,         /**< [in] pointer to a sha256-hmac context */
    uint8_t*               digest,      /**< [out] hmac value */
    size_t*                digest_len   /**< [inout] length of hmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != ctx->sha256_ctx) && (NULL != digest_len) && (*digest_len >= ATCA_SHA2_256_DIGEST_SIZE))
    {
        uint8_t temp_dig[ATCA_SHA2_256_DIGEST_SIZE];

        status = (ATCA_STATUS)atcac_sw_sha2_256_finish(ctx->sha256_ctx, temp_dig);

        if (ATCA_SUCCESS == status)
        {
            (void)atcac_sw_sha2_256_init(ctx->sha256_ctx);
            (void)atcac_sw_sha2_256_update(ctx->sha256_ctx, ctx->opad, ATCA_SHA2_256_BLOCK_SIZE);
            (void)atcac_sw_sha2_256_update(ctx->sha256_ctx, temp_dig, ATCA_SHA2_256_DIGEST_SIZE);
            status = (ATCA_STATUS)atcac_sw_sha2_256_finish(ctx->sha256_ctx, digest);
        }
    }
    return status;
}

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_hmac_ctx * atcac_hmac_ctx_new(void)
{
    return (struct atcac_hmac_ctx*)hal_malloc(sizeof(atcac_hmac_ctx_t));
}
void atcac_hmac_ctx_free(struct atcac_hmac_ctx * ctx)
{
    hal_free(ctx);
}
#endif

#endif /* ATCA_CRYPTO_SHA2_HMAC_EN */

#if ATCA_CRYPTO_SHA2_HMAC_CTR_EN
/** \brief Calculates one iteration of SHA256 HMAC-Counter per NIST SP 800-108 used for KDF like operations */
ATCA_STATUS atcac_sha256_hmac_ctr_iteration(
    struct atcac_hmac_ctx* ctx,                              /**< [in] pointer to a sha256-hmac context */
    uint8_t                iteration,                        /**< [in] Iteration of the KDF to calculate */
    uint16_t               length,                           /**< [in] Total legth of the key in bits - not the length of this iteration */
    const uint8_t*         label,                            /**< [in] kdf label string */
    size_t                 label_len,                        /**< [in] kdf label string length in bytes (does not include a terminating null) */
    const uint8_t *        data,                             /**< [in] Additional mix-in data */
    size_t                 data_len,                         /**< [in] data length in bytes */
    uint8_t                digest[ATCA_SHA2_256_DIGEST_SIZE] /**< [out] resulting digest/key (must be ATCA_SHA2_256_DIGEST_SIZE bytes) */
    )
{
    ATCA_STATUS ret = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        size_t diglen = ATCA_SHA2_256_DIGEST_SIZE;

        (void)atcac_sha256_hmac_update(ctx, &iteration, 1);
        (void)atcac_sha256_hmac_update(ctx, label, label_len);

        iteration = 0;
        (void)atcac_sha256_hmac_update(ctx, &iteration, 1);
        (void)atcac_sha256_hmac_update(ctx, data, data_len);

        length = ATCA_UINT16_HOST_TO_BE(length);
        (void)atcac_sha256_hmac_update(ctx, (uint8_t*)&length, 2);

        ret = atcac_sha256_hmac_finish(ctx, digest, &diglen);
    }

    return ret;
}

/** \brief Implements SHA256 HMAC-Counter per  NIST SP 800-108 used for KDF like operations */
ATCA_STATUS atcac_sha256_hmac_counter(
    uint8_t *       key,                        /**< [in] Source Key */
    size_t          key_len,                    /**< [in] Source Key Length (bytes) */
    const uint8_t * label,                      /**< [in] kdf label string */
    size_t          label_len,                  /**< [in] kdf label string length (bytes - does not include a terminating null) */
    const uint8_t * data,                       /**< [in] Context data */
    size_t          data_len,                   /**< [in] Context data length (bytes) */
    uint8_t *       digest,                     /**< [out] Resulting generated key material */
    size_t          diglen                      /**< [out] desired length of the result (bytes). */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((diglen > 0x1F00U) || (key_len > ATCA_SHA2_256_BLOCK_SIZE))
    {
        return status;
    }

    uint8_t ctr = 1;
    uint16_t length = (uint16_t)((diglen * 8u) & UINT16_MAX);
    uint8_t tmp_dig[ATCA_SHA2_256_DIGEST_SIZE] = { 0 };

    do
    {
        atcac_hmac_ctx_t hmac_ctx;
        atcac_sha2_256_ctx_t sha256_ctx;

        (void)atcac_sha256_hmac_init(&hmac_ctx, &sha256_ctx, key, (uint8_t)key_len);

        status = atcac_sha256_hmac_ctr_iteration(&hmac_ctx, ctr, length, label,
                                                 label_len, data, data_len, tmp_dig);

        if (ATCA_SHA2_256_DIGEST_SIZE <= diglen)
        {
            (void)memcpy(digest, tmp_dig, ATCA_SHA2_256_DIGEST_SIZE);
            diglen -= ATCA_SHA2_256_DIGEST_SIZE;
            digest += ATCA_SHA2_256_DIGEST_SIZE;
        }
        else
        {
            (void)memcpy(digest, tmp_dig, diglen);
            diglen = 0;
        }
        ctr++;
    }
    while ((ATCA_SUCCESS == status) && (0U < diglen) && (ctr < 255U));

    return status;
}
#endif /* ATCA_CRYPTO_SHA2_HMAC_CTR_EN */
