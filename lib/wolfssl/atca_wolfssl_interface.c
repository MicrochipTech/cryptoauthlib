/**
 * \file
 * \brief Crypto abstraction functions for external host side cryptography
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

#include "atca_config.h"
#include "atca_status.h"
#include "crypto/atca_crypto_sw.h"

#ifdef ATCA_WOLFSSL

/** \brief Initialize an AES-GCM context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_start(
    atcac_aes_gcm_ctx * ctx,     /**< [in] AES-GCM Context */
    const uint8_t *     key,     /**< [in] AES Key */
    const uint8_t       key_len, /**< [in] Length of the AES key - should be 16 or 32*/
    const uint8_t *     iv,      /**< [in] Initialization vector input */
    const uint8_t       iv_len   /**< [in] Length of the initialization vector */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        memset(ctx, 0, sizeof(atcac_aes_gcm_ctx));
        ctx->iv_len = iv_len;

        if (iv)
        {
            memcpy(ctx->iv, iv, ctx->iv_len);
        }

        status = !wc_AesGcmSetKey(&ctx->aes, key, key_len) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }

    return status;
}

ATCA_STATUS atcac_aes_gcm_encrypt(
    atcac_aes_gcm_ctx* ctx,
    const uint8_t*     plaintext,
    const size_t       pt_len,
    uint8_t*           ciphertext,
    uint8_t*           tag,
    size_t             tag_len,
    const uint8_t*     aad,
    const size_t       aad_len
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        if (!wc_AesGcmEncrypt(&ctx->aes, ciphertext, plaintext, pt_len, ctx->iv, ctx->iv_len, tag, tag_len, aad, aad_len))
        {
            status = ATCA_SUCCESS;
        }
    }
    return status;
}

/** \brief Initialize an AES-GCM context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_decrypt_start(
    atcac_aes_gcm_ctx* ctx,     /**< [in] AES-GCM Context */
    const uint8_t*     key,     /**< [in] AES Key */
    const uint8_t      key_len, /**< [in] Length of the AES key - should be 16 or 32*/
    const uint8_t*     iv,      /**< [in] Initialization vector input */
    const uint8_t      iv_len   /**< [in] Length of the initialization vector */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        memset(ctx, 0, sizeof(atcac_aes_gcm_ctx));
        ctx->iv_len = iv_len;

        if (iv)
        {
            memcpy(ctx->iv, iv, ctx->iv_len);
        }

        status = !wc_AesGcmSetKey(&ctx->aes, key, key_len) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }

    return status;
}

ATCA_STATUS atcac_aes_gcm_decrypt(
    atcac_aes_gcm_ctx* ctx,
    const uint8_t*     ciphertext,
    const size_t       ct_len,
    uint8_t*           plaintext,
    const uint8_t*     tag,
    size_t             tag_len,
    const uint8_t*     aad,
    const size_t       aad_len,
    bool*              is_verified
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && is_verified)
    {
        if (!wc_AesGcmDecrypt(&ctx->aes, plaintext, ciphertext, ct_len, ctx->iv, ctx->iv_len, tag, tag_len, aad, aad_len))
        {
            *is_verified = true;
            status = ATCA_SUCCESS;
        }
        else
        {
            *is_verified = false;
        }
    }
    return status;
}

/** \brief Initialize context for performing SHA1 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha1_init(
    atcac_sha1_ctx* ctx         /**< [in] pointer to a hash context */
    )
{
    return (!wc_InitSha(ctx)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Add data to a SHA1 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha1_update(
    atcac_sha1_ctx* ctx,        /**< [in] pointer to a hash context */
    const uint8_t*  data,       /**< [in] input data buffer */
    size_t          data_size   /**< [in] input data length */
    )
{
    return (!wc_ShaUpdate(ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Complete the SHA1 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha1_finish(
    atcac_sha1_ctx* ctx,                          /**< [in] pointer to a hash context */
    uint8_t         digest[ATCA_SHA1_DIGEST_SIZE] /**< [out] output buffer (20 bytes) */
    )
{
    return (!wc_ShaFinal(ctx, digest)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Initialize context for performing SHA256 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha2_256_init(
    atcac_sha2_256_ctx* ctx                 /**< [in] pointer to a hash context */
    )
{
    return (!wc_InitSha256(ctx)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Add data to a SHA256 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha2_256_update(
    atcac_sha2_256_ctx* ctx,                /**< [in] pointer to a hash context */
    const uint8_t*      data,               /**< [in] input data buffer */
    size_t              data_size           /**< [in] input data length */
    )
{
    return (!wc_Sha256Update(ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Complete the SHA256 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha2_256_finish(
    atcac_sha2_256_ctx* ctx,                              /**< [in] pointer to a hash context */
    uint8_t             digest[ATCA_SHA2_256_DIGEST_SIZE] /**< [out] output buffer (32 bytes) */
    )
{
    return (!wc_Sha256Final(ctx, digest)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Initialize context for performing CMAC in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_init(
    atcac_aes_cmac_ctx* ctx,                    /**< [in] pointer to a aes-cmac context */
    const uint8_t*      key,                    /**< [in] key value to use */
    const uint8_t       key_len                 /**< [in] length of the key */
    )
{
    return (!wc_InitCmac(ctx, key, key_len, WC_CMAC_AES, NULL)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Update CMAC context with input data
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_update(
    atcac_aes_cmac_ctx* ctx,                /**< [in] pointer to a aes-cmac context */
    const uint8_t*      data,               /**< [in] input data */
    const size_t        data_size           /**< [in] length of input data */
    )
{
    return (!wc_CmacUpdate(ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Finish CMAC calculation and clear the CMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_finish(
    atcac_aes_cmac_ctx* ctx,            /**< [in] pointer to a aes-cmac context */
    uint8_t*            cmac,           /**< [out] cmac value */
    size_t*             cmac_size       /**< [inout] length of cmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (cmac_size)
    {
        word32 out_len = *cmac_size;
        status = (!wc_CmacFinal(ctx, cmac, &out_len)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
        *cmac_size = out_len;
    }
    return status;
}

/** \brief Initialize context for performing HMAC (sha256) in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_init(
    atcac_hmac_sha256_ctx* ctx,                 /**< [in] pointer to a sha256-hmac context */
    const uint8_t*         key,                 /**< [in] key value to use */
    const uint8_t          key_len              /**< [in] length of the key */
    )
{
    int ret = wc_HmacInit(ctx, NULL, 0);

    if (!ret)
    {
        ret = wc_HmacSetKey(ctx, SHA256, key, key_len);
    }

    return (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Update HMAC context with input data
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_update(
    atcac_hmac_sha256_ctx* ctx,                 /**< [in] pointer to a sha256-hmac context */
    const uint8_t*         data,                /**< [in] input data */
    size_t                 data_size            /**< [in] length of input data */
    )
{
    return (!wc_HmacUpdate(ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Finish HMAC calculation and clear the HMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_finish(
    atcac_hmac_sha256_ctx* ctx,                /**< [in] pointer to a sha256-hmac context */
    uint8_t*               digest,             /**< [out] hmac value */
    size_t*                digest_len          /**< [inout] length of hmac */
    )
{
    int ret = wc_HmacFinal(ctx, digest);

    wc_HmacFree(ctx);

    return (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

#endif /* ATCA_WOLFSSL */
