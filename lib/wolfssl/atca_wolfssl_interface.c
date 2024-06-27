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

#include "cryptoauthlib.h"

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "CERT EXP40-C" "The third party wolfssl api converts const to non constant which is out of scope of CAL") \
    (deviate "MISRA C-2012 Rule 10.3" "Third party library (wolfssl) implementation which is tested code") \
    (deviate "MISRA C-2012 Rule 11.3" "Third party library (wolfssl) implementation which is tested code") \
    (deviate "MISRA C-2012 Rule 11.8" "Third party library (wolfssl) implementation which is tested code")
#endif

#ifdef ATCA_WOLFSSL
#include "crypto/atca_crypto_sw.h"
#include "atca_wolfssl_internal.h"
#include "wolfssl/wolfssl/internal.h"
#include "wolfssl/wolfssl/ssl.h"

/** \brief Return Random Bytes
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_random(uint8_t* data, size_t data_size)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    RNG rng;

    if (0 == wc_InitRng(&rng))
    {
        if (UINT32_MAX <= data_size)
        {
            if (0 == wc_RNG_GenerateBlock(&rng, data, (word32)data_size))
            {
                status = ATCA_SUCCESS;
            }
            else
            {
                status =  ATCA_GEN_FAIL;
            }
        }
        (void)wc_FreeRng(&rng);
    }
    else
    {
        status =  ATCA_GEN_FAIL;
    }
    return status;
}

/** \brief Update the GCM context with additional authentication data (AAD)
 *
 *  \param[in] ctx       AES-GCM Context
 *  \param[in] aad       Additional Authentication Data
 *  \param[in] aad_len   Length of AAD
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_aad_update(
    struct atcac_aes_gcm_ctx*   ctx,    /**< [in] AES-GCM Context */
    const uint8_t*              aad,    /**< [in] Additional Authentication Data */
    const size_t                aad_len /**< [in] Length of AAD */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        status = (0 == wc_AesGcmEncryptUpdate(&ctx->aes, NULL, NULL, 0U, aad, (word32)(aad_len & UINT32_MAX))) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }

    return status;
}

/** \brief Initialize an AES-GCM context
 *
 *  \param[in] ctx       AES-GCM Context
 *  \param[in] key       AES Key
 *  \param[in] key_len   Length of the AES key - should be 16 or 32
 *  \param[in] iv        Initialization vector input
 *  \param[in] iv_len    Length of the initialization vector
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_start(
    struct atcac_aes_gcm_ctx *  ctx,        /**< [in] AES-GCM Context */
    const uint8_t *             key,        /**< [in] AES Key */
    const uint8_t               key_len,    /**< [in] Length of the AES key - should be 16 or 32*/
    const uint8_t *             iv,         /**< [in] Initialization vector input */
    const uint8_t               iv_len      /**< [in] Length of the initialization vector */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        (void)memset(ctx, 0, sizeof(atcac_aes_gcm_ctx_t));

        if (0 == wc_AesInit(&ctx->aes, NULL, INVALID_DEVID))
        {
            status = (0 == wc_AesGcmEncryptInit(&ctx->aes, key, key_len, iv, iv_len)) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
        }

    }

    return status;
}

/** \brief Encrypt a data using the initialized context
 *
 *  \param[in]  ctx          AES-GCM Context
 *  \param[in]  plaintext    Data to be encrypted
 *  \param[in]  pt_len       Plain text Length
 *  \param[out] ciphertext   Encrypted data
 *  \param[out] ct_len       Cipher text length
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_update(
    struct atcac_aes_gcm_ctx*   ctx,
    const uint8_t*              plaintext,
    const size_t                pt_len,
    uint8_t*                    ciphertext,
    size_t*                     ct_len
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx && NULL != ciphertext && NULL != ct_len)
    {
        if ((pt_len <= UINT32_MAX))
        {
            status = (0 == wc_AesGcmEncryptUpdate(&ctx->aes, ciphertext, plaintext, (word32)pt_len, NULL, 0U)) ? ATCA_SUCCESS : ATCA_GEN_FAIL;

            if (ATCA_SUCCESS == status)
            {
                *ct_len = pt_len;
            }
        }
    }
    return status;
}

/** \brief Get the AES-GCM tag and free the context
 *
 *  \param[in]  ctx          AES-GCM Context
 *  \param[out] tag          AES-GCM tag
 *  \param[in]  tag_len      tag length
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_finish(
    struct atcac_aes_gcm_ctx*   ctx,
    uint8_t*                    tag,
    size_t                      tag_len
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        if (tag_len <= UINT32_MAX)
        {
            status = (0 == wc_AesGcmEncryptFinal(&ctx->aes, tag, (word32)tag_len)) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
        }
    }
    return status;
}

/** \brief Initialize an AES-GCM context for decryption
 *
 *  \param[in] ctx       AES-GCM Context
 *  \param[in] key       AES Key
 *  \param[in] key_len   Length of the AES key - should be 16 or 32
 *  \param[in] iv        Initialization vector input
 *  \param[in] iv_len    Length of the initialization vector
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_decrypt_start(
    struct atcac_aes_gcm_ctx*   ctx,        /**< [in] AES-GCM Context */
    const uint8_t*              key,        /**< [in] AES Key */
    const uint8_t               key_len,    /**< [in] Length of the AES key - should be 16 or 32*/
    const uint8_t*              iv,         /**< [in] Initialization vector input */
    const uint8_t               iv_len      /**< [in] Length of the initialization vector */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        (void)memset(ctx, 0, sizeof(atcac_aes_gcm_ctx_t));

        if (0 == wc_AesInit(&ctx->aes, NULL, INVALID_DEVID))
        {
            status = (0 == wc_AesGcmDecryptInit(&ctx->aes, key, key_len, iv, iv_len)) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
        }
    }

    return status;
}

/** \brief Decrypt ciphertext using the initialized context
 *
 *  \param[in]  ctx          AES-GCM Context
 *  \param[in]  ciphertext   Encrypted data
 *  \param[in]  ct_len       Ciphertext length
 *  \param[out] plaintext    Data to be encrypted
 *  \param[out] pt_len       Plaintext Length
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_decrypt_update(
    struct atcac_aes_gcm_ctx*   ctx,
    const uint8_t*              ciphertext,
    const size_t                ct_len,
    uint8_t*                    plaintext,
    size_t*                     pt_len
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx && NULL != pt_len)
    {
        if (ct_len <= UINT32_MAX)
        {
            status = (0 == wc_AesGcmDecryptUpdate(&ctx->aes, plaintext, ciphertext, (word32)ct_len, NULL, 0U)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

            if (ATCA_SUCCESS == status)
            {
                *pt_len = ct_len;
            }
        }
    }
    return status;
}

/** \brief Compare the AES-GCM tag and free the context
 *
 *  \param[in]  ctx          AES-GCM Context
 *  \param[out] tag          AES-GCM tag
 *  \param[in]  tag_len      tag length
 *  \param[out] is_verified  verification status
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_decrypt_finish(
    struct atcac_aes_gcm_ctx*   ctx,        /**< [in] AES-GCM Context */
    const uint8_t*              tag,        /**< [in] GCM Tag to Verify */
    size_t                      tag_len,    /**< [in] Length of the GCM tag */
    bool*                       is_verified /**< [out] Tag verified as matching */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != is_verified) && (UINT32_MAX >= tag_len))
    {
        status = (0 == wc_AesGcmDecryptFinal(&ctx->aes, tag, (word32)tag_len)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

        if (ATCA_SUCCESS == status)
        {

            *is_verified = true;
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
ATCA_STATUS atcac_sw_sha1_init(
    struct atcac_sha1_ctx* ctx  /**< [in] pointer to a hash context */
    )
{
    wc_Sha* temp_ptr = &ctx->sha;
    ATCA_STATUS status = (0 == wc_InitSha(temp_ptr)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

    return status;
}

/** \brief Add data to a SHA1 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha1_update(
    struct atcac_sha1_ctx*  ctx,        /**< [in] pointer to a hash context */
    const uint8_t*          data,       /**< [in] input data buffer */
    size_t                  data_size   /**< [in] input data length */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (data_size <= UINT32_MAX)
    {
        wc_Sha* temp_ptr = &ctx->sha;
        status = (0 == wc_ShaUpdate(temp_ptr, data, (word32)data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Complete the SHA1 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha1_finish(
    struct atcac_sha1_ctx*  ctx,                            /**< [in] pointer to a hash context */
    uint8_t                 digest[ATCA_SHA1_DIGEST_SIZE]   /**< [out] output buffer (20 bytes) */
    )
{
    wc_Sha* temp_ptr = &ctx->sha;
    ATCA_STATUS status = (0 == wc_ShaFinal(temp_ptr, digest)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

    return status;
}

/** \brief Initialize context for performing SHA256 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_init(
    struct atcac_sha2_256_ctx* ctx  /**< [in] pointer to a hash context */
    )
{
    wc_Sha256* temp_ptr = &ctx->sha;
    ATCA_STATUS status = (0 == wc_InitSha256(temp_ptr)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

    return status;
}

/** \brief Add data to a SHA256 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_update(
    struct atcac_sha2_256_ctx*  ctx,        /**< [in] pointer to a hash context */
    const uint8_t*              data,       /**< [in] input data buffer */
    size_t                      data_size   /**< [in] input data length */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (data_size <= UINT32_MAX)
    {
        wc_Sha256* temp_ptr = &ctx->sha;
        status = (0 == wc_Sha256Update(temp_ptr, data, (word32)data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Complete the SHA256 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_finish(
    struct atcac_sha2_256_ctx*  ctx,                                /**< [in] pointer to a hash context */
    uint8_t                     digest[ATCA_SHA2_256_DIGEST_SIZE]   /**< [out] output buffer (32 bytes) */
    )
{
    wc_Sha256* temp_ptr = &ctx->sha;
    ATCA_STATUS status = (0 == wc_Sha256Final(temp_ptr, digest)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

    return status;
}

/** \brief Initialize context for performing CMAC in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_init(
    struct atcac_aes_cmac_ctx*  ctx,    /**< [in] pointer to a aes-cmac context */
    const uint8_t*              key,    /**< [in] key value to use */
    const uint8_t               key_len /**< [in] length of the key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx != NULL)
    {
        Cmac* tmp_ptr = &ctx->cmac;
        /* coverity[misra_c_2012_rule_10_3_violation:FALSE] */
        status = (0 == wc_InitCmac(tmp_ptr, key, key_len, (sword32)WC_CMAC_AES, NULL)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }

    return status;
}

/** \brief Update CMAC context with input data
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_update(
    struct atcac_aes_cmac_ctx*  ctx,        /**< [in] pointer to a aes-cmac context */
    const uint8_t*              data,       /**< [in] input data */
    const size_t                data_size   /**< [in] length of input data */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (data_size <= UINT32_MAX)
    {
        Cmac* tmp_ptr = &ctx->cmac;
        status = (0 == wc_CmacUpdate(tmp_ptr, data, (word32)data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Finish CMAC calculation and clear the CMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_finish(
    struct atcac_aes_cmac_ctx*  ctx,        /**< [in] pointer to a aes-cmac context */
    uint8_t*                    cmac,       /**< [out] cmac value */
    size_t*                     cmac_size   /**< [inout] length of cmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cmac_size)
    {
        if ((*cmac_size <= UINT32_MAX) && (ctx != NULL))
        {
            Cmac* tmp_ptr = &ctx->cmac;
            word32 out_len = (word32) * cmac_size;
            status = (0 == wc_CmacFinal(tmp_ptr, cmac, &out_len)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
            *cmac_size = out_len;
        }
    }
    return status;
}

/** \brief Initialize context for performing HMAC (sha256) in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_init(
    struct atcac_hmac_ctx*      ctx,        /**< [in] pointer to a sha256-hmac context */
    struct atcac_sha2_256_ctx*  sha256_ctx, /**< [in] pointer to a sha256 context */
    const uint8_t*              key,        /**< [in] key value to use */
    const uint8_t               key_len     /**< [in] length of the key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx != NULL)
    {
        Hmac* temp_ptr = &ctx->hmac;
        status = (0 == wc_HmacInit(temp_ptr, NULL, 0)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

        (void)sha256_ctx;

        if (ATCA_SUCCESS == status)
        {
#if defined(NO_OLD_SHA_NAMES) && !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
            status = (0 == wc_HmacSetKey(temp_ptr, WC_SHA256, key, key_len)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
#else
            status = (0 == wc_HmacSetKey(temp_ptr, SHA256, key, key_len)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
#endif
        }
    }
    return status;
}

/** \brief Update HMAC context with input data
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_update(
    struct atcac_hmac_ctx*  ctx,        /**< [in] pointer to a sha256-hmac context */
    const uint8_t*          data,       /**< [in] input data */
    size_t                  data_size   /**< [in] length of input data */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((data_size <= UINT32_MAX) && ctx != NULL)
    {
        Hmac* temp_ptr = &ctx->hmac;
        status = (0 == wc_HmacUpdate(temp_ptr, data, (word32)data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Finish HMAC calculation and clear the HMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_finish(
    struct atcac_hmac_ctx*  ctx,        /**< [in] pointer to a sha256-hmac context */
    uint8_t*                digest,     /**< [out] hmac value */
    size_t*                 digest_len  /**< [inout] length of hmac */
    )
{
    ((void)digest_len);
    ATCA_STATUS status = ATCA_BAD_PARAM;
    if (ctx != NULL)
    {
        Hmac* temp_ptr = &ctx->hmac;
        status = (0 == wc_HmacFinal(temp_ptr, digest)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

        wc_HmacFree(temp_ptr);
    }
    return status;
}

/** \brief Set up a public/private key structure for use in asymmetric cryptographic functions
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_init(
    struct atcac_pk_ctx*    ctx,    /**< [in] pointer to a pk context */
    const uint8_t*          buf,    /**< [in] buffer containing a pem encoded key */
    size_t                  buflen, /**< [in] length of the input buffer */
    uint8_t                 key_type,
    bool                    pubkey  /**< [in] buffer is a public key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    ((void)buflen);

    if (NULL != ctx)
    {
        if (0u == key_type)
        {
            ctx->ptr = wc_ecc_key_new(NULL);

            if (NULL != ctx->ptr)
            {
                /* coverity[misra_c_2012_rule_10_3_violation:FALSE] */
                int ret = (0 == wc_ecc_set_curve((ecc_key*)ctx->ptr, 32, (sword32)ECC_SECP256R1)) ? 0 : 1;

                if (0 == ret)
                {
                    if (pubkey)
                    {
                        uint8_t buf_copy[64] = { 0x00 };
                        (void)memcpy(&buf_copy, buf, sizeof(buf_copy));
                        /* Configure the public key */
                        ret = wc_ecc_import_unsigned((ecc_key*)ctx->ptr, (byte*)buf_copy, (byte*)&buf_copy[32], NULL, (sword32)ECC_SECP256R1);

                    }
                    else
                    {
                        /* Configure a private key */
                        ret = wc_ecc_import_private_key((const byte*)buf, 32, NULL, 0, (ecc_key*)ctx->ptr);
                    }

                    if (0 == ret)
                    {
                        status = ATCA_SUCCESS;
                    }
                    else
                    {
                        wc_ecc_key_free((ecc_key*)(ctx->ptr));
                        status = ATCA_GEN_FAIL;
                    }
                }
            }
        }
        if (ATCA_SUCCESS == status)
        {
            ctx->key_type = key_type;
        }
    }
    return status;
}

/** \brief Set up a public/private key structure for use in asymmetric cryptographic functions
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_init_pem(
    struct atcac_pk_ctx*    ctx,    /**< [in] pointer to a pk context */
    const uint8_t *         buf,    /**< [in] buffer containing a pem encoded key */
    size_t                  buflen, /**< [in] length of the input buffer */
    bool                    pubkey  /**< [in] buffer is a public key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx && NULL != buf)
    {
        word32 inOutIdx = 0;
        status = ATCA_FUNC_FAIL;
        uint8_t derbuf[121] = { 0u };   //! ECC_SECP256R1 MAX DER size
        size_t derbuflen = sizeof(derbuf);
        int ret;

        if (buflen <= UINT32_MAX)
        {
            if (TRUE == pubkey)
            {
                ret = wc_PubKeyPemToDer(buf, (int)buflen, derbuf, (int)derbuflen);
            }
            else
            {
                ret = wc_KeyPemToDer(buf, (int)buflen, derbuf, (int)derbuflen, NULL);
            }

            if ((ret >= 0))
            {
                //! Update Der len
                derbuflen = (size_t)ret;

                ctx->ptr = wc_ecc_key_new(NULL);

                if (NULL != ctx->ptr)
                {
                    ret = (0 == wc_ecc_set_curve((ecc_key*)ctx->ptr, 32, (sword32)ECC_SECP256R1)) ? 0 : 1;

                    if (0 == ret)
                    {
                        if (pubkey)
                        {
                            ret = wc_EccPublicKeyDecode(derbuf, &inOutIdx, (ecc_key*)ctx->ptr, (word32)derbuflen);
                        }
                        else
                        {
                            ret = wc_EccPrivateKeyDecode(derbuf, &inOutIdx, (ecc_key*)ctx->ptr, (word32)derbuflen);
                        }
                        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
                    }
                    if (ATCA_SUCCESS == status)
                    {
                        ctx->key_type = 0;
                    }
                }
            }
        }
    }
    return status;
}

/** \brief Get the public key from the context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_public(
    struct atcac_pk_ctx*    ctx,
    uint8_t*                buf,
    size_t*                 buflen
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx  && NULL != ctx->ptr && NULL != buf)
    {
        if (NULL != buflen)
        {
            (void)*buflen;
        }

        int ret = -1;

        if (0U == ctx->key_type)
        {
            word32 xlen = 32;
            word32 ylen = 32;

            ret = wc_ecc_export_public_raw((ecc_key*)ctx->ptr, (byte*)buf, &xlen, (byte*)&buf[32], &ylen);
        }

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Free a public/private key structure
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_free(
    struct atcac_pk_ctx* ctx    /**< [in] pointer to a pk context */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        if (NULL != ctx->ptr)
        {
            wc_ecc_key_free((ecc_key*)(ctx->ptr));
        }
        status = ATCA_SUCCESS;
    }
    return status;
}

/** \brief Perform a signature with the private key in the context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_sign(
    struct atcac_pk_ctx*    ctx,
    const uint8_t *         digest,
    size_t                  dig_len,
    uint8_t*                signature,
    size_t*                 sig_len
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != ctx->ptr) && (NULL != signature) && (NULL != digest) && (NULL != sig_len))
    {
        WC_RNG rng;
        int ret = wc_InitRng(&rng);

        if (0 == ret)
        {
            if ((0u == ctx->key_type) && (ATCA_SHA256_DIGEST_SIZE == dig_len))
            {
                uint8_t sig[72];
                word32 siglen = 72;
                word32 rlen = 32;
                word32 slen = 32;

                (void)memset(signature, 0, *sig_len);

                ret = wc_ecc_sign_hash((const byte*)digest, (word32)dig_len, (byte*)sig, &siglen, &rng, (ecc_key*)ctx->ptr);

                if (0 == ret)
                {
                    ret = wc_ecc_sig_to_rs((byte*)sig, siglen, (byte*)signature, &rlen, (byte*)&signature[32], &slen);
                }

                if (0 == ret)
                {
                    *sig_len = 64;
                }
            }
            else
            {
                // ret = wc_SignatureGenerateHash(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, digest, dig_len, signature,
                //                                *sig_len, (RsaKey*)ctx->ptr, 32, &rng);
            }
            (void)wc_FreeRng(&rng);
        }
        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Perform a verify using the public key in the provided context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_verify(
    struct atcac_pk_ctx*    ctx,
    const uint8_t*          digest,
    size_t                  dig_len,
    const uint8_t*          signature,
    size_t                  sig_len
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != ctx->ptr) && (NULL != signature) && (NULL != digest)
        && (ATCA_SHA256_DIGEST_SIZE == dig_len))
    {
        int ret = -1;
        int res = 0;
        if ((0u == ctx->key_type) && (ATCA_ECCP256_SIG_SIZE == sig_len))
        {
            uint8_t sig[72];
            word32 len = 72;

            ret = (0 == wc_ecc_rs_raw_to_sig(signature, 32, &signature[32], 32, (byte*)sig, &len)) ? 0 : 1;

            if (0 == ret)
            {
                ret = wc_ecc_verify_hash((byte*)sig, len, (const byte*)digest, (word32)dig_len, &res, (ecc_key*)ctx->ptr);
            }
        }
        else
        {
            // ret = wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, digest, 32, signature,
            //                              &sig_len, ctx->ptr, 64);
        }

        status = ATCA_FUNC_FAIL;
        if (0 == ret)
        {
            if (1 == res)
            {
                status = ATCA_SUCCESS;
            }
        }
    }

    return status;

}

/** \brief Execute the key agreement protocol for the provided keys (if they can)
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_derive(
    struct atcac_pk_ctx*    private_ctx,
    struct atcac_pk_ctx*    public_ctx,
    uint8_t*                buf,
    size_t*                 buflen
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((private_ctx != NULL) && (public_ctx != NULL) && (buf != NULL) && (buflen != NULL))
    {
        int ret = -1;

        if ((*buflen <= UINT32_MAX) && (0u == private_ctx->key_type))
        {
            word32 temp_len = (word32) * buflen;
            ret = wc_ecc_shared_secret((ecc_key*)private_ctx->ptr, (ecc_key*)public_ctx->ptr, (byte*)buf, &temp_len);
            *buflen = temp_len;
        }
        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }

    return status;
}


static ATCA_STATUS atcac_read_asn1_string(WOLFSSL_ASN1_TIME* as, cal_buffer* buf, uint8_t* tag)
{
    ATCA_STATUS status;

    if (NULL != as && 0 < as->length)
    {
        if (ATCA_SUCCESS == (status = cal_buf_write_bytes(buf, 0U, as->data, (size_t)as->length)))
        {
            if (NULL != tag)
            {
                if ((as->type >= 0 && as->type <= 255))
                {
                    *tag = (unsigned char)as->type;
                }
            }
            status = cal_buf_set_used(buf, (size_t)as->length);
        }

    }
    else
    {
        /* No data is available */
        status = cal_buf_set_used(buf, 0U);
    }

    return status;
}

ATCA_STATUS atcac_parse_der(struct atcac_x509_ctx** cert, cal_buffer* der)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != der)
    {
        const unsigned char* in = der->buf;
        if (der->len <= UINT32_MAX)
        {
            void** tmp = (void**)cert;
            WOLFSSL_X509** x509 = (WOLFSSL_X509**)tmp;
            /* coverity[misra_c_2012_rule_11_3_violation:FALSE] */
            if (NULL != wolfSSL_d2i_X509((WOLFSSL_X509**)x509, &in, (int)der->len))
            {
                status = ATCA_SUCCESS;
            }
        }
    }
    return status;
}

static WOLFSSL_X509* get_wssl_cert_from_atcac_ctx(const struct atcac_x509_ctx* cert)
{
    /* coverity[cert_exp40_c_violation] wolf ssl api removes const qualifier which is out of scope */
    /* coverity[misra_c_2012_rule_11_8_violation:FALSE] */
    WOLFSSL_X509* wssl_cert = (NULL != cert) ? (WOLFSSL_X509*)(&cert->ptr) : NULL;

    return wssl_cert;
}

ATCA_STATUS atcac_get_subject(const struct atcac_x509_ctx* cert, cal_buffer* cert_subject)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != cert_subject)
    {
        const WOLFSSL_X509_NAME* sub_name = wolfSSL_X509_get_subject_name(get_wssl_cert_from_atcac_ctx(cert));

        if (NULL != sub_name)
        {
            if (sub_name->sz > 0)
            {
                if (ATCA_SUCCESS == (status = cal_buf_write_bytes(cert_subject, 0U, sub_name->name, (size_t)sub_name->sz)))
                {
                    status = ATCA_SUCCESS;
                }
            }
        }
    }
    if (ATCA_SUCCESS != status)
    {
        /* No data is available */
        status = cal_buf_set_used(cert_subject, 0U);
    }
    return status;
}

ATCA_STATUS atcac_get_subj_public_key(const struct atcac_x509_ctx* cert, cal_buffer* subj_public_key)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != subj_public_key)
    {
        WOLFSSL_EVP_PKEY* key;

        if (NULL != (key = wolfSSL_X509_get_pubkey(get_wssl_cert_from_atcac_ctx(cert))))
        {
            ecc_key pubKeyEcc;
            (void)memset(&pubKeyEcc, 0, sizeof(ecc_key));
            word32 idx = 0;
            if (0 == wc_ecc_init(&pubKeyEcc))
            {
                int pkey_sz = key->pkey_sz; // Cast to signed int

                if (pkey_sz >= 0)
                {
                    if (0 == wc_EccPublicKeyDecode((byte*)key->pkey.ptr, &idx, &pubKeyEcc, (word32)key->pkey_sz))
                    {
                        /* coverity[misra_c_2012_rule_9_1_violation:SUPPRESS] wc_ecc_init is called to initialize pubKeyEcc */
                        if (NULL != pubKeyEcc.dp)
                        {
                            word32 xlen = (word32)pubKeyEcc.dp->size;
                            word32 ylen = (word32)pubKeyEcc.dp->size;
                            if (0 == wc_ecc_export_public_raw(&pubKeyEcc, (byte*)subj_public_key->buf, &xlen,
                                                              (byte*)&subj_public_key->buf[pubKeyEcc.dp->size], &ylen))
                            {
                                status = ATCA_SUCCESS;
                            }
                        }
                    }
                }
            }
            wolfSSL_EVP_PKEY_free(key);
            if (0 != wc_ecc_free(&pubKeyEcc))
            {
                status = ATCA_BAD_PARAM;
            }
        }
    }
    return status;
}

ATCA_STATUS atcac_get_subj_key_id(const struct atcac_x509_ctx* cert, cal_buffer* subj_public_key_id)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != subj_public_key_id)
    {
        if (subj_public_key_id->len <= UINT32_MAX)
        {
            int len_as_int = (int)(subj_public_key_id->len);
            if (NULL != wolfSSL_X509_get_subjectKeyID(get_wssl_cert_from_atcac_ctx(cert), subj_public_key_id->buf, &len_as_int))
            {
                status = ATCA_SUCCESS;
            }
        }
    }
    return status;
}

ATCA_STATUS atcac_get_issue_date(const struct atcac_x509_ctx* cert, cal_buffer* not_before, uint8_t* fmt)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != not_before && NULL != fmt)
    {
        WOLFSSL_ASN1_TIME* x509_tm_date = wolfSSL_X509_get_notBefore((const WOLFSSL_X509*)&cert->ptr);

        if (NULL != x509_tm_date)
        {
            status = atcac_read_asn1_string(x509_tm_date, not_before, fmt);
        }
    }
    return status;
}

ATCA_STATUS atcac_get_expire_date(const struct atcac_x509_ctx* cert, cal_buffer* not_after, uint8_t* fmt)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != not_after && NULL != fmt)
    {
        WOLFSSL_ASN1_TIME* x509_tm_date = wolfSSL_X509_get_notAfter((const WOLFSSL_X509*)&cert->ptr);

        if (NULL != x509_tm_date)
        {
            status = atcac_read_asn1_string(x509_tm_date, not_after, fmt);
        }
    }

    return status;
}

ATCA_STATUS atcac_get_cert_sn(const struct atcac_x509_ctx* cert, cal_buffer* cert_sn)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != cert_sn)
    {
        if (cert_sn->len <= UINT32_MAX)
        {
            int len_as_int = (int)(cert_sn->len);
            if (WOLFSSL_SUCCESS == wolfSSL_X509_get_serial_number(get_wssl_cert_from_atcac_ctx(cert), cert_sn->buf, &len_as_int))
            {
                status = ATCA_SUCCESS;
            }
        }
    }
    return status;
}

ATCA_STATUS atcac_get_issuer(const struct atcac_x509_ctx* cert, cal_buffer* issuer_buf)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != issuer_buf)
    {
        WOLFSSL_X509_NAME* sub_name = wolfSSL_X509_get_issuer_name(get_wssl_cert_from_atcac_ctx(cert));

        if (NULL != sub_name)
        {
            if (sub_name->sz > 0)
            {
                if (ATCA_SUCCESS == (status = cal_buf_write_bytes(issuer_buf, 0U, sub_name->name, (size_t)sub_name->sz)))
                {
                    status = ATCA_SUCCESS;
                }
            }
        }
    }
    if (ATCA_SUCCESS != status)
    {
        /* No data is available */
        status = cal_buf_set_used(issuer_buf, 0U);
    }
    return status;
}

ATCA_STATUS atcac_get_auth_key_id(const struct atcac_x509_ctx* cert, cal_buffer* auth_key_id)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != auth_key_id)
    {
        if (auth_key_id->len <= UINT32_MAX)
        {
            int len_as_int = (int)(auth_key_id->len);
            if (NULL != wolfSSL_X509_get_authorityKeyID(get_wssl_cert_from_atcac_ctx(cert), auth_key_id->buf, &len_as_int))
            {
                status = ATCA_SUCCESS;
            }
        }
    }
    return status;
}

void atcac_x509_free(void* cert)
{
    if (NULL != cert)
    {
        wolfSSL_X509_free((WOLFSSL_X509 *)cert);
    }
}

#if defined(ATCA_BUILD_SHARED_LIBS) || defined(ATCA_HEAP)
struct atcac_sha1_ctx * atcac_sha1_ctx_new(void)
{
    return (struct atcac_sha1_ctx*)hal_malloc(sizeof(atcac_sha1_ctx_t));
}

struct atcac_sha2_256_ctx * atcac_sha256_ctx_new(void)
{
    return (struct atcac_sha2_256_ctx*)hal_malloc(sizeof(atcac_sha2_256_ctx_t));
}

struct atcac_hmac_ctx * atcac_hmac_ctx_new(void)
{
    return (struct atcac_hmac_ctx*)hal_malloc(sizeof(atcac_hmac_ctx_t));
}

struct atcac_aes_gcm_ctx * atcac_aes_gcm_ctx_new(void)
{
    return (struct atcac_aes_gcm_ctx*)hal_malloc(sizeof(atcac_aes_gcm_ctx_t));
}

struct atcac_aes_cmac_ctx * atcac_aes_cmac_ctx_new(void)
{
    return (struct atcac_aes_cmac_ctx*)hal_malloc(sizeof(atcac_aes_cmac_ctx_t));
}

struct atcac_pk_ctx * atcac_pk_ctx_new(void)
{
    return (struct atcac_pk_ctx*)hal_malloc(sizeof(atcac_pk_ctx_t));
}

void atcac_sha1_ctx_free(struct atcac_sha1_ctx * ctx)
{
    hal_free(ctx);
}

void atcac_sha256_ctx_free(struct atcac_sha2_256_ctx * ctx)
{
    hal_free(ctx);
}

void atcac_hmac_ctx_free(struct atcac_hmac_ctx * ctx)
{
    hal_free(ctx);
}

void atcac_aes_gcm_ctx_free(struct atcac_aes_gcm_ctx * ctx)
{
    hal_free(ctx);
}

void atcac_aes_cmac_ctx_free(struct atcac_aes_cmac_ctx * ctx)
{
    hal_free(ctx);
}

void atcac_pk_ctx_free(struct atcac_pk_ctx * ctx)
{
    hal_free(ctx);
}
#endif
#endif /* ATCA_WOLFSSL */
#ifdef __COVERITY__
#pragma coverity compliance end_block "CERT EXP40-C" "MISRA C-2012 Rule 10.3" "MISRA C-2012 Rule 11.3" "MISRA C-2012 Rule 11.8"
#endif
