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

#ifdef ATCA_OPENSSL
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/** \brief Update the GCM context with additional authentication data (AAD)
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_aad_update(
    atcac_aes_gcm_ctx* ctx,     /**< [in] AES-GCM Context */
    const uint8_t*     aad,     /**< [in] Additional Authentication Data */
    const size_t       aad_len  /**< [in] Length of AAD */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        int outlen = 0;
        status = (1 == EVP_CipherUpdate((EVP_CIPHER_CTX*)ctx->ptr, NULL, &outlen, aad, (int)aad_len)) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }
    return status;
}

/** \brief Initialize an AES-GCM context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_start(
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
        int ret;
        ctx->ptr = EVP_CIPHER_CTX_new();

        /* Set cipher type and mode */
        if (16 == key_len)
        {
            ret = EVP_EncryptInit_ex((EVP_CIPHER_CTX*)ctx->ptr, EVP_aes_128_gcm(), NULL, NULL, NULL);
        }
        else
        {
            ret = 0;
        }

        if (1 == ret)
        {
            /* Set IV length if default 96 bits is not appropriate */
            ret = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX*)ctx->ptr, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_len, NULL);
        }

        if (1 == ret)
        {
            /* Initialise key and IV */
            ret = EVP_EncryptInit_ex((EVP_CIPHER_CTX*)ctx->ptr, NULL, NULL, key, iv);
        }

        status = (1 == ret) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }

    return status;
}

/** \brief Encrypt a data using the initialized context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_update(
    atcac_aes_gcm_ctx* ctx,        /**< [in] AES-GCM Context */
    const uint8_t *    plaintext,  /**< [in] Input buffer to encrypt */
    const size_t       pt_len,     /**< [in] Length of the input */
    uint8_t *          ciphertext, /**< [out] Output buffer */
    size_t *           ct_len      /**< [inout] Length of the ciphertext buffer */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && ct_len)
    {
        int outlen = (int)*ct_len;
        if (1 == EVP_EncryptUpdate((EVP_CIPHER_CTX*)ctx->ptr, ciphertext, &outlen, plaintext, (int)pt_len))
        {
            *ct_len = outlen;
            status = ATCA_SUCCESS;
        }
        else
        {
            status = ATCA_GEN_FAIL;
        }
    }
    return status;
}

/** \brief Get the AES-GCM tag and free the context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_finish(
    atcac_aes_gcm_ctx* ctx,     /**< [in] AES-GCM Context */
    uint8_t*           tag,     /**< [out] GCM Tag Result */
    size_t             tag_len  /**< [in] Length of the GCM tag */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        int outlen = 0;
        int ret = EVP_EncryptFinal_ex((EVP_CIPHER_CTX*)ctx->ptr, NULL, &outlen);

        if (1 == ret)
        {
            /* Get tag */
            ret = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX*)ctx->ptr, EVP_CTRL_AEAD_GET_TAG, (int)tag_len, tag);
        }

        /* Always try to free the context */
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ctx->ptr);
        ctx->ptr = NULL;

        status = (1 == ret) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }
    return status;
}

/** \brief Initialize an AES-GCM context for decryption
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
        int ret;
        ctx->ptr = EVP_CIPHER_CTX_new();

        /* Set cipher type and mode */
        if (16 == key_len)
        {
            ret = EVP_DecryptInit_ex((EVP_CIPHER_CTX*)ctx->ptr, EVP_aes_128_gcm(), NULL, NULL, NULL);
        }
        else
        {
            ret = 0;
        }

        if (1 == ret)
        {
            /* Set IV length if default 96 bits is not appropriate */
            ret = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX*)ctx->ptr, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_len, NULL);
        }

        if (1 == ret)
        {
            /* Initialise key and IV */
            ret = EVP_DecryptInit_ex((EVP_CIPHER_CTX*)ctx->ptr, NULL, NULL, key, iv);
        }

        status = (1 == ret) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }

    return status;
}

/** \brief Decrypt ciphertext using the initialized context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_decrypt_update(
    atcac_aes_gcm_ctx* ctx,        /**< [in] AES-GCM Context */
    const uint8_t*     ciphertext, /**< [in] Ciphertext to decrypt */
    const size_t       ct_len,     /**< [in] Length of the ciphertext */
    uint8_t*           plaintext,  /**< [out] Resulting decrypted plaintext */
    size_t*            pt_len      /**< [inout] Length of the plaintext buffer */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && pt_len)
    {
        int outlen = (int)*pt_len;
        if (1 == EVP_DecryptUpdate((EVP_CIPHER_CTX*)ctx->ptr, plaintext, &outlen, ciphertext, (int)ct_len))
        {
            *pt_len = outlen;
            status = ATCA_SUCCESS;
        }
        else
        {
            status = ATCA_GEN_FAIL;
        }
    }
    return status;
}

/** \brief Compare the AES-GCM tag and free the context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_decrypt_finish(
    atcac_aes_gcm_ctx* ctx,        /**< [in] AES-GCM Context */
    const uint8_t*     tag,        /**< [in] GCM Tag to Verify */
    size_t             tag_len,    /**< [in] Length of the GCM tag */
    bool*              is_verified /**< [out] Tag verified as matching */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && is_verified)
    {
        int ret = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX*)ctx->ptr, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, (void*)tag);

        if (1 == ret)
        {
            int outlen = 0;
            ret = EVP_DecryptFinal_ex((EVP_CIPHER_CTX*)ctx->ptr, NULL, &outlen);
        }

        /* Always try to free the context */
        EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX*)ctx->ptr);

        if (ret > 0)
        {
            *is_verified = true;
            status = ATCA_SUCCESS;
        }
        else
        {
            *is_verified = false;
            status = ATCA_FUNC_FAIL;
        }
    }

    return status;
}

/** \brief OpenSSL Message Digest Abstraction - Init
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS _atca_openssl_md_init(atca_evp_ctx* ctx, const EVP_MD* md_alg)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        int ret;
        ctx->ptr = EVP_MD_CTX_new();

        ret = EVP_MD_CTX_init((EVP_MD_CTX*)ctx->ptr);

        if (1 == ret)
        {
            ret = EVP_DigestInit_ex((EVP_MD_CTX*)ctx->ptr, md_alg, NULL);
        }

        status = (1 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief OpenSSL Message Digest Abstraction - Update
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS _atca_openssl_md_update(atca_evp_ctx* ctx, const uint8_t* data, size_t data_size)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        status = (1 == EVP_DigestUpdate((EVP_MD_CTX*)ctx->ptr, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief OpenSSL Message Digest Abstraction - Finish
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS _atca_openssl_md_finish(atca_evp_ctx* ctx, uint8_t * digest, unsigned int * outlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        status = (1 == EVP_DigestFinal_ex((EVP_MD_CTX*)ctx->ptr, digest, outlen)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

        EVP_MD_CTX_free(ctx->ptr);
        ctx->ptr = NULL;
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
    return _atca_openssl_md_init(ctx, EVP_sha1());
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
    return _atca_openssl_md_update(ctx, data, data_size);
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
    unsigned int outlen = ATCA_SHA1_DIGEST_SIZE;

    return _atca_openssl_md_finish(ctx, digest, &outlen);
}

/** \brief Initialize context for performing SHA256 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha2_256_init(
    atcac_sha2_256_ctx* ctx                 /**< [in] pointer to a hash context */
    )
{
    return _atca_openssl_md_init(ctx, EVP_sha256());
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
    return _atca_openssl_md_update(ctx, data, data_size);
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
    unsigned int outlen = ATCA_SHA2_256_DIGEST_SIZE;

    return _atca_openssl_md_finish(ctx, digest, &outlen);
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
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        int ret;
        ctx->ptr = CMAC_CTX_new();

        if (16 == key_len)
        {
            ret = CMAC_Init((CMAC_CTX*)ctx->ptr, key, 16, EVP_aes_128_cbc(), NULL);
        }
        else
        {
            ret = 0;
        }

        status = (1 == ret) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }
    return status;
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
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        status = (1 == CMAC_Update((CMAC_CTX*)ctx->ptr, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Finish CMAC calculation and clear the CMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_finish(
    atcac_aes_cmac_ctx* ctx,            /**< [in] pointer to a aes-cmac context */
    uint8_t*            cmac,           /**< [out] cmac value */
    size_t *            cmac_size       /**< [inout] length of cmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        status = (1 == CMAC_Final((CMAC_CTX*)ctx->ptr, cmac, cmac_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

        CMAC_CTX_free((CMAC_CTX*)ctx->ptr);
        ctx->ptr = NULL;
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
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        ctx->ptr = HMAC_CTX_new();

        status = (1 == HMAC_Init_ex((HMAC_CTX*)ctx->ptr, key, key_len, EVP_sha256(), NULL)) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }
    return status;
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
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        status = (1 == HMAC_Update((HMAC_CTX*)ctx->ptr, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Finish CMAC calculation and clear the HMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_finish(
    atcac_hmac_sha256_ctx* ctx,                 /**< [in] pointer to a sha256-hmac context */
    uint8_t*               digest,              /**< [out] hmac value */
    size_t *               digest_len           /**< [inout] length of hmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && digest_len)
    {
        unsigned int outlen = (unsigned int)*digest_len;
        status = (1 == HMAC_Final((HMAC_CTX*)ctx->ptr, digest, &outlen)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

        *digest_len = outlen;
        HMAC_CTX_free((HMAC_CTX*)ctx->ptr);
        ctx->ptr = NULL;
    }

    return status;
}

#endif /* ATCA_OPENSSL */
