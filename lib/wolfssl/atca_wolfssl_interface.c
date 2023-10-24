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

#ifdef ATCA_WOLFSSL
#include "crypto/atca_crypto_sw.h"
#include "atca_wolfssl_internal.h"

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
    }
    else
    {
        status =  ATCA_GEN_FAIL;
    }
    return status;
}

/** \brief Initialize an AES-GCM context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_start(
    struct atcac_aes_gcm_ctx * ctx,     /**< [in] AES-GCM Context */
    const uint8_t *            key,     /**< [in] AES Key */
    const uint8_t              key_len, /**< [in] Length of the AES key - should be 16 or 32*/
    const uint8_t *            iv,      /**< [in] Initialization vector input */
    const uint8_t              iv_len   /**< [in] Length of the initialization vector */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        memset(ctx, 0, sizeof(atcac_aes_gcm_ctx_t));
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
    struct atcac_aes_gcm_ctx* ctx,
    const uint8_t*            plaintext,
    const size_t              pt_len,
    uint8_t*                  ciphertext,
    uint8_t*                  tag,
    size_t                    tag_len,
    const uint8_t*            aad,
    const size_t              aad_len
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
    struct atcac_aes_gcm_ctx* ctx,     /**< [in] AES-GCM Context */
    const uint8_t*            key,     /**< [in] AES Key */
    const uint8_t             key_len, /**< [in] Length of the AES key - should be 16 or 32*/
    const uint8_t*            iv,      /**< [in] Initialization vector input */
    const uint8_t             iv_len   /**< [in] Length of the initialization vector */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        memset(ctx, 0, sizeof(atcac_aes_gcm_ctx_t));
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
    struct atcac_aes_gcm_ctx* ctx,
    const uint8_t*            ciphertext,
    const size_t              ct_len,
    uint8_t*                  plaintext,
    const uint8_t*            tag,
    size_t                    tag_len,
    const uint8_t*            aad,
    const size_t              aad_len,
    bool*                     is_verified
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
    struct atcac_sha1_ctx* ctx         /**< [in] pointer to a hash context */
    )
{
    return (!wc_InitSha((wc_Sha*)ctx)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Add data to a SHA1 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha1_update(
    struct atcac_sha1_ctx* ctx,      /**< [in] pointer to a hash context */
    const uint8_t*         data,     /**< [in] input data buffer */
    size_t                 data_size /**< [in] input data length */
    )
{
    return (!wc_ShaUpdate((wc_Sha*)ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Complete the SHA1 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha1_finish(
    struct atcac_sha1_ctx* ctx,                          /**< [in] pointer to a hash context */
    uint8_t                digest[ATCA_SHA1_DIGEST_SIZE] /**< [out] output buffer (20 bytes) */
    )
{
    return (!wc_ShaFinal((wc_Sha*)ctx, digest)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Initialize context for performing SHA256 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha2_256_init(
    struct atcac_sha2_256_ctx* ctx  /**< [in] pointer to a hash context */
    )
{
    return (!wc_InitSha256((wc_Sha256*)ctx)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Add data to a SHA256 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha2_256_update(
    struct atcac_sha2_256_ctx* ctx,      /**< [in] pointer to a hash context */
    const uint8_t*             data,     /**< [in] input data buffer */
    size_t                     data_size /**< [in] input data length */
    )
{
    return (!wc_Sha256Update((wc_Sha256*)ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Complete the SHA256 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha2_256_finish(
    struct atcac_sha2_256_ctx* ctx,                              /**< [in] pointer to a hash context */
    uint8_t                    digest[ATCA_SHA2_256_DIGEST_SIZE] /**< [out] output buffer (32 bytes) */
    )
{
    return (!wc_Sha256Final((wc_Sha256*)ctx, digest)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Initialize context for performing CMAC in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_init(
    struct atcac_aes_cmac_ctx* ctx,    /**< [in] pointer to a aes-cmac context */
    const uint8_t*             key,    /**< [in] key value to use */
    const uint8_t              key_len /**< [in] length of the key */
    )
{
    return (!wc_InitCmac((Cmac*)ctx, key, key_len, WC_CMAC_AES, NULL)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Update CMAC context with input data
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_update(
    struct atcac_aes_cmac_ctx* ctx,      /**< [in] pointer to a aes-cmac context */
    const uint8_t*             data,     /**< [in] input data */
    const size_t               data_size /**< [in] length of input data */
    )
{
    return (!wc_CmacUpdate((Cmac*)ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Finish CMAC calculation and clear the CMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_finish(
    struct atcac_aes_cmac_ctx* ctx,      /**< [in] pointer to a aes-cmac context */
    uint8_t*                   cmac,     /**< [out] cmac value */
    size_t*                    cmac_size /**< [inout] length of cmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (cmac_size)
    {
        word32 out_len = *cmac_size;
        status = (!wc_CmacFinal((Cmac*)ctx, cmac, &out_len)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
        *cmac_size = out_len;
    }
    return status;
}

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
    int ret = wc_HmacInit((Hmac*)ctx, NULL, 0);

    (void)sha256_ctx;

    if (!ret)
    {
        ret = wc_HmacSetKey((Hmac*)ctx, SHA256, key, key_len);
    }

    return (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Update HMAC context with input data
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_update(
    struct atcac_hmac_ctx* ctx,                 /**< [in] pointer to a sha256-hmac context */
    const uint8_t*         data,                /**< [in] input data */
    size_t                 data_size            /**< [in] length of input data */
    )
{
    return (!wc_HmacUpdate((Hmac*)ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Finish HMAC calculation and clear the HMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_finish(
    struct atcac_hmac_ctx* ctx,                /**< [in] pointer to a sha256-hmac context */
    uint8_t*               digest,             /**< [out] hmac value */
    size_t*                digest_len          /**< [inout] length of hmac */
    )
{
    ((void)digest_len);

    int ret = wc_HmacFinal((Hmac*)ctx, digest);

    wc_HmacFree((Hmac*)ctx);

    return (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
}

/** \brief Set up a public/private key structure for use in asymmetric cryptographic functions
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_init(
    struct atcac_pk_ctx* ctx,                     /**< [in] pointer to a pk context */
    const uint8_t*       buf,                     /**< [in] buffer containing a pem encoded key */
    size_t               buflen,                  /**< [in] length of the input buffer */
    uint8_t              key_type,
    bool                 pubkey                   /**< [in] buffer is a public key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    ((void)buflen);

    if (ctx)
    {
        if (!key_type)
        {
            ctx->ptr = wc_ecc_key_new(NULL);

            if (ctx->ptr)
            {
                int ret = wc_ecc_set_curve((ecc_key*)ctx->ptr, 32, ECC_SECP256R1);

                if (!ret)
                {
                    if (pubkey)
                    {
                        /* Configure the public key */
                        ret = wc_ecc_import_unsigned((ecc_key*)ctx->ptr, (byte*)buf, (byte*)&buf[32], NULL, ECC_SECP256R1);
                    }
                    else
                    {
                        /* Configure a private key */
                        ret = wc_ecc_import_private_key((byte*)buf, 32, NULL, 0, (ecc_key*)ctx->ptr);
                    }

                    if (!ret)
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
    struct atcac_pk_ctx* ctx,                     /**< [in] pointer to a pk context */
    const uint8_t *      buf,                     /**< [in] buffer containing a pem encoded key */
    size_t               buflen,                  /**< [in] length of the input buffer */
    bool                 pubkey                   /**< [in] buffer is a public key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && buf)
    {
        int ret = -1;
        int ecckey = 0;
        int type = ECC_PRIVATEKEY_TYPE;
        word32 inOutIdx = 0;
        DerBuffer* der = NULL;
        status = ATCA_FUNC_FAIL;

        if (pubkey)
        {
            type = ECC_PUBLICKEY_TYPE;
        }

        ret = PemToDer((const unsigned char*)buf, (long)buflen, type, &der, NULL, NULL, &ecckey);

        if ((ret >= 0) && (der != NULL))
        {
            ctx->ptr = wc_ecc_key_new(NULL);

            if (ctx->ptr)
            {
                ret = wc_ecc_set_curve((ecc_key*)ctx->ptr, 32, ECC_SECP256R1);

                if (!ret)
                {
                    if (pubkey)
                    {
                        ret = wc_EccPublicKeyDecode(der->buffer, &inOutIdx, (ecc_key*)ctx->ptr, der->length);
                    }
                    else
                    {
                        ret = wc_EccPrivateKeyDecode(der->buffer, &inOutIdx, (ecc_key*)ctx->ptr, der->length);
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
    return status;
}

/** \brief Get the public key from the context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_public(
    struct atcac_pk_ctx* ctx,
    uint8_t*             buf,
    size_t*              buflen
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx && ctx->ptr && buf)
    {
        if (buflen)
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

    if (ctx)
    {
        if (ctx->ptr)
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
    struct atcac_pk_ctx* ctx,
    const uint8_t *      digest,
    size_t               dig_len,
    uint8_t*             signature,
    size_t*              sig_len
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != ctx->ptr) && (NULL != signature) && (NULL != digest) && (NULL != sig_len))
    {
        WC_RNG rng;
        int ret = wc_InitRng(&rng);

        if (0 == ret)
        {
            if ((0 == ctx->key_type) && (ATCA_SHA256_DIGEST_SIZE == dig_len))
            {
                uint8_t sig[72];
                word32 siglen = sizeof(sig);
                word32 rlen = 32;
                word32 slen = 32;

                memset(signature, 0, *sig_len);

                ret = wc_ecc_sign_hash((byte*)digest, (word32)dig_len, (byte*)sig, &siglen, &rng, (ecc_key*)ctx->ptr);

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
            wc_FreeRng(&rng);
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
    struct atcac_pk_ctx* ctx,
    const uint8_t*       digest,
    size_t               dig_len,
    const uint8_t*       signature,
    size_t               sig_len
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != ctx->ptr) && (NULL != signature) && (NULL != digest)
        && (ATCA_SHA256_DIGEST_SIZE == dig_len))
    {
        int ret = -1;
        int res = 0;
        if ((0 == ctx->key_type) && (ATCA_ECCP256_SIG_SIZE == sig_len))
        {
            uint8_t sig[72];
            word32 len = sizeof(sig);

            ret = wc_ecc_rs_raw_to_sig(signature, 32, &signature[32], 32, (byte*)sig, &len);

            if (!ret)
            {
                ret = wc_ecc_verify_hash((byte*)sig, len, (byte*)digest, (word32)dig_len, &res, (ecc_key*)ctx->ptr);
            }
        }
        else
        {
            // ret = wc_SignatureVerifyHash(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA, digest, 32, signature,
            //                              &sig_len, ctx->ptr, 64);
        }

        status = ATCA_FUNC_FAIL;
        if (!ret)
        {
            if (res)
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
    struct atcac_pk_ctx* private_ctx,
    struct atcac_pk_ctx* public_ctx,
    uint8_t*             buf,
    size_t*              buflen
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((private_ctx != NULL) && (public_ctx != NULL) && (buf != NULL) && (buflen != NULL))
    {
        int ret = -1;

        if (0 == private_ctx->key_type)
        {
            ret = wc_ecc_shared_secret((ecc_key*)private_ctx->ptr, (ecc_key*)public_ctx->ptr, (byte*)buf, (word32*)buflen);
        }
        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }

    return status;
}

#if defined(ATCA_BUILD_SHARED_LIBS) || !defined(ATCA_NO_HEAP)
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
