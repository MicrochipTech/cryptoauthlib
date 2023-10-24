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
#include "crypto/atca_crypto_sw.h"

#ifdef ATCA_OPENSSL
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

typedef struct
{
    void* ptr;
} atca_evp_ctx;

/** \brief Return Random Bytes
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_random(uint8_t* data, size_t data_size)
{
    if (((size_t)INT_MAX) < data_size)
    {
        return ATCA_GEN_FAIL;
    }

    if (1 == RAND_bytes(data, (int)data_size))
    {
        return ATCA_SUCCESS;
    }
    else
    {
        return ATCA_GEN_FAIL;
    }
}

/** \brief Update the GCM context with additional authentication data (AAD)
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_aad_update(
    struct atcac_aes_gcm_ctx* ctx,    /**< [in] AES-GCM Context */
    const uint8_t*            aad,    /**< [in] Additional Authentication Data */
    const size_t              aad_len /**< [in] Length of AAD */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && ((size_t)INT_MAX > aad_len))
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
    struct atcac_aes_gcm_ctx* ctx,     /**< [in] AES-GCM Context */
    const uint8_t*            key,     /**< [in] AES Key */
    const uint8_t             key_len, /**< [in] Length of the AES key - should be 16 or 32*/
    const uint8_t*            iv,      /**< [in] Initialization vector input */
    const uint8_t             iv_len   /**< [in] Length of the initialization vector */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        int ret;
        ctx->ptr = EVP_CIPHER_CTX_new();

        /* Set cipher type and mode */
        if (16u == key_len)
        {
            ret = EVP_EncryptInit_ex((EVP_CIPHER_CTX*)ctx->ptr, EVP_aes_128_gcm(), NULL, NULL, NULL);
        }
        else if (32U == key_len)
        {
            ret = EVP_EncryptInit_ex((EVP_CIPHER_CTX*)ctx->ptr, EVP_aes_256_gcm(), NULL, NULL, NULL);
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
    struct atcac_aes_gcm_ctx* ctx,        /**< [in] AES-GCM Context */
    const uint8_t *           plaintext,  /**< [in] Input buffer to encrypt */
    const size_t              pt_len,     /**< [in] Length of the input */
    uint8_t *                 ciphertext, /**< [out] Output buffer */
    size_t *                  ct_len      /**< [inout] Length of the ciphertext buffer */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != ct_len) && ((size_t)INT_MAX > *ct_len) && ((size_t)INT_MAX > pt_len))
    {
        int outlen = (int)*ct_len;
        if (1 == EVP_EncryptUpdate((EVP_CIPHER_CTX*)ctx->ptr, ciphertext, &outlen, plaintext, (int)pt_len))
        {
            if (0 <= outlen)
            {
                *ct_len = (size_t)outlen;
                status = ATCA_SUCCESS;
            }
            else
            {
                status = ATCA_GEN_FAIL;
            }
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
    struct atcac_aes_gcm_ctx* ctx,    /**< [in] AES-GCM Context */
    uint8_t*                  tag,    /**< [out] GCM Tag Result */
    size_t                    tag_len /**< [in] Length of the GCM tag */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != tag) && ((size_t)INT_MAX > tag_len))
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
    struct atcac_aes_gcm_ctx* ctx,     /**< [in] AES-GCM Context */
    const uint8_t*            key,     /**< [in] AES Key */
    const uint8_t             key_len, /**< [in] Length of the AES key - should be 16 or 32*/
    const uint8_t*            iv,      /**< [in] Initialization vector input */
    const uint8_t             iv_len   /**< [in] Length of the initialization vector */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        int ret;
        ctx->ptr = EVP_CIPHER_CTX_new();

        /* Set cipher type and mode */
        if (16u == key_len)
        {
            ret = EVP_DecryptInit_ex((EVP_CIPHER_CTX*)ctx->ptr, EVP_aes_128_gcm(), NULL, NULL, NULL);
        }
        else if (32u == key_len)
        {
            ret = EVP_DecryptInit_ex((EVP_CIPHER_CTX*)ctx->ptr, EVP_aes_256_gcm(), NULL, NULL, NULL);
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
    struct atcac_aes_gcm_ctx* ctx,        /**< [in] AES-GCM Context */
    const uint8_t*            ciphertext, /**< [in] Ciphertext to decrypt */
    const size_t              ct_len,     /**< [in] Length of the ciphertext */
    uint8_t*                  plaintext,  /**< [out] Resulting decrypted plaintext */
    size_t*                   pt_len      /**< [inout] Length of the plaintext buffer */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != pt_len) && ((size_t)INT_MAX > *pt_len) && ((size_t)INT_MAX > ct_len))
    {
        int outlen = (int)*pt_len;
        if (1 == EVP_DecryptUpdate((EVP_CIPHER_CTX*)ctx->ptr, plaintext, &outlen, ciphertext, (int)ct_len))
        {
            if (0 <= outlen)
            {
                *pt_len = (size_t)outlen;
                status = ATCA_SUCCESS;
            }
            else
            {
                status = ATCA_GEN_FAIL;
            }
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
    struct atcac_aes_gcm_ctx* ctx,        /**< [in] AES-GCM Context */
    const uint8_t*            tag,        /**< [in] GCM Tag to Verify */
    size_t                    tag_len,    /**< [in] Length of the GCM tag */
    bool*                     is_verified /**< [out] Tag verified as matching */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != is_verified) && (NULL != tag) && ((size_t)INT_MAX > tag_len))
    {
        /* coverity[cert_exp40_c_violation] Correct usage of OpenSSL 1.1 API */
        /* coverity[cert_str30_c_violation:FALSE] tag is a byte buffer not a string */
        /* coverity[misra_c_2012_rule_11_8_violation] Correct usage of OpenSSL 1.1 API */
        int ret = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX*)ctx->ptr, EVP_CTRL_AEAD_SET_TAG, (int)tag_len, (void*)tag);

        if (1 == ret)
        {
            int outlen = 0;
            ret = EVP_DecryptFinal_ex((EVP_CIPHER_CTX*)ctx->ptr, NULL, &outlen);
        }

        /* Always try to free the context */
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)ctx->ptr);
        ctx->ptr = NULL;

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
static ATCA_STATUS atca_openssl_md_init(atca_evp_ctx* ctx, const EVP_MD* md_alg)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
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
static ATCA_STATUS atca_openssl_md_update(atca_evp_ctx* ctx, const uint8_t* data, size_t data_size)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        status = (1 == EVP_DigestUpdate((EVP_MD_CTX*)ctx->ptr, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief OpenSSL Message Digest Abstraction - Finish
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS atca_openssl_md_finish(atca_evp_ctx* ctx, uint8_t * digest, unsigned int * outlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx && NULL != ctx->ptr)
    {
        status = (1 == EVP_DigestFinal_ex((EVP_MD_CTX*)ctx->ptr, digest, outlen)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

        EVP_MD_CTX_free((EVP_MD_CTX*)ctx->ptr);
        ctx->ptr = NULL;
    }
    return status;
}

/** \brief Initialize context for performing SHA1 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha1_init(
    struct atcac_sha1_ctx* ctx         /**< [in] pointer to a hash context */
    )
{
    return atca_openssl_md_init((atca_evp_ctx*)ctx, EVP_sha1());
}

/** \brief Add data to a SHA1 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha1_update(
    struct atcac_sha1_ctx* ctx,      /**< [in] pointer to a hash context */
    const uint8_t*         data,     /**< [in] input data buffer */
    size_t                 data_size /**< [in] input data length */
    )
{
    return atca_openssl_md_update((atca_evp_ctx*)ctx, data, data_size);
}

/** \brief Complete the SHA1 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha1_finish(
    struct atcac_sha1_ctx* ctx,                          /**< [in] pointer to a hash context */
    uint8_t                digest[ATCA_SHA1_DIGEST_SIZE] /**< [out] output buffer (20 bytes) */
    )
{
    unsigned int outlen = ATCA_SHA1_DIGEST_SIZE;

    return atca_openssl_md_finish((atca_evp_ctx*)ctx, digest, &outlen);
}

/** \brief Initialize context for performing SHA256 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_init(
    struct atcac_sha2_256_ctx* ctx  /**< [in] pointer to a hash context */
    )
{
    return atca_openssl_md_init((atca_evp_ctx*)ctx, EVP_sha256());
}

/** \brief Add data to a SHA256 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_update(
    struct atcac_sha2_256_ctx* ctx,      /**< [in] pointer to a hash context */
    const uint8_t*             data,     /**< [in] input data buffer */
    size_t                     data_size /**< [in] input data length */
    )
{
    return atca_openssl_md_update((atca_evp_ctx*)ctx, data, data_size);
}

/** \brief Complete the SHA256 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_finish(
    struct atcac_sha2_256_ctx* ctx,                              /**< [in] pointer to a hash context */
    uint8_t                    digest[ATCA_SHA2_256_DIGEST_SIZE] /**< [out] output buffer (32 bytes) */
    )
{
    unsigned int outlen = ATCA_SHA2_256_DIGEST_SIZE;

    return atca_openssl_md_finish((atca_evp_ctx*)ctx, digest, &outlen);
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
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        int ret;
        ctx->ptr = CMAC_CTX_new();

        if (16u == key_len)
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
    struct atcac_aes_cmac_ctx* ctx,      /**< [in] pointer to a aes-cmac context */
    const uint8_t*             data,     /**< [in] input data */
    const size_t               data_size /**< [in] length of input data */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
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
    struct atcac_aes_cmac_ctx* ctx,      /**< [in] pointer to a aes-cmac context */
    uint8_t*                   cmac,     /**< [out] cmac value */
    size_t *                   cmac_size /**< [inout] length of cmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
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
    struct atcac_hmac_ctx*     ctx,         /**< [in] pointer to a sha256-hmac context */
    struct atcac_sha2_256_ctx* sha256_ctx,  /**< [in] pointer to a sha256 context */
    const uint8_t*             key,         /**< [in] key value to use */
    const uint8_t              key_len      /**< [in] length of the key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    (void)sha256_ctx;

    if (NULL != ctx)
    {
        ctx->ptr = HMAC_CTX_new();

        status = (1 == HMAC_Init_ex((HMAC_CTX*)ctx->ptr, key, (int)key_len, EVP_sha256(), NULL)) ? ATCA_SUCCESS : ATCA_GEN_FAIL;
    }
    return status;
}

/** \brief Update HMAC context with input data
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_update(
    struct atcac_hmac_ctx* ctx,         /**< [in] pointer to a sha256-hmac context */
    const uint8_t*         data,        /**< [in] input data */
    size_t                 data_size    /**< [in] length of input data */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
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
    struct atcac_hmac_ctx* ctx,                 /**< [in] pointer to a sha256-hmac context */
    uint8_t*               digest,              /**< [out] hmac value */
    size_t *               digest_len           /**< [inout] length of hmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx && NULL != digest_len)
    {
        unsigned int outlen = (unsigned int)(*digest_len & 0xffffffffu);
        status = (1 == HMAC_Final((HMAC_CTX*)ctx->ptr, digest, &outlen)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;

        *digest_len = outlen;
        HMAC_CTX_free((HMAC_CTX*)ctx->ptr);
        ctx->ptr = NULL;
    }

    return status;
}

/** \brief Set up a public/private key structure for use in asymmetric cryptographic functions
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_init(
    struct atcac_pk_ctx* ctx,                   /**< [in] pointer to a pk context */
    const uint8_t*       buf,                   /**< [in] buffer containing a pem encoded key */
    size_t               buflen,                /**< [in] length of the input buffer */
    uint8_t              key_type,
    bool                 pubkey                 /**< [in] buffer is a public key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    ((void)key_type);

    if ((NULL != ctx) && (NULL != buf) && ((size_t)INT_MAX > buflen))
    {
        ctx->ptr = EVP_PKEY_new();

        if (NULL != ctx->ptr)
        {
            int ret = EVP_PKEY_set_type((EVP_PKEY*)ctx->ptr, EVP_PKEY_EC);
            if (0 < ret)
            {
                EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                const EC_GROUP * ec_group = EC_KEY_get0_group(ec_key);
                EC_POINT* ec_point = EC_POINT_new(ec_group);

                if (pubkey)
                {
                    BIGNUM * x = BN_bin2bn(buf, 32, NULL);
                    BIGNUM * y = BN_bin2bn(&buf[32], 32, NULL);
                    ret = EC_POINT_set_affine_coordinates(ec_group, ec_point, x, y, NULL);
                    BN_free(y);
                    BN_free(x);
                }
                else
                {
                    /* Configure a private key */
                    BIGNUM* d = BN_bin2bn(buf, (int)buflen, NULL);
                    if (1 == (ret = EC_KEY_set_private_key(ec_key, d)))
                    {
                        /* Generate the public key */
                        ret = EC_POINT_mul(ec_group, ec_point, NULL, NULL, d, NULL);
                    }
                    BN_free(d);
                }

                if (1 == ret)
                {
                    ret = EC_KEY_set_public_key(ec_key, ec_point);
                }
                EC_POINT_free(ec_point);

                if (0 < ret)
                {
                    ret = EVP_PKEY_set1_EC_KEY((EVP_PKEY*)ctx->ptr, ec_key);
                }

                /* pkey context copies the key when it is attached */
                EC_KEY_free(ec_key);

                if (0 < ret)
                {
                    status = ATCA_SUCCESS;
                }
                else
                {
                    EVP_PKEY_free((EVP_PKEY*)ctx->ptr);
                    status = ATCA_GEN_FAIL;
                }
            }
        }
    }
    return status;
}


/** \brief Set up a public/private key structure for use in asymmetric cryptographic functions
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_init_pem(
    struct atcac_pk_ctx* ctx,                   /**< [in] pointer to a pk context */
    const uint8_t *      buf,                   /**< [in] buffer containing a pem encoded key */
    size_t               buflen,                /**< [in] length of the input buffer */
    bool                 pubkey                 /**< [in] buffer is a public key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        if (buflen <= (size_t)INT_MAX)
        {
            /* coverity[cert_exp40_c_violation] Correct usage of OpenSSL 1.1 API */
            /* coverity[misra_c_2012_rule_11_8_violation] Correct usage of OpenSSL 1.1 API */
            BIO* bio = BIO_new_mem_buf((void*)buf, (int)buflen);
            if (pubkey)
            {
                ctx->ptr = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
            }
            else
            {
                ctx->ptr = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
            }
        }

        status = ctx->ptr != NULL ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
            EVP_PKEY_free((EVP_PKEY*)ctx->ptr);
        }
        status = ATCA_SUCCESS;
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

    if (NULL != ctx && NULL != ctx->ptr && NULL != buf && NULL != buflen && *buflen >= 64u)
    {
        int ret = -1;
        if (EVP_PKEY_EC == EVP_PKEY_id((EVP_PKEY*)ctx->ptr))
        {
            const EC_KEY * ec_key = EVP_PKEY_get0_EC_KEY((EVP_PKEY*)ctx->ptr);
            if (NULL != ec_key)
            {
                BIGNUM * x = BN_new();
                BIGNUM * y = BN_new();

                if (1 == (ret = EC_POINT_get_affine_coordinates(EC_KEY_get0_group(ec_key), EC_KEY_get0_public_key(ec_key), x, y, NULL)))
                {
                    (void)BN_bn2bin(x, buf);
                    (void)BN_bn2bin(y, &buf[32]);
                    *buflen = 64u;
                }
                BN_free(x);
                BN_free(y);
            }
        }
        status = (ret > 0) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
    int ret = 0;

    if ((NULL != ctx) && (NULL != ctx->ptr) && (ATCA_SHA2_256_DIGEST_SIZE == dig_len))
    {
        if (EVP_PKEY_EC == EVP_PKEY_id((EVP_PKEY*)ctx->ptr))
        {
            /* coverity[cert_exp40_c_violation] Correct usage of OpenSSL 1.1 API */
            /* coverity[misra_c_2012_rule_11_8_violation] Correct usage of OpenSSL 1.1 API */
            ECDSA_SIG* ec_sig = ECDSA_do_sign(digest, (int)dig_len, (EC_KEY*)EVP_PKEY_get0_EC_KEY((EVP_PKEY*)ctx->ptr));

            if (NULL != ec_sig)
            {
                ret = BN_bn2bin(ECDSA_SIG_get0_r(ec_sig), signature);
                if (0 < ret)
                {
                    *sig_len = (size_t)ret;
                    ret = BN_bn2bin(ECDSA_SIG_get0_s(ec_sig), &signature[ret]);
                }
                if (0 < ret)
                {
                    *sig_len += (size_t)ret;
                }
                ECDSA_SIG_free(ec_sig);
            }
        }
        else
        {
            EVP_PKEY_CTX* sign_ctx = EVP_PKEY_CTX_new((EVP_PKEY*)ctx->ptr, NULL);

            if (NULL != sign_ctx)
            {
                ret = EVP_PKEY_sign_init(sign_ctx);

                if (0 < ret)
                {
                    ret = EVP_PKEY_CTX_set_rsa_padding(sign_ctx, RSA_PKCS1_PADDING);
                }

                if (0 < ret)
                {
                    ret = EVP_PKEY_CTX_set_signature_md(sign_ctx, EVP_sha256());
                }

                if (0 < ret)
                {
                    ret = EVP_PKEY_sign(sign_ctx, signature, sig_len, digest, dig_len);
                }

                EVP_PKEY_CTX_free(sign_ctx);
            }
        }
        status = (0 < ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
    int ret = 0;

    if ((NULL != ctx) && (NULL != ctx->ptr) && (ATCA_SHA2_256_DIGEST_SIZE == dig_len))
    {
        ret = -1;
        if (EVP_PKEY_EC == EVP_PKEY_id((EVP_PKEY*)ctx->ptr))
        {
            ECDSA_SIG* ec_sig = ECDSA_SIG_new();
            BIGNUM* r = BN_bin2bn(signature, 32, NULL);
            BIGNUM* s = BN_bin2bn(&signature[32], 32, NULL);

            (void)ECDSA_SIG_set0(ec_sig, r, s);

            /* coverity[cert_exp40_c_violation] Correct usage of OpenSSL 1.1 API */
            /* coverity[misra_c_2012_rule_11_8_violation] Correct usage of OpenSSL 1.1 API */
            ret = ECDSA_do_verify(digest, (int)dig_len, ec_sig, (EC_KEY*)EVP_PKEY_get0_EC_KEY((EVP_PKEY*)ctx->ptr));
            ECDSA_SIG_free(ec_sig);
        }
        else
        {

            EVP_PKEY_CTX* verify_ctx = EVP_PKEY_CTX_new((EVP_PKEY*)ctx->ptr, NULL);

            if (NULL != verify_ctx)
            {
                ret = EVP_PKEY_verify_init(verify_ctx);

                if (0 < ret)
                {
                    ret = EVP_PKEY_CTX_set_signature_md(verify_ctx, EVP_sha256());
                }

                if (0 < ret)
                {
                    if (EVP_PK_RSA == EVP_PKEY_id((EVP_PKEY*)ctx->ptr))
                    {
                        ret = EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PADDING);
                    }
                }

                if (0 < ret)
                {
                    ret = EVP_PKEY_verify(verify_ctx, signature, sig_len, digest, dig_len);
                }
                EVP_PKEY_CTX_free(verify_ctx);
            }
        }
        status = (0 < ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        int keytype = EVP_PKEY_id((EVP_PKEY*)private_ctx->ptr);

        if (keytype == EVP_PKEY_id((EVP_PKEY*)public_ctx->ptr))
        {
            int ret;
            switch (keytype)
            {
            case EVP_PKEY_EC:
            {
                const EC_POINT *pub_key = EC_KEY_get0_public_key(
                    EVP_PKEY_get0_EC_KEY((EVP_PKEY*)public_ctx->ptr));

                ret = ECDH_compute_key(buf, *buflen, pub_key,
                                       EVP_PKEY_get0_EC_KEY((EVP_PKEY*)private_ctx->ptr), NULL);
                break;
            }
            default:
                ret = -1;
                break;
            }
            status = (ret > 0) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
        }
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

#endif /* ATCA_OPENSSL */
