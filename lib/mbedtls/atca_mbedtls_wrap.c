/**
 * \file
 * \brief Wrapper functions to replace cryptoauthlib software crypto functions
 *        with the mbedTLS equivalent
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

/* mbedTLS boilerplate includes */
#include "atca_config_check.h"

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "CERT EXP40-C" "The third party mbedtls api converts const to non constant which is out of scope of CAL") \
    (deviate "MISRA C-2012 Rule 11.8" "Third party library (mbedtls) implementation which require const to non constant")\
    (deviate "MISRA C-2012 Rule 11.3" "Third party library (mbedtls) implementation requires pointer type casting")
#endif

#ifdef ATCA_MBEDTLS

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#define mbedtls_calloc    calloc
#define mbedtls_free       free
#endif

#include "mbedtls/cmac.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/oid.h"


/* Cryptoauthlib Includes */
#include "cryptoauthlib.h"
#include "atca_mbedtls_wrap.h"
#include "atca_mbedtls_patch.h"

#include "crypto/atca_crypto_sw.h"
#if ATCA_CA_SUPPORT
#include "atcacert/atcacert_client.h"
#include "atcacert/atcacert_def.h"
#endif

#ifdef ATCA_HEAP
struct atcac_sha1_ctx* atcac_sha1_ctx_new(void)
{
    return (struct atcac_sha1_ctx*)hal_malloc(sizeof(atcac_sha1_ctx_t));
}

#if ATCAC_SHA256_EN
struct atcac_sha2_256_ctx* atcac_sha256_ctx_new(void)
{
    return (struct atcac_sha2_256_ctx*)hal_malloc(sizeof(atcac_sha2_256_ctx_t));
}
#endif

#if ATCAC_SHA384_EN
struct atcac_sha2_384_ctx* atcac_sha384_ctx_new(void)
{
    return (struct atcac_sha2_384_ctx*)hal_malloc(sizeof(atcac_sha2_384_ctx_t));
}
#endif

#if ATCAC_SHA512_EN
struct atcac_sha2_512_ctx* atcac_sha512_ctx_new(void)
{
    return (struct atcac_sha2_512_ctx*)hal_malloc(sizeof(atcac_sha2_512_ctx_t));
}
#endif

struct atcac_hmac_ctx* atcac_hmac_ctx_new(void)
{
    return (struct atcac_hmac_ctx*)hal_malloc(sizeof(atcac_hmac_ctx_t));
}

struct atcac_aes_gcm_ctx* atcac_aes_gcm_ctx_new(void)
{
    return (struct atcac_aes_gcm_ctx*)hal_malloc(sizeof(atcac_aes_gcm_ctx_t));
}

struct atcac_aes_cmac_ctx* atcac_aes_cmac_ctx_new(void)
{
    return (struct atcac_aes_cmac_ctx*)hal_malloc(sizeof(atcac_aes_cmac_ctx_t));
}

struct atcac_pk_ctx* atcac_pk_ctx_new(void)
{
    return (struct atcac_pk_ctx*)hal_malloc(sizeof(atcac_pk_ctx_t));
}

struct mbedtls_x509_crt* atcac_mbedtls_new(void)
{
    return (struct mbedtls_x509_crt*)hal_malloc(sizeof(mbedtls_x509_crt));
}

struct atcac_x509_ctx* atcac_x509_ctx_new(void)
{
    return (struct atcac_x509_ctx*)hal_malloc(sizeof(atcac_x509_ctx_t));
}

void atcac_sha1_ctx_free(struct atcac_sha1_ctx* ctx)
{
    hal_free(ctx);
}

#if ATCAC_SHA256_EN
void atcac_sha256_ctx_free(struct atcac_sha2_256_ctx* ctx)
{
    hal_free(ctx);
}
#endif

#if ATCAC_SHA384_EN
void atcac_sha384_ctx_free(struct atcac_sha2_384_ctx* ctx)
{
    hal_free(ctx);
}
#endif

#if ATCAC_SHA512_EN
void atcac_sha512_ctx_free(struct atcac_sha2_512_ctx* ctx)
{
    hal_free(ctx);
}
#endif

void atcac_hmac_ctx_free(struct atcac_hmac_ctx* ctx)
{
    hal_free(ctx);
}

void atcac_aes_gcm_ctx_free(struct atcac_aes_gcm_ctx* ctx)
{
    hal_free(ctx);
}

void atcac_aes_cmac_ctx_free(struct atcac_aes_cmac_ctx* ctx)
{
    hal_free(ctx);
}

void atcac_pk_ctx_free(struct atcac_pk_ctx* ctx)
{
    hal_free(ctx);
}

void atcac_x509_ctx_free(struct atcac_x509_ctx* ctx)
{
    hal_free(ctx);
}

#endif

static int mbedtls_x509_time_to_asn1_generalized_time(const mbedtls_x509_time* x509_time, char* asn1_time, size_t asn1_time_len);

/** \brief Return Random Bytes
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_random(uint8_t* data, size_t data_size)
{
    return (0 == mbedtls_ctr_drbg_random(mbedtls_entropy_func, data, data_size) ? ATCA_SUCCESS : ATCA_FUNC_FAIL);
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

    if (NULL != ctx)
    {
        void* tmp_ptr = ctx;
        int ret = mbedtls_cipher_update_ad((mbedtls_cipher_context_t*)tmp_ptr, aad, aad_len);
        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        void* tmp_ptr = ctx;
        mbedtls_cipher_init((mbedtls_cipher_context_t*)tmp_ptr);

        ret = mbedtls_cipher_setup((mbedtls_cipher_context_t*)tmp_ptr, mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, (int)(key_len) * 8, MBEDTLS_MODE_GCM));

        if (0 == ret)
        {
            ret = mbedtls_cipher_setkey((mbedtls_cipher_context_t*)tmp_ptr, key, (int)key_len * 8, MBEDTLS_ENCRYPT);
        }

        if (0 == ret)
        {
            ret = mbedtls_cipher_set_iv((mbedtls_cipher_context_t*)tmp_ptr, iv, iv_len);
        }

        if (0 == ret)
        {
            ret = mbedtls_cipher_reset((mbedtls_cipher_context_t*)tmp_ptr);
        }

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }

    return status;
}

/** \brief Encrypt a data using the initialized context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_update(
    struct atcac_aes_gcm_ctx* ctx,        /**< [in] AES-GCM Context */
    const uint8_t*            plaintext,  /**< [in] Input buffer to encrypt */
    const size_t              pt_len,     /**< [in] Length of the input */
    uint8_t*                  ciphertext, /**< [out] Output buffer */
    size_t*                   ct_len      /**< [inout] Length of the ciphertext buffer */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        void* tmp_ptr = ctx;
        int ret = mbedtls_cipher_update((mbedtls_cipher_context_t*)tmp_ptr, plaintext, pt_len, ciphertext, ct_len);
        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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

    if (NULL != ctx)
    {
        void* tmp_ptr = ctx;
        int ret = mbedtls_cipher_write_tag((mbedtls_cipher_context_t*)tmp_ptr, tag, tag_len);

        mbedtls_cipher_free((mbedtls_cipher_context_t*)ctx);

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        void* tmp_ptr = ctx;
        mbedtls_cipher_init((mbedtls_cipher_context_t*)tmp_ptr);

        ret = mbedtls_cipher_setup((mbedtls_cipher_context_t*)tmp_ptr, mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, (int)(key_len) * 8, MBEDTLS_MODE_GCM));

        if (0 == ret)
        {
            ret = mbedtls_cipher_setkey((mbedtls_cipher_context_t*)tmp_ptr, key, (int)key_len * 8, MBEDTLS_DECRYPT);
        }

        if (0 == ret)
        {
            ret = mbedtls_cipher_set_iv((mbedtls_cipher_context_t*)tmp_ptr, iv, iv_len);
        }

        if (0 == ret)
        {
            ret = mbedtls_cipher_reset((mbedtls_cipher_context_t*)tmp_ptr);
        }

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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

    if (NULL != ctx)
    {
        void* tmp_ptr = ctx;
        int ret = mbedtls_cipher_update((mbedtls_cipher_context_t*)tmp_ptr, ciphertext, ct_len, plaintext, pt_len);
        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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

    if ((NULL != ctx) && (NULL != is_verified))
    {
        int ret;
        *is_verified = false;
        void* tmp_ptr = ctx;
        ret = mbedtls_cipher_check_tag((mbedtls_cipher_context_t*)tmp_ptr, tag, tag_len);

        if (0 == ret)
        {
            *is_verified = true;
        }

        mbedtls_cipher_free((mbedtls_cipher_context_t*)ctx);

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief MBedTLS Message Digest Abstraction - Init
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS atca_mbedtls_md_init(mbedtls_md_context_t* ctx, const mbedtls_md_info_t* md_info)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        int ret;
        mbedtls_md_init(ctx);

        ret = mbedtls_md_setup(ctx, md_info, 0);

        if (0 == ret)
        {
            ret = mbedtls_md_starts(ctx);
        }

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief MbedTLS Message Digest Abstraction - Update
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS atca_mbedtls_md_update(mbedtls_md_context_t* ctx, const uint8_t* data, size_t data_size)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        status = (0 == mbedtls_md_update(ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief MbedTLS Message Digest Abstraction - Finish
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS atca_mbedtls_md_finish(mbedtls_md_context_t* ctx, uint8_t* digest, unsigned int* outlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    (void)outlen;

    if (NULL != ctx)
    {
        int ret = mbedtls_md_finish(ctx, digest);

        mbedtls_md_free(ctx);

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_init((mbedtls_md_context_t*)tmp_ptr, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1));
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
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_update((mbedtls_md_context_t*)tmp_ptr, data, data_size);
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
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_finish((mbedtls_md_context_t*)tmp_ptr, digest, NULL);
}

#if ATCAC_SHA256_EN
/** \brief Initialize context for performing SHA256 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_init(
    struct atcac_sha2_256_ctx* ctx  /**< [in] pointer to a hash context */
    )
{
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_init((mbedtls_md_context_t*)tmp_ptr, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256));
}

/** \brief Add data to a SHA256 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_256_update(
    struct atcac_sha2_256_ctx* ctx,         /**< [in] pointer to a hash context */
    const uint8_t*             data,        /**< [in] input data buffer */
    size_t                     data_size    /**< [in] input data length */
    )
{
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_update((mbedtls_md_context_t*)tmp_ptr, data, data_size);
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
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_finish((mbedtls_md_context_t*)tmp_ptr, digest, NULL);
}
#endif /* ATCAC_SHA256_EN */

#if ATCAC_SHA384_EN
/** \brief Initialize context for performing SHA384 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_384_init(
    struct atcac_sha2_384_ctx* ctx  /**< [in] pointer to a hash context */
    )
{
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_init((mbedtls_md_context_t*)tmp_ptr, mbedtls_md_info_from_type(MBEDTLS_MD_SHA384));
}

/** \brief Add data to a SHA384 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_384_update(
    struct atcac_sha2_384_ctx* ctx,         /**< [in] pointer to a hash context */
    const uint8_t*             data,        /**< [in] input data buffer */
    size_t                     data_size    /**< [in] input data length */
    )
{
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_update((mbedtls_md_context_t*)tmp_ptr, data, data_size);
}

/** \brief Complete the SHA384 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_384_finish(
    struct atcac_sha2_384_ctx* ctx,                              /**< [in] pointer to a hash context */
    uint8_t                    digest[ATCA_SHA2_384_DIGEST_SIZE] /**< [out] output buffer (48 bytes) */
    )
{
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_finish((mbedtls_md_context_t*)tmp_ptr, digest, NULL);
}
#endif /* ATCAC_SHA384_EN */

#if ATCAC_SHA512_EN
/** \brief Initialize context for performing SHA512 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_512_init(
    struct atcac_sha2_512_ctx* ctx  /**< [in] pointer to a hash context */
    )
{
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_init((mbedtls_md_context_t*)tmp_ptr, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512));
}

/** \brief Add data to a SHA512 hash.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_512_update(
    struct atcac_sha2_512_ctx* ctx,         /**< [in] pointer to a hash context */
    const uint8_t*             data,        /**< [in] input data buffer */
    size_t                     data_size    /**< [in] input data length */
    )
{
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_update((mbedtls_md_context_t*)tmp_ptr, data, data_size);
}

/** \brief Complete the SHA512 hash in software and return the digest.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sw_sha2_512_finish(
    struct atcac_sha2_512_ctx* ctx,                              /**< [in] pointer to a hash context */
    uint8_t                    digest[ATCA_SHA2_512_DIGEST_SIZE] /**< [out] output buffer (64 bytes) */
    )
{
    void* tmp_ptr = ctx;

    return atca_mbedtls_md_finish((mbedtls_md_context_t*)tmp_ptr, digest, NULL);
}
#endif /* ATCAC_SHA512_EN*/

/** \brief Initialize context for performing CMAC in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_init(
    struct atcac_aes_cmac_ctx* ctx,             /**< [in] pointer to a aes-cmac context */
    const uint8_t*             key,             /**< [in] key value to use */
    const uint8_t              key_len          /**< [in] length of the key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        int ret = 0;
        void* tmp_ptr = ctx;
        mbedtls_cipher_init((mbedtls_cipher_context_t*)tmp_ptr);

        ret = mbedtls_cipher_setup((mbedtls_cipher_context_t*)tmp_ptr, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB));

        if (0 == ret)
        {
            ret = mbedtls_cipher_cmac_starts((mbedtls_cipher_context_t*)tmp_ptr, key, (size_t)key_len * 8u);
        }

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }

    return status;
}

/** \brief Update CMAC context with input data
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_update(
    struct atcac_aes_cmac_ctx* ctx,         /**< [in] pointer to a aes-cmac context */
    const uint8_t*             data,        /**< [in] input data */
    const size_t               data_size    /**< [in] length of input data */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        void* tmp_ptr = ctx;
        status = (0 == mbedtls_cipher_cmac_update((mbedtls_cipher_context_t*)tmp_ptr, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
    size_t*                    cmac_size /**< [inout] length of cmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    (void)cmac_size;

    if (NULL != ctx)
    {
        void* tmp_ptr = ctx;
        int ret = mbedtls_cipher_cmac_finish((mbedtls_cipher_context_t*)tmp_ptr, cmac);

        mbedtls_cipher_free((mbedtls_cipher_context_t*)ctx);

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Initialize context for performing HMAC (sha256) in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_init(
    struct atcac_hmac_ctx*     ctx,        /**< [in] pointer to a sha256-hmac context */
    struct atcac_sha2_256_ctx* sha256_ctx, /**< [in] pointer to a sha256 context */
    const uint8_t*             key,        /**< [in] key value to use */
    const uint8_t              key_len     /**< [in] length of the key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != ctx) && (NULL != sha256_ctx))
    {
        int ret;
        void* tmp_ptr = sha256_ctx;
        ctx->mctx = (mbedtls_md_context_t*)tmp_ptr;

        mbedtls_md_init(ctx->mctx);

        ret = mbedtls_md_setup(ctx->mctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

        if (0 == ret)
        {
            ret = mbedtls_md_hmac_starts(ctx->mctx, key, key_len);
        }

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        status = (0 == mbedtls_md_hmac_update(ctx->mctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Finish CMAC calculation and clear the HMAC context
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

    (void)digest_len;

    if (NULL != ctx)
    {
        int ret = mbedtls_md_hmac_finish(ctx->mctx, digest);

        mbedtls_md_free(ctx->mctx);

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Set up a public/private key structure for use in asymmetric cryptographic functions
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_init(
    struct atcac_pk_ctx* ctx,               /**< [in] pointer to a pk context */
    const uint8_t*       buf,               /**< [in] buffer containing a pem encoded key */
    size_t               buflen,            /**< [in] length of the input buffer */
    uint8_t              key_type,
    bool                 pubkey             /**< [in] buffer is a public key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    (void)key_type;

    if (NULL != ctx)
    {
        int ret;
        uint8_t temp = 1;
        mbedtls_ecp_keypair* ecp = NULL;

        void* tmp_ptr = ctx;
        mbedtls_pk_init((mbedtls_pk_context*)tmp_ptr);
        ret = mbedtls_pk_setup((mbedtls_pk_context*)tmp_ptr, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

        if (0 == ret)
        {
            ecp = mbedtls_pk_ec(ctx->mctx);
            ret = mbedtls_ecp_group_load(&ecp->grp, MBEDTLS_ECP_DP_SECP256R1);
        }

        if (pubkey)
        {
            if (0 == ret)
            {
                ret = mbedtls_mpi_read_binary(&(ecp->Q.X), buf, buflen / 2u);
            }

            if (0 == ret)
            {
                ret = mbedtls_mpi_read_binary(&(ecp->Q.Y), &buf[buflen / 2u], buflen / 2u);
            }

            if (0 == ret)
            {
                ret = mbedtls_mpi_read_binary(&(ecp->Q.Z), &temp, 1);
            }
        }
        else
        {
            if (0 == ret)
            {
                ret = mbedtls_mpi_read_binary(&(ecp->d), buf, buflen);
            }
        }

        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Set up a public/private key structure for use in asymmetric cryptographic functions
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_init_pem(
    struct atcac_pk_ctx* ctx,               /**< [in] pointer to a pk context */
    const uint8_t*       buf,               /**< [in] buffer containing a pem encoded key */
    size_t               buflen,            /**< [in] length of the input buffer */
    bool                 pubkey             /**< [in] buffer is a public key */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        int ret;
        void* tmp_ptr = ctx;
        mbedtls_pk_init((mbedtls_pk_context*)tmp_ptr);

        if (pubkey)
        {
            ret = mbedtls_pk_parse_public_key((mbedtls_pk_context*)ctx, buf, buflen);
        }
        else
        {
            ret = mbedtls_pk_parse_key((mbedtls_pk_context*)ctx, buf, buflen, NULL, 0);
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
    struct atcac_pk_ctx* ctx /**< [in] pointer to a pk context */
    )
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if (NULL != ctx)
    {
        void* tmp_ptr = ctx;
        mbedtls_pk_free((mbedtls_pk_context*)tmp_ptr);
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

    if (NULL != ctx)
    {
        int ret = -1;
        void* tmp_ptr = ctx;
        switch (mbedtls_pk_get_type((mbedtls_pk_context*)tmp_ptr))
        {
        case MBEDTLS_PK_ECKEY:
        /* fallthrough */
        case MBEDTLS_PK_ECDSA:
        {
            (void)mbedtls_mpi_write_binary(&mbedtls_pk_ec(ctx->mctx)->Q.X, buf, 32);
            ret = mbedtls_mpi_write_binary(&mbedtls_pk_ec(ctx->mctx)->Q.Y, &buf[32], 32);
            *buflen = 64;
            break;
        }
        default:
            /* Empty default case to satisfy MISRA */
            break;
        }
        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Perform a signature with the private key in the context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_pk_sign(
    struct atcac_pk_ctx* ctx,
    const uint8_t*       digest,
    size_t               dig_len,
    uint8_t*             signature,
    size_t*              sig_len
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != ctx)
    {
        int ret = -1;
        switch (mbedtls_pk_get_type((mbedtls_pk_context*)ctx))
        {
        case MBEDTLS_PK_ECKEY:
        /* fallthrough */
        case MBEDTLS_PK_ECDSA:
        {
            mbedtls_mpi r;
            mbedtls_mpi s;

            mbedtls_mpi_init(&r);
            mbedtls_mpi_init(&s);

            //ret = mbedtls_ecdsa_sign(&mbedtls_pk_ec(*ctx)->grp, &r, &s, &mbedtls_pk_ec(*ctx)->d, digest, dig_len, NULL, NULL);
            ret = mbedtls_ecdsa_sign_det(&mbedtls_pk_ec(ctx->mctx)->grp, &r, &s,
                                         &mbedtls_pk_ec(ctx->mctx)->d, digest, dig_len, MBEDTLS_MD_SHA256);

            if (0 == ret)
            {
                ret = mbedtls_mpi_write_binary(&r, signature, 32);
            }

            if (0 == ret)
            {
                ret = mbedtls_mpi_write_binary(&s, &signature[32], 32);
            }

            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);

            *sig_len = 64;
            break;
        }
        case MBEDTLS_PK_RSA:
            ret = mbedtls_pk_sign((mbedtls_pk_context*)ctx, MBEDTLS_MD_SHA256, digest, dig_len, signature, sig_len, NULL, NULL);
            break;
        default:
            /* Empty default case to satisfy MISRA */
            break;
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

    if (NULL != ctx)
    {
        int ret = -1;
        void* tmp_ptr = ctx;
        switch (mbedtls_pk_get_type((mbedtls_pk_context*)tmp_ptr))
        {
        case MBEDTLS_PK_ECKEY:
        /* fallthrough */
        case MBEDTLS_PK_ECDSA:
        {
            mbedtls_mpi r;
            mbedtls_mpi s;

            mbedtls_mpi_init(&r);
            mbedtls_mpi_init(&s);

            (void)mbedtls_mpi_read_binary(&r, signature, sig_len / 2u);
            (void)mbedtls_mpi_read_binary(&s, &signature[sig_len / 2u], sig_len / 2u);

            ret = mbedtls_ecdsa_verify(&mbedtls_pk_ec(ctx->mctx)->grp, digest, dig_len, &mbedtls_pk_ec(ctx->mctx)->Q, &r, &s);

            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }
        case MBEDTLS_PK_RSA:
            ret = mbedtls_pk_verify((mbedtls_pk_context*)ctx, MBEDTLS_MD_SHA256, digest, dig_len, signature, sig_len);
            break;
        default:
            /* Empty default case to satisfy MISRA */
            break;
        }
        status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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

    if ((NULL != private_ctx) && (NULL != public_ctx))
    {
        void* tmp_ptr = private_ctx;
        mbedtls_pk_type_t keytype = mbedtls_pk_get_type((mbedtls_pk_context*)tmp_ptr);

        if (mbedtls_pk_get_type((mbedtls_pk_context*)public_ctx) == keytype)
        {
            int ret = -1;
            switch (keytype)
            {
            case MBEDTLS_PK_ECKEY:
            /* fallthrough */
            case MBEDTLS_PK_ECDSA:
            {
                mbedtls_mpi result;

                mbedtls_mpi_init(&result);

                ret = mbedtls_ecdh_compute_shared(&mbedtls_pk_ec(private_ctx->mctx)->grp, &result,
                                                  &mbedtls_pk_ec(public_ctx->mctx)->Q,
                                                  &mbedtls_pk_ec(private_ctx->mctx)->d, NULL, NULL);

                (void)mbedtls_mpi_write_binary(&result, buf, *buflen);
                mbedtls_mpi_free(&result);
                break;
            }
            default:
                /* Empty default case to satisfy MISRA */
                break;
            }
            status = (0 == ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
        }
    }
    return status;
}


#ifndef MBEDTLS_ECDSA_SIGN_ALT
#include "mbedtls/pk_internal.h"
#include "atcacert/atcacert_der.h"

static size_t atca_mbedtls_eckey_get_bitlen(const void * ctx)
{
    return mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)->get_bitlen(ctx);
}

static int atca_mbedtls_eckey_can_do(mbedtls_pk_type_t type)
{
    return mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)->can_do(type);
}

static int atca_mbedtls_eckey_verify(void *ctx, mbedtls_md_type_t md_alg,
                                     const unsigned char *hash, size_t hash_len,
                                     const unsigned char *sig, size_t sig_len)
{
#if defined(MBEDTLS_ECDSA_VERIFY_ALT) || !(CALIB_VERIFY_EXTERN_EN || TALIB_VERIFY_EXTERN_EN)
    return mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)->verify_func(ctx, md_alg, hash, hash_len, sig, sig_len);
#else
    int ret = -1;
    mbedtls_ecp_keypair *ecp = (mbedtls_ecp_keypair*)ctx;

    (void)md_alg;
    (void)hash_len;

    if ((NULL != ecp) && (NULL != hash) && (NULL != sig))
    {
        mbedtls_mpi r, s;
        atca_mbedtls_eckey_t key_info;
        uint8_t signature[ATCA_ECCP256_SIG_SIZE] = { 0x00 };
        (void)memset(&key_info, 0, sizeof(atca_mbedtls_eckey_t));

        /* Signature is in ASN.1 format so we have to parse it out manually */
        size_t len = 0;
        unsigned char tmp[74] = { 0x00 };
        (void)memcpy(tmp, sig, 74);
        unsigned char* tmp1 = (unsigned char*)tmp;
        const unsigned char *end = tmp1 + sig_len;

        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        ret = mbedtls_mpi_write_binary(&ecp->d, (unsigned char*)&key_info, sizeof(atca_mbedtls_eckey_t));

        if (0 == ret)
        {
            ret = mbedtls_asn1_get_tag(&tmp1, end, &len, (int)((unsigned int)MBEDTLS_ASN1_CONSTRUCTED | (unsigned int)MBEDTLS_ASN1_SEQUENCE));

            if (tmp1 + len != end)
            {
                /* Some sort of parsing error */
                ret = -1;
            }
        }

        if (0 == ret)
        {
            ret = mbedtls_asn1_get_mpi(&tmp1, end, &r);
        }

        if (0 == ret)
        {
            ret = mbedtls_asn1_get_mpi(&tmp1, end, &s);
        }

        if (0 == ret)
        {
            ret = mbedtls_mpi_write_binary(&r, signature, 32);
        }

        if (0 == ret)
        {
            ret = mbedtls_mpi_write_binary(&s, &signature[32], 32);
        }

        if (0 == ret)
        {
            bool is_verified = false;

            //           if (0x01 & key_info.flags)
            {
                uint8_t public_key[ATCA_ECCP256_PUBKEY_SIZE] = { 0x00 };
                if (0 == (ret = mbedtls_mpi_write_binary(&ecp->Q.X, public_key, ATCA_ECCP256_PUBKEY_SIZE / 2u)))
                {
                    if (0 == (ret = mbedtls_mpi_write_binary(&ecp->Q.Y, &public_key[ATCA_ECCP256_PUBKEY_SIZE / 2u], ATCA_ECCP256_PUBKEY_SIZE / 2u)))
                    {
                        ret = atcab_verify_extern_ext(key_info.device, hash, signature, public_key, &is_verified);
                    }
                }
            }
//            else
//            {
//                ret = atcab_verify_stored_ext(key_info.device, hash, signature, key_info.handle, &is_verified);
//            }

            if (ATCA_SUCCESS == ret)
            {
                ret = is_verified ? 0 : -1;
            }
        }

        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
    }

    return ret;
#endif
}

static int atca_mbedtls_eckey_sign(void *ctx, mbedtls_md_type_t md_alg,
                                   const unsigned char *hash, size_t hash_len,
                                   unsigned char *sig, size_t *sig_len,
                                   int (*f_rng)(void *d1, unsigned char *d2, size_t d3),
                                   void *p_rng)
{
    int ret = -1;
    mbedtls_ecp_keypair *ecp = (mbedtls_ecp_keypair*)ctx;

    ((void)md_alg);
    ((void)f_rng);
    ((void)p_rng);

    if ((NULL != ecp) && (NULL != hash) && (NULL != sig) && (NULL != sig_len))
    {
        mbedtls_mpi r, s;

        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        ret = atca_mbedtls_ecdsa_sign(&ecp->d, &r, &s, hash, hash_len);

        if (0 == ret)
        {
            ret = mbedtls_ecdsa_signature_to_asn1(&r, &s, sig, sig_len);
        }

        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
    }
    return ret;
}

static int atca_mbedtls_eckey_check_pair(const void *pub, const void *prv)
{
    return mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)->check_pair_func(pub, prv);
}

static void * atca_mbedtls_eckey_alloc(void)
{
    return mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)->ctx_alloc_func();
}

static void atca_mbedtls_eckey_free(void * ctx)
{
    mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)->ctx_free_func(ctx);
}

static void atca_mbedtls_eckey_debug(const void *ctx, mbedtls_pk_debug_item *items)
{
    mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)->debug_func(ctx, items);
}

const mbedtls_pk_info_t atca_mbedtls_eckey_info = {
    MBEDTLS_PK_ECKEY,
    "EC",
    atca_mbedtls_eckey_get_bitlen,
    atca_mbedtls_eckey_can_do,
    atca_mbedtls_eckey_verify,
    atca_mbedtls_eckey_sign,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* Required to maintain structure alignment */
    NULL,
    NULL,
#endif
    NULL,
    NULL,
    atca_mbedtls_eckey_check_pair,
    atca_mbedtls_eckey_alloc,
    atca_mbedtls_eckey_free,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    /* Required to maintain structure alignment */
    NULL,
    NULL,
#endif
    atca_mbedtls_eckey_debug,
};

#endif


/** \brief Initializes an mbedtls pk context for use with EC operations
 * \param[in,out] pkey ptr to space to receive version string
 * \param[in] slotid Associated with this key
 * \return 0 on success, otherwise an error code.
 */
int atca_mbedtls_pk_init_ext(ATCADevice device, mbedtls_pk_context * pkey, const uint16_t slotid)
{
    int ret = 0;
    uint8_t public_key[ATCA_ECCP256_SIG_SIZE];
    mbedtls_ecp_keypair * ecp = NULL;
    uint8_t temp = 1;
    bool is_private = false;

    if (NULL == pkey)
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (0 == ret)
    {
        mbedtls_pk_init(pkey);
#ifdef MBEDTLS_ECDSA_SIGN_ALT
        ret = mbedtls_pk_setup(pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
#else
        ret = mbedtls_pk_setup(pkey, &atca_mbedtls_eckey_info);
#endif
    }


    if (0 == ret)
    {
        ecp = mbedtls_pk_ec(*pkey);
        if (NULL != ecp)
        {
            ret = mbedtls_ecp_group_load(&ecp->grp, MBEDTLS_ECP_DP_SECP256R1);
        }
    }

    if (0 == ret)
    {
        ret = atcab_is_private_ext(device, slotid, &is_private);
    }

    if (0 == ret)
    {
        if (is_private)
        {
            ret = atcab_get_pubkey_ext(device, slotid, public_key);
        }
        else
        {
            ret = atcab_read_pubkey_ext(device, slotid, public_key);
        }
    }

    if (NULL != ecp)
    {
        if (0 == ret)
        {
            ret = mbedtls_mpi_read_binary(&(ecp->Q.X), public_key, ATCA_ECCP256_SIG_SIZE / 2u);
        }

        if (0 == ret)
        {
            ret = mbedtls_mpi_read_binary(&(ecp->Q.Y), &public_key[ATCA_ECCP256_SIG_SIZE / 2u], ATCA_ECCP256_SIG_SIZE / 2u);
        }

        if (0 == ret)
        {
            atca_mbedtls_eckey_t key_info = { device, slotid };

            /* This is a bit of a hack to force a context into the mbedtls keypair structure but it should
               work on any platform as it is in essence directly copying memory exactly as it appears in the
               structure */

#ifndef MBEDTLS_ECDSA_VERIFY_ALT
            if (0 == (ret = mbedtls_mpi_read_binary(&(ecp->Q.Z), &temp, 1)))
            {
                ret = mbedtls_mpi_read_binary(&ecp->d, (const unsigned char*)&key_info, sizeof(atca_mbedtls_eckey_t));
            }
#else
            if (is_private)
            {
                if (0 == (ret = mbedtls_mpi_read_binary(&(ecp->Q.Z), &temp, 1)))
                {
                    ret = mbedtls_mpi_read_binary(&ecp->d, (const unsigned char*)&key_info, sizeof(atca_mbedtls_eckey_t));
                }
            }
            else
            {
                ret = mbedtls_mpi_read_binary(&ecp->Q.Z, (const unsigned char*)&key_info, sizeof(atca_mbedtls_eckey_t));
            }
#endif
        }
    }
    return ret;
}

/** \brief Initializes an mbedtls pk context for use with EC operations
 * \param[in,out] pkey ptr to space to receive version string
 * \param[in] slotid Associated with this key
 * \return 0 on success, otherwise an error code.
 */
int atca_mbedtls_pk_init(mbedtls_pk_context * pkey, const uint16_t slotid)
{
    return atca_mbedtls_pk_init_ext(atcab_get_device(), pkey, slotid);
}

#if (ATCA_CA_SUPPORT && ATCACERT_COMPCERT_EN)
#if defined(ATCA_HEAP)
/** \brief Rebuild a certificate from an atcacert_def_t structure, and then add
 * it to an mbedtls cert chain.
 * \param[in,out] cert mbedtls cert chain. Must have already been initialized
 * \param[in] cert_def Certificate definition that will be rebuilt and added
 * \return 0 on success, otherwise an error code.
 */
int atca_mbedtls_cert_add(mbedtls_x509_crt * cert, const atcacert_def_t * cert_def)
{
    uint8_t ca_key[64] = { 0x00 };
    int ret = ATCA_SUCCESS;
    size_t cert_len;
    uint8_t * cert_buf = NULL;

    if (NULL != cert_def->ca_cert_def)
    {
        const atcacert_device_loc_t * ca_key_cfg = &cert_def->ca_cert_def->public_key_dev_loc;

        if (NULL != ca_key_cfg)
        {
            if (0u == ca_key_cfg->is_genkey)
            {
                ret = atcab_get_pubkey(ca_key_cfg->slot, ca_key);
            }
            else
            {
                ret = atcab_read_pubkey(ca_key_cfg->slot, ca_key);
            }
        }
    }

    cert_len = cert_def->cert_template_size + 8;

    if (NULL == (cert_buf = mbedtls_calloc(1, cert_len)))
    {
        ret = -1;
    }

    if (0 == ret)
    {
        ret = atcacert_read_cert(cert_def, (cert_def->ca_cert_def != NULL) ? ca_key : NULL, cert_buf, &cert_len);
    }

    if (0 == ret)
    {
        ret = mbedtls_x509_crt_parse(cert, (const unsigned char*)cert_buf, cert_len);
    }

    if (NULL != cert_buf)
    {
        mbedtls_free(cert_buf);
    }
    return ret;
}
#endif
#endif

ATCA_STATUS atcac_parse_der(struct atcac_x509_ctx** cert, cal_buffer* der)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != der)
    {
#if defined(ATCA_HEAP)
        mbedtls_x509_crt* xcert = atcac_mbedtls_new();

        if (xcert == NULL)
        {
            return status;
        }

        mbedtls_x509_crt_init(xcert);

        int ret = mbedtls_x509_crt_parse_der(xcert, der->buf, der->len);

        if (ret != 0)
        {
            atcac_x509_free(xcert);
            return status;
        }

        /* coverity[misra_c_2012_rule_11_3_violation:FALSE] The mbetls x509 struct pointer is made to point the atcac_x509_ctx void ptr*/
        /*The memory allocated will be traversed using the void ptr in atcac_x509_ctx and is the only member*/
        /* Our library uses structure of type atcac_x509_ctx to be mapped to third party specific certificate structre and this cannot be changed*/
        *cert = (struct atcac_x509_ctx*)xcert;
        status = ATCA_SUCCESS;
#endif
    }
    return status;
}

ATCA_STATUS atcac_get_subject(const struct atcac_x509_ctx* cert, cal_buffer* cert_subject)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != cert_subject)
    {
        /* coverity[cert_exp40_c_violation:FALSE] mbedtls ssl api requires non const qualifier in lower apis*/
        /* coverity[misra_c_2012_rule_11_8_violation:FALSE] */
        const void* tmp_ptr = cert;
        const mbedtls_x509_crt* x509_cert = (const mbedtls_x509_crt*)(tmp_ptr);

        const mbedtls_x509_name *subjname = (const mbedtls_x509_name*)&x509_cert->subject;
        int ret = mbedtls_x509_dn_gets((char*)cert_subject->buf, cert_subject->len, subjname);
        if (ret > 0)
        {
            status = ATCA_SUCCESS;
        }
    }
    return status;
}

ATCA_STATUS atcac_get_subj_public_key(const struct atcac_x509_ctx* cert, cal_buffer* subj_public_key)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != subj_public_key)
    {
        /* coverity[cert_exp40_c_violation:FALSE] mbedtls ssl api requires non const qualifier in lower apis*/
        /* coverity[misra_c_2012_rule_11_8_violation:FALSE] */
        const void* tmp_ptr = cert;
        const mbedtls_x509_crt* x509_cert = (const mbedtls_x509_crt*)(tmp_ptr);
        const mbedtls_pk_context *pk = (const mbedtls_pk_context *)&x509_cert->pk;

        if (MBEDTLS_PK_ECKEY == mbedtls_pk_get_type(pk))
        {
            // Extract the Qx and Qy values of the EC public key
            const mbedtls_ecp_keypair* ec = mbedtls_pk_ec(*pk);
            if (NULL == ec)
            {
                return status;
            }

            // Calculate the expected buffer length for both Qx and Qy
            size_t expected_len = mbedtls_mpi_size(&ec->Q.X) + mbedtls_mpi_size(&ec->Q.Y);

            // Check if subj_public_key buffer is large enough
            if (subj_public_key->len < expected_len)
            {
                return status;  // Error: Buffer too small
            }

            // Write the binary representation of Qx into the buffer
            size_t bytes_written = 0;
            int ret = mbedtls_mpi_write_binary(&ec->Q.X, subj_public_key->buf, mbedtls_mpi_size(&ec->Q.X));
            if (ret != 0)
            {
                return status;  // Error: writing Qx to buffer failed
            }
            bytes_written += mbedtls_mpi_size(&ec->Q.X);

            // Write the binary representation of Qy into the buffer
            ret = mbedtls_mpi_write_binary(&ec->Q.Y, subj_public_key->buf + bytes_written, mbedtls_mpi_size(&ec->Q.Y));
            if (ret != 0)
            {
                return status;  // Error: writing Qy to buffer failed
            }

            subj_public_key->len = expected_len;
            status = ATCA_SUCCESS;
        }
        else
        {
            // Extract the RSA public key
            const mbedtls_rsa_context* rsa = mbedtls_pk_rsa(*pk);
            if (NULL == rsa)
            {
                return status;
            }

            // Calculate the expected buffer length for the modulus (N)
            size_t expected_len = mbedtls_mpi_size(&rsa->N);

            // Check if subj_public_key buffer is large enough
            if (subj_public_key->len < expected_len)
            {
                return status;  // Error: Buffer too small
            }

            // Write the binary representation of the modulus (N) into the buffer
            int ret = mbedtls_mpi_write_binary(&rsa->N, subj_public_key->buf, mbedtls_mpi_size(&rsa->N));
            if (ret != 0)
            {
                return status; // Error: writing modulus N to buffer failed
            }

            subj_public_key->len = expected_len;
            status = ATCA_SUCCESS;
        }
    }
    return status;
}

ATCA_STATUS atcac_get_subj_key_id(const struct atcac_x509_ctx* cert, cal_buffer* subj_public_key_id)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    //Below logic can be minimized if using v3.5.0 mbedtls

    if (NULL != cert && NULL != subj_public_key_id)
    {
#if defined(ATCA_HEAP)
        /* coverity[misra_c_2012_rule_21_3_violation:FALSE] Using mbedtls memory allocation api for initializing asn1 sequence object */
        // By design mbedtls prefers calloc as it not only allocates but also initializes the data
        mbedtls_asn1_sequence *extns = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
        mbedtls_asn1_sequence* next = extns;

        /* coverity[cert_exp40_c_violation:FALSE] mbedtls ssl api requires non const qualifier in lower apis*/
        /* coverity[misra_c_2012_rule_11_8_violation:FALSE] */
        const void* tmp_ptr = cert;
        const mbedtls_x509_crt* x509_cert = (const mbedtls_x509_crt*)(tmp_ptr);
        size_t tag_len = 0x00;
        mbedtls_x509_buf buf = x509_cert->v3_ext;
        uint8_t SKID[sizeof(MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER)] = MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER;
        size_t SKID_OID_len = (sizeof(SKID)-((unsigned)1));

        if ((NULL != extns) &&
            (0 == mbedtls_asn1_get_sequence_of(&buf.p, buf.p + buf.len, extns,
                        (int)((unsigned int)MBEDTLS_ASN1_CONSTRUCTED | (unsigned int)MBEDTLS_ASN1_SEQUENCE))))
        {
            while (NULL != next)
            {
                if (0 != mbedtls_asn1_get_tag(&(next->buf.p), next->buf.p + next->buf.len, &tag_len, MBEDTLS_ASN1_OID))
                {
                    break;
                }

                /* coverity[misra_c_2012_rule_21_14_violation:FALSE] SKID_OID_len excluded NULL character before performing memcmp */
                if (tag_len == SKID_OID_len && memcmp(next->buf.p, SKID, SKID_OID_len) == 0)
                {
                    // Extract the SKI value
                    unsigned char* p = next->buf.p + tag_len;
                    if (0 != mbedtls_asn1_get_tag(&p, p + next->buf.len - tag_len, &tag_len, MBEDTLS_ASN1_OCTET_STRING))
                    {
                        break;
                    }

                    // Include OCTET STRING TL = 2
                    if (0 != mbedtls_asn1_get_tag(&p, p + next->buf.len - 2, &tag_len, MBEDTLS_ASN1_OCTET_STRING))
                    {
                        break;
                    }

                    if (tag_len != 20u)
                    {
                        break;
                    }

                    // Copy the SKI value to the destination buffer
                    if (ATCA_SUCCESS == (status = cal_buf_write_bytes(subj_public_key_id, 0U, p, 20)))
                    {
                        status = cal_buf_set_used(subj_public_key_id, subj_public_key_id->len);
                    }
                    break;
                }
                next = next->next;
            }
        }

        if (NULL != extns)
        {
            mbedtls_asn1_sequence_free(extns);
        }
#endif
    }
    return status;
}

static int mbedtls_x509_time_to_asn1_generalized_time(const mbedtls_x509_time* x509_time, char* asn1_time, size_t asn1_time_len)
{
    int ret = 1;

    if (NULL == x509_time || NULL == asn1_time)
    {
        return ret;
    }
    // Check for buffer size to make sure snprintf usage doesn not lead to buffer overflow
    if (asn1_time_len < 15u)
    {
        // Buffer is too small to hold the ASN.1 GeneralizedTime
        asn1_time[0] = '\0';
        return ret;
    }

    // Format the time in ASN.1 GeneralizedTime format (YYYYMMDDHHMMSSZ)
    /* coverity[misra_c_2012_rule_21_6_violation:FALSE] It is third party library implementation and tested code and also the length of buffer is checked before usage*/
    int num_written = mbedtls_snprintf(asn1_time, asn1_time_len, "%04d%02d%02d%02d%02d%02dZ", x509_time->year, x509_time->mon, x509_time->day,
                                       x509_time->hour, x509_time->min, x509_time->sec);

    if (num_written > 0)
    {
        if ((size_t)num_written < asn1_time_len)
        {
            ret = 0;
        }
    }
    return ret;
}

ATCA_STATUS atcac_get_issue_date(const struct atcac_x509_ctx* cert, cal_buffer* not_before, uint8_t* fmt)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    UNUSED_VAR(fmt);

    if (NULL != cert && NULL != not_before)
    {
        /* coverity[cert_exp40_c_violation:FALSE] mbedtls ssl api requires non const qualifier in lower apis*/
        /* coverity[misra_c_2012_rule_11_8_violation:FALSE] */
        const void* tmp_ptr = cert;
        const mbedtls_x509_crt* x509_cert = (const mbedtls_x509_crt*)(tmp_ptr);
        // Access the validity structure within the certificate
        const mbedtls_x509_time *valid_from = (const mbedtls_x509_time *)&x509_cert->valid_from;
        if (0 == mbedtls_x509_time_to_asn1_generalized_time(valid_from, (char*)not_before->buf, not_before->len))
        {
            status = ATCA_SUCCESS;
        }
    }
    return status;
}
ATCA_STATUS atcac_get_expire_date(const struct atcac_x509_ctx* cert, cal_buffer* not_after, uint8_t* fmt)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    UNUSED_VAR(fmt);

    if (NULL != cert && NULL != not_after)
    {
        /* coverity[cert_exp40_c_violation:FALSE] mbedtls ssl api requires non const qualifier in lower apis*/
        /* coverity[misra_c_2012_rule_11_8_violation:FALSE] */
        const void* tmp_ptr = cert;
        const mbedtls_x509_crt* x509_cert = (const mbedtls_x509_crt*)(tmp_ptr);
        // Access the validity structure within the certificate
        const mbedtls_x509_time *valid_to = (const mbedtls_x509_time *)&x509_cert->valid_to;
        if (0 == mbedtls_x509_time_to_asn1_generalized_time(valid_to, (char*)not_after->buf, not_after->len))
        {
            status = ATCA_SUCCESS;
        }
    }
    return status;
}

ATCA_STATUS atcac_get_issuer(const struct atcac_x509_ctx* cert, cal_buffer* issuer_buf)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != issuer_buf)
    {
        /* coverity[cert_exp40_c_violation:FALSE] mbedtls ssl api requires non const qualifier in lower apis*/
        /* coverity[misra_c_2012_rule_11_8_violation:FALSE] */
        const void* tmp_ptr = cert;
        const mbedtls_x509_crt* x509_cert = (const mbedtls_x509_crt*)(tmp_ptr);
        const mbedtls_x509_name *issuer_name = (const mbedtls_x509_name*)&x509_cert->issuer;
        int ret = mbedtls_x509_dn_gets((char*)issuer_buf->buf, issuer_buf->len, issuer_name);
        if (ret > 0)
        {
            status = ATCA_SUCCESS;
        }
    }
    return status;
}

ATCA_STATUS atcac_get_cert_sn(const struct atcac_x509_ctx* cert, cal_buffer* cert_sn)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != cert && NULL != cert_sn)
    {
        /* coverity[cert_exp40_c_violation:FALSE] mbedtls ssl api requires non const qualifier in lower apis*/
        /* coverity[misra_c_2012_rule_11_8_violation:FALSE] */
        const void* tmp_ptr = cert;
        const mbedtls_x509_crt* x509_cert = (const mbedtls_x509_crt*)(tmp_ptr);
        const mbedtls_x509_buf* serial = &(x509_cert->serial);
        if (ATCA_SUCCESS == (status = cal_buf_write_bytes(cert_sn, 0U, serial->p, serial->len)))
        {
            status = cal_buf_set_used(cert_sn, cert_sn->len);
        }
    }
    return status;
}

ATCA_STATUS atcac_get_auth_key_id(const struct atcac_x509_ctx* cert, cal_buffer* auth_key_id)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    bool akid_found = false;

    if (NULL != cert && NULL != auth_key_id)
    {
#if defined(ATCA_HEAP)
        /* coverity[misra_c_2012_rule_21_3_violation:FALSE] Using mbedtls memory allocation api for initializing asn1 sequence object */
        // By design mbedtls prefers calloc as it not only allocates but also initializes the data
        mbedtls_asn1_sequence *extns = mbedtls_calloc(1, sizeof(mbedtls_asn1_sequence));
        mbedtls_asn1_sequence* next = extns;

        /* coverity[cert_exp40_c_violation:FALSE] mbedtls ssl api requires non const qualifier in lower apis*/
        /* coverity[misra_c_2012_rule_11_8_violation:FALSE] */
        const void* tmp_ptr = cert;
        const mbedtls_x509_crt* x509_cert = (const mbedtls_x509_crt*)(tmp_ptr);
        size_t tag_len = 0x00;
        mbedtls_x509_buf buf = x509_cert->v3_ext;
        uint8_t AKID[sizeof(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER)] = MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER;
        size_t AKID_OID_len = (sizeof(AKID) - ((unsigned)1));

        if ((NULL != extns) &&
            (0 == mbedtls_asn1_get_sequence_of(&buf.p, buf.p + buf.len, extns,
                        (int)((unsigned int)MBEDTLS_ASN1_CONSTRUCTED | (unsigned int)MBEDTLS_ASN1_SEQUENCE))))
        {
            while (NULL != next)
            {
                if (0 != mbedtls_asn1_get_tag(&(next->buf.p), next->buf.p + next->buf.len, &tag_len, MBEDTLS_ASN1_OID))
                {
                    break;
                }

                // Check if the OID is the Authority Key Identifier OID
                /* coverity[misra_c_2012_rule_21_14_violation:FALSE] AKID_OID_len excluded NULL character before performing memcmp */
                if (tag_len == AKID_OID_len && memcmp(next->buf.p, AKID, AKID_OID_len) == 0)
                {
                    // Extract the AKI value
                    unsigned char* p = next->buf.p + tag_len;
                    if (0 != mbedtls_asn1_get_tag(&p, p + next->buf.len - tag_len, &tag_len, MBEDTLS_ASN1_OCTET_STRING))
                    {
                        break;
                    }
                    p = p + MBEDTLS_ASN1_OCTET_STRING;
                    // Copy the AKI value to the destination buffer
                    if (ATCA_SUCCESS == (status = cal_buf_write_bytes(auth_key_id, 0U, p, (tag_len - ((size_t)MBEDTLS_ASN1_OCTET_STRING)))))
                    {
                        status = cal_buf_set_used(auth_key_id, auth_key_id->len);
                    }
                    akid_found = true; 
                    break;
                }
                next = next->next;
            }
        }

        if (NULL != extns)
        {
            mbedtls_asn1_sequence_free(extns);
        }

        if (false == akid_found)
        {
            /* No data is available */
            status = cal_buf_set_used(auth_key_id, 0U);
        }
#endif
    }
    return status;
}

void atcac_x509_free(void* cert)
{
    /* coverity[misra_c_2012_rule_21_3_violation:FALSE] The mbedtls certificate structure need to be freed and the below are library specific apis */
    if (NULL != cert)
    {
        mbedtls_x509_crt_free((mbedtls_x509_crt *)cert);
        //As per https://github.com/Mbed-TLS/mbedtls/issues/2098 , mbedtls_free need to be added as well
        mbedtls_free(cert);
    }
}

#endif /* ATCA_MBEDTLS */
#ifdef __COVERITY__
#pragma coverity compliance end_block "CERT EXP40-C" "MISRA C-2012 Rule 11.8"
#endif
