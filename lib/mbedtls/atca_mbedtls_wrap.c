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
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/x509_crt.h"

/* Cryptoauthlib Includes */
#include "cryptoauthlib.h"
#include "crypto/atca_crypto_sw.h"
#if ATCA_CA_SUPPORT
#include "atcacert/atcacert_client.h"
#include "atcacert/atcacert_def.h"
#endif

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
        int ret = mbedtls_cipher_update_ad(ctx, aad, aad_len);
        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        mbedtls_cipher_init(ctx);

        ret = mbedtls_cipher_setup(ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM));

        if (!ret)
        {
            ret = mbedtls_cipher_setkey(ctx, key, key_len * 8, MBEDTLS_ENCRYPT);
        }

        if (!ret)
        {
            ret = mbedtls_cipher_set_iv(ctx, iv, iv_len);
        }

        if (!ret)
        {
            ret = mbedtls_cipher_reset(ctx);
        }

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }

    return status;
}

/** \brief Encrypt a data using the initialized context
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_gcm_encrypt_update(
    atcac_aes_gcm_ctx* ctx,        /**< [in] AES-GCM Context */
    const uint8_t*     plaintext,  /**< [in] Input buffer to encrypt */
    const size_t       pt_len,     /**< [in] Length of the input */
    uint8_t*           ciphertext, /**< [out] Output buffer */
    size_t*            ct_len      /**< [inout] Length of the ciphertext buffer */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        int ret = mbedtls_cipher_update(ctx, plaintext, pt_len, ciphertext, ct_len);
        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        size_t outlen = 0;
        int ret = mbedtls_cipher_finish(ctx, NULL, &outlen);

        if (!ret)
        {
            ret = mbedtls_cipher_write_tag(ctx, tag, tag_len);
        }

        mbedtls_cipher_free(ctx);

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        mbedtls_cipher_init(ctx);

        ret = mbedtls_cipher_setup(ctx, mbedtls_cipher_info_from_values(MBEDTLS_CIPHER_ID_AES, key_len * 8, MBEDTLS_MODE_GCM));

        if (!ret)
        {
            ret = mbedtls_cipher_setkey(ctx, key, key_len * 8, MBEDTLS_DECRYPT);
        }

        if (!ret)
        {
            ret = mbedtls_cipher_set_iv(ctx, iv, iv_len);
        }

        if (!ret)
        {
            ret = mbedtls_cipher_reset(ctx);
        }

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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

    if (ctx)
    {
        int ret = mbedtls_cipher_update(ctx, ciphertext, ct_len, plaintext, pt_len);
        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        int ret;
        size_t outlen = 0;
        *is_verified = false;

        ret = mbedtls_cipher_finish(ctx, NULL, &outlen);

        if (!ret)
        {
            ret = mbedtls_cipher_check_tag(ctx, tag, tag_len);
        }

        if (!ret)
        {
            *is_verified = true;
        }

        mbedtls_cipher_free(ctx);

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief MBedTLS Message Digest Abstraction - Init
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS _atca_mbedtls_md_init(mbedtls_md_context_t* ctx, const mbedtls_md_info_t* md_info)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        int ret;
        mbedtls_md_init(ctx);

        ret = mbedtls_md_setup(ctx,  md_info, false);

        if (!ret)
        {
            ret = mbedtls_md_starts(ctx);
        }

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief MbedTLS Message Digest Abstraction - Update
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS _atca_mbedtls_md_update(mbedtls_md_context_t* ctx, const uint8_t* data, size_t data_size)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (ctx)
    {
        status = (!mbedtls_md_update(ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief MbedTLS Message Digest Abstraction - Finish
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS _atca_mbedtls_md_finish(mbedtls_md_context_t* ctx, uint8_t* digest, unsigned int* outlen)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    (void)outlen;

    if (ctx)
    {
        int ret = mbedtls_md_finish(ctx, digest);

        mbedtls_md_free(ctx);

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
    return _atca_mbedtls_md_init(ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1));
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
    return _atca_mbedtls_md_update(ctx, data, data_size);
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
    return _atca_mbedtls_md_finish(ctx, digest, NULL);
}

/** \brief Initialize context for performing SHA256 hash in software.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
int atcac_sw_sha2_256_init(
    atcac_sha2_256_ctx* ctx                 /**< [in] pointer to a hash context */
    )
{
    return _atca_mbedtls_md_init(ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256));
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
    return _atca_mbedtls_md_update(ctx, data, data_size);
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
    return _atca_mbedtls_md_finish(ctx, digest, NULL);
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
        int ret = 0;
        mbedtls_cipher_init(ctx);

        ret = mbedtls_cipher_setup(ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB));

        if (!ret)
        {
            ret = mbedtls_cipher_cmac_starts(ctx, key, (size_t)key_len * 8);
        }

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        status = (!mbedtls_cipher_cmac_update(ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Finish CMAC calculation and clear the CMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_aes_cmac_finish(
    atcac_aes_cmac_ctx* ctx,           /**< [in] pointer to a aes-cmac context */
    uint8_t*            cmac,          /**< [out] cmac value */
    size_t*             cmac_size      /**< [inout] length of cmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    (void)cmac_size;

    if (ctx)
    {
        int ret = mbedtls_cipher_cmac_finish(ctx, cmac);

        mbedtls_cipher_free(ctx);

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        int ret;
        mbedtls_md_init(ctx);

        ret = mbedtls_md_setup(ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), true);

        if (!ret)
        {
            ret = mbedtls_md_hmac_starts(ctx, key, key_len);
        }

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
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
        status = (!mbedtls_md_hmac_update(ctx, data, data_size)) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}

/** \brief Finish CMAC calculation and clear the HMAC context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcac_sha256_hmac_finish(
    atcac_hmac_sha256_ctx* ctx,                /**< [in] pointer to a sha256-hmac context */
    uint8_t*               digest,             /**< [out] hmac value */
    size_t*                digest_len          /**< [inout] length of hmac */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    (void)digest_len;

    if (ctx)
    {
        int ret = mbedtls_md_hmac_finish(ctx, digest);

        mbedtls_md_free(ctx);

        status = (!ret) ? ATCA_SUCCESS : ATCA_FUNC_FAIL;
    }
    return status;
}


/** \brief Initializes an mbedtls pk context for use with EC operations
 * \param[in,out] pkey ptr to space to receive version string
 * \param[in] slotid Associated with this key
 * \return 0 on success, otherwise an error code.
 */
int atca_mbedtls_pk_init(mbedtls_pk_context * pkey, const uint16_t slotid)
{
    int ret = 0;
    uint8_t public_key[ATCA_ECCP256_SIG_SIZE];
    mbedtls_ecp_keypair * ecp = NULL;
    uint8_t temp = 1;

    if (!pkey)
    {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (!ret)
    {
        mbedtls_pk_init(pkey);
        ret = mbedtls_pk_setup(pkey, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    }

    if (!ret)
    {
        ecp = mbedtls_pk_ec(*pkey);
        ret = mbedtls_ecp_group_load(&ecp->grp, MBEDTLS_ECP_DP_SECP256R1);
    }

    if (!ret)
    {
        ret = atcab_get_pubkey(slotid, public_key);
    }

    if (!ret)
    {
        ret = mbedtls_mpi_read_binary(&(ecp->Q.X), public_key, ATCA_ECCP256_SIG_SIZE / 2);
    }

    if (!ret)
    {
        ret = mbedtls_mpi_read_binary(&(ecp->Q.Y), &public_key[ATCA_ECCP256_SIG_SIZE / 2], ATCA_ECCP256_SIG_SIZE / 2);
    }

    if (!ret)
    {
        ret = mbedtls_mpi_read_binary(&(ecp->Q.Z), &temp, 1);
    }

    if (!ret)
    {
        ret = mbedtls_mpi_lset(&ecp->d, slotid);
    }

    return ret;
}

#if ATCA_CA_SUPPORT
/** \brief Rebuild a certificate from an atcacert_def_t structure, and then add
 * it to an mbedtls cert chain.
 * \param[in,out] cert mbedtls cert chain. Must have already been initialized
 * \param[in] cert_def Certificate definition that will be rebuilt and added
 * \return 0 on success, otherwise an error code.
 */
int atca_mbedtls_cert_add(mbedtls_x509_crt * cert, const atcacert_def_t * cert_def)
{
    uint8_t ca_key[64];
    int ret = ATCA_SUCCESS;
    size_t cert_len;
    uint8_t * cert_buf = NULL;

    if (cert_def->ca_cert_def)
    {
        const atcacert_device_loc_t * ca_key_cfg = &cert_def->ca_cert_def->public_key_dev_loc;

        if (ca_key_cfg->is_genkey)
        {
            ret = atcab_get_pubkey(ca_key_cfg->slot, ca_key);
        }
        else
        {
            ret = atcab_read_pubkey(ca_key_cfg->slot, ca_key);
        }
    }

    cert_len = cert_def->cert_template_size + 8;
    if (NULL == (cert_buf = mbedtls_calloc(1, cert_len)))
    {
        ret = -1;
    }

    if (0 == ret)
    {
        ret = atcacert_read_cert(cert_def, cert_def->ca_cert_def ? ca_key : NULL, cert_buf, &cert_len);
    }

    if (0 == ret)
    {
        ret = mbedtls_x509_crt_parse(cert, (const unsigned char*)cert_buf, cert_len);
    }

    if (cert_buf)
    {
        mbedtls_free(cert_buf);
    }

    return ret;
}
#endif
