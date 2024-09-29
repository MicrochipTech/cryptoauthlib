/**
 * \file
 * \brief Common Wrapper for host side AES-GCM implementations that feature
 * update APIs rather than an all at once implementation
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

#include "atca_crypto_sw.h"

#if ATCAC_AES_GCM_EN

ATCA_STATUS atcac_aes_gcm_encrypt(
    struct atcac_aes_gcm_ctx* ctx,
    const uint8_t*            plaintext,
    const size_t              pt_len,
    uint8_t*                  ciphertext,
    uint8_t*                  tag,
    size_t                    tag_len,
    const uint8_t*            aad,
    const size_t              aad_len)
{
    ATCA_STATUS status;

    if (ATCA_SUCCESS == (status = atcac_aes_gcm_aad_update(ctx, aad, aad_len)))
    {
        size_t ct_len = pt_len;
        if (NULL != plaintext && 0u != pt_len)
        {
            (void)atcac_aes_gcm_encrypt_update(ctx, plaintext, pt_len, ciphertext, &ct_len);
        }
        status = atcac_aes_gcm_encrypt_finish(ctx, tag, tag_len);
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
    bool*                     is_verified)
{
    ATCA_STATUS status;

    if (ATCA_SUCCESS == (status = atcac_aes_gcm_aad_update(ctx, aad, aad_len)))
    {
        size_t pt_len = ct_len;
        if (ATCA_SUCCESS == (status = atcac_aes_gcm_decrypt_update(ctx, ciphertext, ct_len, plaintext, &pt_len)))
        {
            status = atcac_aes_gcm_decrypt_finish(ctx, tag, tag_len, is_verified);
        }
    }
    return status;
}

#endif

#if ATCA_CRYPTO_AES_GCM_EN

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-GCM operations
 *  \brief Initialize an AES-GCM context
 *
 *  \param[in] ctx       AES-GCM Context
 *  \param[in] key       AES Key
 *  \param[in] key_len   Length of the AES key - should be 16 or 32
 *  \param[in] iv        Initialization vector input
 *  \param[in] iv_len    Length of the initialization vector
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_gcm_encrypt_start(
    struct atcac_aes_gcm_ctx *  ctx,
    const uint8_t *             key,
    const uint8_t               key_len,
    const uint8_t *             iv,
    const uint8_t               iv_len
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(key);
    UNUSED_VAR(key_len);
    UNUSED_VAR(iv);
    UNUSED_VAR(iv_len);
    return ATCA_UNIMPLEMENTED;
}

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-GCM operations
 *  \brief Initialize an AES-GCM context for decryption
 *
 *  \param[in] ctx       AES-GCM Context
 *  \param[in] key       AES Key
 *  \param[in] key_len   Length of the AES key - should be 16 or 32
 *  \param[in] iv        Initialization vector input
 *  \param[in] iv_len    Length of the initialization vector
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_gcm_decrypt_start(
    struct atcac_aes_gcm_ctx*   ctx,
    const uint8_t*              key,
    const uint8_t               key_len,
    const uint8_t*              iv,
    const uint8_t               iv_len
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(key);
    UNUSED_VAR(key_len);
    UNUSED_VAR(iv);
    UNUSED_VAR(iv_len);
    return ATCA_UNIMPLEMENTED;
}

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-GCM operations
 *  \brief Update the GCM context with additional authentication data (AAD)
 *
 *  \param[in] ctx       AES-GCM Context
 *  \param[in] aad       Additional Authentication Data
 *  \param[in] aad_len   Length of AAD
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_gcm_aad_update(
    struct atcac_aes_gcm_ctx*   ctx,
    const uint8_t*              aad,
    const size_t                aad_len
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(aad);
    UNUSED_VAR(aad_len);
    return ATCA_UNIMPLEMENTED;
}

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-GCM operations
 *  \brief Encrypt a data using the initialized context
 *
 *  \param[in]  ctx          AES-GCM Context
 *  \param[in]  plaintext    Data to be encrypted
 *  \param[in]  pt_len       Plain text Length
 *  \param[out] ciphertext   Encrypted data
 *  \param[out] ct_len       Cipher text length
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_gcm_encrypt_update(
    struct atcac_aes_gcm_ctx*   ctx,
    const uint8_t*              plaintext,
    const size_t                pt_len,
    uint8_t*                    ciphertext,
    size_t*                     ct_len
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(plaintext);
    UNUSED_VAR(pt_len);
    UNUSED_VAR(ciphertext);
    UNUSED_VAR(ct_len);
    return ATCA_UNIMPLEMENTED;
}

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-GCM operations
 *  \brief Decrypt ciphertext using the initialized context
 *
 *  \param[in]  ctx          AES-GCM Context
 *  \param[in]  ciphertext   Encrypted data
 *  \param[in]  ct_len       Ciphertext length
 *  \param[out] plaintext    Data to be encrypted
 *  \param[out] pt_len       Plaintext Length
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_gcm_decrypt_update(
    struct atcac_aes_gcm_ctx*   ctx,
    const uint8_t*              ciphertext,
    const size_t                ct_len,
    uint8_t*                    plaintext,
    size_t*                     pt_len
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(ciphertext);
    UNUSED_VAR(ct_len);
    UNUSED_VAR(plaintext);
    UNUSED_VAR(pt_len);
    return ATCA_UNIMPLEMENTED;
}

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-GCM operations
 *  \brief Get the AES-GCM tag and free the context
 *
 *  \param[in]  ctx          AES-GCM Context
 *  \param[out] tag          AES-GCM tag
 *  \param[in]  tag_len      tag length
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_gcm_encrypt_finish(
    struct atcac_aes_gcm_ctx*   ctx,
    uint8_t*                    tag,
    size_t                      tag_len
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(tag);
    UNUSED_VAR(tag_len);
    return ATCA_UNIMPLEMENTED;
}

/** NOTE: Use third party libraries like openSSL/WolfSSL/mbedTLS to enable AES-GCM operations
 *  \brief Compare the AES-GCM tag and free the context
 *
 *  \param[in]  ctx          AES-GCM Context
 *  \param[out] tag          AES-GCM tag
 *  \param[in]  tag_len      tag length
 *  \param[out] is_verified  verification status
 *
 *  \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS atcac_aes_gcm_decrypt_finish(
    struct atcac_aes_gcm_ctx*   ctx,
    const uint8_t*              tag,
    size_t                      tag_len,
    bool*                       is_verified
    )
{
    UNUSED_VAR(ctx);
    UNUSED_VAR(tag);
    UNUSED_VAR(tag_len);
    UNUSED_VAR(is_verified);
    return ATCA_UNIMPLEMENTED;
}

#endif
