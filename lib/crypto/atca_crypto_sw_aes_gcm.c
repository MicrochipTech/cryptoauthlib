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

#if ATCAC_AES_GCM_EN && ATCAC_AES_GCM_UPDATE_EN

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
