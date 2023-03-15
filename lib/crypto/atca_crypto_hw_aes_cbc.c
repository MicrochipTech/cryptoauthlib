/**
 * \file
 * \brief CryptoAuthLib Basic API methods for AES CBC mode.
 *
 * The AES command supports 128-bit AES encryption or decryption of small
 * messages or data packets in ECB mode.
 *
 * \note List of devices that support this command - ATECC608A, ATECC608B,
 *       & TA100. Refer to device datasheet for full details.
 *
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
#include "atca_crypto_hw_aes.h"

#ifdef _WIN32
#include <stdlib.h>
#endif

#if (ATCAB_AES_CBC_ENCRYPT_EN || ATCAB_AES_CBC_DECRYPT_EN)
/** \brief Initialize context for AES CBC operation.
 *
 * \param[in] device     Device context pointer
 * \param[in] ctx        AES CBC context to be initialized
 * \param[in] key_id     Key location. Can either be a slot/handles or
 *                       in TempKey.
 * \param[in] key_block  Index of the 16-byte block to use within the key
 *                       location for the actual key.
 * \param[in] iv         Initialization vector (16 bytes).
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_aes_cbc_init_ext(ATCADevice device, atca_aes_cbc_ctx_t* ctx, uint16_t key_id, uint8_t key_block, const uint8_t* iv)
{
    if (ctx == NULL || iv == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->device = device;
    ctx->key_id = key_id;
    ctx->key_block = key_block;
    memcpy(ctx->ciphertext, iv, sizeof(ctx->ciphertext));

    return ATCA_SUCCESS;
}

/** \brief Initialize context for AES CBC operation.
 *
 * \param[in] ctx        AES CBC context to be initialized
 * \param[in] key_id     Key location. Can either be a slot/handles or
 *                       in TempKey.
 * \param[in] key_block  Index of the 16-byte block to use within the key
 *                       location for the actual key.
 * \param[in] iv         Initialization vector (16 bytes).
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_aes_cbc_init(atca_aes_cbc_ctx_t* ctx, uint16_t key_id, uint8_t key_block, const uint8_t* iv)
{
    return atcab_aes_cbc_init_ext(atcab_get_device(), ctx, key_id, key_block, iv);
}
#endif /* ATCAB_AES_CBC_ENCRYPT || ATCAB_AES_CBC_DECRYPT */

#if ATCAB_AES_CBC_ENCRYPT_EN
/** \brief Encrypt a block of data using CBC mode and a key within the
 *         device. atcab_aes_cbc_init() should be called before the
 *         first use of this function.
 *
 * \param[in]  ctx         AES CBC context.
 * \param[in]  plaintext   Plaintext to be encrypted (16 bytes).
 * \param[out] ciphertext  Encrypted data is returned here (16 bytes).
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_aes_cbc_encrypt_block(atca_aes_cbc_ctx_t* ctx, const uint8_t* plaintext, uint8_t* ciphertext)
{
    uint8_t input[ATCA_AES128_BLOCK_SIZE];
    int i;
    ATCA_STATUS status = ATCA_SUCCESS;

    if (ctx == NULL || plaintext == NULL || ciphertext == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    // XOR plaintext with previous block's ciphertext to get input value to block encrypt
    for (i = 0; i < ATCA_AES128_BLOCK_SIZE; i++)
    {
        input[i] = plaintext[i] ^ ctx->ciphertext[i];
    }

    // Block encrypt of input data
    if (ATCA_SUCCESS != (status = atcab_aes_encrypt_ext(ctx->device, ctx->key_id, ctx->key_block, input, ciphertext)))
    {
        return status;
    }

    // Save copy of ciphertext for next block operation
    memcpy(ctx->ciphertext, ciphertext, ATCA_AES128_BLOCK_SIZE);

    return status;
}
#endif /* ATCAB_AES_CBC_ENCRYPT_EN */

#if ATCAB_AES_CBC_DECRYPT_EN
/** \brief Decrypt a block of data using CBC mode and a key within the
 *         device. atcab_aes_cbc_init() should be called before the
 *         first use of this function.
 *
 * \param[in]  ctx         AES CBC context.
 * \param[in]  ciphertext  Ciphertext to be decrypted (16 bytes).
 * \param[out] plaintext   Decrypted data is returned here (16 bytes).
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_aes_cbc_decrypt_block(atca_aes_cbc_ctx_t* ctx, const uint8_t* ciphertext, uint8_t* plaintext)
{
    uint8_t output[ATCA_AES128_BLOCK_SIZE];
    int i;
    ATCA_STATUS status = ATCA_SUCCESS;

    if (ctx == NULL || ciphertext == NULL || plaintext == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    // Block decrypt of ciphertext
    if (ATCA_SUCCESS != (status = atcab_aes_decrypt_ext(ctx->device, ctx->key_id, ctx->key_block, ciphertext, output)))
    {
        return status;
    }

    // XOR output with previous block's ciphertext to get plaintext
    for (i = 0; i < ATCA_AES128_BLOCK_SIZE; i++)
    {
        plaintext[i] = output[i] ^ ctx->ciphertext[i];
    }

    // Save copy of ciphertext for next block operation
    memcpy(ctx->ciphertext, ciphertext, ATCA_AES128_BLOCK_SIZE);

    return status;
}

#ifdef ATCAB_AES_CBC_UPDATE_EN

ATCA_STATUS atcab_aes_cbc_encrypt_update(atca_aes_cbc_ctx_t* ctx, uint8_t* plaintext, size_t plaintext_len, uint8_t* ciphertext, size_t * ciphertext_len)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if (!ctx || !plaintext || !ciphertext || !ciphertext_len)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    if ((ctx->block_size + plaintext_len) / ATCA_AES128_BLOCK_SIZE > *ciphertext_len)
    {
        return ATCA_TRACE(ATCA_SMALL_BUFFER, "Output buffer is too small");
    }
    
    *ciphertext_len = 0;

    do
    {
        if (ctx->block_size)
        {
            size_t copy_size = ATCA_AES128_BLOCK_SIZE - ctx->block_size;
            if (plaintext_len < copy_size)
            {
                copy_size = plaintext_len;
            }
            memcpy(&ctx->block[ctx->block_size], plaintext, copy_size);
            plaintext += copy_size;
            ctx->block_size += copy_size;
            plaintext_len -= copy_size;
        }
        if (ATCA_AES128_BLOCK_SIZE == ctx->block_size)
        {
            if (ATCA_SUCCESS != (status = atcab_aes_cbc_encrypt_block(ctx, ctx->block, ciphertext)))
            {
                break;
            }
            ctx->block_size = 0;
            ciphertext += ATCA_AES128_BLOCK_SIZE;
            *ciphertext_len += ATCA_AES128_BLOCK_SIZE;
        }
        if (ATCA_AES128_BLOCK_SIZE <= plaintext_len)
        {
            if (ATCA_SUCCESS != (status = atcab_aes_cbc_encrypt_block(ctx, plaintext, ciphertext)))
            {
                break;
            }
            plaintext += ATCA_AES128_BLOCK_SIZE;
            ciphertext += ATCA_AES128_BLOCK_SIZE;
            *ciphertext_len += ATCA_AES128_BLOCK_SIZE;
            plaintext_len -= ATCA_AES128_BLOCK_SIZE;
        }
        if (plaintext_len && (ATCA_AES128_BLOCK_SIZE > plaintext_len))
        {
            memcpy(ctx->block, plaintext, plaintext_len);
            ctx->block_size = plaintext_len;
            plaintext_len -= plaintext_len;
        }
    } while(plaintext_len);

    return status;
}

ATCA_STATUS atcab_aes_cbc_encrypt_finish(atca_aes_cbc_ctx_t* ctx, uint8_t* ciphertext, size_t * ciphertext_len, uint8_t padding)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if (!ctx || !ciphertext || !ciphertext_len)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    if (padding == 1)
    {
        /* Use PKCS7 padding */
        size_t buflen = ATCA_AES128_BLOCK_SIZE;
        status = atcac_pkcs7_pad(ctx->block, &buflen, ctx->block_size, ATCA_AES128_BLOCK_SIZE);
        ctx->block_size = ATCA_AES128_BLOCK_SIZE;
    }
    else
    {
        if (ctx->block_size)
        {
            /* Pad with zeros */
            memset(ctx->block, 0, ATCA_AES128_BLOCK_SIZE - ctx->block_size);
        }
    }

    if (ATCA_SUCCESS == status && ctx->block_size)
    {
        if (*ciphertext_len >= ATCA_AES128_BLOCK_SIZE)
        {
        status = atcab_aes_cbc_encrypt_block(ctx, ctx->block, ciphertext);
        *ciphertext_len = ATCA_AES128_BLOCK_SIZE;
    }
    else
    {
            status = ATCA_SMALL_BUFFER;
        }
    }
    else
    {
        *ciphertext_len = 0;
    }

    memset(ctx, 0, sizeof(atca_aes_cbc_ctx_t));

    return status;
}

ATCA_STATUS atcab_aes_cbc_decrypt_update(atca_aes_cbc_ctx_t* ctx, const uint8_t* ciphertext, size_t ciphertext_len, uint8_t* plaintext, size_t * plaintext_len)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if (!ctx || !ciphertext || !ciphertext_len || !plaintext || !plaintext_len)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    if ((ctx->block_size + ciphertext_len) / ATCA_AES128_BLOCK_SIZE > *plaintext_len)
    {
        return ATCA_TRACE(ATCA_SMALL_BUFFER, "Output buffer is too small");
    }
    
    *plaintext_len = 0;

    do
    {
        if (ctx->block_size && ctx->block_size < ATCA_AES128_BLOCK_SIZE)
        {
            size_t copy_size = ATCA_AES128_BLOCK_SIZE - ctx->block_size;
            if (ciphertext_len < copy_size)
            {
                copy_size = ciphertext_len;
            }
            memcpy(&ctx->block[ctx->block_size], ciphertext, copy_size);
            ciphertext += copy_size;
            ctx->block_size += copy_size;
            ciphertext_len -= copy_size;
        }
        if (ATCA_AES128_BLOCK_SIZE == ctx->block_size && ciphertext_len)
        {
            if (ATCA_SUCCESS != (status = atcab_aes_cbc_decrypt_block(ctx, ctx->block, plaintext)))
            {
                break;
            }
            ctx->block_size = 0;
            plaintext += ATCA_AES128_BLOCK_SIZE;
            *plaintext_len += ATCA_AES128_BLOCK_SIZE;
        }
        if (ATCA_AES128_BLOCK_SIZE < ciphertext_len)
        {
            if (ATCA_SUCCESS != (status = atcab_aes_cbc_decrypt_block(ctx, ciphertext, plaintext)))
            {
                break;
            }
            plaintext += ATCA_AES128_BLOCK_SIZE;
            ciphertext += ATCA_AES128_BLOCK_SIZE;
            ciphertext_len -= ATCA_AES128_BLOCK_SIZE;
            *plaintext_len += ATCA_AES128_BLOCK_SIZE;
        }

        if (ciphertext_len && (ATCA_AES128_BLOCK_SIZE >= ciphertext_len))
        {
            /* Saves the remainder which may be partial or a full block of data */
            memcpy(ctx->block, ciphertext, ciphertext_len);
            ctx->block_size = ciphertext_len;
            ciphertext_len -= ciphertext_len;
        }
    } while(ciphertext_len);

    return status;
}

ATCA_STATUS atcab_aes_cbc_decrypt_finish(atca_aes_cbc_ctx_t* ctx, uint8_t* plaintext, size_t * plaintext_len, uint8_t padding)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if (!ctx || !plaintext || !plaintext_len)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    if (ATCA_AES128_BLOCK_SIZE == ctx->block_size)
    {
        if (*plaintext_len >= ATCA_AES128_BLOCK_SIZE)
        {
        status = atcab_aes_cbc_decrypt_block(ctx, ctx->block, plaintext);
        *plaintext_len = ATCA_AES128_BLOCK_SIZE;

        if ((ATCA_SUCCESS == status) && (padding == 1))
        {
            status = atcac_pkcs7_unpad(plaintext, plaintext_len, ATCA_AES128_BLOCK_SIZE);
        }
    }
        else
        {
            status = ATCA_SMALL_BUFFER;
        }
    }
    else if (ctx->block_size)
    {
        status = ATCA_TRACE(ATCA_GEN_FAIL, "Provided ciphertext is incomplete - the total length needs to be multiple of 16 bytes");
    }

    memset(ctx, 0, sizeof(atca_aes_cbc_ctx_t));

    return status;
}
#endif /* ATCAB_AES_CBC_UPDATE_EN */

#endif /* ATCAB_AES_CBC_DECRYPT_EN */
