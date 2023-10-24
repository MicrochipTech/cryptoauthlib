/**
 * \file
 * \brief CryptoAuthLib Basic API methods for AES CBC_MAC mode.
 *
 * The AES command supports 128-bit AES encryption or decryption of small
 * messages or data packets in ECB mode.
 *
 * \note List of devices that support this command - ATECC608A, ATECC608B,
 *       & TA10x. Refer to device datasheet for full details.
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

#if ATCAB_AES_CMAC_EN

static const uint8_t g_aes_zero_block[ATCA_AES128_BLOCK_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/** \brief Initialize a CMAC calculation using an AES-128 key in the device.
 *
 * \param[in] device     Device context pointer
 * \param[in] ctx        AES-128 CMAC context.
 * \param[in] key_id     Key location. Can either be a slot/handles or
 *                       in TempKey.
 * \param[in] key_block  Index of the 16-byte block to use within the key
 *                       location for the actual key.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_aes_cmac_init_ext(ATCADevice device, atca_aes_cmac_ctx_t* ctx, uint16_t key_id, uint8_t key_block)
{
    if (ctx == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }
    (void)memset(ctx, 0, sizeof(*ctx));
    // IV for CMAC CBC calculations is all zeros
    return atcab_aes_cbc_init_ext(device, &ctx->cbc_ctx, key_id, key_block, g_aes_zero_block, 0);
}

/** \brief Initialize a CMAC calculation using an AES-128 key in the device.
 *
 * \param[in] ctx        AES-128 CMAC context.
 * \param[in] key_id     Key location. Can either be a slot/handles or
 *                       in TempKey.
 * \param[in] key_block  Index of the 16-byte block to use within the key
 *                       location for the actual key.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_aes_cmac_init(atca_aes_cmac_ctx_t* ctx, uint16_t key_id, uint8_t key_block)
{
    return atcab_aes_cmac_init_ext(atcab_get_device(), ctx, key_id, key_block);
}

/** \brief Add data to an initialized CMAC calculation.
 *
 * \param[in] ctx        AES-128 CMAC context.
 * \param[in] data       Data to be added.
 * \param[in] data_size  Size of the data to be added in bytes.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_aes_cmac_update(atca_aes_cmac_ctx_t* ctx, const uint8_t* data, uint32_t data_size)
{
    uint32_t rem_size;
    size_t copy_size;
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t ciphertext[ATCA_AES128_BLOCK_SIZE];
    uint32_t block_count;
    uint32_t i;

    if (ctx == NULL || data == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    rem_size = ATCA_AES128_BLOCK_SIZE - ctx->block_size;
    copy_size = data_size > rem_size ? (size_t)rem_size : (size_t)data_size;

    (void)memcpy(&ctx->block[ctx->block_size], data, copy_size);

    if (ctx->block_size + data_size < ATCA_AES128_BLOCK_SIZE + 1u)
    {
        // The last block of a CMAC operation is handled specially, so we don't
        // process a complete block unless we know there's data afterwards.
        ctx->block_size += data_size;
        return ATCA_SUCCESS;
    }

    // Process the current block
    if (ATCA_SUCCESS != (status = atcab_aes_cbc_encrypt_block(&ctx->cbc_ctx, ctx->block, ciphertext)))
    {
        return status;
    }

    // Process any additional blocks
    data_size -= (uint32_t)copy_size; // Adjust to the remaining message bytes
    block_count = data_size / ATCA_AES128_BLOCK_SIZE;
    if (block_count > 0u && data_size % ATCA_AES128_BLOCK_SIZE == 0u)
    {
        block_count--; // Don't process last block because it may need special handling
    }
    for (i = 0; i < block_count; i++)
    {
        if (ATCA_SUCCESS != (status = atcab_aes_cbc_encrypt_block(&ctx->cbc_ctx, &data[copy_size + (size_t)i * ATCA_AES128_BLOCK_SIZE], ciphertext)))
        {
            return status;
        }
        data_size -= ATCA_AES128_BLOCK_SIZE;
    }

    // Save any remaining data
    ctx->block_size = data_size;
    (void)memcpy(ctx->block, &data[copy_size + (size_t)block_count * ATCA_AES128_BLOCK_SIZE], (size_t)ctx->block_size);

    return ATCA_SUCCESS;
}

/** \brief Left shift an MSB buffer by 1 bit.
 *
 * \param[in,out] data       Data to left shift.
 * \param[in]    data_size  Size of data in bytes.
 */
static void left_shift_one(uint8_t* data, size_t data_size)
{
    size_t i;

    for (i = 0; i < data_size; i++)
    {
        /* coverity[cert_int34_c_violation:FALSE] Overflow is handled in the subsequent step */
        data[i] = (uint8_t)(data[i] << 1);
        if (i + 1u < data_size && (0x80u == (data[i + 1u] & 0x80u)))
        {
            data[i] |= 0x01u; // Next byte has a bit that needs to be shifted into this one
        }
    }
}

/** \brief Finish a CMAC operation returning the CMAC value.
 *
 * \param[in]  ctx        AES-128 CMAC context.
 * \param[out] cmac       CMAC is returned here.
 * \param[in]  cmac_size  Size of CMAC requested in bytes (max 16 bytes).
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_aes_cmac_finish(atca_aes_cmac_ctx_t* ctx, uint8_t* cmac, uint32_t cmac_size)
{
    uint32_t i;
    uint8_t subkey[ATCA_AES128_BLOCK_SIZE];
    ATCA_STATUS status = ATCA_SUCCESS;
    bool is_msb_one;
    uint8_t cmac_full[ATCA_AES128_BLOCK_SIZE];

    if (ctx == NULL || cmac == NULL || cmac_size > ATCA_AES128_BLOCK_SIZE)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Either NULL pointer or invalid cmac size received");
    }

    // Calculate L as AES Encrypt of an all zero block
    if (ATCA_SUCCESS != (status = atcab_aes_encrypt_ext(ctx->cbc_ctx.device, ctx->cbc_ctx.key_id, ctx->cbc_ctx.key_block, g_aes_zero_block, subkey)))
    {
        return status;
    }

    // Calculate subkey 1
    is_msb_one = ((subkey[0] >> 7u) == 0x1u);
    left_shift_one(subkey, sizeof(subkey)); // L << 1
    if (is_msb_one)
    {
        subkey[ATCA_AES128_BLOCK_SIZE - 1u] ^= 0x87u; // (L << 1) XOR R128
    }

    if (ctx->block_size != ATCA_AES128_BLOCK_SIZE)
    {
        // Data is not a complete block, we calculate subkey 2
        is_msb_one = ((subkey[0] >> 7u) == 0x1u);
        left_shift_one(subkey, sizeof(subkey)); // K1 << 1
        if (is_msb_one)
        {
            subkey[ATCA_AES128_BLOCK_SIZE - 1u] ^= 0x87u; // (K1 << 1) XOR R128
        }

        // Pad out an incomplete block starting with a 1 bit, followed by zeros
        for (i = 0; i < ATCA_AES128_BLOCK_SIZE - ctx->block_size; i++)
        {
            ctx->block[ctx->block_size + i] = (uint8_t)(i == 0u ? 0x80u : 0x00u);
        }
    }

    // XOR last block with subkey
    for (i = 0; i < ATCA_AES128_BLOCK_SIZE; i++)
    {
        ctx->block[i] ^= subkey[i];
    }

    // Process last block
    if (ATCA_SUCCESS != (status = atcab_aes_cbc_encrypt_block(&ctx->cbc_ctx, ctx->block, cmac_full)))
    {
        return status;
    }

    (void)memcpy(cmac, cmac_full, (size_t)cmac_size);

    return ATCA_SUCCESS;
}
#endif /* ATCAB_AES_CMAC_EN */
