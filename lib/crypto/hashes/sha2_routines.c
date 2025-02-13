/**
 * \file
 * \brief Software implementation of the SHA256, SHA384 and SHA512 algorithm.
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
#include "sha2_routines.h"

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "CERT INT30-C" "Wrap doesnt affect functionality for SHA")
#endif

#define rotate_right(value, places) (((value) >> (places)) | ((value) << (32U - (places))))
#define rotate_right_64bit(value, places) (((value) >> (places)) | ((value) << (64U - (places))))

#if ATCA_CRYPTO_SHA256_EN
/**
 * \brief Processes whole blocks (64 bytes) of data.
 *
 * \param[in] ctx          SHA256 hash context
 * \param[in] blocks       Raw blocks to be processed
 * \param[in] block_count  Number of 64-byte blocks to process
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS sw_sha256_process(sw_sha256_ctx* ctx, const uint8_t* blocks, uint32_t block_count)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    uint16_t i = 0u;
    uint32_t block = 0u;

    if((NULL == ctx) || (NULL == blocks))
    {
        return status;
    }

    union
    {
        uint32_t w_word[SHA256_BLOCK_SIZE];
        uint8_t  w_byte[SHA256_BLOCK_SIZE * sizeof(uint32_t)];
    } w_union;

    static const uint32_t k[] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

    (void)memset(&w_union, 0, sizeof(w_union));

    // Loop through all the blocks to process
    for (block = 0; block < block_count; block++)
    {
        uint32_t w_index = 0U;
        uint32_t word_value = 0U;
        uint32_t s0, s1 = 0U;
        uint32_t t1, t2 = 0U;
        uint32_t maj, ch = 0U;
        uint32_t rotate_register[8] = {0U};
        const uint8_t* cur_msg_block = &blocks[block * SHA256_BLOCK_SIZE];

        // Swap word bytes
        for (i = 0U; i < SHA256_BLOCK_SIZE; i += 4U)
        {
            w_union.w_byte[i + 3U] = cur_msg_block[i + 0U];
            w_union.w_byte[i + 2U] = cur_msg_block[i + 1U];
            w_union.w_byte[i + 1U] = cur_msg_block[i + 2U];
            w_union.w_byte[i + 0U] = cur_msg_block[i + 3U];
            w_union.w_word[i / 4U] = ATCA_UINT32_HOST_TO_LE(w_union.w_word[i / 4U]);
        }

        w_index = 16u;
        while (w_index < SHA256_BLOCK_SIZE)
        {
            // right rotate for 32-bit variable in C: (value >> places) | (value << 32 - places)
            word_value = w_union.w_word[w_index - 15U];
            s0 = rotate_right(word_value, 7U) ^ rotate_right(word_value, 18U) ^ (word_value >> 3U);

            word_value = w_union.w_word[w_index - 2U];
            s1 = rotate_right(word_value, 17U) ^ rotate_right(word_value, 19U) ^ (word_value >> 10U);

            w_union.w_word[w_index] = w_union.w_word[w_index - 16U] + s0 + w_union.w_word[w_index - 7U] + s1;

            w_index++;
        }

        // Initialize hash value for this chunk.
        for (i = 0U; i < 8U; i++)
        {
            rotate_register[i] = ctx->hash[i];
        }

        // hash calculation loop
        for (i = 0U; i < SHA256_BLOCK_SIZE; i++)
        {
            s0 = rotate_right(rotate_register[0], 2U)
                 ^ rotate_right(rotate_register[0], 13U)
                 ^ rotate_right(rotate_register[0], 22U);
            maj = (rotate_register[0] & rotate_register[1])
                  ^ (rotate_register[0] & rotate_register[2])
                  ^ (rotate_register[1] & rotate_register[2]);
            t2 = s0 + maj;
            s1 = rotate_right(rotate_register[4], 6U)
                 ^ rotate_right(rotate_register[4], 11U)
                 ^ rotate_right(rotate_register[4], 25U);
            ch = (rotate_register[4] & rotate_register[5])
                 ^ (~rotate_register[4] & rotate_register[6]);
            t1 = rotate_register[7] + s1 + ch + k[i] + w_union.w_word[i];

            rotate_register[7] = rotate_register[6];
            rotate_register[6] = rotate_register[5];
            rotate_register[5] = rotate_register[4];
            rotate_register[4] = rotate_register[3] + t1;
            rotate_register[3] = rotate_register[2];
            rotate_register[2] = rotate_register[1];
            rotate_register[1] = rotate_register[0];
            rotate_register[0] = t1 + t2;
        }

        // Add the hash of this block to current result.
        for (i = 0U; i < 8U; i++)
        {
            ctx->hash[i] += rotate_register[i];
        }
    }

    return (status = ATCA_SUCCESS);
}
#endif

#if ATCA_CRYPTO_SHA512_EN
/**
 * \brief Processes whole blocks (128 bytes) of data.
 *
 * \param[in] ctx          SHA512 hash context
 * \param[in] blocks       Raw blocks to be processed
 * \param[in] block_count  Number of 128-byte blocks to process
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS sw_sha512_process(sw_sha512_ctx* ctx, const uint8_t* blocks, uint32_t block_count)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    uint16_t i = 0u;
    uint32_t block = 0u;

    if((NULL == ctx) || (NULL == blocks))
    {
        return status;
    }

    union
    {
        uint64_t w_dword[SHA512_BLOCK_SIZE];
        uint8_t  w_byte[SHA512_BLOCK_SIZE * sizeof(uint64_t)];
    } w_union;

    static const uint64_t k[] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };

    (void)memset(&w_union, 0, sizeof(w_union));

    // Loop through all the blocks to process
    for (block = 0; block < block_count; block++)
    {
         uint32_t w_index =0U;
         uint64_t word_value =0U;
         uint64_t s0, s1 = 0U;
         uint64_t t1, t2 = 0U;
         uint64_t maj, ch = 0U ;
         uint64_t rotate_register[8] = {0U};
         const uint8_t* cur_msg_block = &blocks[block * SHA512_BLOCK_SIZE];

         // Swap word bytes
        for (i = 0U; i < SHA512_BLOCK_SIZE; i += 8U)
        {
            w_union.w_byte[i + 7U] = cur_msg_block[i + 0U];
            w_union.w_byte[i + 6U] = cur_msg_block[i + 1U];
            w_union.w_byte[i + 5U] = cur_msg_block[i + 2U];
            w_union.w_byte[i + 4U] = cur_msg_block[i + 3U];
            w_union.w_byte[i + 3U] = cur_msg_block[i + 4U];
            w_union.w_byte[i + 2U] = cur_msg_block[i + 5U];
            w_union.w_byte[i + 1U] = cur_msg_block[i + 6U];
            w_union.w_byte[i + 0U] = cur_msg_block[i + 7U];
            w_union.w_dword[i / 8U] = ATCA_UINT64_HOST_TO_LE(w_union.w_dword[i / 8U]);
        }

        w_index = 16u;
        while (w_index < 80u)
        {
            // right rotate for 64-bit variable in C: (value >> places) | (value << 64 - places)
            word_value = w_union.w_dword[w_index - 15u];
            s0 = (rotate_right_64bit(word_value, 1U)) ^ (rotate_right_64bit(word_value, 8U)) ^ (word_value >> 7U);

            word_value = w_union.w_dword[w_index - 2u];
            s1 = (rotate_right_64bit(word_value, 19U)) ^ (rotate_right_64bit(word_value, 61U)) ^ (word_value >> 6U);

            w_union.w_dword[w_index] = w_union.w_dword[w_index - 16u] + s0 + w_union.w_dword[w_index - 7u] + s1;

            w_index++;
        }

        // Initialize hash value for this chunk.
        for (i = 0U; i < 8U; i++)
        {
            rotate_register[i] = ctx->hash[i];
        }

        // hash calculation loop
        for (i = 0U; i < 80U; i++)
        {
            s0 = (rotate_right_64bit(rotate_register[0], 28U))
                 ^ (rotate_right_64bit(rotate_register[0], 34U))
                 ^ (rotate_right_64bit(rotate_register[0], 39U));
            maj = (rotate_register[0] & rotate_register[1])
                  ^ (rotate_register[0] & rotate_register[2])
                  ^ (rotate_register[1] & rotate_register[2]);
            t2 = s0 + maj;
            s1 = (rotate_right_64bit(rotate_register[4], 14U))
                 ^ (rotate_right_64bit(rotate_register[4], 18U))
                 ^ (rotate_right_64bit(rotate_register[4], 41U));
            ch = (rotate_register[4] & rotate_register[5])
                 ^ (~rotate_register[4] & rotate_register[6]);
            t1 = rotate_register[7] + s1 + ch + k[i] + w_union.w_dword[i];

            rotate_register[7] = rotate_register[6];
            rotate_register[6] = rotate_register[5];
            rotate_register[5] = rotate_register[4];
            rotate_register[4] = rotate_register[3] + t1;
            rotate_register[3] = rotate_register[2];
            rotate_register[2] = rotate_register[1];
            rotate_register[1] = rotate_register[0];
            rotate_register[0] = t1 + t2;
        }

        // Add the hash of this block to current result.
        for (i = 0U; i < 8U; i++)
        {
            ctx->hash[i] += rotate_register[i];
        }
    }

    return (status = ATCA_SUCCESS);
}
#endif

#if ATCA_CRYPTO_SHA256_EN
/**
 * \brief Intialize the software SHA256.
 *
 * \param[in] ctx          SHA256 hash context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS sw_sha256_init(sw_sha256_ctx* ctx)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    static const uint32_t hash_init[] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    int i;

    if(NULL == ctx)
    {
        return status;
    }

    (void)memset(ctx, 0, sizeof(*ctx));
    for (i = 0; i < 8; i++)
    {
        ctx->hash[i] = hash_init[i];
    }

    return (status = ATCA_SUCCESS);
}

/**
 * \brief updates the running hash with the next block of data, called iteratively for the entire
 *  stream of data to be hashed using the SHA256 software
 *
 * \param[in] ctx          SHA256 hash context
 * \param[in] msg          Raw blocks to be processed
 * \param[in] msg_size     The size of the message passed
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS sw_sha256_update(sw_sha256_ctx* ctx, const uint8_t* msg, uint32_t msg_size)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    uint32_t block_count;

    if(NULL == ctx)
    {
        return status;
    }

    uint32_t rem_size = SHA256_BLOCK_SIZE - ctx->block_size;
    uint32_t copy_size = msg_size > rem_size ? rem_size : msg_size;

    if (0u == msg_size || NULL == msg)
    {
        status = ATCA_SUCCESS;
        return status;
    }

    // Copy data into current block
    (void)memcpy(&ctx->block[ctx->block_size], msg, (size_t)copy_size);

    if (ctx->block_size + msg_size < SHA256_BLOCK_SIZE)
    {
        // Not enough data to finish off the current block
        // This data will be processed in sw_sha256_final
        ctx->block_size += msg_size;
        status = ATCA_SUCCESS;
        return status;
    }

    // Process the current block
    if(ATCA_SUCCESS != (status = sw_sha256_process(ctx, ctx->block, 1)))
    {
        return status;
    }

    // Process any additional blocks
    msg_size -= copy_size; // Adjust to the remaining message bytes
    block_count = msg_size / SHA256_BLOCK_SIZE;
    if(ATCA_SUCCESS != (status = sw_sha256_process(ctx, &msg[copy_size], block_count)))
    {
        return status;
    }

    // Save any remaining data
    ctx->total_msg_size += (block_count + 1U) * SHA256_BLOCK_SIZE;
    ctx->block_size = msg_size % SHA256_BLOCK_SIZE;
    (void)memcpy(ctx->block, &msg[copy_size + block_count * SHA256_BLOCK_SIZE], (size_t)ctx->block_size);

    return status;
}


/** \brief completes the final SHA256 calculation and returns the final digest/hash
 * \param[in]  ctx     ptr to context data structure
 * \param[out] digest  receives the computed digest of the SHA 256
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS sw_sha256_final(sw_sha256_ctx* ctx, uint8_t digest[SHA256_DIGEST_SIZE])
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    int32_t  i, j;
    uint32_t msg_size_bits = 0U;
    uint32_t pad_zero_count = 0u;
    int32_t byte_cnt = (int32_t)(sizeof(uint32_t));

    if(NULL == ctx)
    {
        return status;
    }

    // Calculate the total message size in bits
    ctx->total_msg_size += ctx->block_size;

    if(true == IS_MUL_SAFE_UINT32_T(ctx->total_msg_size, 8U))
    {
        msg_size_bits = ctx->total_msg_size * 8U;
    }

    // Calculate the number of padding zero bytes required between the 1 bit byte and the 64 bit message size in bits.
    pad_zero_count = (SHA256_BLOCK_SIZE - ((ctx->block_size + 9U) % SHA256_BLOCK_SIZE)) % SHA256_BLOCK_SIZE;

    // Append a single 1 bit
    ctx->block[ctx->block_size++] = 0x80;

    // Add padding zeros plus upper 4 bytes of total msg size in bits (only supporting 32bit message bit counts)
    (void)memset(&ctx->block[ctx->block_size], 0, (size_t)pad_zero_count + 4U);

    pad_zero_count +=4U;

    if(true == IS_ADD_SAFE_UINT32_T(ctx->block_size, pad_zero_count))
    {
        ctx->block_size += pad_zero_count;
    }

    // Add the total message size in bits to the end of the current block. Technically this is
    // supposed to be 8 bytes. This shortcut will reduce the max message size to 536,870,911 bytes.
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 24U) & UINT8_MAX);
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 16U) & UINT8_MAX);
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 8U) & UINT8_MAX);
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 0U) & UINT8_MAX);

    if(ATCA_SUCCESS != (status = sw_sha256_process(ctx, ctx->block, ctx->block_size / SHA256_BLOCK_SIZE)))
    {
        return status;
    }

    // All blocks have been processed.
    // Concatenate the hashes to produce digest, MSB of every hash first.
    for (i = 0; i < 8; i++)
    {
        for (j = byte_cnt - 1; j >= 0; j--)
        {
            if ((i <= (INT32_MAX / byte_cnt)) && ((i * byte_cnt) <= (INT32_MAX - j)))
            {
                digest[i * byte_cnt + j] = (uint8_t)(ctx->hash[i] & 0xFFu);
            }
            ctx->hash[i] >>= 8u;
        }
    }

    return status;
}

/** \brief single call convenience function which computes Hash of given data using SHA256 software
 * \param[in]  message       pointer to stream of data to hash
 * \param[in]  len           size of data stream to hash
 * \param[out] digest        result
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS sw_sha256(const uint8_t* message, unsigned int len, uint8_t digest[SHA256_DIGEST_SIZE])
{
    ATCA_STATUS status;
    sw_sha256_ctx ctx;

    if(ATCA_SUCCESS == (status = sw_sha256_init(&ctx)))
    {
        if(ATCA_SUCCESS == (status = sw_sha256_update(&ctx, message, len)))
        {
            status = sw_sha256_final(&ctx, digest);
        }
    }

    return status;
}
#endif

#if ATCA_CRYPTO_SHA512_EN
/**
 * \brief Intialize the software SHA512.
 *
 * \param[in] ctx          SHA512 hash context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS sw_sha512_init(sw_sha512_ctx* ctx)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    int i;

    if(NULL == ctx)
    {
        return status;
    }

    static const uint64_t hash_init[] = {
        0x6a09e667f3bcc908U, 0xbb67ae8584caa73bU, 0x3c6ef372fe94f82bU, 0xa54ff53a5f1d36f1U,
        0x510e527fade682d1U, 0x9b05688c2b3e6c1fU, 0x1f83d9abfb41bd6bU, 0x5be0cd19137e2179U
    };

    (void)memset(ctx, 0, sizeof(*ctx));
    for (i = 0; i < 8; i++)
    {
        ctx->hash[i] = hash_init[i];
    }

    return (status = ATCA_SUCCESS);
}

/**
 * \brief updates the running hash with the next block of data, called iteratively for the entire
 *  stream of data to be hashed using the SHA512 software
 *
 * \param[in] ctx          SHA512 hash context
 * \param[in] msg          Raw blocks to be processed
 * \param[in] msg_size     The size of the message passed
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS sw_sha512_update(sw_sha512_ctx* ctx, const uint8_t* msg, uint32_t msg_size)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    uint32_t block_count;
    uint32_t tmp_size = 0U;

    if(NULL == ctx)
    {
        return status;
    }

    uint32_t rem_size = SHA512_BLOCK_SIZE - ctx->block_size;
    uint32_t copy_size = msg_size > rem_size ? rem_size : msg_size;

    if (0u == msg_size || NULL == msg)
    {
        status = ATCA_SUCCESS;
        return status;
    }

    // Copy data into current block
    (void)memcpy(&ctx->block[ctx->block_size], msg, copy_size);

    if(true == IS_ADD_SAFE_UINT32_T(ctx->block_size, msg_size))
    {
        if (ctx->block_size + msg_size < SHA512_BLOCK_SIZE)
        {
            // Not enough data to finish off the current block
            // This data will be processed in sw_sha512_final
            ctx->block_size += msg_size;
            status = ATCA_SUCCESS;
            return status;
        }
    }

    // Process the current block
    if(ATCA_SUCCESS != (status = sw_sha512_process(ctx, ctx->block, 1)))
    {
        return status;
    }

    // Process any additional blocks
    msg_size -= copy_size; // Adjust to the remaining message bytes
    block_count = msg_size / SHA512_BLOCK_SIZE;
    if(ATCA_SUCCESS != (status = sw_sha512_process(ctx, &msg[copy_size], block_count)))
    {
         return status;
    }

    // Save any remaining data
    if(true == IS_ADD_SAFE_UINT32_T(block_count, 1U))
    {
        tmp_size = block_count + 1U;
    }

    if(true == IS_MUL_SAFE_UINT32_T(tmp_size, SHA512_BLOCK_SIZE))
    {
        tmp_size *= SHA512_BLOCK_SIZE;
    }

    if(true == IS_ADD_SAFE_UINT32_T(ctx->total_msg_size, tmp_size))
    {
        ctx->total_msg_size += tmp_size;
    }

    ctx->block_size = msg_size % SHA512_BLOCK_SIZE;
    (void)memcpy(ctx->block, &msg[copy_size + block_count * SHA512_BLOCK_SIZE], (size_t)ctx->block_size);

    return status;
}

/** \brief completes the final SHA512 calculation and returns the final digest/hash
 * \param[in]  ctx     ptr to context data structure
 * \param[out] digest  receives the computed digest of the SHA 512
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS sw_sha512_final(sw_sha512_ctx* ctx, uint8_t digest[SHA512_DIGEST_SIZE])
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    int32_t i, j;
    uint32_t msg_size_bits = 0u;
    uint32_t pad_zero_count = 0u;
    int32_t byte_cnt = (int32_t)(sizeof(uint64_t));

    if (NULL == ctx)
    {
            return status;
    }

    // Calculate the total message size in bits
    if(true == IS_ADD_SAFE_UINT32_T(ctx->total_msg_size, ctx->block_size))
    {
        ctx->total_msg_size += ctx->block_size;
    }

    if(true == IS_MUL_SAFE_UINT32_T(ctx->total_msg_size, 8U))
    {
        msg_size_bits = ctx->total_msg_size * 8U;
    }

    // Calculate the number of padding zero bytes required between the 1 bit byte and the 128 bit message size in bits.
    pad_zero_count = (SHA512_BLOCK_SIZE - ((ctx->block_size + 17u) % SHA512_BLOCK_SIZE)) % SHA512_BLOCK_SIZE;

    // Append a single 1 bit
    ctx->block[ctx->block_size++] = 0x80;

    // Add padding zeros plus upper 12 bytes of total msg size in bits (only supporting 32bit message bit counts)
    (void)memset(&ctx->block[ctx->block_size], 0, (size_t)pad_zero_count + 12U);

    pad_zero_count += 12U;

    if(true == IS_ADD_SAFE_UINT32_T(ctx->block_size, pad_zero_count))
    {
        ctx->block_size += pad_zero_count;
    }

    // Add the total message size in bits to the end of the current block. Technically this is
    // supposed to be 8 bytes. This shortcut will reduce the max message size to 536,870,911 bytes.
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 24) & UINT8_MAX);
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 16) & UINT8_MAX);
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 8)& UINT8_MAX);
    ctx->block[ctx->block_size++] = (uint8_t)((msg_size_bits >> 0)& UINT8_MAX);

    if(ATCA_SUCCESS != (status = sw_sha512_process(ctx, ctx->block, ctx->block_size / SHA512_BLOCK_SIZE)))
    {
        return status;
    }

    // All blocks have been processed.
    // Concatenate the hashes to produce digest, MSB of every hash first.
    for (i = 0; i < 8; i++)
    {
        for (j = byte_cnt - 1; j >= 0; j--)
        {
            if ((i <= (INT32_MAX / byte_cnt)) && ((i * byte_cnt) <= (INT32_MAX - j)))
            {
                digest[i * byte_cnt + j] = (uint8_t)(ctx->hash[i] & 0xFFu);
            }
            ctx->hash[i] >>= 8u;
        }
    }

    return status;
}

/** \brief single call convenience function which computes Hash of given data using SHA512 software
 * \param[in]  message       pointer to stream of data to hash
 * \param[in]  len           size of data stream to hash
 * \param[out] digest        result
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS sw_sha512(const uint8_t* message, unsigned int len, uint8_t digest[SHA512_DIGEST_SIZE])
{
    ATCA_STATUS status;
    sw_sha512_ctx ctx;

    if(ATCA_SUCCESS == (status = sw_sha512_init(&ctx)))
    {
       if(ATCA_SUCCESS == (status = sw_sha512_update(&ctx, message, len)))
       {
            status = sw_sha512_final(&ctx, digest);
       }
    }

    return status;
}
#endif

#if ATCA_CRYPTO_SHA384_EN
/**
 * \brief Intialize the software SHA384.
 *
 * \param[in] ctx          SHA384 hash context
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS sw_sha384_init(sw_sha512_ctx* ctx)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    int i;

    if(NULL == ctx)
    {
        return status;
    }

    static const uint64_t hash_init[] = {
        0xcbbb9d5dc1059ed8U, 0x629a292a367cd507U, 0x9159015a3070dd17U, 0x152fecd8f70e5939U,
        0x67332667ffc00b31U, 0x8eb44a8768581511U, 0xdb0c2e0d64f98fa7U, 0x47b5481dbefa4fa4U
    };

    (void)memset(ctx, 0, sizeof(*ctx));
    for (i = 0; i < 8; i++)
    {
        ctx->hash[i] = hash_init[i];
    }

    return (status = ATCA_SUCCESS);
}

/**
 * \brief updates the running hash with the next block of data, called iteratively for the entire
 *  stream of data to be hashed using the SHA384 software
 *
 * \param[in] ctx          SHA384 hash context
 * \param[in] msg          Raw blocks to be processed
 * \param[in] msg_size     The size of the message passed
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS sw_sha384_update(sw_sha512_ctx* ctx, const uint8_t* msg, uint32_t msg_size)
{
    ATCA_STATUS status;
    status = sw_sha512_update(ctx, msg, msg_size);
    return status;
}


/** \brief completes the final SHA384 calculation and returns the final digest/hash
 * \param[in]  ctx     ptr to context data structure
 * \param[out] digest  receives the computed digest of the SHA 384
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS sw_sha384_final(sw_sha512_ctx* ctx, uint8_t digest[SHA384_DIGEST_SIZE])
{
   ATCA_STATUS status;
   uint8_t tmp_dgst[SHA512_DIGEST_SIZE] = {0u};

   status = sw_sha512_final(ctx, tmp_dgst);
   // For SHA384 copy only 48 bytes to O/P digest
   (void)memcpy(digest, tmp_dgst, SHA384_DIGEST_SIZE);

   return status;
}

/** \brief single call convenience function which computes Hash of given data using SHA384 software
 * \param[in]  message       pointer to stream of data to hash
 * \param[in]  len           size of data stream to hash
 * \param[out] digest        result
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS sw_sha384(const uint8_t* message, unsigned int len, uint8_t digest[SHA384_DIGEST_SIZE])
{
    ATCA_STATUS status;
    sw_sha512_ctx ctx;

    if(ATCA_SUCCESS == (status = sw_sha384_init(&ctx)))
    {
        if(ATCA_SUCCESS == (status = sw_sha384_update(&ctx, message, len)))
        {
            status = sw_sha384_final(&ctx, digest);
        }
    }

    return status;
}
#endif
