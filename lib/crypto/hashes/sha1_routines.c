/**
 * \file
 * \brief Software implementation of the SHA1 algorithm.
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

#include "sha1_routines.h"
#include <string.h>
#include "atca_compiler.h"
#include "cryptoauthlib.h"

#if ATCA_CRYPTO_SHA1_EN
/**
 * \brief Initialize context for performing SHA1 hash in software.
 *
 * \param[in] ctx  Hash context
 */
void CL_hashInit(CL_HashContext *ctx)
{
    static const U32 hashContext_h_init[] = {
        0x67452301U,
        0xefcdab89U,
        0x98badcfeU,
        0x10325476U,
        0xc3d2e1f0U
    };

    // Initialize context
    (void)memset(ctx, 0, sizeof(*ctx));
    (void)memcpy_P(ctx->h, hashContext_h_init, sizeof(ctx->h));
}



/**
 * \brief Add arbitrary data to a SHA1 hash.
 *
 * \param[in] ctx     Hash context
 * \param[in] src     Data to be added to the hash
 * \param[in] nbytes  Data size in bytes
 */

void CL_hashUpdate(CL_HashContext *ctx, const U8 *src, int nbytes)
{

    /*
       Digest src bytes, updating context.
     */

    U8 i, freeBytes;
    U32 temp32;

    // Get number of free bytes in the buf
    freeBytes = (U8)(ctx->byteCount);
    freeBytes &= 63u;
    freeBytes = (U8)(64u - freeBytes);

    while (nbytes > 0)
    {

        // Get i, number of bytes to transfer from src
        i = freeBytes;
        if (nbytes < i)
        {
            i = (U8)nbytes;
        }

        // Copy src bytes to buf
        if (i == 64u)
        {
            (void)memcpy(((U8*)ctx->buf), src, i);
        }
        else
        {
            // Have to use memcpy, size is other than 64 bytes.
            (void)memcpy(((U8*)ctx->buf) + 64u - freeBytes, src, i);
        }

        // Adjust for transferred bytes
        src += i;
        nbytes -= i;
        freeBytes -= i;

        // Do SHA crunch if buf is full
        if (freeBytes == 0u)
        {
            shaEngine(ctx->buf, ctx->h);
        }

        // Update 64-bit byte count
        temp32 = (ctx->byteCount += i);
        if (temp32 == 0u)
        {
            ++ctx->byteCountHi;
        }

        // Set up for next iteration
        freeBytes = 64u;
    }
}



/** \brief Complete the SHA1 hash in software and return the digest.
 * \param[in]  ctx   Hash context
 * \param[out] dest  Digest is returned here (20 bytes)
 */
void CL_hashFinal(CL_HashContext *ctx, U8 *dest)
{

    /*
       Finish a hash calculation and put result in dest.
     */

    U8 i;
    U8 nbytes;
    U32 temp;
    U8 *ptr;

    /* Append pad byte, clear trailing bytes */
    nbytes = (U8)(ctx->byteCount & 63u);
    ((U8*)ctx->buf)[nbytes] = 0x80u;
    for (i = (nbytes + 1u); i < 64u; i++)
    {
        ((U8*)ctx->buf)[i] = 0u;
    }

    /*
       If no room for an 8-byte count at end of buf, digest the buf,
       then clear it
     */
    if (nbytes > (64u - 9u))
    {
        shaEngine(ctx->buf, ctx->h);
        (void)memset(ctx->buf, 0, 64u);
    }

    /*
       Put the 8-byte bit count at end of buf.  We have been tracking
       bytes, not bits, so we left-shift our byte count by 3 as we do
       this.
     */
    temp = ctx->byteCount << 3u; // low 4 bytes of bit count
    ptr = &((U8*)ctx->buf)[63u]; // point to low byte of bit count
    for (i = 0; i < 4u; i++)
    {
        *ptr-- = (U8)temp;
        temp >>= 8u;
    }
    //
    temp = ctx->byteCountHi << 3u;
    temp |= ctx->byteCount >> (32u - 3u); // high 4 bytes of bit count
    for (i = 0u; i < 4u; i++)
    {
        *ptr-- = (U8)temp;
        temp >>= 8u;
    }
    //show("final SHA crunch", ctx->buf, 64);

    /* Final digestion */
    shaEngine(ctx->buf, ctx->h);

    /* Unpack chaining variables to dest bytes. */
    for (i = 0; i < 5u; i++)
    {
        temp = ATCA_UINT32_BE_TO_HOST(ctx->h[i]);
        (void)memcpy(dest, &temp, sizeof(temp));
        dest += sizeof(temp);
    }
}



/** \brief Perform SHA1 hash of data in software.
 * \param[in]  msg       Data to be hashed
 * \param[in]  msgBytes  Data size in bytes
 * \param[out] dest      Digest is returned here (20 bytes)
 */
void CL_hash(U8 *msg, int msgBytes, U8 *dest)
{
    CL_HashContext ctx;

    CL_hashInit(&ctx);
    CL_hashUpdate(&ctx, msg, msgBytes);
    CL_hashFinal(&ctx, dest);
}

void shaEngine(U32 *buf, U32 *h)
{

    /*
       SHA-1 Engine.  From FIPS 180.

       On entry, buf[64] contains the 64 bytes to digest.  These bytes
       are destroyed.

       _H[20] contains the 5 chaining variables.  They must have the
       proper value on entry and are updated on exit.

       The order of bytes in buf[] and _h[] matches that used by the
       hardware SHA engine.
     */

    U8 t;
    U32 a, b, c, d, e;
    U64 temp = 0u;
    U8 *p;
    U32 *w = (U32*)buf;

    /*
       Pack first 64 bytes of buf into w[0,...,15].  Within a word,
       bytes are big-endian.  Do this in place -- buf[0,...,63]
       overlays w[0,...,15].
     */
    p = (U8*)w;
    for (t = 0u; t < 16u; t++)
    {
        temp = (temp << 8u) | *p++;
        temp = (temp << 8u) | *p++;
        temp = (temp << 8u) | *p++;
        temp = (temp << 8u) | *p++;
        /* coverity[cert_int31_c_violation:FALSE] temp is always less than UINT32_MAX */
        w[t] = (U32)temp;
    }

    /*
       Pack the 20 bytes of _h[] into h[0,...,4].  Do in place using
       same convention as for buidling w[].
     */
    //p = (U8*)h;
    //for (t = 0; t < 5; t++) {
    //temp = (temp << 8) | *p++;
    //temp = (temp << 8) | *p++;
    //temp = (temp << 8) | *p++;
    //temp = (temp << 8) | *p++;
    //h[t] = temp;
    //}

    /* Copy the chaining variables to a, b, c, d, e */
    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];

    /* Now do the 80 rounds */
    for (t = 0u; t < 80u; t++)
    {

        temp = a;
        leftRotate(temp, 5);
        temp += e;
        if(true == IS_ADD_SAFE_UINT64_T(temp, w[t & 0xfu]))
        {
            temp += w[t & 0xfu];
        }

        if (t < 20u)
        {
            temp += (b & c) | (~b & d);
            if(true == IS_ADD_SAFE_UINT64_T(temp, 0x5a827999U))
            {
                temp += 0x5a827999U;
            }
        }
        else if (t < 40u)
        {
            temp += b ^ c ^ d;
            if(true == IS_ADD_SAFE_UINT64_T(temp, 0x6ed9eba1U))
            {
                temp += 0x6ed9eba1U;
            }
        }
        else if (t < 60u)
        {
            temp += (b & c) | (b & d) | (c & d);
            if(true == IS_ADD_SAFE_UINT64_T(temp, 0x8f1bbcdcU))
            {
                temp += 0x8f1bbcdcU;
            }
        }
        else
        {
            temp += b ^ c ^ d;
            if(true == IS_ADD_SAFE_UINT64_T(temp, 0xca62c1d6U))
            {
                temp += 0xca62c1d6U;
            }
        }

        e = d;
        d = c;
        c = b; leftRotate(c, 30);
        b = a;
        a = (U32)temp;

        temp = (U64)(w[t & 0xfu]) ^ (U64)(w[(t - 3u) & 0xfu]) ^ (U64)(w[(t - 8u) & 0xfu]) ^ (U64)(w[(t - 14u) & 0xfu]);
        
        leftRotate(temp, 1);
        w[t & 0xfu] = (uint32_t)temp;

    }

    /* Update the chaining variables */
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;

    /* Unpack the chaining variables into _h[] buffer. */
    //p = (U8*)h;
    //for (t = 0; t < 5; t++) {
    //temp = h[t];
    //p[3] = (U8)temp; temp >>= 8;
    //p[2] = (U8)temp; temp >>= 8;
    //p[1] = (U8)temp; temp >>= 8;
    //p[0] = (U8)temp;
    //p += 4;
    //}

}
#endif /* ATCA_CRYPTO_SHA1_EN */
