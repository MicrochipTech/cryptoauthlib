/**
 * \file
 * \brief Implementation of PKCS7 Padding for block encryption
 *
 * \copyright (c) 2022 Microchip Technology Inc. and its subsidiaries.
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
#include "atca_crypto_sw.h"

#ifdef ATCAC_PKCS7_PAD_EN

ATCA_STATUS atcac_pkcs7_pad(
    uint8_t *     buf,      /**< [in/out] The buffer that will be padded */
    size_t *      buflen,   /**< [in/out] Input: the length of the buffer, Ouput: The padded length */
    const size_t  datalen,  /**< [in] Length of the input data */
    const uint8_t blocksize /**< [in] The block size in bytes to pad to */
    )
{
    size_t outlen;
    uint8_t padsym;

    if ((NULL == buf) || (NULL == buflen))
    {
        return ATCA_BAD_PARAM;
    }

    if (datalen < blocksize)
    {
        outlen = blocksize;
    }
    else
    {
        /* Whole number of blocks */
        outlen = datalen / blocksize;
        /* Round to the next block */
        outlen = outlen * blocksize + blocksize;
    }

    if (*buflen < outlen)
    {
        return ATCA_SMALL_BUFFER;
    }

    /* Determine what padding symbol to use - should never be 0 */
    padsym = (uint8_t)(outlen - datalen);

    /* Fill the end of the buffer with the symbol */
    (void)memset(&buf[datalen], (int)padsym, (size_t)padsym);

    *buflen = outlen;

    return ATCA_SUCCESS;
}

ATCA_STATUS atcac_pkcs7_unpad(
    uint8_t *     buf,      /**< [in/out] The buffer that will be padded */
    size_t *      buflen,   /**< [in/out] Input: the length of the buffer, Ouput: The actual length */
    const uint8_t blocksize /**< [in] The block size in bytes to pad to */
    )
{
    uint8_t padsym;
    size_t i;
    size_t outlen;

    if ((NULL == buf) || (NULL == buflen) || (0u == *buflen))
    {
        return ATCA_BAD_PARAM;
    }

    /* There must at minimum one padding byte */
    padsym = buf[*buflen - 1u];

    /* Padding bytes must be in the range 1..blocksize */
    if ((0u == padsym) || padsym > blocksize)
    {
        return ATCA_GEN_FAIL;
    }

    outlen = *buflen - padsym;

    for (i = *buflen; i > outlen; i--)
    {
        if (buf[i - 1U] != padsym)
        {
            /* Bad padding byte found */
            break;
        }
        else
        {
            /* null it */
            buf[i - 1U] = 0;
        }
    }

    if (i == outlen)
    {
        *buflen = outlen;
        return ATCA_SUCCESS;
    }
    else
    {
        return ATCA_GEN_FAIL;
    }
}

#endif /* ATCAC_PKCS7_PAD_EN */
