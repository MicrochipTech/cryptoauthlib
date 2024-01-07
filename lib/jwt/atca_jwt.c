/**
 * \file
 * \brief Utilities to create and verify a JSON Web Token (JWT)
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
#include "atca_helpers.h"
#include "crypto/atca_crypto_sw_sha2.h"
#include "jwt/atca_jwt.h"
#include <stdio.h>

#ifdef ATCA_JWT_EN

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "MISRA C-2012 Rule 10.4" "Casting character constants to char type reduces readability")
#endif

/** \brief The only supported JWT format for this library */
static const char g_jwt_header[] = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}";

/**
 * \brief Check the provided context to see what character needs to be added in
 * order to append a claim
 */
void atca_jwt_check_payload_start(
    atca_jwt_t* jwt /**< [in] JWT Context to use */
    )
{
    /* Rationality checks: a) must be valid, b) buf must be valid, c) must not be at the start, d) must have room */
    if ((NULL != jwt) && (NULL != jwt->buf) && (0u < jwt->cur) && (jwt->cur < jwt->buflen - 1u))
    {
        /* Check the previous */
        char c = jwt->buf[jwt->cur - 1u];
        if ('.' == c)
        {
            jwt->buf[jwt->cur++] = (char)'{';
        }
        else if ('{' != c)
        {
            jwt->buf[jwt->cur++] = (char)',';
        }
        else
        {
            /* do nothing */
        }
    }
}

/**
 * \brief Initialize a JWT structure
 */
ATCA_STATUS atca_jwt_init(
    atca_jwt_t* jwt,    /**< [in] JWT Context to initialize */
    char*       buf,    /**< [inout] Pointer to a buffer to store the token */
    uint16_t    buflen  /**< [in] Length of the buffer */
    )
{
    ATCA_STATUS ret = ATCA_BAD_PARAM;
    size_t tSize;

    if ((NULL != jwt) && (NULL != buf) && (0u < buflen))
    {
        jwt->buf = buf;
        jwt->buflen = buflen;
        jwt->cur = 0u;

        /* Encode the header into the buffer */
        tSize = jwt->buflen;
        ret = atcab_base64encode_((const uint8_t*)g_jwt_header, strlen(g_jwt_header), jwt->buf,
                                  &tSize, atcab_b64rules_urlsafe());
        if (ATCA_SUCCESS == ret)
        {
            /* coverity[cert_int31_c_violation:FALSE] tSize is always less than UINT16_MAX */
            jwt->cur += (uint16_t)tSize;

            /* Check length */
            if (jwt->cur < jwt->buflen - 1u)
            {
                /* Add the separator */
                jwt->buf[jwt->cur++] = (char)'.';
            }
            else
            {
                ret = ATCA_INVALID_SIZE;
            }
        }
    }
    return ret;
}

/**
 * \brief Close the claims of a token, encode them, then sign the result
 */
ATCA_STATUS atca_jwt_finalize(
    atca_jwt_t* jwt,    /**< [in] JWT Context to use */
    uint16_t    key_id  /**< [in] Key Id (Slot number) used to sign */
    )
{
    ATCA_STATUS status;
    uint16_t i;
    size_t rem;
    size_t tSize;

    if ((NULL == jwt) || (NULL == jwt->buf) || (0u == jwt->buflen) || (0u == jwt->cur))
    {
        return ATCA_BAD_PARAM;
    }

    /* Verify the payload is closed */
    if ('}' != jwt->buf[jwt->cur - 1u])
    {
        jwt->buf[jwt->cur++] = (char)'}';
    }

    /* Find the start of the "claims" portion of the token - header should
       already be encoded */
    i = 0;
    while (i < jwt->cur)
    {
        if ('.' == jwt->buf[i])
        {
            i++;
            break;
        }
        i++;
    }

    /* Make sure there is enough remaining buffer given base64 4/3 expansion */
    rem = ((size_t)jwt->cur - (size_t)i + ATCA_ECCP256_SIG_SIZE) * 4u;
    rem /= 3u;

    /* Increase Count to accomodate: 1 for the '.', 1 for the null terminator,
        and 1 for padding */
    rem += 3u;

    if (rem > ((size_t)jwt->buflen - (size_t)jwt->cur))
    {
        return ATCA_INVALID_SIZE;
    }

    /* Calculate the payload length */
    rem = (size_t)jwt->cur - (size_t)i;
    /* Move the payload to make room for the encoding */
    (void)memmove(jwt->buf + jwt->buflen - jwt->cur, &jwt->buf[i], rem);

    /* Encode the payload into the buffer */
    tSize = jwt->buflen;
    status = atcab_base64encode_((uint8_t*)(jwt->buf + jwt->buflen - jwt->cur), rem,
                                 &jwt->buf[i], &tSize, atcab_b64rules_urlsafe());
    if (ATCA_SUCCESS != status)
    {
        return status;
    }

    /* coverity[cert_int31_c_violation:FALSE] tSize is always less than UINT16_MAX */
    jwt->cur = (uint16_t)(i + tSize);

    /* Make sure there room to add the signature
        ECDSA(P256) -> 64 bytes -> base64 -> 86.3 (87) -> 88 including null */
    if (jwt->cur >= jwt->buflen - 88u)
    {
        /* Something broke */
        return ATCA_INVALID_SIZE;
    }

    /* Create digest of the message store and store in the buffer */
    status = (ATCA_STATUS)atcac_sw_sha2_256((const uint8_t*)jwt->buf, jwt->cur, (uint8_t*)(jwt->buf + jwt->buflen - 32u));
    if (ATCA_SUCCESS != status)
    {
        return status;
    }

    /* Create ECSDA signature of the digest and store it back in the buffer */
#if CALIB_SIGN_EN || CALIB_SIGN_ECC204_EN || TALIB_SIGN_EN
    status = atcab_sign(key_id, (const uint8_t*)(jwt->buf + jwt->buflen - ATCA_SHA256_DIGEST_SIZE),
                        (uint8_t*)(jwt->buf + jwt->buflen - 64u));
    if (ATCA_SUCCESS != status)
    {
        return status;
    }
#endif

    /* Add the separator */
    jwt->buf[jwt->cur++] = (char)'.';

    /* Encode the signature and store it in the buffer */
    tSize = (size_t)jwt->buflen - (size_t)jwt->cur;
    status = atcab_base64encode_((const uint8_t*)(jwt->buf + jwt->buflen - ATCA_ECCP256_SIG_SIZE), ATCA_ECCP256_SIG_SIZE,
                                 &jwt->buf[jwt->cur], &tSize, atcab_b64rules_urlsafe());
    if (ATCA_SUCCESS != status)
    {
        return status;
    }
    /* coverity[cert_int31_c_violation] tSize can't exceed UINT16_MAX */
    jwt->cur += (uint16_t)tSize;

    if (jwt->cur >= jwt->buflen)
    {
        /* Something broke */
        return ATCA_INVALID_SIZE;
    }

    /* Make sure resulting buffer is null terminated */
    jwt->buf[jwt->cur] = 0;

    return status;
}

/**
 * \brief Add a string claim to a token
 * \note This function does not escape strings so the user has to ensure they
 *       are valid for use in a JSON string first
 */
ATCA_STATUS atca_jwt_add_claim_string(
    atca_jwt_t* jwt,    /**< [in] JWT Context to use */
    const char* claim,  /**< [in] Name of the claim to be inserted */
    const char* value   /**< [in] Null terminated string to be insterted */
    )
{
    int32_t written;
    int32_t remaining;

    if ((NULL != jwt) && (NULL != jwt->buf) && (0u < jwt->buflen) && (NULL != claim) && (NULL != value))
    {
        atca_jwt_check_payload_start(jwt);

        remaining = (int32_t)jwt->buflen - (int32_t)jwt->cur;
        /* coverity[cert_int31_c_violation:FALSE] remaining can never be negative */
        /* coverity[misra_c_2012_rule_21_6_violation] snprintf is approved for formatted string writes to buffers */
        written = snprintf(&jwt->buf[jwt->cur], (size_t)remaining, "\"%s\":\"%s\"", claim, value);
        if (0 < written && written < remaining)
        {
            jwt->cur += written;
            return ATCA_SUCCESS;
        }
        else
        {
            return ATCA_GEN_FAIL;
        }
    }
    else
    {
        return ATCA_BAD_PARAM;
    }
}

/**
 * \brief Add a numeric claim to a token
 * \note This function does not escape strings so the user has to ensure the
 *       claim is valid first
 */
ATCA_STATUS atca_jwt_add_claim_numeric(
    atca_jwt_t* jwt,    /**< [in] JWT Context to use */
    const char* claim,  /**< [in] Name of the claim to be inserted */
    int32_t     value   /**< [in] integer value to be inserted */
    )
{
    int32_t written;
    int32_t remaining;

    if ((NULL != jwt) && (NULL != jwt->buf) && (0u < jwt->buflen) && (NULL != claim))
    {
        atca_jwt_check_payload_start(jwt);

        remaining = (int32_t)jwt->buflen - (int32_t)jwt->cur;
        /* coverity[cert_int31_c_violation:FALSE] remaining is never negative */
        /* coverity[misra_c_2012_rule_21_6_violation] snprintf is approved for formatted string writes to buffers */
        written = snprintf(&jwt->buf[jwt->cur], (size_t)remaining, "\"%s\":%ld", claim, (long)value);
        if (0 < written && written < remaining)
        {
            jwt->cur += written;
            return ATCA_SUCCESS;
        }
        else
        {
            return ATCA_GEN_FAIL;
        }
    }
    else
    {
        return ATCA_BAD_PARAM;
    }
}

#if ATCA_HOSTLIB_EN || CALIB_VERIFY_EXTERN_EN || TALIB_VERIFY_EXTERN_EN
/**
 * \brief Verifies the signature of a jwt using the provided public key
 */
ATCA_STATUS atca_jwt_verify(
    const char*     buf,    /**< [in] Buffer holding an encoded jwt */
    uint16_t        buflen, /**< [in] Length of the buffer/jwt */
    const uint8_t*  pubkey  /**< [in] Public key (raw byte format) */
    )
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t digest[ATCA_SHA256_DIGEST_SIZE];
    uint8_t signature[ATCA_ECCP256_SIG_SIZE];
    size_t sig_len = sizeof(signature);
    const char* pStr = buf;

    bool verified = false;

    if ((NULL == buf) || (0u == buflen) || (NULL == pubkey))
    {
        return ATCA_BAD_PARAM;
    }

    do
    {
        /* Payload */
        if (NULL == (pStr = strchr(pStr, (int)'.')))
        {
            break;
        }
        pStr++;

        /* Signature */
        if (NULL == (pStr = strchr(pStr, (int)'.')))
        {
            break;
        }
        pStr++;

        /* Extract the signature */
        if (ATCA_SUCCESS != (status = atcab_base64decode_(pStr, strlen(pStr),
                                                          signature, &sig_len, atcab_b64rules_urlsafe())))
        {
            break;
        }

        /* Digest the token */
        if (ATCA_SUCCESS != (status = atcac_sw_sha2_256((const uint8_t*)buf, atcab_pointer_delta(pStr, buf) - 1U, digest)))
        {
            break;
        }

#if CALIB_VERIFY_EXTERN_EN || TALIB_VERIFY_EXTERN_EN
        /* Do a signature verification using the device */
        if (ATCA_SUCCESS != (status = atcab_verify_extern(digest, signature,
                                                          pubkey, &verified)))
        {
            break;
        }
#elif ATCA_HOSTLIB_EN
        atcac_pk_ctx pkey_ctx;

        /* Initialize the key using the provided X,Y cordinantes */
        if (ATCA_SUCCESS != (status = atcac_pk_init(&pkey_ctx, pubkey,
                                                    sizeof(pubkey), 0, true)))
        {
            break;
        }

        /* Perform the verification */
        if (ATCA_SUCCESS == (status = atcac_pk_verify(&pkey_ctx, digest,
                                                      sizeof(digest),
                                                      signature, sizeof(signature))))
        {
            verified = true;
        }

        /* Make sure to free the key before testing the result of the verify */
        atcac_pk_free(&pkey_ctx);
#endif

        if (!verified)
        {
            status = ATCA_CHECKMAC_VERIFY_FAILED;
        }
    } while (false);

    return status;
}
#endif

#ifdef __COVERITY__
#pragma coverity compliance end_block "MISRA C-2012 Rule 10.4"
#endif

#endif
