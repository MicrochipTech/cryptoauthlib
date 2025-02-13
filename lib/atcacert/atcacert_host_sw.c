/**
 * \file
 * \brief host side methods using software implementations
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

#include "atcacert_host_sw.h"
#include "crypto/atca_crypto_sw.h"
#include "cal_internal.h"

#if ATCACERT_EN 

#if ATCAC_VERIFY_EN && ATCACERT_COMPCERT_EN
ATCA_STATUS atcacert_verify_cert_sw(const atcacert_def_t* cert_def,
                                    const uint8_t*        cert,
                                    size_t                cert_size,
                                    const cal_buffer*     ca_public_key)
{
    ATCA_STATUS ret = 0;
    uint8_t tbs_digest[ATCA_SHA2_512_DIGEST_SIZE];
    cal_buffer dig = CAL_BUF_INIT(0u, tbs_digest);
    uint8_t signature[ATCA_MAX_ECC_SIG_SIZE];
    cal_buffer sig = CAL_BUF_INIT(0u, signature);
    atcac_pk_ctx_t pkey_ctx;

#if ATCA_CHECK_PARAMS_EN
    if (cert_def == NULL || ca_public_key == NULL || cert == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

    switch(ca_public_key->len)
    {
        case ATCA_KEY_TYPE_ECCP256:
            dig.len = ATCA_SHA2_256_DIGEST_SIZE;
            break;
#if ATCA_TA_SUPPORT
        case TA_KEY_TYPE_ECCP384_SIZE:
            dig.len = ATCA_SHA2_384_DIGEST_SIZE;
            break;
        case TA_KEY_TYPE_ECCP521_SIZE:
            dig.len = ATCA_SHA2_512_DIGEST_SIZE;
            break;
#endif
        default:
            ret = ATCACERT_E_BAD_PARAMS;
            break;
    }
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    ret = atcacert_get_tbs_digest(cert_def, cert, cert_size, &dig);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    sig.len = (0u == cert_def->std_sig_size) ? ATCA_ECCP256_SIG_SIZE : cert_def->std_sig_size;
    ret = atcacert_get_signature(cert_def, cert, cert_size, &sig);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    /* Initialize the key using the provided X,Y cordinantes */
    ret = atcac_pk_init(&pkey_ctx, ca_public_key->buf, ca_public_key->len, 0, true);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    /* Perform the verification */
    ret = atcac_pk_verify(&pkey_ctx, tbs_digest, sizeof(tbs_digest), signature, sig.len);

    /* Make sure to free the key before testing the result of the verify */
    (void)atcac_pk_free(&pkey_ctx);

    return ret;
}
#endif /* ATCAC_VERIFY_EN */

#if ATCAC_RANDOM_EN
ATCA_STATUS atcacert_gen_challenge_sw(cal_buffer* challenge)
{
#if ATCA_CHECK_PARAMS_EN
    if (challenge == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

    return atcac_sw_random(challenge->buf, challenge->len);
}
#endif /* ATCAC_RANDOM_EN */

#if ATCAC_VERIFY_EN
ATCA_STATUS atcacert_verify_response_sw(const cal_buffer* device_public_key,
                                        const cal_buffer* challenge,
                                        const cal_buffer* response)
{
    atcac_pk_ctx_t pkey_ctx;
    ATCA_STATUS ret = ATCACERT_E_BAD_PARAMS;

#if ATCA_CHECK_PARAMS_EN
    if (device_public_key == NULL || challenge == NULL || response == NULL)
    {
        return ret;
    }
#endif

    (void)memset(&pkey_ctx, 0, sizeof(pkey_ctx));

    /* Initialize the key using the provided X,Y cordinantes */
    ret = atcac_pk_init(&pkey_ctx, device_public_key->buf, device_public_key->len, 0, true);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    /* Perform the verification */
    ret = atcac_pk_verify(&pkey_ctx, challenge->buf, challenge->len, response->buf, response->len);

    /* Make sure to free the key before testing the result of the verify */
    (void)atcac_pk_free(&pkey_ctx);

    return ret;
}
#endif /* ATCAC_VERIFY_EN */

#endif /* ATCACERT_EN */
