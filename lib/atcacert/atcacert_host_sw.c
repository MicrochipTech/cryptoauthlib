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

#if ATCAC_VERIFY_EN && ATCACERT_COMPCERT_EN
int atcacert_verify_cert_sw(const atcacert_def_t* cert_def,
                            const uint8_t*        cert,
                            size_t                cert_size,
                            const uint8_t         ca_public_key[64])
{
    int ret = 0;
    uint8_t tbs_digest[32];
    uint8_t signature[64];
    atcac_pk_ctx pkey_ctx;

    if (cert_def == NULL || ca_public_key == NULL || cert == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    ret = atcacert_get_tbs_digest(cert_def, cert, cert_size, tbs_digest);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    ret = atcacert_get_signature(cert_def, cert, cert_size, signature);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    /* Initialize the key using the provided X,Y cordinantes */
    ret = atcac_pk_init(&pkey_ctx, ca_public_key, 64, 0, true);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    /* Perform the verification */
    ret = atcac_pk_verify(&pkey_ctx, tbs_digest, sizeof(tbs_digest), signature, sizeof(signature));

    /* Make sure to free the key before testing the result of the verify */
    atcac_pk_free(&pkey_ctx);

    return ret;
}
#endif /* ATCAC_VERIFY_EN */

#if ATCAC_RANDOM_EN
int atcacert_gen_challenge_sw(uint8_t challenge[32])
{
    if (challenge == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    return atcac_sw_random(challenge, 32);
}
#endif /* ATCAC_RANDOM_EN */

#if ATCAC_VERIFY_EN
int atcacert_verify_response_sw(const uint8_t device_public_key[64],
                                const uint8_t challenge[32],
                                const uint8_t response[64])
{
    atcac_pk_ctx pkey_ctx;
    int ret = ATCACERT_E_BAD_PARAMS;

    if (device_public_key == NULL || challenge == NULL || response == NULL)
    {
        return ret;
    }

    /* Initialize the key using the provided X,Y cordinantes */
    ret = atcac_pk_init(&pkey_ctx, device_public_key, 64, 0, true);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    /* Perform the verification */
    ret = atcac_pk_verify(&pkey_ctx, challenge, 32, response, 32);

    /* Make sure to free the key before testing the result of the verify */
    atcac_pk_free(&pkey_ctx);

    return ret;
}
#endif /* ATCAC_VERIFY_EN */
