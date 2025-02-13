/**
 * \file
 * \brief host side methods using CryptoAuth hardware
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

#include "atcacert_host_hw.h"
#include "atca_basic.h"
#include "crypto/atca_crypto_sw_sha2.h"

#if ATCACERT_EN

#if ATCACERT_HW_VERIFY_EN && ATCACERT_COMPCERT_EN
ATCA_STATUS atcacert_verify_cert_hw(ATCADevice            device,
                                    const atcacert_def_t* cert_def,
                                    const uint8_t*        cert,
                                    size_t                cert_size,
                                    cal_buffer*           ca_public_key)
{
    ATCA_STATUS ret = 0;
    uint8_t tbs_digest[ATCA_SHA2_512_DIGEST_SIZE] = { 0 };
    cal_buffer dig = CAL_BUF_INIT(0u, tbs_digest);
    uint8_t signature[ATCA_MAX_ECC_SIG_SIZE];
    cal_buffer sig = CAL_BUF_INIT(0u, signature);
    bool is_verified = false;
    ATCADeviceType dev_type = atcab_get_device_type_ext(device);
#if ATCA_TA_SUPPORT
    uint8_t key_type = ATCA_KEY_TYPE_ECCP256;
#endif

#if ATCA_CHECK_PARAMS_EN
    if (device == NULL || cert_def == NULL || ca_public_key == NULL || cert == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

    switch(ca_public_key->len)
    {
        case ATCA_ECCP256_PUBKEY_SIZE:
            dig.len = ATCA_SHA2_256_DIGEST_SIZE;
            break;
#if ATCA_TA_SUPPORT
        case ATCA_ECCP384_PUBKEY_SIZE:
            key_type = TA_KEY_TYPE_ECCP384;
            dig.len = ATCA_SHA2_384_DIGEST_SIZE;
            break;
        case ATCA_ECCP521_PUBKEY_SIZE:
            key_type = TA_KEY_TYPE_ECCP521;
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

#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
    if (atcab_is_ca_device(dev_type) || atcab_is_ca2_device(dev_type))
    {
        ret = atcab_verify_extern(tbs_digest, signature, ca_public_key->buf, &is_verified);
    }
#endif
#if ATCA_TA_SUPPORT
    if (atcab_is_ta_device(dev_type))
    {
        ret = talib_verify_extern(device, key_type, TA_HANDLE_INPUT_BUFFER, ca_public_key, &sig,
                                  &dig, &is_verified);                 
    }
#endif
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    return is_verified ? ATCACERT_E_SUCCESS : ATCACERT_E_VERIFY_FAILED;
}
#endif

#if ATCACERT_HW_CHALLENGE_EN
ATCA_STATUS atcacert_gen_challenge_hw(ATCADevice device, cal_buffer* challenge)
{
    ATCADeviceType dev_type = atcab_get_device_type_ext(device);
    ATCA_STATUS ret = 0;

#if ATCA_CHECK_PARAMS_EN
    if (device == NULL || challenge == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
    if (atcab_is_ca_device(dev_type) || atcab_is_ca2_device(dev_type))
    {
       ret = atcab_random(challenge->buf);
    }
#endif
#if ATCA_TA_SUPPORT
    if (atcab_is_ta_device(dev_type))
    {
        ret = talib_random(device, NULL, challenge);
    }
#endif
    return ret;
}
#endif

#if ATCACERT_HW_VERIFY_EN && ATCACERT_COMPCERT_EN
ATCA_STATUS atcacert_verify_response_hw(ATCADevice  device,
                                        cal_buffer* device_public_key,
                                        cal_buffer* challenge,
                                        cal_buffer* response)
{
    ATCA_STATUS ret = 0;
    bool is_verified = false;
    ATCADeviceType dev_type = atcab_get_device_type_ext(device);
#if ATCA_TA_SUPPORT
    uint8_t key_type = 0u;
#endif

#if ATCA_CHECK_PARAMS_EN
    if (device == NULL || device_public_key == NULL || challenge == NULL || response == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
    if (atcab_is_ca_device(dev_type) || atcab_is_ca2_device(dev_type))
    {
        ret = atcab_verify_extern(challenge->buf, response->buf, device_public_key->buf, &is_verified);
    }
#endif
#if ATCA_TA_SUPPORT
    if (atcab_is_ta_device(dev_type))
    {
        switch(device_public_key->len)
        {
            case ATCA_ECCP256_PUBKEY_SIZE:
                key_type = TA_KEY_TYPE_ECCP256;
                break;
            case ATCA_ECCP384_PUBKEY_SIZE:
                key_type = TA_KEY_TYPE_ECCP384;
                break;
            case ATCA_ECCP521_PUBKEY_SIZE:
                key_type = TA_KEY_TYPE_ECCP521;
                break;
            default:
                ret = ATCA_BAD_PARAM;
                break;
        }

        if (ret == ATCA_SUCCESS)
        {
            ret = talib_verify_extern(device, key_type, TA_HANDLE_INPUT_BUFFER, device_public_key,
                                      response, challenge, &is_verified);
        }
    }
#endif
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    return is_verified ? ATCACERT_E_SUCCESS : ATCACERT_E_VERIFY_FAILED;
}
#endif

#endif /* ATCACERT_EN */