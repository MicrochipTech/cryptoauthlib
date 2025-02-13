/**
 * \file
 * \brief Client side certificate I/O functions for TNG devices.
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

#include "tng_atca.h"
#include "atcacert/atcacert_client.h"
#include "tng_atcacert_client.h"
#include "tngtls_cert_def_1_signer.h"
#include "tng_root_cert.h"
#include <limits.h>

#if ATCACERT_COMPCERT_EN

int tng_atcacert_max_device_cert_size(size_t* max_cert_size)
{
    int ret = ATCACERT_E_WRONG_CERT_DEF;
    int index = 0;
    size_t cert_size = 0;
    const atcacert_def_t* cert_def;

    if (NULL != max_cert_size)
    {
        do
        {
            cert_def = tng_map_get_device_cert_def(index);

            if (NULL != cert_def)
            {
                ret = atcacert_max_cert_size(cert_def, &cert_size);
                if (ATCACERT_E_SUCCESS == ret)
                {
                    *max_cert_size = cert_size;
                }
                else
                {
                    break;
                }

                if (index < INT_MAX)
                {
                    index++;
                }
                else
                {
                    ret = ATCACERT_E_WRONG_CERT_DEF;
                    break;
                }
            }
        } while ((NULL != cert_def) && (ret == ATCACERT_E_SUCCESS));
    }

    return ret;
}

int tng_atcacert_read_device_cert(uint8_t* cert, size_t* cert_size, const uint8_t* signer_cert)
{
    int ret;
    const atcacert_def_t* cert_def = NULL;
    uint8_t ca_public_key[72];
    cal_buffer ca_pubkey = CAL_BUF_INIT(ATCA_ECCP256_PUBKEY_SIZE, ca_public_key);

    ret = tng_get_device_cert_def(&cert_def);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }
    // Get the CA (signer) public key
    if (signer_cert != NULL)
    {
        // Signer certificate is supplied, get the public key from there
        ret = atcacert_get_subj_public_key(
            cert_def->ca_cert_def,
            signer_cert,
            cert_def->ca_cert_def->cert_template_size,  // Cert size doesn't need to be accurate
            &ca_pubkey);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }
    }
    else
    {
        // No signer certificate supplied, read from the device
        ret = atcacert_read_device_loc(&cert_def->ca_cert_def->public_key_dev_loc, ca_public_key);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }
        if (cert_def->ca_cert_def->public_key_dev_loc.count == 72u)
        {
            // Public key is formatted with padding bytes in front of the X and Y components
            atcacert_public_key_remove_padding(ca_public_key, ca_public_key);
        }
    }

    return atcacert_read_cert(cert_def, &ca_pubkey, cert, cert_size);
}

int tng_atcacert_device_public_key(uint8_t* public_key, uint8_t* cert)
{
    int ret;
    const atcacert_def_t* cert_def = NULL;
    uint8_t raw_public_key[72];

    (void)cert;

    if (public_key == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    ret = (int)tng_get_device_cert_def(&cert_def);
    if (ret != ATCA_SUCCESS)
    {
        return ret;
    }

    ret = atcacert_read_device_loc(&cert_def->public_key_dev_loc, raw_public_key);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }
    if (cert_def->public_key_dev_loc.count == 72u)
    {
        // Public key is formatted with padding bytes in front of the X and Y components
        atcacert_public_key_remove_padding(raw_public_key, public_key);
    }
    else
    {
        (void)memcpy(public_key, raw_public_key, 64);
    }

    return ATCACERT_E_SUCCESS;
}

int tng_atcacert_max_signer_cert_size(size_t* max_cert_size)
{
    return atcacert_max_cert_size(&g_tngtls_cert_def_1_signer, max_cert_size);
}

int tng_atcacert_read_signer_cert(uint8_t* cert, size_t* cert_size)
{
    int ret;
    const atcacert_def_t* cert_def = NULL;
    uint8_t* ca_public_key = NULL;
    cal_buffer ca_pubkey = CAL_BUF_INIT(ATCA_ECCP256_PUBKEY_SIZE, NULL);

    ret = tng_get_device_cert_def(&cert_def);
    if (ATCA_SUCCESS == ret)
    {
        cert_def = cert_def->ca_cert_def;

        // Get the CA (root) public key
        ca_public_key = &g_cryptoauth_root_ca_002_cert[CRYPTOAUTH_ROOT_CA_002_PUBLIC_KEY_OFFSET];

        ca_pubkey.buf = ca_public_key;
        ret = atcacert_read_cert(cert_def, &ca_pubkey, cert, cert_size);
    }

    return ret;
}

int tng_atcacert_signer_public_key(uint8_t* public_key, uint8_t* cert)
{
    int ret;
    const atcacert_def_t* cert_def = NULL;
    uint8_t raw_public_key[72];
    cal_buffer pubkey = CAL_BUF_INIT(ATCA_ECCP256_PUBKEY_SIZE, public_key);

    if (public_key == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (cert != NULL)
    {
        // TNG TLS cert def will work for either if the certificate is supplied
        ret = atcacert_get_subj_public_key(
            &g_tngtls_cert_def_1_signer,
            cert,
            g_tngtls_cert_def_1_signer.cert_template_size,  // cert size doesn't need to be accurate
            &pubkey);
    }
    else
    {
        ret = (int)tng_get_device_cert_def(&cert_def);
        if (ATCA_SUCCESS == ret)
        {
            cert_def = cert_def->ca_cert_def;

            ret = atcacert_read_device_loc(&cert_def->public_key_dev_loc, raw_public_key);
            if (ATCACERT_E_SUCCESS == ret)
            {
                if (cert_def->public_key_dev_loc.count == 72u)
                {
                    // Public key is formatted with padding bytes in front of the X and Y components
                    atcacert_public_key_remove_padding(raw_public_key, public_key);
                }
                else
                {
                    (void)memcpy(public_key, raw_public_key, 64);
                }
            }
        }
    }

    return ret;
}

int tng_atcacert_root_cert_size(size_t* cert_size)
{
    if (cert_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    *cert_size = g_cryptoauth_root_ca_002_cert_size;

    return ATCACERT_E_SUCCESS;
}

int tng_atcacert_root_cert(uint8_t* cert, size_t* cert_size)
{
    if (cert == NULL || cert_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (*cert_size < g_cryptoauth_root_ca_002_cert_size)
    {
        return ATCACERT_E_BUFFER_TOO_SMALL;
    }

    (void)memcpy(cert, g_cryptoauth_root_ca_002_cert, g_cryptoauth_root_ca_002_cert_size);
    *cert_size = g_cryptoauth_root_ca_002_cert_size;

    return ATCACERT_E_SUCCESS;
}

int tng_atcacert_root_public_key(uint8_t* public_key)
{
    if (public_key == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    (void)memcpy(public_key, &g_cryptoauth_root_ca_002_cert[CRYPTOAUTH_ROOT_CA_002_PUBLIC_KEY_OFFSET], 64);

    return ATCACERT_E_SUCCESS;
}

#endif