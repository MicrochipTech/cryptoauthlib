/**
 * \file
 * \brief Client side cert i/o methods. These declarations deal with the client-side, the node being authenticated,
 *        of the authentication process. It is assumed the client has an ECC CryptoAuthentication device
 *        (e.g. ATECC508A) and the certificates are stored on that device.
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

#include <limits.h>
#include <stdlib.h>
#include "atcacert_client.h"
#include "atcacert_der.h"
#include "atcacert_pem.h"
#include "cryptoauthlib.h"
#include "calib/calib_basic.h"


#if ATCACERT_COMPCERT_EN

#define DEVZONE_TO_BYTEVAL(zone)    (((int)(zone) < UCHAR_MAX) ? ((uint8_t)(zone) & 0xFFu) : 0x07u)

#if ATCAB_WRITE_EN
// Perform floor integer division (-1 / 2 == -1) instead of truncate towards zero (-1 / 2 == 0)
static int floor_div(int a, int b)
{
    int d = 0;

    bool t1 = (a < 0);
    bool t2 = (b < 0);

    if (b != 0)
    {
        d = a / b;

        if ((a % b) != 0)
        {
            if (t1 != t2)
            {
                d -= 1;
            }
        }
    }
    return d;
}
#endif


ATCA_STATUS atcacert_get_response(uint8_t       device_private_key_slot,
                                  const uint8_t challenge[32],
                                  uint8_t       response[64])
{
    if ((device_private_key_slot > 15U) || (challenge == NULL) || (response == NULL))
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    return atcab_sign(device_private_key_slot, challenge, response);
}

ATCA_STATUS atcacert_read_device_loc_ext(ATCADevice                   device,
                                         const atcacert_device_loc_t* device_loc,
                                         uint8_t*                     data)
{
    ATCA_STATUS ret = 0;

    if (device_loc->zone == DEVZONE_DATA && (0U != device_loc->is_genkey))
    {
        uint8_t public_key[ATCA_PUB_KEY_SIZE];
        if (device_loc->offset + device_loc->count > ATCA_PUB_KEY_SIZE) // sizeof public_key, in bytes
        {
            return ATCACERT_E_BAD_PARAMS;
        }

        ret = atcab_get_pubkey_ext(device, device_loc->slot, public_key);
        if (ret != ATCA_SUCCESS)
        {
            return ret;
        }
        (void)memcpy(data, &public_key[device_loc->offset], device_loc->count);
    }
    else
    {
        size_t count = device_loc->count;
        size_t zone_size = 0u;
        ret = atcab_get_zone_size_ext(device, (uint8_t)device_loc->zone, device_loc->slot, &zone_size);
        if (ret != ATCA_SUCCESS)
        {
            return ret;
        }
        if ((size_t)device_loc->offset + (size_t)device_loc->count > zone_size)
        {
            if (device_loc->offset > zone_size)
            {
                return ATCACERT_E_BAD_PARAMS;
            }
            count = zone_size - device_loc->offset;
        }

        ret = atcab_read_bytes_zone_ext(
            device,
            (uint8_t)device_loc->zone,
            device_loc->slot,
            device_loc->offset,
            data,
            count);
        if (ret != ATCA_SUCCESS)
        {
            return ret;
        }
    }

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_read_device_loc(const atcacert_device_loc_t* device_loc,
                                     uint8_t*                     data)
{
    return atcacert_read_device_loc_ext(atcab_get_device(), device_loc, data);
}

ATCA_STATUS atcacert_read_cert_ext(ATCADevice            device,
                                   const atcacert_def_t* cert_def,
                                   const uint8_t         ca_public_key[64],
                                   uint8_t*              cert,
                                   size_t*               cert_size)
{
    ATCA_STATUS ret = 0;
    atcacert_device_loc_t device_locs[16];
    size_t device_locs_count = 0;
    size_t i = 0;
    atcacert_build_state_t build_state;

    if (cert_def == NULL || cert_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (cert == NULL)
    {
        return atcacert_read_cert_size_ext(device, cert_def, cert_size);
    }

    ret = atcacert_get_device_locs(
        cert_def,
        device_locs,
        &device_locs_count,
        sizeof(device_locs) / sizeof(device_locs[0]),
        ATCA_BLOCK_SIZE);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    ret = atcacert_cert_build_start(&build_state, cert_def, cert, cert_size, ca_public_key);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    for (i = 0; i < device_locs_count; i++)
    {
        static uint8_t data[416];
        ret = atcacert_read_device_loc_ext(device, &device_locs[i], data);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }

        ret = atcacert_cert_build_process(&build_state, &device_locs[i], data);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }
    }

    ret = atcacert_cert_build_finish(&build_state);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_read_cert(const atcacert_def_t* cert_def,
                               const uint8_t         ca_public_key[64],
                               uint8_t*              cert,
                               size_t*               cert_size)
{
    return atcacert_read_cert_ext(atcab_get_device(), cert_def, ca_public_key, cert, cert_size);
}

#if ATCAB_WRITE_EN
ATCA_STATUS atcacert_write_cert_ext(ATCADevice            device,
                                    const atcacert_def_t* cert_def,
                                    const uint8_t*        cert,
                                    size_t                cert_size)
{
    ATCA_STATUS ret = 0;
    atcacert_device_loc_t device_locs[16];
    size_t device_locs_count = 0;
    size_t i = 0;

    if (cert_def == NULL || cert == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    ret = atcacert_get_device_locs(
        cert_def,
        device_locs,
        &device_locs_count,
        sizeof(device_locs) / sizeof(device_locs[0]),
        ATCA_BLOCK_SIZE);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    for (i = 0; i < device_locs_count; i++)
    {
        int end_block;
        int start_block;
        static uint8_t data[416];
        int block;

        if (device_locs[i].zone == DEVZONE_CONFIG)
        {
            continue;  // Cert data isn't written to the config zone, only read
        }
        if (device_locs[i].zone == DEVZONE_DATA && (0U != device_locs[i].is_genkey))
        {
            continue;  // Public key is generated not written

        }
        ret = atcacert_get_device_data(cert_def, cert, cert_size, &device_locs[i], data);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }

        start_block = (int)device_locs[i].offset / (int)ATCA_BLOCK_SIZE;
        end_block = floor_div(((int)device_locs[i].offset + (int)device_locs[i].count) - 1, (int)ATCA_BLOCK_SIZE);
        for (block = start_block; block <= end_block; block++)
        {
            ret = atcab_write_zone_ext(
                device,
                (uint8_t)device_locs[i].zone,
                device_locs[i].slot,
                (uint8_t)block,
                0,
                &data[(block - start_block) * (int)ATCA_BLOCK_SIZE],
                ATCA_BLOCK_SIZE);
            if (ret != ATCA_SUCCESS)
            {
                return ret;
            }
        }
    }

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_write_cert(const atcacert_def_t* cert_def,
                                const uint8_t*        cert,
                                size_t                cert_size)
{
    return atcacert_write_cert_ext(atcab_get_device(), cert_def, cert, cert_size);
}
#endif

ATCA_STATUS atcacert_create_csr_pem(const atcacert_def_t* csr_def, char* csr, size_t* csr_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    size_t csr_max_size;
    size_t csr_der_size;

    // Check the pointers
    if (csr_def == NULL || csr == NULL || csr_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
    csr_max_size = *csr_size;
    *csr_size = 0;

    // Create DER CSR
    csr_der_size = csr_max_size;
    status = atcacert_create_csr(csr_def, (uint8_t*)csr, &csr_der_size);
    if (status != ATCACERT_E_SUCCESS)
    {
        return status;
    }

    // Move the DER CSR to the end of the buffer, so we can encode it into
    // PEM in place.
    /* coverity[cert_int30_c_violation:FALSE] csr_der_size will never be greater than csr_max_size */
    (void)memmove(csr + (csr_max_size - csr_der_size), csr, csr_der_size);

    *csr_size = csr_max_size;
    status = atcacert_encode_pem_csr((uint8_t*)(csr + (csr_max_size - csr_der_size)), csr_der_size, csr, csr_size);
    if (status != ATCACERT_E_SUCCESS)
    {
        return status;
    }

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_create_csr(const atcacert_def_t* csr_def, uint8_t* csr, size_t* csr_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t pub_key[ATCA_PUB_KEY_SIZE] = { 0 };
    uint8_t sig[ATCA_SIG_SIZE] = { 0 };
    const atcacert_device_loc_t* pub_dev_loc = NULL;
    const atcacert_cert_loc_t* pub_loc = NULL;
    uint16_t key_slot = 0;
    uint16_t priv_key_slot = 0;
    uint8_t tbs_digest[ATCA_BLOCK_SIZE] = { 0 };
    size_t csr_max_size = 0;

    do
    {
        // Check the pointers
        if ((csr_def == NULL) || (csr == NULL) || (csr_size == NULL))
        {
            status = (ATCA_STATUS)ATCACERT_E_BAD_PARAMS;
            (void)ATCA_TRACE(status, "Null input parameter"); break;
        }
        // Check the csr buffer size
        if (*csr_size < csr_def->cert_template_size)
        {
            status = (ATCA_STATUS)ATCACERT_E_BUFFER_TOO_SMALL;
            (void)ATCA_TRACE(status, "CSR buffer size too small"); break;
        }
        // Copy the CSR template into the CSR that will be returned
        (void)memcpy(csr, csr_def->cert_template, csr_def->cert_template_size);
        csr_max_size = *csr_size;
        *csr_size = csr_def->cert_template_size;

        // Get a few elements from the csr_def structure
        pub_loc = &(csr_def->std_cert_elements[STDCERT_PUBLIC_KEY]);
        pub_dev_loc = &(csr_def->public_key_dev_loc);
        key_slot = pub_dev_loc->slot;
        priv_key_slot = csr_def->private_key_slot;

        // Get the public key from the device
        if (0U != pub_dev_loc->is_genkey)
        {
            // Calculate the public key from the private key
            status = atcab_get_pubkey(key_slot, pub_key);
            if (status != ATCA_SUCCESS)
            {
                (void)ATCA_TRACE(status, "Could not generate public key"); break;
            }
        }
        else
        {
            // Read the public key from a slot
            status = atcab_read_pubkey(key_slot, pub_key);
            if (status != ATCA_SUCCESS)
            {
                (void)ATCA_TRACE(status, "Could not read public key"); break;
            }
        }
        // Insert the public key into the CSR template
        status = atcacert_set_cert_element(csr_def, pub_loc, csr, *csr_size, pub_key, ATCA_PUB_KEY_SIZE);
        if (status != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Setting CSR public key failed"); break;
        }

        // Get the CSR TBS digest
        status = atcacert_get_tbs_digest(csr_def, csr, *csr_size, tbs_digest);
        if (status != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Get TBS digest failed"); break;
        }

        // Sign the TBS digest
        status = atcab_sign(priv_key_slot, tbs_digest, sig);
        if (status != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Signing CSR failed"); break;
        }

        // Insert the signature into the CSR template
        status = atcacert_set_signature(csr_def, csr, csr_size, csr_max_size, sig);
        if (status != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Setting CSR signature failed"); break;
        }

        // The exact size of the csr cannot be determined until after adding the signature
        // it is returned in the csr_size parameter.  (*csr_size = *csr_size;)

    }
    while (false);

    return status;
}

ATCA_STATUS atcacert_read_subj_key_id_ext(ATCADevice device, const atcacert_def_t* cert_def, uint8_t subj_key_id[20])
{
    ATCA_STATUS ret = ATCACERT_E_DECODING_ERROR;
    uint8_t subj_public_key[72] = { 0 };

    if (cert_def == NULL || subj_key_id == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (DEVZONE_DATA == cert_def->public_key_dev_loc.zone)
    {
        if (0U != cert_def->public_key_dev_loc.is_genkey)
        {
            /* generate the key */
            ret = atcab_get_pubkey_ext(device, cert_def->public_key_dev_loc.slot, subj_public_key);
        }
        else
        {
            /* Load the public key from a slot */
            ret = atcab_read_bytes_zone_ext(device, (uint8_t)cert_def->public_key_dev_loc.zone,
                                            cert_def->public_key_dev_loc.slot,
                                            cert_def->public_key_dev_loc.offset,
                                            subj_public_key, cert_def->public_key_dev_loc.count);

            /* IF the public key is stored in device public key format */
            if ((ATCA_SUCCESS == ret) && (72U == cert_def->public_key_dev_loc.count))
            {
                atcacert_public_key_remove_padding(subj_public_key, subj_public_key);
            }
        }

        if (ATCA_SUCCESS == ret)
        {
            /* Calculate the key_id */
            ret = atcacert_get_key_id(subj_public_key, subj_key_id);
        }
    }
    return ret;
}

ATCA_STATUS atcacert_read_subj_key_id(const atcacert_def_t* cert_def, uint8_t subj_key_id[20])
{
    return atcacert_read_subj_key_id_ext(atcab_get_device(), cert_def, subj_key_id);
}

ATCA_STATUS atcacert_read_cert_size_ext(ATCADevice            device,
                                        const atcacert_def_t* cert_def,
                                        size_t*               cert_size)
{
    uint8_t buffer[75];
    size_t buflen = sizeof(buffer);
    ATCA_STATUS ret = ATCACERT_E_SUCCESS;

    if ((NULL == cert_def) || (NULL == cert_size))
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    ret = atcab_read_bytes_zone_ext(device, (uint8_t)DEVZONE_TO_BYTEVAL(cert_def->comp_cert_dev_loc.zone),
                                    cert_def->comp_cert_dev_loc.slot,
                                    cert_def->comp_cert_dev_loc.offset,
                                    &buffer[8], ATCA_ECCP256_SIG_SIZE);

    if (ATCACERT_E_SUCCESS == ret)
    {
        ret = atcacert_der_enc_ecdsa_sig_value(&buffer[8], buffer, &buflen);
    }

    if (ATCACERT_E_SUCCESS == ret)
    {
        *cert_size = cert_def->std_cert_elements[STDCERT_SIGNATURE].offset + buflen;
    }

    return ret;
}

ATCA_STATUS atcacert_read_cert_size(const atcacert_def_t* cert_def,
                                    size_t*               cert_size)
{
    return atcacert_read_cert_size_ext(atcab_get_device(), cert_def, cert_size);
}

#endif
