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

#if ATCA_CA_SUPPORT
#include "calib/calib_basic.h"
#endif

#if ATCA_TA_SUPPORT && !LIBRARY_USAGE_EN_CHECK
#include "talib/talib_basic.h"
#include "talib/talib_internal.h"
#endif

#if ATCACERT_EN

#if ATCACERT_COMPCERT_EN

#define DEVZONE_TO_BYTEVAL(zone)    (((int)(zone) < UCHAR_MAX) ? ((uint8_t)(zone) & 0xFFu) : 0x07u)

#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
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


ATCA_STATUS atcacert_get_response(uint16_t          device_private_key_slot,
                                  cal_buffer*       challenge,
                                  cal_buffer*       response)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    ATCADeviceType dev_type = atcab_get_device_type();
#if ATCA_TA_SUPPORT
    ta_handle_info handle_info;
    uint8_t key_type = 0u;
    uint8_t alg_mode = 0u;
#endif

#if ATCA_CHECK_PARAMS_EN
    if ((false == atcab_is_ta_device(dev_type)) && device_private_key_slot > 15U)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if ((challenge == NULL) || (challenge->buf == NULL) || (response == NULL) || (response->buf == NULL))
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
    if (atcab_is_ca_device(dev_type) || atcab_is_ca2_device(dev_type))
    {
        status = atcab_sign(device_private_key_slot, challenge->buf, response->buf);
    }
#endif
#if ATCA_TA_SUPPORT
    if (atcab_is_ta_device(dev_type))
    {
        if (ATCA_SUCCESS == (status = talib_info_get_handle_info(atcab_get_device(), device_private_key_slot, &handle_info)))
        {
            key_type = (handle_info.attributes.element_CKA & TA_HANDLE_INFO_KEY_TYPE_MASK) >> TA_HANDLE_INFO_KEY_TYPE_SHIFT;
            alg_mode = handle_info.attributes.element_CKA & TA_HANDLE_INFO_ALG_MODE_MASK;
            status = talib_sign_external(atcab_get_device(), key_type | (uint8_t)(alg_mode << TA_ALG_MODE_SHIFT), device_private_key_slot,
                                         TA_HANDLE_INPUT_BUFFER, challenge, response);                 
        }
    }
#endif
    return status;
}

ATCA_STATUS atcacert_read_device_loc_ext(ATCADevice                     device,
                                         const atcacert_device_loc_t*   device_loc,
                                         uint8_t*                       data)
{
    ATCA_STATUS ret = 0;
    ATCADeviceType dev_type = atcab_get_device_type_ext(device);

    if (device_loc->zone == DEVZONE_DATA && (0U != device_loc->is_genkey))
    {
        uint8_t public_key[ATCA_MAX_ECC_PB_KEY_SIZE];
#if ATCA_TA_SUPPORT
        cal_buffer pub_key = CAL_BUF_INIT(device_loc->count, public_key);
#endif

#if ATCA_CHECK_PARAMS_EN
        if (device_loc->offset + device_loc->count > ATCA_MAX_ECC_PB_KEY_SIZE) // sizeof public_key, in bytes
        {
            return ATCACERT_E_BAD_PARAMS;
        }
#endif

#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
        if (atcab_is_ca_device(dev_type) || atcab_is_ca2_device(dev_type))
        {
            ret = atcab_get_pubkey_ext(device, device_loc->slot, public_key);
        }
#endif
#if ATCA_TA_SUPPORT
        if (atcab_is_ta_device(dev_type))
        {
            ret = talib_get_pubkey(device, device_loc->slot, &pub_key);
        }
#endif
        if (ret != ATCA_SUCCESS)
        {
            return ret;
        }
        (void)memcpy(data, &public_key[device_loc->offset], device_loc->count);
    }
    else if (device_loc->zone == DEVZONE_DEDICATED_DATA)
    {
#if ATCA_TA_SUPPORT
        ret = talib_info_serial_number(device, data);
        if (ret != ATCA_SUCCESS)
        {
            return ret;
        }
#endif
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
            count = (zone_size != 0u) ? (zone_size - device_loc->offset) : (count);
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

ATCA_STATUS atcacert_read_device_loc(const atcacert_device_loc_t*   device_loc,
                                     uint8_t*                       data)
{
    return atcacert_read_device_loc_ext(atcab_get_device(), device_loc, data);
}
#endif

ATCA_STATUS atcacert_read_cert_ext(ATCADevice               device,
                                   const atcacert_def_t*    cert_def,
                                   const cal_buffer*        ca_public_key,
                                   uint8_t*                 cert,
                                   size_t*                  cert_size)
{
    ATCA_STATUS ret = ATCACERT_E_BAD_PARAMS;

#if ATCACERT_COMPCERT_EN
    atcacert_device_loc_t device_locs[ATCA_MAX_SLOT_NUM];
    size_t device_locs_count = 0;
    size_t i = 0;
    atcacert_build_state_t build_state;
#endif

    UNUSED_VAR(ca_public_key->buf[0]);

#if ATCA_CHECK_PARAMS_EN
    if (cert_def == NULL || cert_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

    if (cert == NULL)
    {
        return atcacert_read_cert_size_ext(device, cert_def, cert_size);
    }

    if (CERTTYPE_X509_FULL_STORED == cert_def->type)
    {
#if ATCACERT_FULLSTOREDCERT_EN
        if (ATCACERT_E_SUCCESS == (ret = atcab_read_bytes_zone_ext(device, (uint8_t)cert_def->comp_cert_dev_loc.zone,
                                                                   cert_def->comp_cert_dev_loc.slot, 0u, cert, *cert_size)))
        {   
            ATCADeviceType dev_type = atcab_get_device_type_ext(device);
            if (atcab_is_ta_device(dev_type))
            {
    #if ATCA_TA_SUPPORT
                size_t actual_cert_len = 0x00;
                if (ATCACERT_E_SUCCESS == (ret = talib_get_x509_cert_size(device, cert_def->comp_cert_dev_loc.slot, cert, &actual_cert_len)))
                {
                    if (*cert_size > actual_cert_len)
                    {
                        *cert_size = actual_cert_len;
                    }
                }
                else
                {
                    return ret;
                }
    #endif
            }
    #if ATCACERT_INTEGRATION_EN
            cal_buffer buf = CAL_BUF_INIT(*cert_size, cert);
            /* Load parsed certificate if not already done */
            if (NULL == *cert_def->parsed)
            {
                if (ATCACERT_E_SUCCESS != (ret = atcac_parse_der(cert_def->parsed, &buf)))
                {
                    return ret;
                }
            }
    #endif
        }
        else
        {
            return ret;
        }
#endif
    }
    else
    {
#if ATCACERT_COMPCERT_EN
        ret = atcacert_get_device_locs(
            device,
            cert_def,
            device_locs,
            &device_locs_count,
            sizeof(device_locs) / sizeof(device_locs[0]),
            ATCA_BLOCK_SIZE);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }

        ret = atcacert_cert_build_start(device, &build_state, cert_def, cert, cert_size, ca_public_key);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }

        for (i = 0; i < device_locs_count; i++)
        {
            static uint8_t data[ATCA_MAX_DATA_SIZE];
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
#endif
    }

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_read_cert(const atcacert_def_t*    cert_def,
                               const cal_buffer*        ca_public_key,
                               uint8_t*                 cert,
                               size_t*                  cert_size)
{
    return atcacert_read_cert_ext(atcab_get_device(), cert_def, ca_public_key, cert, cert_size);
}

#if ATCAB_WRITE_EN
ATCA_STATUS atcacert_write_cert_ext(ATCADevice              device,
                                    const atcacert_def_t*   cert_def,
                                    const uint8_t*          cert,
                                    size_t                  cert_size)
{
    ATCA_STATUS ret = 0;

#if ATCACERT_COMPCERT_EN
    ATCADeviceType devtype = atcab_get_device_type_ext(device);
    atcacert_device_loc_t device_locs[ATCA_MAX_SLOT_NUM];
    size_t device_locs_count = 0;
    size_t i = 0;
#if ATCA_TA_SUPPORT
    size_t handle_size = 0u;
#endif
#endif

#if ATCA_CHECK_PARAMS_EN
    if (cert_def == NULL || cert == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

    if (CERTTYPE_X509_FULL_STORED == cert_def->type)
    {
#if ATCACERT_FULLSTOREDCERT_EN
        ATCADeviceType dev_type = atcab_get_device_type_ext(device);
        if (atcab_is_ta_device(dev_type))
        {
    #if ATCA_TA_SUPPORT
            cal_buffer cert_data_buf = cal_buf_init_const_ptr(cert_size, cert);
            ret = talib_write_X509_cert(device, cert_def->comp_cert_dev_loc.slot, &cert_data_buf);
    #endif
        }
        else
        {
    #if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
            ret = atcab_write_bytes_zone_ext(device, (uint8_t)cert_def->comp_cert_dev_loc.zone,
                                             cert_def->comp_cert_dev_loc.slot, 0, cert, cert_size);
    #endif
        }

        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }
#endif
    }
    else
    {
#if ATCACERT_COMPCERT_EN
        ret = atcacert_get_device_locs(
            device,
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
            static uint8_t data[ATCA_MAX_DATA_SIZE];
#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
            int end_block;
            int start_block; 
            int block;
#endif

            if (device_locs[i].zone == DEVZONE_CONFIG || device_locs[i].zone == DEVZONE_DEDICATED_DATA)
            {
                continue;   // Cert data isn't written to the config/dedicated data zone, only read
            }
            if (device_locs[i].zone == DEVZONE_DATA && (0U != device_locs[i].is_genkey))
            {
                continue;   // Public key is generated not written

            }
            ret = atcacert_get_device_data(cert_def, cert, cert_size, &device_locs[i], data);
            if (ret != ATCACERT_E_SUCCESS)
            {
                return ret;
            }

            if (true == atcab_is_ta_device(devtype))
            {
    #if ATCA_TA_SUPPORT
                if (ATCA_SUCCESS == (ret = atcab_get_zone_size_ext(device, (uint8_t)device_locs[i].zone, device_locs[i].slot, &handle_size)))
                {
                    if (handle_size >= ((size_t)device_locs[i].offset + (size_t)device_locs[i].count))
                    {
                        ret = talib_write_bytes_zone(device, (const uint8_t)device_locs[i].zone, device_locs[i].slot, device_locs[i].offset, 
                                                     data, device_locs[i].count);
                    }
                    else
                    {
                        return ATCACERT_E_ELEM_OUT_OF_BOUNDS;
                    }
                }
                else
                {
                    return ret;
                }
    #endif
            }
            else
            {
    #if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
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
    #endif
            }
        }
#endif
    }
    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_write_cert(const atcacert_def_t*   cert_def,
                                const uint8_t*          cert,
                                size_t                  cert_size)
{
    return atcacert_write_cert_ext(atcab_get_device(), cert_def, cert, cert_size);
}
#endif

#if ATCACERT_COMPCERT_EN
ATCA_STATUS atcacert_create_csr_pem(const atcacert_def_t* csr_def, char* csr, size_t* csr_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    size_t csr_max_size;
    size_t csr_der_size;

#if ATCA_CHECK_PARAMS_EN
    // Check the pointers
    if (csr_def == NULL || csr == NULL || csr_size == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif
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
    ATCADeviceType dev_type = atcab_get_device_type();
    uint8_t pub_key[ATCA_MAX_ECC_PB_KEY_SIZE] = { 0 };
    uint8_t sig[ATCA_MAX_ECC_SIG_SIZE] = { 0 };
    cal_buffer signature = CAL_BUF_INIT(0u, sig);
    const atcacert_device_loc_t* pub_dev_loc = NULL;
    const atcacert_cert_loc_t* pub_loc = NULL;
    uint16_t key_slot = 0;
    uint16_t priv_key_slot = 0;
    uint8_t tbs_digest[ATCA_SHA512_DIGEST_SIZE] = { 0 };
    cal_buffer tbs_dig_buf = CAL_BUF_INIT(sizeof(tbs_digest), tbs_digest);
    size_t csr_max_size = 0;
#if ATCA_TA_SUPPORT
    cal_buffer pub_key_buf = CAL_BUF_INIT(0u, pub_key);
    ta_handle_info handle_info;
    uint8_t key_type = 0u;
    uint8_t alg_mode = 0u;
#endif

    do
    {
#if ATCA_CHECK_PARAMS_EN
        // Check the pointers
        if ((csr_def == NULL) || (csr == NULL) || (csr_size == NULL))
        {
            status = (ATCA_STATUS)ATCACERT_E_BAD_PARAMS;
            (void)ATCA_TRACE(status, "Null input parameter"); break;
        }
#endif
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
#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
            if (atcab_is_ca_device(dev_type) || atcab_is_ca2_device(dev_type))
            {
                status = atcab_get_pubkey(key_slot, pub_key);
            }
#endif
#if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(dev_type))
            {
                pub_key_buf.len = pub_dev_loc->count;
                status = talib_get_pubkey(atcab_get_device(), key_slot, &pub_key_buf);
            }
#endif   
            if (status != ATCA_SUCCESS)
            {
                (void)ATCA_TRACE(status, "Could not generate public key"); break;
            }
        }
        else
        {
            // Read the public key from a slot
#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
            if (atcab_is_ca_device(dev_type) || atcab_is_ca2_device(dev_type))
            {
                status = atcab_read_pubkey(key_slot, pub_key);
            }
#endif
#if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(dev_type))
            {
                pub_key_buf.len = pub_dev_loc->count;
                status = talib_read_element(atcab_get_device(), key_slot, &pub_key_buf);
            }
#endif
            if (status != ATCA_SUCCESS)
            {
                (void)ATCA_TRACE(status, "Could not read public key"); break;
            }
        }
        // Insert the public key into the CSR template
        status = atcacert_set_cert_element(csr_def, pub_loc, csr, *csr_size, pub_key, pub_loc->count);
        if (status != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Setting CSR public key failed"); break;
        }

#if ATCA_TA_SUPPORT
        if (ATCA_ECCP384_SIG_SIZE == csr_def->std_sig_size)
        {
            tbs_dig_buf.len = ATCA_SHA2_384_DIGEST_SIZE;
            signature.len = ATCA_ECCP384_SIG_SIZE;
        }
        else if (ATCA_ECCP521_SIG_SIZE == csr_def->std_sig_size)
        {
            tbs_dig_buf.len = ATCA_SHA2_512_DIGEST_SIZE;
            signature.len = ATCA_ECCP521_SIG_SIZE;
        }
        else
#endif
        {
            tbs_dig_buf.len = ATCA_SHA2_256_DIGEST_SIZE;
            signature.len = ATCA_ECCP256_SIG_SIZE;
        }

        // Get the CSR TBS digest
        status = atcacert_get_tbs_digest(csr_def, csr, *csr_size, &tbs_dig_buf);
        if (status != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Get TBS digest failed"); break;
        }

        // Sign the TBS digest
#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
        if (atcab_is_ca_device(dev_type) || atcab_is_ca2_device(dev_type))
        {
            status = atcab_sign(priv_key_slot, tbs_digest, sig);
        }
#endif
#if ATCA_TA_SUPPORT
        if (atcab_is_ta_device(dev_type))
        {
            if (ATCA_SUCCESS == (status = talib_info_get_handle_info(atcab_get_device(), priv_key_slot, &handle_info)))
            {
                key_type = (handle_info.attributes.element_CKA & TA_HANDLE_INFO_KEY_TYPE_MASK) >> TA_HANDLE_INFO_KEY_TYPE_SHIFT;
                alg_mode = handle_info.attributes.element_CKA & TA_HANDLE_INFO_ALG_MODE_MASK;
                status = talib_sign_external(atcab_get_device(), key_type | (uint8_t)(alg_mode << TA_ALG_MODE_SHIFT), priv_key_slot,
                                             TA_HANDLE_INPUT_BUFFER, &tbs_dig_buf, &signature);                 
            }
        }
#endif
        if (status != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Signing CSR failed"); break;
        }

        // Insert the signature into the CSR template
        status = atcacert_set_signature(csr_def, csr, csr_size, csr_max_size, &signature);
        if (status != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Setting CSR signature failed"); break;
        }

        // The exact size of the csr cannot be determined until after adding the signature
        // it is returned in the csr_size parameter.  (*csr_size = *csr_size;)

    } while (false);

    return status;
}

ATCA_STATUS atcacert_read_subj_key_id_ext(ATCADevice device, const atcacert_def_t* cert_def, uint8_t subj_key_id[20])
{
    ATCA_STATUS ret = ATCACERT_E_DECODING_ERROR;
    uint8_t subj_public_key[ATCA_MAX_ECC_PB_KEY_SIZE] = { 0 };
    uint16_t subj_pub_key_len = (72U == cert_def->public_key_dev_loc.count) ? (ATCA_ECCP256_PUBKEY_SIZE) : (cert_def->public_key_dev_loc.count);
    cal_buffer subj_pub_key = CAL_BUF_INIT(subj_pub_key_len, subj_public_key);
    ATCADeviceType dev_type = atcab_get_device_type_ext(device);

#if ATCA_CHECK_PARAMS_EN
    if (cert_def == NULL || subj_key_id == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

    if (DEVZONE_DATA == cert_def->public_key_dev_loc.zone)
    {
        if (0U != cert_def->public_key_dev_loc.is_genkey)
        {
            /* generate the key */
#if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
            if (atcab_is_ca_device(dev_type) || atcab_is_ca2_device(dev_type))
            {
                ret = atcab_get_pubkey_ext(device, cert_def->public_key_dev_loc.slot, subj_public_key);
            }
#endif
#if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(dev_type))
            {
                ret = talib_get_pubkey(device, cert_def->public_key_dev_loc.slot, &subj_pub_key);
            }
#endif
        }
        else
        {
            /* Load the public key from a slot */
            ret = atcab_read_bytes_zone_ext(device, (uint8_t)cert_def->public_key_dev_loc.zone,
                                            cert_def->public_key_dev_loc.slot,
                                            cert_def->public_key_dev_loc.offset,
                                            subj_public_key, cert_def->public_key_dev_loc.count);

#if ATCA_CA_SUPPORT
            /* IF the public key is stored in device public key format */
            if ((ATCA_SUCCESS == ret) && (72U == cert_def->public_key_dev_loc.count))
            {
                atcacert_public_key_remove_padding(subj_public_key, subj_public_key);
            }
#endif
        }

        if (ATCA_SUCCESS == ret)
        {
            /* Calculate the key_id */
            ret = atcacert_get_key_id(&subj_pub_key, subj_key_id);
        }
    }
    return ret;
}

ATCA_STATUS atcacert_read_subj_key_id(const atcacert_def_t* cert_def, uint8_t subj_key_id[20])
{
    return atcacert_read_subj_key_id_ext(atcab_get_device(), cert_def, subj_key_id);
}
#endif

ATCA_STATUS atcacert_read_cert_size_ext(ATCADevice              device,
                                        const atcacert_def_t*   cert_def,
                                        size_t*                 cert_size)
{
    ATCA_STATUS ret = ATCACERT_E_SUCCESS;

#if ATCACERT_COMPCERT_EN
    uint8_t buf[ATCA_MAX_ECC_SIG_SIZE + ATCACERT_MAX_SIG_OVERHEAD + ATCACERT_COMPCERT_OVERHEAD];
    size_t buflen = sizeof(buf);
    cal_buffer sig_buf = CAL_BUF_INIT(0u, &buf[ATCACERT_MAX_R_SIG_OFFSET]);
    size_t length = 0;
#endif

#if ATCA_CHECK_PARAMS_EN
    if ((NULL == cert_def) || (NULL == cert_size))
    {
        return ATCACERT_E_BAD_PARAMS;
    }
#endif

    if (CERTTYPE_X509_FULL_STORED == cert_def->type)
    {   
#if ATCACERT_FULLSTOREDCERT_EN
        ATCADeviceType dev_type = atcab_get_device_type_ext(device);
        if (atcab_is_ta_device(dev_type))
        {
    #if ATCA_TA_SUPPORT
            ret = talib_get_x509_cert_size(device, cert_def->comp_cert_dev_loc.slot, NULL, cert_size);
    #endif
        }
        else
        {
    #if ATCA_CA_SUPPORT || ATCA_CA2_SUPPORT
            ret = atcab_get_zone_size_ext(device, (uint8_t)cert_def->comp_cert_dev_loc.zone,
                                      cert_def->comp_cert_dev_loc.slot, cert_size);
    #endif
        }
#endif
    }
    else
    {
#if ATCACERT_COMPCERT_EN
        sig_buf.len = (0u == cert_def->std_sig_size) ? ATCA_ECCP256_SIG_SIZE : cert_def->std_sig_size;
        length = (sig_buf.len > ATCA_ECCP256_SIG_SIZE) ? (ATCACERT_COMP_CERT_MAX_SIZE) : (sig_buf.len);

        (void)memset(buf, 0, sizeof(buf));
        ret = atcab_read_bytes_zone_ext(device, (uint8_t)DEVZONE_TO_BYTEVAL(cert_def->comp_cert_dev_loc.zone),
                                        cert_def->comp_cert_dev_loc.slot,
                                        cert_def->comp_cert_dev_loc.offset,
                                        &buf[ATCACERT_MAX_R_SIG_OFFSET], length);

    #if ATCA_TA_SUPPORT
        if (sig_buf.len > ATCA_ECCP256_SIG_SIZE)
        {
            (void)memmove(&buf[ATCACERT_MAX_R_SIG_OFFSET + ATCA_ECCP256_SIG_SIZE], 
                          &buf[ATCACERT_MAX_R_SIG_OFFSET + ATCA_ECCP256_SIG_SIZE + ATCACERT_COMPCERT_OVERHEAD], 
                          (sig_buf.len - ATCA_ECCP256_SIG_SIZE));
        }    
    #endif

        if (ATCACERT_E_SUCCESS == ret)
        { 
            ret = atcacert_der_enc_ecdsa_sig_value(&sig_buf, buf, &buflen);
        }

        if (ATCACERT_E_SUCCESS == ret)
        {
            *cert_size = cert_def->std_cert_elements[STDCERT_SIGNATURE].offset + buflen;
        }
#endif
    }

    return ret;
}

ATCA_STATUS atcacert_read_cert_size(const atcacert_def_t*   cert_def,
                                    size_t*                 cert_size)
{
    return atcacert_read_cert_size_ext(atcab_get_device(), cert_def, cert_size);
}

#endif /* ATCACERT_EN */