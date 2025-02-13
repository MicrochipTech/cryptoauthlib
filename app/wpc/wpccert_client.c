/**
 * \file
 * \brief Provides api interfaces for accessing WPC certificates from device.
 *
 * \copyright (c) 2015-2021 Microchip Technology Inc. and its subsidiaries.
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

#include "wpc_check_config.h"
#include "wpccert_client.h"

#include "atcacert/atcacert_def.h"
#include "atcacert/atcacert_der.h"
#include "atcacert/atcacert_client.h"
#include "atca_basic.h"

#if WPC_MSG_PT_EN

#ifdef WPC_CHAIN_CERT_DEF_0
extern const atcacert_def_t WPC_CHAIN_CERT_DEF_0;
#endif

#ifdef WPC_CHAIN_CERT_DEF_1
extern const atcacert_def_t WPC_CHAIN_CERT_DEF_1;
#endif

#ifdef WPC_CHAIN_CERT_DEF_2
extern const atcacert_def_t WPC_CHAIN_CERT_DEF_2;
#endif

#ifdef WPC_CHAIN_CERT_DEF_3
extern const atcacert_def_t WPC_CHAIN_CERT_DEF_3;
#endif

#ifdef WPC_CHAIN_ROOT_DIGEST_0
extern const uint8_t WPC_CHAIN_ROOT_DIGEST_0[];
#endif

#ifdef WPC_CHAIN_ROOT_DIGEST_1
extern const uint8_t WPC_CHAIN_ROOT_DIGEST_1[];
#endif

#ifdef WPC_CHAIN_ROOT_DIGEST_2
extern const uint8_t WPC_CHAIN_ROOT_DIGEST_2[];
#endif

#ifdef WPC_CHAIN_ROOT_DIGEST_3
extern const uint8_t WPC_CHAIN_ROOT_DIGEST_3[];
#endif


#if ATCA_CA2_SUPPORT
#ifdef WPC_CHAIN_MFG_CERT_0
extern const uint8_t WPC_CHAIN_MFG_CERT_0[];
#endif

#ifdef WPC_CHAIN_MFG_CERT_1
extern const uint8_t WPC_CHAIN_MFG_CERT_1[];
#endif

#ifdef WPC_CHAIN_MFG_CERT_2
extern const uint8_t WPC_CHAIN_MFG_CERT_2[];
#endif

#ifdef WPC_CHAIN_MFG_CERT_3
extern const uint8_t WPC_CHAIN_MFG_CERT_3[];
#endif
#endif

typedef struct wpc_slot_info_s
{
#if !WPC_STRICT_SLOT_INDEX_EN
    uint8_t id;
#endif
    uint16_t                handle; // Chain digest Handle
    const uint8_t*          root;   // Root digest
    uint8_t*                mfg;    // Manufacturer certificate
    const atcacert_def_t*   def;    // Cert def
#if ATCA_TA_SUPPORT
    uint16_t root_dgst_handle;      // Root Digest Handle
#endif
} wpc_slot_info_t;

#if ATCA_ECC_SUPPORT
    #if !WPC_STRICT_SLOT_INDEX_EN
    #define WPC_INFO(n)                { n, WPC_CHAIN_DIGEST_HANDLE_ ## n, WPC_CHAIN_ROOT_DIGEST_ ## n, NULL, &WPC_CHAIN_CERT_DEF_ ## n }
    #else
    #define WPC_INFO(n)                { WPC_CHAIN_DIGEST_HANDLE_ ## n, WPC_CHAIN_ROOT_DIGEST_ ## n, NULL, &WPC_CHAIN_CERT_DEF_ ## n }
    #endif
#elif ATCA_CA2_SUPPORT
    #if !WPC_STRICT_SLOT_INDEX_EN
    #define WPC_INFO(n)                { n, WPC_CHAIN_DIGEST_HANDLE_ ## n, WPC_CHAIN_ROOT_DIGEST_ ## n, WPC_CHAIN_MFG_CERT_ ## n, &WPC_CHAIN_CERT_DEF_ ## n }
    #else
    #define WPC_INFO(n)                { WPC_CHAIN_DIGEST_HANDLE_ ## n, WPC_CHAIN_ROOT_DIGEST_ ## n, WPC_CHAIN_MFG_CERT_ ## n, &WPC_CHAIN_CERT_DEF_ ## n }
    #endif
#elif ATCA_TA_SUPPORT
    #if !WPC_STRICT_SLOT_INDEX_EN
    #define WPC_INFO(n)                { n, WPC_CHAIN_DIGEST_HANDLE_ ## n, NULL, NULL, &WPC_CHAIN_CERT_DEF_ ## n, WPC_CHAIN_ROOT_DIGEST_HANDLE_ ## n }
    #else
    #define WPC_INFO(n)                { WPC_CHAIN_DIGEST_HANDLE_ ## n, NULL, NULL, &WPC_CHAIN_CERT_DEF_ ## n, WPC_CHAIN_ROOT_DIGEST_HANDLE_ ## n }
    #endif
#endif

static const wpc_slot_info_t wpc_slot_info[] = {
#ifdef WPC_CHAIN_DIGEST_HANDLE_0
    WPC_INFO(0),
#endif
#ifdef WPC_CHAIN_DIGEST_HANDLE_1
    WPC_INFO(1),
#endif
#ifdef WPC_CHAIN_DIGEST_HANDLE_2
    WPC_INFO(2),
#endif
#ifdef WPC_CHAIN_DIGEST_HANDLE_3
    WPC_INFO(3),
#endif
};

static const uint8_t wpc_slot_info_count = (uint8_t)(sizeof(wpc_slot_info) / sizeof(wpc_slot_info_t));

uint8_t wpccert_get_slot_count(void)
{
    return wpc_slot_info_count;
}

uint8_t wpccert_get_slots_populated(void)
{
    uint8_t i, populated;

    for (i = 0, populated = 0; i < wpc_slot_info_count; i++)
    {
#if WPC_STRICT_SLOT_INDEX_EN
        populated |= (1 << wpc_slot_info[i].id);
#else
        populated |= (1 << i);
#endif
    }
    return ATCA_SUCCESS;
}

ATCA_STATUS wpccert_get_slot_info(
    uint16_t *              handle,             /**< [out] Digest handle */
    const atcacert_def_t**  def,                /**< [out] Chain definition (device) */
    uint8_t**               mfg,                /**< [out] Manufacture cert */
    uint8_t *               root_dgst,          /**< [out] Root digest */
    uint16_t *              root_dgst_handle,   /**< [out] Root digest handle*/
    uint8_t                 slot                /**< [in] Chain slot number */
    )
{
#if WPC_STRICT_SLOT_INDEX_EN
    ATCA_CHECK_INVALID_MSG(!(slot < wpc_slot_info_count), ATCA_BAD_PARAM, "Index out of range");
    if (handle)
    {
        *handle = wpc_slot_info[slot].handle;
    }
    if (def)
    {
        *def = wpc_slot_info[slot].def;
    }
    if (mfg)
    {
        *mfg = wpc_slot_info[slot].mfg;
    }
    if (root_dgst)
    {
        *root_dgst = wpc_slot_info[slot].root;
    }
#if ATCA_TA_SUPPORT
    if (root_dgst_handle)
    {
        *root_dgst_handle = wpc_slot_info[slot].root_dgst_handle;
    }
#endif
    return ATCA_SUCCESS;
#else
    uint8_t i;
    for (i = 0; (i < wpc_slot_info_count); i++)
    {
        if (wpc_slot_info[i].id == slot)
        {
            if (handle)
            {
                *handle = wpc_slot_info[i].handle;
            }
            if (def)
            {
                *def = wpc_slot_info[i].def;
            }
            if (mfg)
            {
                *mfg = wpc_slot_info[i].mfg;
            }
            if (root_dgst)
            {
                *root_dgst = wpc_slot_info[slot].root;
            }
#if ATCA_TA_SUPPORT
            if (root_dgst_handle)
            {
                *root_dgst_handle = wpc_slot_info[slot].root_dgst_handle;
            }
#endif
            return ATCA_SUCCESS;
        }
    }
    return ATCA_FUNC_FAIL;
#endif
}
#endif

ATCA_STATUS wpccert_read_cert_size(ATCADevice               device,
                                   const atcacert_def_t*    cert_def,
                                   size_t*                  cert_size)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL == cert_def) || (NULL == cert_size))
    {
        return ATCA_BAD_PARAM;
    }

    if (CERTTYPE_X509_FULL_STORED == cert_def->type)
    {
        uint8_t cert_hdr[4u] = { 0x00 };
        if (ATCA_SUCCESS != (status = atcab_read_bytes_zone_ext(device, (uint8_t)cert_def->comp_cert_dev_loc.zone,
                                                                cert_def->comp_cert_dev_loc.slot, 0u, cert_hdr, sizeof(cert_hdr))))
        {
            status = ATCA_TRACE(status, "atcab_read_bytes_zone_ext execution is failed for wpccert_read_cert_size");
            return status;
        }

        *cert_size = (size_t)((cert_hdr[2] << 8) | cert_hdr[3]) + 4u;
    }
    else
    {
#if ATCACERT_COMPCERT_EN
        uint8_t buffer[75];
        size_t buflen = sizeof(buffer);
        size_t max_cert_size;
        atcacert_device_loc_t comp_cert_loc = cert_def->comp_cert_dev_loc;
        cal_buffer sig_buf = CAL_BUF_INIT(ATCA_ECCP256_SIG_SIZE, &buffer[8]);

        /* Read cert size */
        if (ATCA_SUCCESS != (status =  atcab_read_bytes_zone_ext(device, comp_cert_loc.zone, comp_cert_loc.slot, 0, &buffer[8], 64)))
        {
            status = ATCA_TRACE(status, "read_sig failed");
            return status;
        }

        if (ATCA_SUCCESS != (status = atcacert_der_enc_ecdsa_sig_value(&sig_buf, buffer, &buflen)))
        {
            status = ATCA_TRACE(status, "ecdsa signature encode failed");
            return status;
        }

        max_cert_size = cert_def->std_cert_elements[STDCERT_SIGNATURE].offset + buflen;
        *cert_size = max_cert_size;

        if (*cert_size > cert_def->cert_template_size)
        {
            *cert_size = cert_def->cert_template_size;
        }
#endif
    }

    return status;
}


/** \brief WPC API -
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS wpccert_read_cert(
    ATCADevice              device,
    const atcacert_def_t *  cert_def,
    uint8_t *               cert,
    size_t *                cert_size)
{
    ATCA_STATUS status = ATCA_UNIMPLEMENTED;

#if ATCA_ECC_SUPPORT
    uint8_t subj_public_key[72];
    uint8_t buffer[75], enc_dates[3];
    size_t buflen = sizeof(buffer);
    cal_buffer buf = CAL_BUF_INIT(buflen, buffer);
    size_t max_cert_size = 0;
    atcacert_device_loc_t comp_cert_loc = cert_def->comp_cert_dev_loc;
    atcacert_device_loc_t cert_sn_loc = cert_def->cert_sn_dev_loc;
    atcacert_tm_utc_t issue_date, expire_date;
    uint8_t formatted_date[DATEFMT_MAX_SIZE];
    size_t formatted_date_size = ATCACERT_DATE_FORMAT_SIZES[cert_def->issue_date_format];
#endif

    ATCA_CHECK_INVALID_MSG((cert_def == NULL || cert_size == NULL), ATCA_BAD_PARAM, "NULL pointer received");

    if (CERTTYPE_X509_FULL_STORED == cert_def->type)
    {
        if (cert == NULL)
        {
            return wpccert_read_cert_size(device, cert_def, cert_size);
        }

        if (ATCA_SUCCESS != (status = atcab_read_bytes_zone_ext(device, (uint8_t)cert_def->comp_cert_dev_loc.zone,
                                                                cert_def->comp_cert_dev_loc.slot, 0u, cert, *cert_size)))
        {
            status = ATCA_TRACE(status, "read cert failed");
            return status;
        }

        #if ATCACERT_INTEGRATION_EN
        cal_buffer buf = CAL_BUF_INIT(*cert_size, cert);
        /* Load parsed certificate if not already done */
        if (NULL == *cert_def->parsed)
        {
            if (ATCACERT_E_SUCCESS != (status = atcac_parse_der(cert_def->parsed, &buf)))
            {
                return status;
            }
        }
        #endif
    }
    else
    {
#if ATCA_ECC_SUPPORT
        if (ATCA_SUCCESS != wpccert_read_cert_size(device, cert_def, cert_size))
        {
            return status;
        }

        memcpy(cert, cert_def->cert_template, *cert_size);
        max_cert_size = cert_def->std_cert_elements[STDCERT_SIGNATURE].offset + buflen;

        // set comp_cert
        if (ATCA_SUCCESS != (status = atcab_read_bytes_zone_ext(device, comp_cert_loc.zone, comp_cert_loc.slot,
                                                                comp_cert_loc.offset, buffer, comp_cert_loc.count)))
        {
            status = ATCA_TRACE(status, "read comp cert failed");
            return status;
        }

        // set signature
        if (ATCA_SUCCESS != (status = atcacert_set_signature(cert_def, cert, cert_size, max_cert_size, &buf)))
        {
            status = ATCA_TRACE(status, "set signature failed");
            return status;
        }

        memcpy(enc_dates, &buffer[64], 3);
        if (ATCA_SUCCESS != (status = atcacert_date_dec_compcert(enc_dates, cert_def->expire_date_format,
                                                                 &issue_date, &expire_date)))
        {
            status = ATCA_TRACE(status, "atcacert_date_dec_compcert failed");
            return status;
        }

        // set issue date
        if (ATCA_SUCCESS != (status = atcacert_date_enc(cert_def->issue_date_format, &issue_date,
                                                        formatted_date, &formatted_date_size)))
        {
            status = ATCA_TRACE(status, "date encoding failed");
            return status;
        }
        memcpy(&cert[cert_def->std_cert_elements[STDCERT_ISSUE_DATE].offset], formatted_date, formatted_date_size);

        // set cert_sn
        if (cert_sn_loc.zone != DEVZONE_NONE)
        {
            if (ATCA_SUCCESS != (status = atcab_read_bytes_zone_ext(device, cert_sn_loc.zone, cert_sn_loc.slot,
                                                                    cert_sn_loc.offset, buffer, cert_sn_loc.count)))
            {
                status = ATCA_TRACE(status, "read cert sn failed");
                return status;
            }
            memcpy(&cert[cert_def->std_cert_elements[STDCERT_CERT_SN].offset], buffer, cert_sn_loc.count);
        }

        // set subj_public_key
        if (ATCA_SUCCESS != (status = wpccert_public_key(cert_def, subj_public_key, NULL)))
        {
            status = ATCA_TRACE(status, "subj public key read failed");
            return status;
        }

        // set cert elements
        for (uint8_t i = 0; i < cert_def->cert_elements_count; i++)
        {
            if (ATCA_SUCCESS != (status = atcab_read_bytes_zone_ext(device, cert_def->cert_elements[i].device_loc.zone,
                                                                    cert_def->cert_elements[i].device_loc.slot,
                                                                    cert_def->cert_elements[i].device_loc.offset,
                                                                    buffer, cert_def->cert_elements[i].device_loc.count)))
            {
                status = ATCA_TRACE(status, "read cert elements failed");
                return status;
            }

            memcpy(&cert[cert_def->cert_elements[i].cert_loc.offset], buffer, cert_def->cert_elements[i].cert_loc.count);
        }
#ifdef WPC_CERT_SN_FROM_HASH
        if (cert_def->sn_source == SNSRC_PUB_KEY_HASH)
        {
            uint8_t cert_sn_msg[64 + 3], sn[32];

            // Add public key to hash input
            memcpy(&cert_sn_msg[0], &cert[cert_def->std_cert_elements[STDCERT_PUBLIC_KEY].offset], 64);

            // Add compressed/encoded dates to hash input
            memcpy(formatted_date, &cert[cert_def->std_cert_elements[STDCERT_ISSUE_DATE].offset], formatted_date_size);

            if (ATCA_SUCCESS != (status = atcacert_date_dec(cert_def->issue_date_format, formatted_date, formatted_date_size, &issue_date)))
            {
                status = ATCA_TRACE(status, "cert date decoding failed");
                return status;
            }

            // Issue and expire dates are compressed/encoded
            memset(&cert_sn_msg[64], 0, 3);

            cert_sn_msg[64] = (cert_sn_msg[64] & 0x07) | (uint8_t)(((issue_date.tm_year + 1900 - 2000) & 0x1F) << 3);
            cert_sn_msg[64] = (uint8_t)((cert_sn_msg[64] & 0xF8) | (((issue_date.tm_mon + 1) & 0x0F) >> 1));
            cert_sn_msg[65] = (uint8_t)((cert_sn_msg[65] & 0x7F) | (((issue_date.tm_mon + 1) & 0x0F) << 7));
            cert_sn_msg[65] = (uint8_t)((cert_sn_msg[65] & 0x83) | ((issue_date.tm_mday & 0x1F) << 2));
            cert_sn_msg[65] = (uint8_t)((cert_sn_msg[65] & 0xFC) | ((issue_date.tm_hour & 0x1F) >> 3));
            cert_sn_msg[66] = (uint8_t)((cert_sn_msg[66] & 0x1F) | ((issue_date.tm_hour & 0x1F) << 5));
            cert_sn_msg[66] = (uint8_t)((cert_sn_msg[66] & 0xE0) | (cert_def->expire_years & 0x1F));

            if (ATCA_SUCCESS != (status = atcab_hw_sha2_256(cert_sn_msg, 64 + 3, sn)))
            {
                status = ATCA_TRACE(status, "sha failed");
                return status;
            }

            sn[0] &= 0x7F;  // Ensure the SN is positive
            sn[0] |= 0x40;  // Ensure the SN doesn't have any trimmable bytes

            memcpy(&cert[cert_def->std_cert_elements[STDCERT_CERT_SN].offset], sn, cert_def->std_cert_elements[STDCERT_CERT_SN].count);
        }
#endif /* WPC_CERT_SN_FROM_HASH */
#endif /* ATCA_ECC_SUPPORT*/
    }

    return status;
}

#if ATCAB_WRITE_EN
ATCA_STATUS wpccert_write_cert(ATCADevice device, const atcacert_def_t* cert_def, const uint8_t* cert, size_t cert_size)
{
    ATCA_STATUS status;

#if ATCA_ECC_SUPPORT
    atcacert_device_loc_t comp_cert_loc = cert_def->comp_cert_dev_loc;
    atcacert_device_loc_t public_key_loc = cert_def->public_key_dev_loc;
    atcacert_device_loc_t cert_sn_loc = cert_def->cert_sn_dev_loc;
    uint8_t temp_buf[256];  // Must be at least 72 bytes
    cal_buffer buf = CAL_BUF_INIT(sizeof(temp_buf), temp_buf);
    uint8_t formatted_date[DATEFMT_MAX_SIZE];
    size_t der_sig_size = 0;
    size_t formatted_date_size = ATCACERT_DATE_FORMAT_SIZES[cert_def->issue_date_format];
    size_t sig_offset = cert_def->std_cert_elements[STDCERT_SIGNATURE].offset;
    atcacert_tm_utc_t issue_date;
#endif

    if (cert_def == NULL || cert == NULL)
    {
        status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
        return status;
    }

    if (CERTTYPE_X509_FULL_STORED == cert_def->type)
    {
        status = atcab_write_bytes_zone_ext(device, (uint8_t)cert_def->comp_cert_dev_loc.zone,
                                            cert_def->comp_cert_dev_loc.slot, 0, cert, cert_size);
    }
    else
    {
#if ATCA_ECC_SUPPORT
        // get comp cert
        der_sig_size = cert_size - sig_offset;

        if (ATCA_SUCCESS != (status = atcacert_der_dec_ecdsa_sig_value(&cert[sig_offset], &der_sig_size, &buf)))
        {
            status = ATCA_TRACE(status, "atcacert_der_dec_ecdsa_sig_value failed");
            return status;
        }
        memcpy(formatted_date, &cert[cert_def->std_cert_elements[STDCERT_ISSUE_DATE].offset], formatted_date_size);

        if (ATCA_SUCCESS != (status = atcacert_date_dec(cert_def->issue_date_format, formatted_date, formatted_date_size, &issue_date)))
        {
            status = ATCA_TRACE(status, "date decoding failed");
            return status;
        }

        memset(&temp_buf[64], 0, 3);

        temp_buf[64] = (temp_buf[64] & 0x07) | (uint8_t)(((issue_date.tm_year + 1900 - 2000) & 0x1F) << 3);
        temp_buf[64] = (uint8_t)((temp_buf[64] & 0xF8) | (((issue_date.tm_mon + 1) & 0x0F) >> 1));
        temp_buf[65] = (uint8_t)((temp_buf[65] & 0x7F) | (((issue_date.tm_mon + 1) & 0x0F) << 7));
        temp_buf[65] = (uint8_t)((temp_buf[65] & 0x83) | ((issue_date.tm_mday & 0x1F) << 2));
        temp_buf[65] = (uint8_t)((temp_buf[65] & 0xFC) | ((issue_date.tm_hour & 0x1F) >> 3));
        temp_buf[66] = (uint8_t)((temp_buf[66] & 0x1F) | ((issue_date.tm_hour & 0x1F) << 5));
        temp_buf[66] = (uint8_t)((temp_buf[66] & 0xE0) | (cert_def->expire_years & 0x1F));

        memset(&temp_buf[67], 0, sizeof(uint16_t)); // no signer_id in cert use 0

        temp_buf[69] = (uint8_t)(((cert_def->template_id & 0x0F) << 4) | (cert_def->chain_id & 0x0F));
        temp_buf[70] = (uint8_t)(((cert_def->sn_source & 0x0F) << 4) | 0);
        temp_buf[71] = 0;

        if (ATCA_SUCCESS != (status = atcab_write_bytes_zone_ext(device,
                                                                 comp_cert_loc.zone,
                                                                 comp_cert_loc.slot,
                                                                 comp_cert_loc.offset,
                                                                 temp_buf, comp_cert_loc.count)))
        {
            status = ATCA_TRACE(status, "compcert write failed");
            return status;
        }

        // get certificate serial number
        if (cert_sn_loc.count != 0)
        {
            memcpy(temp_buf, &cert[cert_def->std_cert_elements[STDCERT_CERT_SN].offset], cert_sn_loc.count);
            if (ATCA_SUCCESS != (status = atcab_write_bytes_zone_ext(device,
                                                                     cert_sn_loc.zone,
                                                                     cert_sn_loc.slot,
                                                                     cert_sn_loc.offset,
                                                                     temp_buf, cert_sn_loc.count)))
            {
                status = ATCA_TRACE(status, "write cert serial number failed");
                return status;
            }
        }

        if (public_key_loc.is_genkey == 0)
        {
            //get subj public key
            memcpy(temp_buf, &cert[cert_def->std_cert_elements[STDCERT_PUBLIC_KEY].offset], 64);

            if (public_key_loc.count == 72)
            {
                // Public key is formatted with padding bytes in front of the X and Y components
                memmove(&temp_buf[40], &temp_buf[32], 32);  // Move Y to padded position
                memset(&temp_buf[36], 0, sizeof(uint32_t)); // Add Y padding bytes
                memmove(&temp_buf[4], &temp_buf[0], 32);    // Move X to padded position
                memset(&temp_buf[0], 0, sizeof(uint32_t));  // Add X padding bytes
            }
            else if (public_key_loc.count != 64)
            {
                status = ATCA_TRACE(status, "public key count not valid");
                return status;  // Unexpected public key size
            }

            if (ATCA_SUCCESS != (status = atcab_write_bytes_zone_ext(device,
                                                                     public_key_loc.zone,
                                                                     public_key_loc.slot,
                                                                     public_key_loc.offset,
                                                                     temp_buf, public_key_loc.count)))
            {
                status = ATCA_TRACE(status, "write subj public key failed");
                return status;
            }
        }

        //get cert elements
        for (uint8_t i = 0; i < cert_def->cert_elements_count; i++)
        {
            memcpy(temp_buf, &cert[cert_def->cert_elements[i].cert_loc.offset], cert_def->cert_elements[i].cert_loc.count);
            comp_cert_loc = cert_def->cert_elements[i].device_loc;
            if (ATCA_SUCCESS != (status = atcab_write_bytes_zone_ext(device,
                                                                     comp_cert_loc.zone,
                                                                     comp_cert_loc.slot,
                                                                     comp_cert_loc.offset,
                                                                     temp_buf, comp_cert_loc.count)))
            {
                status = ATCA_TRACE(status, "write cert elements failed");
                return status;
            }
        }
#endif
    }

    return status;
}
#endif

ATCA_STATUS wpccert_read_pdu_cert(ATCADevice device, uint8_t* cert, size_t* cert_size, uint8_t slot)
{
    ATCA_STATUS status;
    const atcacert_def_t* chain;

    if (ATCA_SUCCESS == (status = wpccert_get_slot_info(NULL, &chain, NULL, NULL, NULL, slot)))
    {
        status = wpccert_read_cert(device, chain, cert, cert_size);
    }
    return status;
}

ATCA_STATUS wpccert_read_mfg_cert(ATCADevice device, uint8_t* cert, size_t* cert_size, uint8_t slot)
{
    ATCA_STATUS status;
    const atcacert_def_t* chain;
    uint8_t *mfg;

    if (ATCA_SUCCESS == (status = wpccert_get_slot_info(NULL, &chain, &mfg, NULL, NULL, slot)))
    {
        if (NULL == chain)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL Pointer receieved for cert def");
            return status;
        }

        if (NULL != chain->ca_cert_def)
        {
            //! CA or TA device MFG Cert
            status = wpccert_read_cert(device, chain->ca_cert_def, cert, cert_size);
        }
        else if (NULL != mfg)
        {
            //! CA2 device MFG Cert
            memcpy(cert, mfg, *cert_size);
            status = ATCA_SUCCESS;
        }
        else
        {
            /* Do Nothing */
        }
    }
    return status;
}

ATCA_STATUS wpccert_public_key(const atcacert_def_t* cert_def, uint8_t* public_key, uint8_t* cert)
{
    ATCA_STATUS status;

    if (public_key == NULL || cert_def == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (cert == NULL)
    {
        atcacert_device_loc_t public_key_loc;

        memset(&public_key_loc, 0, sizeof(atcacert_device_loc_t));

#if ATCACERT_COMPCERT_EN
        (void)memcpy(&public_key_loc, &cert_def->public_key_dev_loc, sizeof(atcacert_device_loc_t));
#endif
        uint8_t raw_public_key[72];

        if (public_key_loc.is_genkey)
        {
            uint8_t pub_key[ATCA_PUB_KEY_SIZE];

            if (ATCA_SUCCESS != (status = atcab_get_pubkey(public_key_loc.slot, pub_key)))
            {
                status = ATCA_TRACE(status, "subj public key read failed");
                return status;
            }
            memcpy(raw_public_key, &pub_key[public_key_loc.offset], public_key_loc.count);
        }
        else
        {
            if (ATCA_SUCCESS != (status = atcab_read_bytes_zone(public_key_loc.zone, public_key_loc.slot, public_key_loc.offset,
                                                                raw_public_key, public_key_loc.count)))
            {
                status = ATCA_TRACE(status, "subj public key read failed");
                return status;
            }
        }

        if (public_key_loc.count == 72)
        {
            // Public key is formatted with padding bytes in front of the X and Y components
            memmove(&public_key[0], &raw_public_key[4], 32);    // Move X
            memmove(&public_key[32], &raw_public_key[40], 32);  // Move Y
        }
        else
        {
            memcpy(public_key, raw_public_key, ATCA_PUB_KEY_SIZE);
        }
    }
    else
    {
        if (CERTTYPE_X509_FULL_STORED == cert_def->type)
        {
#if ATCACERT_INTEGRATION_EN
            cal_buffer pk_buf = CAL_BUF_INIT(ATCA_PUB_KEY_SIZE, public_key);
            status = (NULL != cert_def->parsed) ? atcac_get_subj_public_key(*cert_def->parsed, &pk_buf) : ATCACERT_E_ERROR;
#endif
        }
        else
        {
#if ATCACERT_COMPCERT_EN
            memcpy(public_key, &cert[cert_def->std_cert_elements[STDCERT_PUBLIC_KEY].offset], ATCA_PUB_KEY_SIZE);
#endif
        }
    }

    return ATCA_SUCCESS;
}
