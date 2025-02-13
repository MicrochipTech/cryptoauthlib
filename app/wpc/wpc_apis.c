/**
 * \file
 * \brief Provides api interfaces for WPC authentication.
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

#include "cryptoauthlib.h"
#include "wpc_apis.h"
#include "wpccert_client.h"
#include "atcacert/atcacert_client.h"

#if WPC_MSG_PR_EN

#define CA2_TRANSPORT_KEY       0x8000

/** \brief WPC API - Builds the CHALLENGE message
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS wpc_msg_challenge(
    ATCADevice      device,     /**< [in] Device Context */
    uint8_t *const  message,    /**< [out] Message Buffer */
    uint16_t *const msg_len,    /**< [in/out] In: message buffer size, Out: message length */
    const uint8_t   slot        /**< [in] Slot number */
    )
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    uint8_t nonce[32] = { 0U };

    ATCA_CHECK_INVALID_MSG((!message || !msg_len), ATCA_BAD_PARAM, "NULL pointer received");

    message[0] = WPC_CHALLENGE_HEADER;
    message[1] = slot & 0x03;

#if ATCAC_RANDOM_EN
    if (!device)
    {
        status = ATCA_TRACE(atcac_sw_random(nonce, WPC_CHALLENGE_NONCE_LENGTH), "atcac_sw_random failed");
    }
    else
#endif
    {
        if (true == atcab_is_ca2_device(atcab_get_device_type_ext(device)))
        {
#if ATCA_CA2_SUPPORT
            uint8_t num_in[20] = { 0u };
            status = ATCA_TRACE(calib_nonce_gen_session_key(device, CA2_TRANSPORT_KEY, num_in, nonce), "atcab_nonce_rand failed");
#endif
        }
        else
        {
#if (ATCA_ECC_SUPPORT || ATCA_TA_SUPPORT)
            status = ATCA_TRACE(atcab_random_ext(device, nonce), "atcab_random failed");
#endif
        }
    }

    if (ATCA_SUCCESS == status)
    {
        memcpy(&message[2], nonce, WPC_CHALLENGE_NONCE_LENGTH);
        *msg_len = WPC_CHALLENGE_LENGTH;
    }

    return status;
}

/** \brief WPC API - Builds the GET_DIGESTS message
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS wpc_msg_get_digests(
    uint8_t *const  message,    /**< [out] Message Buffer */
    uint16_t *const msg_len,    /**< [in/out] In: message buffer size, Out: message length */
    const uint8_t   slot_mask   /**< [in] Slots to request */
    )
{
    ATCA_CHECK_INVALID_MSG((!message || !msg_len), ATCA_BAD_PARAM, "NULL pointer received");

    message[0] = WPC_GET_DIGESTS_HEADER;
    message[1] = slot_mask & 0x0F;

    *msg_len = WPC_GET_DIGESTS_LENGTH;

    return ATCA_SUCCESS;
}

/** \brief WPC API - Builds the GET_CERTIFICATE message
 *
 *  \note Offset and length are actually 11 bits
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS wpc_msg_get_certificate(
    uint8_t *const  message,    /**< [out] Message Buffer */
    uint16_t *const msg_len,    /**< [in/out] In: message buffer size, Out: message length */
    const uint8_t   slot,       /**< [in] Slot number */
    const uint16_t  offset,     /**< [in] byte offset requested */
    const uint16_t  length      /**< [in] length requested */
    )
{
    ATCA_CHECK_INVALID_MSG((!message || !msg_len), ATCA_BAD_PARAM, "NULL pointer received");

    uint8_t offset_a8 = (uint8_t)((offset >> 3) & 0xE0);
    uint8_t length_a8 = (uint8_t)((length >> 5) & 0x1C);

    message[0] = WPC_GET_CERTIFICATE_HEADER;
    message[1] = offset_a8 | length_a8 | (slot & 0x03);
    message[2] = (offset & 0xFF);
    message[3] = (length & 0xFF);

    *msg_len = WPC_GET_CERTIFICATE_LENGTH;

    return ATCA_SUCCESS;
}
#endif

#if WPC_MSG_PT_EN
/** \brief WPC API - Builds the WPC Error response based on code and data
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS wpc_msg_error(
    uint8_t  *const response,   /**< [out] Response Message */
    uint16_t *const resp_len,   /**< [in/out] In: response buffer size, Out: response length */
    const uint8_t   error_code, /**< [in] Error code to include in the Error response */
    const uint8_t   error_data  /**< [in]  Error data to include in the Error response*/
    )
{
    ATCA_CHECK_INVALID_MSG((!response || !resp_len), ATCA_BAD_PARAM, "NULL pointer received");
    ATCA_CHECK_INVALID_MSG((*resp_len < 3), ATCA_BAD_PARAM, "Buffer too small");

    response[0] = WPC_ERROR_HEADER;
    response[1] = error_code;
    response[2] = error_data;
    *resp_len = WPC_ERROR_LENGTH;

    return ATCA_FUNC_FAIL;
}

/** \brief WPC API - Builds the WPC Authentication Challenge response
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS wpc_msg_challenge_auth(
    ATCADevice      device,     /**< [in] Device Context */
    uint8_t  *const response,   /**< [out] Response Message */
    uint16_t *const resp_len,   /**< [in/out] In: response buffer size, Out: response length */
    const uint8_t * request     /**< [in] Request Message */
    )
{
    ATCA_STATUS status;
    uint8_t chain_digest[ATCA_SHA_DIGEST_SIZE];
    uint8_t slot;
    uint16_t handle = 0;
    const atcacert_def_t * cert_def;

    ATCA_CHECK_INVALID_MSG((!response || !resp_len || !request), ATCA_BAD_PARAM, "NULL pointer received");

    slot = request[1] & 0x03;

    response[0] = WPC_CHALLENGE_AUTH_HEADER;
    response[1] = (WPC_PROTOCOL_MAX_VERSION << 4) | wpccert_get_slots_populated();

    if (ATCA_SUCCESS != (status = wpccert_get_slot_info(&handle, &cert_def, NULL, NULL, NULL, slot)))
    {
        return wpc_msg_error(response, resp_len, WPC_ERROR_INVALID_REQUEST, 0);
    }

    if (NULL == cert_def)
    {
        status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received for cert def");
        return status;
    }

    if (ATCA_SUCCESS != (status = atcab_read_bytes_zone_ext(device, ATCA_ZONE_DATA, handle, 0,
                                                            chain_digest, sizeof(chain_digest))))
    {
        ATCA_TRACE(status, "atcab_read_bytes_zone execution is failed");
        return wpc_msg_error(response, resp_len, WPC_ERROR_UNSPECIFIED, 0);
    }

    /* Return the LSB of the digest - SHA digests are stored as big endian */
    response[2] = chain_digest[ATCA_SHA_DIGEST_SIZE - 1];

    /* Generate the signature */
    if (ATCA_SUCCESS != (status = wpc_auth_signature(device, chain_digest, cert_def->private_key_slot, request,
                                                     response, &response[3])))
    {
        ATCA_TRACE(status, "wpc_auth_signature execution is failed");
        return wpc_msg_error(response, resp_len, WPC_ERROR_UNSPECIFIED, 0);
    }

    *resp_len = WPC_CHALLENGE_AUTH_LENGTH;

    return ATCA_SUCCESS;
}

ATCA_STATUS wpc_msg_digests(
    ATCADevice      device,     /**< [in] Device Context */
    uint8_t  *const response,   /**< [out] Response Message */
    uint16_t *const resp_len,   /**< [in/out] In: response buffer size, Out: response length */
    const uint8_t * request     /**< [in] Request Message */
    )
{
    ATCA_STATUS status;
    uint8_t slot;
    uint8_t * digest;

    ATCA_CHECK_INVALID_MSG((!request || !response), ATCA_BAD_PARAM, "NULL pointer received");

    response[0] = WPC_DIGESTS_HEADER;
    response[1] = (wpccert_get_slots_populated() << 4);

    digest = &response[2];
    for (slot = 0; slot < wpccert_get_slot_count(); slot++)
    {
        uint16_t handle = 0;
        uint8_t slot_mask = (1 << slot);
        if (request[1] & slot_mask)
        {
            if (ATCA_SUCCESS == wpccert_get_slot_info(&handle, NULL, NULL, NULL, NULL, slot))
            {
                if (ATCA_SUCCESS != (status = atcab_read_bytes_zone_ext(device, ATCA_ZONE_DATA, handle, 0,
                                                                        digest, ATCA_SHA256_DIGEST_SIZE)))
                {
                    ATCA_TRACE(status, "atcab_read_bytes_zone execution failed");
                    return wpc_msg_error(response, resp_len, WPC_ERROR_UNSPECIFIED, 0);
                }
                else
                {
                    response[1] |= slot_mask;
                    digest += ATCA_SHA256_DIGEST_SIZE;
                }
            }
        }
    }
    *resp_len = (uint16_t)(digest - response);

    return ATCA_SUCCESS;
}

/** \brief WPC API - Provides response to certificates request
 *
 * WPC Certificate chain format:
 * [0-1]            Length          Total Length of the chain - Big endian
 * [2-(1+n_rh)]     Root Hash       Hash of the root certificate - len: n_rh = 32
 * [2+n_rh ...      Manufacturer    Signing certificate - len: n_mc
 *   1+n_rh+n_mc]
 * [2+n_rh+n_mc ... Product         Product certificate - len: n_puc
 *   1+n_rh+n_mc+n_puc
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS wpc_msg_certificate(
    ATCADevice      device,     /**< [in] Device Context */
    uint8_t *const  response,   /**< [out] WPC authentication challenge response from device */
    uint16_t *const resp_len,   /**< [in] response buffer size
                                   [out] data size on response */
    const uint8_t * request,    /**< [in] WPC authentication challenge request from host */
    uint8_t *       buffer,     /**< [in] Temporary buffer - large enough to hold a certificate */
    const uint16_t  buflen      /**< [in] Length of the temporary buffer */
    )
{
    ATCA_STATUS status;
    size_t n_mc = 0;
    size_t n_puc = 0;
    uint16_t offset;
    uint16_t length;
    uint8_t * data;
    const atcacert_def_t * cert_def;
    uint8_t* mfg_cert = NULL;
    uint8_t root_digest[32] = { 0 };
    uint16_t root_digest_handle = 0;

    ATCA_CHECK_INVALID_MSG((!buffer || !request || !response || !resp_len),
                           ATCA_BAD_PARAM, "NULL pointer received");

#if (ATCA_TA_SUPPORT)
    if (ATCA_SUCCESS != (status = wpccert_get_slot_info(NULL, &cert_def, NULL, NULL, &root_digest_handle, request[1] & 0x03)))
#else
    if (ATCA_SUCCESS != (status = wpccert_get_slot_info(NULL, &cert_def, &mfg_cert, root_digest, NULL, request[1] & 0x03)))
#endif
    {
        return wpc_msg_error(response, resp_len, WPC_ERROR_INVALID_REQUEST, 0);
    }

#if ATCA_TA_SUPPORT
    if (ATCA_SUCCESS != (status = atcab_read_bytes_zone_ext(device, ATCA_ZONE_DATA, root_digest_handle, 0,
                                                            root_digest, ATCA_SHA256_DIGEST_SIZE)))
    {
        ATCA_TRACE(status, "atcab_read_bytes_zone execution failed");
        return wpc_msg_error(response, resp_len, WPC_ERROR_UNSPECIFIED, 0);
    }
#endif

    if (NULL == cert_def)
    {
        status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received for Product cert def");
        return status;
    }

    offset = (((uint16_t)(request[1] & 0xE0)) << 8) | request[2];
    length = (((uint16_t)(request[1] & 0x1C)) << 8) | request[3];

    /* Get the manufacturer certificate length if read will cross the region in anyway or include
     * the total length of the chain */
    if ((offset < 2) || ((offset < WPC_CONST_OS_MC) && ((length == 0) || (length + offset > WPC_CONST_OS_MC)))
        || ((offset > WPC_CONST_OS_MC) && (0x600 > offset)))
    {
        if ((NULL != mfg_cert) && (NULL == cert_def->ca_cert_def))
        {
            n_mc = (size_t)((mfg_cert[2] << 8) | mfg_cert[3]) + 4u;
        }
        else
        {
            /* Get the manufacturer certificate length */
            if (ATCA_SUCCESS != (status = wpccert_read_cert_size(device, cert_def->ca_cert_def, &n_mc)))
            {
                status = ATCA_TRACE(status, "atcacert_read_cert_size execution is failed for mfg cert");
                return status;
            }
        }
    }

    /* Get the product certificate length if the read will include it or the total chain length */
    if ((length == 0) || (offset < 2) || ((WPC_CONST_OS_MC < offset) && ((0x600 <= offset) || (n_mc < offset + length))))
    {
        if (ATCA_SUCCESS != wpccert_read_cert_size(device, cert_def, &n_puc))
        {
            status = ATCA_TRACE(status, "wpccert_read_cert_size execution is failed for pdu cert");
            return status;
        }
    }
    ATCA_CHECK_INVALID_MSG((n_puc > buflen || n_mc > buflen), ATCA_SMALL_BUFFER, "temporary buffer is too small for certificates");

    /* Adjustment the total length if required */
    if (length == 0)
    {
        if (offset < 0x600)
        {
            length = WPC_CONST_OS_MC + (uint16_t)n_mc + (uint16_t)n_puc - offset;
        }
        else
        {
            length = (uint16_t)n_puc - (offset - 0x600);
        }
    }

    ATCA_CHECK_INVALID_MSG((length > *resp_len), ATCA_SMALL_BUFFER, "response buffer is too small");

    *resp_len = length;

    /* Start the response creation */
    data = response;
    *data++ = WPC_CERTIFICATE_HEADER;

    /* Skip over most of the chain if the special product certificate offset is being used */
    if (offset < 0x600)
    {
        /* Include chain length if the offset includes it */
        if (offset < 2)
        {
            uint16_t chain_length = WPC_CONST_OS_MC + n_mc + n_puc;
            if (0 == offset)
            {
                *data++ = ((chain_length >> 8) & 0xFF);
                length--;
                offset += 1u;
            }
            *data++ = (chain_length & 0xFF);
            length--;
            offset += 1u;
        }

        /* Copy in the root hash if the read includes it */
        if (offset < WPC_CONST_OS_MC)
        {
            uint16_t rh_length = length < WPC_CONST_N_RH ? length : WPC_CONST_N_RH;

            memcpy(data, root_digest, rh_length);
            data += rh_length;
            length -= rh_length;
            offset += rh_length;
        }

        /* Read the manufacturer certificate */
        if ((offset >= WPC_CONST_OS_MC) && (offset < (WPC_CONST_OS_MC + n_mc)))
        {
            uint16_t mc_length = length < n_mc ? length : n_mc;

            if ((NULL != mfg_cert) && (NULL == cert_def->ca_cert_def))
            {
                memcpy(buffer, mfg_cert, mc_length);
            }
            else
            {
                if (ATCA_SUCCESS != (status = wpccert_read_cert(device, cert_def->ca_cert_def, buffer, &n_mc)))
                {
                    return ATCA_TRACE(status, "wpccert_read_cert execution is failed for mfg cert");
                }
            }

            memcpy(data, &buffer[offset - WPC_CONST_OS_MC], mc_length);
            data += mc_length;
            length -= mc_length;
            offset += mc_length;
        }
    }
    else
    {
        if ((size_t)(offset - 0x600) > n_puc)
        {
            return ATCA_TRACE(ATCA_BAD_PARAM, "Offset provided exceeds the length of the product certificate");
        }
    }

    /* Read the product cert if there is remaining bytes to be read */
    if (length)
    {
        uint16_t puc_length = length < n_puc ? length : n_puc;

        if (offset < 0x600)
        {
            if (offset > WPC_CONST_OS_MC + n_mc)
            {
                offset -= WPC_CONST_OS_MC + n_mc;
            }
            else
            {
                offset = 0;
            }
        }
        else
        {
            offset -= 0x600;
        }

        if (ATCA_SUCCESS != (status = wpccert_read_cert(device, cert_def, buffer, &n_puc)))
        {
            return ATCA_TRACE(status, "wpccert_read_cert execution is failed for mfg cert");
        }

        memcpy(data, &buffer[offset], puc_length);
        data += puc_length;
        length -= puc_length;
    }

    return status;
}

/** \brief WPC API - Calculated the TBS Auth Signature for the given Chain digest
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS wpc_auth_signature(
    ATCADevice      device,             /**< [in] Device Context */
    const uint8_t * chain_digest,       /**< [in] WPC Authentication Cert Chain digest*/
    const uint16_t  private_key_slot,   /**< [in] WPC Authentication private key slot*/
    const uint8_t * request,            /**< [in] WPC authentication challenge request from host */
    const uint8_t * other_data,         /**< [in] Challegen response b0, b1 and Digest LSB*/
    uint8_t *const  signature           /**< [out] Signature for WPC authentication TBS */
    )
{
    ATCA_STATUS status;

    uint8_t TBSAuth_data[54];
    uint8_t tbs_digest[ATCA_SHA_DIGEST_SIZE];
    uint8_t *data = TBSAuth_data;

    ATCA_CHECK_INVALID_MSG((!chain_digest || !request || !other_data || !signature),
                           ATCA_BAD_PARAM, "NULL pointer received");

    *data++ = WPC_TBS_AUTH_PREFIX;
    memcpy(data, chain_digest, ATCA_SHA_DIGEST_SIZE);
    data += ATCA_SHA_DIGEST_SIZE;
    memcpy(data, request, WPC_CHALLENGE_LENGTH);
    data += WPC_CHALLENGE_LENGTH;
    memcpy(data, other_data, 3);
    data += 3;

    if (ATCA_SUCCESS != (status = atcab_hw_sha2_256(TBSAuth_data, sizeof(TBSAuth_data), tbs_digest)))
    {
        status = ATCA_TRACE(status, "atcab_hw_sha2_256 execution is failed");
        return status;
    }

    if (ATCA_SUCCESS != (status = atcab_sign_ext(device, private_key_slot, tbs_digest, signature)))
    {
        status = ATCA_TRACE(status, "atcab_sign execution is failed");
        return status;
    }

    return status;
}

#endif
