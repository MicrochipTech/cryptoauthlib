/**
 * \file
 * \brief CryptoAuthLib Basic API methods for CheckMAC command.
 *
 * The CheckMac command calculates a MAC response that would have been
 * generated on a different CryptoAuthentication device and then compares the
 * result with input value.
 *
 * \note List of devices that support this command - ATSHA204A, ATECC108A,
 *       ATECC508A, and ATECC608A/B. There are differences in the modes that they
 *       support. Refer to device datasheets for full details.
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

#if CALIB_CHECKMAC_EN

#if (CA_MAX_PACKET_SIZE < (ATCA_CMD_SIZE_MIN + CHECKMAC_CLIENT_CHALLENGE_SIZE + CHECKMAC_CLIENT_RESPONSE_SIZE + CHECKMAC_OTHER_DATA_SIZE))
#error "Checkmac command packet cannot be accommodated inside the maximum packet size provided"
#endif

/** \brief Compares a MAC response with input values
 *         Returns output response mac if requested for SHA105 device
 *
 *  \param[in] device      Device context pointer
 *	\param[in] mode        Controls which fields within the device are used in
 *                         the message
 *	\param[in] key_id      Key location in the CryptoAuth device to use for the
 *                         MAC
 *	\param[in] challenge   Challenge data (32 bytes)
 *	\param[in] response    MAC response data (32 bytes)
 *	\param[in] other_data  OtherData parameter (13 bytes)
 *  \param[out] resp_mac   Output response mac (32 bytes) if mode[3] is set
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_checkmac_base(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t *challenge, const uint8_t *response, const uint8_t *other_data,
                                uint8_t *resp_mac)
{
    ATCAPacket * packet = NULL;
    ATCA_STATUS status;

    do
    {
        // Verify the inputs
        if ((device == NULL) || (response == NULL) || (other_data == NULL) ||
            (((mode & CHECKMAC_MODE_BLOCK2_TEMPKEY) != CHECKMAC_MODE_BLOCK2_TEMPKEY) && challenge == NULL) ||
            (((mode & CHECKMAC_MODE_OUTPUT_MAC_RESPONSE) == CHECKMAC_MODE_OUTPUT_MAC_RESPONSE) && resp_mac == NULL))
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
            break;
        }

        packet = calib_packet_alloc();
        if(NULL == packet)
        {
            (void)ATCA_TRACE(ATCA_ALLOC_FAILURE, "calib_packet_alloc - failed");
            status = ATCA_ALLOC_FAILURE;
            break;
        }

        (void)memset(packet, 0x00, sizeof(ATCAPacket));

        // build Check MAC command
        packet->param1 = mode;
        packet->param2 = key_id;
        if (challenge != NULL)
        {
            (void)memcpy(&packet->data[0], challenge, CHECKMAC_CLIENT_CHALLENGE_SIZE);
        }
        else
        {
            (void)memset(&packet->data[0], 0, CHECKMAC_CLIENT_CHALLENGE_SIZE);
        }
        (void)memcpy(&packet->data[32], response, CHECKMAC_CLIENT_RESPONSE_SIZE);
        (void)memcpy(&packet->data[64], other_data, CHECKMAC_OTHER_DATA_SIZE);

        if ((status = atCheckMAC(atcab_get_device_type_ext(device), packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atCheckMAC - failed");
            break;
        }

        if ((status = atca_execute_command((void*)packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_checkmac_base - execution failed");
            break;
        }

        // The Checkmac command may return output response MAC if requested
        if ((resp_mac != NULL) && (packet->data[ATCA_COUNT_IDX] == (ATCA_PACKET_OVERHEAD + CHECKMAC_SINGLE_BYTE_BOOL_RESP + MAC_SIZE)))
        {
            (void)memcpy(resp_mac, &packet->data[ATCA_RSP_DATA_IDX + CHECKMAC_SINGLE_BYTE_BOOL_RESP], MAC_SIZE);
        }
    } while (false);

    calib_packet_free(packet);
    return status;
}

/** \brief Compares a MAC response with input values
 *
 *  \param[in] device      Device context pointer
 *	\param[in] mode        Controls which fields within the device are used in
 *                         the message
 *	\param[in] key_id      Key location in the CryptoAuth device to use for the
 *                         MAC
 *	\param[in] challenge   Challenge data (32 bytes)
 *	\param[in] response    MAC response data (32 bytes)
 *	\param[in] other_data  OtherData parameter (13 bytes)
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_checkmac(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t *challenge, const uint8_t *response, const uint8_t *other_data)
{
    return calib_checkmac_base(device, mode, key_id, challenge, response, other_data, NULL);
}

/** \brief Compares a MAC response with input values.SHA105 device can generate optional mac
 *         Output response mac mode only supports in SHA105 device
 *
 *  \param[in] device      Device context pointer
 *	\param[in] mode        Controls which fields within the device are used in the message.
 *                         On mode[3] being set output response mac is generated.
 *	\param[in] challenge   Challenge data (32 bytes)
 *	\param[in] response    MAC response data (32 bytes)
 *	\param[in] other_data  OtherData parameter (13 bytes)
 *	\param[out] mac        Mac output (32 bytes)
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_checkmac_with_response_mac(ATCADevice device, uint8_t mode, const uint8_t *challenge, const uint8_t *response, const uint8_t *other_data,
                                             uint8_t *mac)
{
    return calib_checkmac_base(device, mode, CHECKMAC_SHA105_DEFAULT_KEYID, challenge, response, other_data, mac);
}
#endif /* CALIB_CHECKMAC_EN */
