/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Delete command.
 *
 * The Delete command, when executed, will clear all of the Data zone slots and set
 * all bytes of each slot to 0xFF.The Configuration zone will be untouched, except for the
 * value of the Primary_Deleted byte.
 *
 * \note List of devices that support this command - ECC204, TA010, SHA10x.Refer to device datasheets for full details.
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

#include "host/atca_host.h"

#if CALIB_DELETE_EN

#if (CA_MAX_PACKET_SIZE < (ATCA_CMD_SIZE_MIN + DELETE_MAC_SIZE))
#error "Delete command packet cannot be accommodated inside the maximum packet size provided"
#endif

/** \brief Clears all Data zone slots and all the bytes of each slot is set to 0xFF.The
 *  Configuration zone will be untouched, except for the value of the Primary_Deleted byte.
 *
 *  Note: After the Delete command is run, the device will no longer be functional. Only the
 *  Info command can be run successfully
 *
 *  \param[in] device      Device context pointer
 *	\param[in] mode        Mode must be 0x00
 *	\param[in] key_id      Key id must be 0x0000
 *  \param[in] mac         MAC value
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_delete_base(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* mac)
{
    ATCAPacket * packet = NULL;
    ATCA_STATUS status;

    do
    {
        // Verify the inputs
        if ((device == NULL) || (mac == NULL))
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

        // build Delete command
        packet->param1 = mode;
        packet->param2 = key_id;

        (void)memcpy(&packet->data[0], mac, DELETE_MAC_SIZE);

        (void)atDelete(atcab_get_device_type_ext(device), packet);

        if ((status = atca_execute_command((void*)packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_delete - execution failed");
            break;
        }
    } while (false);

    calib_packet_free(packet);
    return status;
}

/** \brief Runs Nonce Command, calculates mac and performs delete operation
 *
 *  \param[in] device      Device context pointer
 *	\param[in] num_in      Input value from the system
 *  \param[in] key         Key input (HMAC/Secret Key)
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_delete(ATCADevice device, uint8_t num_in[NONCE_NUMIN_SIZE], const uint8_t *key)
{
    ATCA_STATUS status;
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE] = { 0 };
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    atca_delete_in_out_t delete_mac_params;
    uint8_t mac[DELETE_MAC_SIZE] = { 0 };

    do
    {
        // Read device serial number
        if (ATCA_SUCCESS != (status = atcab_read_serial_number(serial_number)))
        {
            (void)ATCA_TRACE(status, "Read serial number failed");
            break;
        }

        // Generate random
        if (ATCA_SUCCESS != (status = calib_nonce_gen_session_key(device, DELETE_NONCE_KEY_ID, num_in, rand_out)))
        {
            (void)ATCA_TRACE(status, "calib_nonce_gen_session_key - failed");
            break;
        }

        // Calculate host side mac for delete operation
        (void)memset(&delete_mac_params, 0, sizeof(delete_mac_params));
        delete_mac_params.key_id = (uint16_t)0x0000;
        delete_mac_params.sn = serial_number;
        delete_mac_params.key = key;
        delete_mac_params.nonce = rand_out;
        delete_mac_params.mac = mac;

        if ((status = atcah_delete_mac(&delete_mac_params)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Delete Mac failed");
            break;
        }
    } while (false);

    return calib_delete_base(device, DELETE_MODE, (uint16_t)0x0000, mac);
}
#endif /* CALIB_DELETE */
