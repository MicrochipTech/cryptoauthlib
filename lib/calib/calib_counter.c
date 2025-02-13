/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Counter command.
 *
 * The Counter command reads or increments the binary count value for one of the
 * two monotonic counters
 *
 * \note List of devices that support this command -  ATECC508A and ATECC608A/B.
 *       There are differences in the modes that they support. Refer to device
 *       datasheets for full details.
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

#if CALIB_COUNTER_EN

#if (CA_MAX_PACKET_SIZE < ATCA_CMD_SIZE_MIN)
#error "Counter command packet cannot be accommodated inside the maximum packet size provided"
#endif

/** \brief Compute the Counter functions
 *  \param[in]  device         Device context pointer
 *  \param[in]  mode           the mode used for the counter
 *  \param[in]  counter_id     The counter to be used
 *  \param[out] counter_value  pointer to the counter value returned from device
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_counter(ATCADevice device, uint8_t mode, uint16_t counter_id, uint32_t *counter_value)
{
    ATCAPacket * packet = NULL;
    ATCA_STATUS status;

    do
    {
        if ((device == NULL) || (counter_id > 1u))
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "Either NULL pointer or invalid counter id received");
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

        // build a Counter command
        packet->param1 = mode;
        packet->param2 = counter_id;

        if ((status = atCounter(atcab_get_device_type_ext(device), packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atCounter - failed");
            break;
        }

        if ((status = atca_execute_command(packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_counter - execution failed");
            break;
        }

        if (counter_value != NULL)
        {
            if (packet->data[ATCA_COUNT_IDX] == 7u)
            {
                if (atcab_is_ca2_device(device->mIface.mIfaceCFG->devtype))
                {
                    #if ATCA_CA2_SUPPORT
                    *counter_value = ((uint32_t)packet->data[ATCA_RSP_DATA_IDX + 3u] <<  0) |
                                     ((uint32_t)packet->data[ATCA_RSP_DATA_IDX + 2u] <<  8) |
                                     ((uint32_t)packet->data[ATCA_RSP_DATA_IDX + 1u] << 16) |
                                     ((uint32_t)packet->data[ATCA_RSP_DATA_IDX + 0u] << 24);
                    #endif
                }
                else
                {
                    *counter_value = ((uint32_t)packet->data[ATCA_RSP_DATA_IDX + 0u] <<  0) |
                                     ((uint32_t)packet->data[ATCA_RSP_DATA_IDX + 1u] <<  8) |
                                     ((uint32_t)packet->data[ATCA_RSP_DATA_IDX + 2u] << 16) |
                                     ((uint32_t)packet->data[ATCA_RSP_DATA_IDX + 3u] << 24);
                }
            }
            else
            {
                status = ATCA_TRACE(ATCA_RX_FAIL, "Response received failure");
            }

        }
    } while (false);

    calib_packet_free(packet);
    return status;
}

/** \brief Increments one of the device's monotonic counters
 *  \param[in]  device         Device context pointer
 *  \param[in]  counter_id     Counter to be incremented
 *  \param[out] counter_value  New value of the counter is returned here. Can be
 *                             NULL if not needed.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_counter_increment(ATCADevice device, uint16_t counter_id, uint32_t* counter_value)
{
    return calib_counter(device, COUNTER_MODE_INCREMENT, counter_id, counter_value);
}

/** \brief Read one of the device's monotonic counters
 *  \param[in]  device         Device context pointer
 *  \param[in]  counter_id     Counter to be read
 *  \param[out] counter_value  Counter value is returned here.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_counter_read(ATCADevice device, uint16_t counter_id, uint32_t* counter_value)
{
    return calib_counter(device, COUNTER_MODE_READ, counter_id, counter_value);
}
#endif /* CALIB_COUNTER_EN */
