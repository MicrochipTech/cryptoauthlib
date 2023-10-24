/**
 * \file
 * \brief CryptoAuthLib Basic API methods for UpdateExtra command.
 *
 * The UpdateExtra command is used to update the values of the two extra bytes
 * within the Configuration zone after the Configuration zone has been locked.
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

#if CALIB_UPDATEEXTRA_EN

#if (CA_MAX_PACKET_SIZE < ATCA_CMD_SIZE_MIN)
#error "UpdateExtra command packet cannot be accommodated inside the maximum packet size provided"
#endif

/** \brief Executes UpdateExtra command to update the values of the two
 *          extra bytes within the Configuration zone (bytes 84 and 85).
 *
 * Can also be used to decrement the limited use counter associated with the
 * key in slot NewValue.
 *
 * \param[in] device     Device context pointer
 * \param[in] mode       Mode determines what operations the UpdateExtra
 *                      command performs.
 * \param[in] new_value  Value to be written.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_updateextra(ATCADevice device, uint8_t mode, uint16_t new_value)
{
    ATCAPacket packet;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    do
    {
        if (device == NULL)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
            break;
        }

        // Build command
        (void)memset(&packet, 0, sizeof(packet));
        packet.param1 = mode;
        packet.param2 = new_value;

        if ((status = atUpdateExtra(atcab_get_device_type_ext(device), &packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atUpdateExtra - failed");
            break;
        }

        if ((status = atca_execute_command(&packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_updateextra - execution failed");
            break;
        }

    }
    while (false);

    return status;
}
#endif  /* CALIB_UPDATEEXTRA */
