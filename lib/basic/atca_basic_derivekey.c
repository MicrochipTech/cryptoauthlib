/**
 * \file
 * \brief CryptoAuthLib Basic API methods for DeriveKey command.
 *
 * The DeriveKey command combines the current value of a key with the nonce
 * stored in TempKey using SHA-256 and derives a new key.
 *
 * \note List of devices that support this command - ATSHA204A, ATECC108A,
 *       ATECC508A, and ATECC608A. There are differences in the modes that they
 *       support. Refer to device datasheets for full details.
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */

#include "atca_basic.h"
#include "atca_execution.h"

/** \brief Executes the DeviveKey command for deriving a new key from a
 *          nonce (TempKey) and an existing key.
 *
 *  \param[in] mode        Bit 2 must match the value in TempKey.SourceFlag
 *  \param[in] target_key  Key slot to be written
 *  \param[in] mac         Optional 32 byte MAC used to validate operation. NULL
 *                         if not required.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_derivekey(uint8_t mode, uint16_t target_key, const uint8_t* mac)
{
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    do
    {
        // build a deriveKey command (pass through mode)
        packet.param1 = mode;
        packet.param2 = target_key;

        if (mac != NULL)
        {
            memcpy(packet.data, mac, MAC_SIZE);
        }

        if ((status = atDeriveKey(ca_cmd, &packet, mac != NULL)) != ATCA_SUCCESS)
        {
            break;
        }

        if ((status = atca_execute_command(&packet, _gDevice)) != ATCA_SUCCESS)
        {
            break;
        }

    }
    while (0);

    return status;
}
