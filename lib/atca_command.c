/**
 * \file
 * \brief Microchip CryptoAuthentication device command builder - this is the main object that builds the command
 * byte strings for the given device.  It does not execute the command.  The basic flow is to call
 * a command method to build the command you want given the parameters and then send that byte string
 * through the device interface.
 *
 * The primary goal of the command builder is to wrap the given parameters with the correct packet size and CRC.
 * The caller should first fill in the parameters required in the ATCAPacket parameter given to the command.
 * The command builder will deal with the mechanics of creating a valid packet using the parameter information.
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

#include <stdlib.h>
#include <string.h>
#include "atca_command.h"
#include "cryptoauthlib.h"


/** \brief Initializer for ATCACommand
 * \param[in] device_type  Specifies which set of commands and execution times
 *                         should be associated with this command object.
 * \param[in] ca_cmd       Pre-allocated command structure to initialize.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS initATCACommand(ATCADeviceType device_type, ATCACommand ca_cmd)
{
    if (ca_cmd == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    ca_cmd->dt = device_type;
    ca_cmd->clock_divider = 0;

    return ATCA_SUCCESS;
}

#ifndef ATCA_NO_HEAP
/** \brief constructor for ATCACommand
 * \param[in] device_type  Specifies which set of commands and execution times
 *                         should be associated with this command object.
 * \return Initialized object on success. NULL on failure.
 */
ATCACommand newATCACommand(ATCADeviceType device_type)
{
    ATCACommand ca_cmd;
    ATCA_STATUS status;

    ca_cmd = (ATCACommand)malloc(sizeof(*ca_cmd));
    status = initATCACommand(device_type, ca_cmd);
    if (status != ATCA_SUCCESS)
    {
        free(ca_cmd);
        ca_cmd = NULL;
        return NULL;
    }

    return ca_cmd;
}
#endif

#ifndef ATCA_NO_HEAP
/** \brief ATCACommand destructor
 * \param[in] ca_cmd instance of a command object
 */
void deleteATCACommand(ATCACommand *ca_cmd)
{
    if (ca_cmd == NULL)
    {
        return;
    }

    free(*ca_cmd);
    *ca_cmd = NULL;
}
#endif
