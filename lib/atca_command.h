/**
 * \file
 * \brief Microchip Crypto Auth device command object - this is a command builder only, it does
 * not send the command.  The result of a command method is a fully formed packet, ready to send
 * to the ATCAIFace object to dispatch.
 *
 * This command object supports the ATSHA and ATECC device family.
 * The command list is a superset of all device commands for this family.  The command object
 * differentiates the packet contents based on specific device type within the family.
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
/* lint --e{755} */

#ifndef ATCA_COMMAND_H
#define ATCA_COMMAND_H

#include "atca_compiler.h"
#include "atca_status.h"
#include "atca_devtypes.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup command ATCACommand (atca_)
   \brief CryptoAuthLib command builder object, ATCACommand.  Member functions for the ATCACommand object.
   @{
 */

/** \brief atca_command is the C object backing ATCACommand.
 */
struct atca_command
{
    ATCADeviceType dt;
    uint8_t        clock_divider;
    uint16_t       execution_time_msec;
};

/*--- ATCACommand ---------*/
typedef struct atca_command* ATCACommand;

ATCA_STATUS initATCACommand(ATCADeviceType device_type, ATCACommand ca_cmd);
ATCACommand newATCACommand(ATCADeviceType device_type);
void deleteATCACommand(ATCACommand *ca_cmd);


#ifdef __cplusplus
}
#endif

/** @} */
#endif

