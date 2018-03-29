/**
 * \file
 * \brief Defines an execution handler that executes a given command on a
 *        device and returns the results.
 *
 * The basic flow is to wake the device, send the command, wait/poll for
 * completion, and finally receives the response from the device and does
 * basic checks before returning to caller.
 *
 * This handler supports the ATSHA and ATECC device family.
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


#ifndef ATCA_EXECUTION_H
#define ATCA_EXECUTION_H

#include "atca_status.h"
#include "atca_command.h"
#include "atca_device.h"

#ifdef __linux__
#include <stddef.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ATCA_UNSUPPORTED_CMD ((uint16_t)0xFFFF)

#ifdef ATCA_NO_POLL
/** \brief Structure to hold the device execution time and the opcode for the
 *         corresponding command
 */
typedef struct
{
    uint8_t  opcode;
    uint16_t execution_time_msec;
}device_execution_time_t;

ATCA_STATUS atGetExecTime(uint8_t opcode, ATCACommand ca_cmd);
#endif

ATCA_STATUS atca_execute_command(ATCAPacket* packet, ATCADevice device);

#ifdef __cplusplus
}
#endif
#endif

