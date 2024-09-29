/**
 * \file
 *
 * \brief  Microchip Crypto Auth status codes
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

#ifndef ATCA_STATUS_H
#define ATCA_STATUS_H

#include <stdint.h>
#include "atca_compiler.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int ATCA_STATUS;

/** STATUS (0x00): Function Successful */
#define ATCA_SUCCESS                (0)

#define ATCA_CONFIG_ZONE_LOCKED     (0x01)
#define ATCA_DATA_ZONE_LOCKED       (0x02)

/** STATUS (0xD0): response status byte indicates CheckMac failure(status byte = 0x01) */
#define ATCA_WAKE_FAILED            (-48)

/** STATUS (0xD1): response status byte indicates CheckMac failure(status byte = 0x01) */
#define ATCA_CHECKMAC_VERIFY_FAILED (-47)

/** STATUS (0xD2): response status byte indicates parsing error(status byte = 0x03) */
#define ATCA_PARSE_ERROR            (-46)

/** STATUS (0xD4): response status byte indicates DEVICE did not receive data properly(status byte = 0xFF) */
#define ATCA_STATUS_CRC             (-44)

/** STATUS (0xD5): response status byte is unknown */
#define ATCA_STATUS_UNKNOWN         (-43)

/** STATUS (0xD6): response status byte is ECC fault(status byte = 0x05) */
#define ATCA_STATUS_ECC             (-42)

/** STATUS (0xD7): response status byte is Self Test Error, chip in failure mode (status byte = 0x07) */
#define ATCA_STATUS_SELFTEST_ERROR  (-41)

/** STATUS (0xE0): Function could not execute due to incorrect condition / state. */
#define ATCA_FUNC_FAIL              (-32)

/** STATUS (0xE1): unspecified error */
#define ATCA_GEN_FAIL               (-31)

/** STATUS (0xE2): bad argument (out of range, null pointer, etc.) */
#define ATCA_BAD_PARAM              (-30)

/** STATUS (0xE3: invalid device id, id not set */
#define ATCA_INVALID_ID             (-29)

/** STATUS (0xE4): Count value is out of range or greater than buffer size. */
#define ATCA_INVALID_SIZE           (-28)

/** STATUS (0xE5): CRC error in data received from device */
#define ATCA_RX_CRC_ERROR           (-27)

/** STATUS (0xE6): Timed out while waiting for response. Number of bytes received is > 0. */
#define ATCA_RX_FAIL                (-26)

/** STATUS (0xE7): Not an error while the Command layer is polling for a command response. */
#define ATCA_RX_NO_RESPONSE         (-25)

/** STATUS (0xE8): Re-synchronization succeeded, but only after generating a Wake-up */
#define ATCA_RESYNC_WITH_WAKEUP     (-24)

/** STATUS (0xE9): for protocols needing parity */
#define ATCA_PARITY_ERROR           (-23)

/** STATUS (0xEA): for Microchip PHY protocol, timeout on transmission waiting for master */
#define ATCA_TX_TIMEOUT             (-22)

/** STATUS (0xEB): for Microchip PHY protocol, timeout on receipt waiting for master */
#define ATCA_RX_TIMEOUT             (-21)

/** STATUS (0xEC): Device did not respond too many times during a transmission. Could indicate no device present. */
#define ATCA_TOO_MANY_COMM_RETRIES  (-20)

/** STATUS (0xED): Supplied buffer is too small for data required */
#define ATCA_SMALL_BUFFER           (-19)

/** STATUS (0xF0): Communication with device failed. Same as in hardware dependent modules. */
#define ATCA_COMM_FAIL              (-16)

/** STATUS (0xF1): Timed out while waiting for response. Number of bytes received is 0. */
#define ATCA_TIMEOUT                (-15)

/** STATUS (0xF2): opcode is not supported by the device */
#define ATCA_BAD_OPCODE             (-14)

/** STATUS (0xF3): received proper wake token */
#define ATCA_WAKE_SUCCESS           (-13)

/** STATUS (0xF4): chip was in a state where it could not execute the command, response status byte indicates command execution error (status byte = 0x0F) */
#define ATCA_EXECUTION_ERROR        (-12)

/** STATUS (0xF5): Function or some element of it hasn't been implemented yet */
#define ATCA_UNIMPLEMENTED          (-11)

/** STATUS (0xF6): Code failed run-time consistency check */
#define ATCA_ASSERT_FAILURE         (-10)

/** STATUS (0xF7): Failed to write */
#define ATCA_TX_FAIL                (-9)

/** STATUS (0xF8): required zone was not locked */
#define ATCA_NOT_LOCKED             (-8)

/** STATUS (0xF9): For protocols that support device discovery (kit protocol), no devices were found */
#define ATCA_NO_DEVICES             (-7)

/** STATUS (0xFA): random number generator health test error */
#define ATCA_HEALTH_TEST_ERROR      (-6)

/** STATUS (0xFB): Couldn't allocate required memory */
#define ATCA_ALLOC_FAILURE          (-5)

/** STATUS (0xFC): Use flags on the device indicates its consumed fully */
#define ATCA_USE_FLAGS_CONSUMED     (-4)

/** STATUS (0xFD): The library has not been initialized so the command could not be executed */
#define ATCA_NOT_INITIALIZED        (-3)


#define ATCA_STATUS_AUTH_BIT                        0x40u
#define ATCA_STATUS_AUTH_BIT_COMPLEMENT             ~(ATCA_STATUS_AUTH_BIT & 0xffu)

#ifdef __cplusplus
}
#endif

#endif /* ATCA_STATUS_H */
