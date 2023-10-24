/**
 * \file
 *
 * \brief
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

#ifndef KIT_PROTOCOL_H_
#define KIT_PROTOCOL_H_

#include "cryptoauthlib.h"

// Define this for debugging communication
//#define KIT_DEBUG

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

// The number of bytes to wrap a command in kit protocol.  sizeof("d:send()\n<null>")
#define KIT_TX_WRAP_SIZE    (10)

// The number of bytes to wrap a response in kit protocol.  sizeof("<KIT_MSG_SIZE>00()\n<null>")
#define KIT_MSG_SIZE        (32u)
#define KIT_RX_WRAP_SIZE    (KIT_MSG_SIZE + 6u)

#ifdef __cplusplus
extern "C" {
#endif

ATCA_STATUS kit_init(ATCAIface iface, ATCAIfaceCfg* cfg);
ATCA_STATUS kit_post_init(ATCAIface iface);
ATCA_STATUS kit_send(ATCAIface iface, uint8_t word_address, uint8_t* txdata, int txlength);
ATCA_STATUS kit_receive(ATCAIface iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxsize);
ATCA_STATUS kit_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen);
ATCA_STATUS kit_release(void* hal_data);

ATCA_STATUS kit_wrap_cmd(const uint8_t* txdata, int txlen, char* pkitcmd, int* nkitcmd, const char* target);
ATCA_STATUS kit_parse_rsp(const char* pkitbuf, int nkitbuf, uint8_t* kitstatus, uint8_t* rxdata, int* datasize);

ATCA_STATUS kit_wake(ATCAIface iface);
ATCA_STATUS kit_idle(ATCAIface iface);
ATCA_STATUS kit_sleep(ATCAIface iface);

ATCA_STATUS kit_phy_send(ATCAIface iface, uint8_t* txdata, int txlength);
ATCA_STATUS kit_phy_receive(ATCAIface iface, uint8_t* rxdata, int* rxsize);

const char* kit_id_from_devtype(ATCADeviceType devtype);
const char* kit_interface_from_kittype(ATCAKitType kittype);
const char * kit_interface(ATCAKitType kittype);

#ifdef __cplusplus
}
#endif

/** @} */

#endif // KIT_PROTOCOL_H
