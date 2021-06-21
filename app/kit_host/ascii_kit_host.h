/**
 * \file
 *
 * \brief  KIT protocol intepreter
 *
 * \copyright (c) 2018 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2018 Microchip Technology Inc. and its subsidiaries. You may use this
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

#ifndef ASCII_KIT_HOST_H
#define ASCII_KIT_HOST_H

#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define KIT_LAYER_DELIMITER       ':'
#define KIT_DATA_BEGIN_DELIMITER  '('
#define KIT_DATA_END_DELIMITER    ')'
#define KIT_MESSAGE_DELIMITER     '\n'

/**
 * \brief The Kit Protocol maximum message size.
 * \note
 *    Send:    <target>:<command>(optional hex bytes to send)\n
 *    Receive: <status hex byte>(optional hex bytes of response)\n
 */
#ifdef KIT_PROTOCOL_MESSAGE_MAX
#define KIT_MESSAGE_SIZE_MAX       KIT_PROTOCOL_MESSAGE_MAX
#elif ATCA_TA_SUPPORT
#define KIT_MESSAGE_SIZE_MAX       (2500)
#else
#define KIT_MESSAGE_SIZE_MAX       (512)
#endif // KIT_PROTOCOL_MESSAGE_MAX

#define KIT_SECTION_NAME_SIZE_MAX  KIT_MESSAGE_SIZE_MAX  //! The maximum message section size
#define KIT_VERSION_SIZE_MAX       (32)                  //! The maximum Kit Protocol version size
#define KIT_FIRMWARE_SIZE_MAX      (32)                  //! The maximum Kit Protocol firmware size


typedef struct _ascii_kit_host_context
{
    const atca_hal_kit_phy_t* phy;
    uint8_t                   buffer[KIT_MESSAGE_SIZE_MAX];
    ATCADevice                device;
    ATCAIfaceCfg**            iface;
    size_t                    iface_count;
    uint32_t                  flags;
} ascii_kit_host_context_t;

/** Used to create command tables for the kit host parser */
typedef struct _kit_host_map_entry
{
    const char* id;
    ATCA_STATUS (*fp_command)(ascii_kit_host_context_t* ctx, int argc, char* argv[], uint8_t* response, size_t* rlen);
} kit_host_map_entry_t;

/* Kit Initialization */
ATCA_STATUS kit_host_init_phy(atca_hal_kit_phy_t* phy, ATCAIface iface);

ATCA_STATUS kit_host_init(ascii_kit_host_context_t * ctx, ATCAIfaceCfg * iface[],
                          const size_t iface_count, const atca_hal_kit_phy_t* phy, const uint32_t flags);

/* Kit APIs for commands - can be used to create custom board commands */
size_t kit_host_format_response(uint8_t* response, size_t rlen, ATCA_STATUS status, uint8_t* data, size_t dlen);
ATCA_STATUS kit_host_process_cmd(ascii_kit_host_context_t* ctx, const kit_host_map_entry_t * cmd_list,
                                 int argc, char* argv[], uint8_t* response, size_t* rlen);

/* Kit Protocol Runners */
ATCA_STATUS kit_host_process_line(ascii_kit_host_context_t* ctx, uint8_t * input_line,
                                  size_t ilen, uint8_t* response, size_t* rlen);

void kit_host_task(ascii_kit_host_context_t* ctx);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif
