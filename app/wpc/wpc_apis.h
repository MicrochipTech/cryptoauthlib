/**
 * \file
 * \brief Provides api interfaces for WPC authentication.
 *
 * \copyright (c) 2015-2021 Microchip Technology Inc. and its subsidiaries.
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

#ifndef WPC_APIS_H
#define WPC_APIS_H

#include "wpc_check_config.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* WPC Protocol Definitions */

#define WPC_PROTOCOL_VERSION            0x01
#define WPC_PROTOCOL_MAX_VERSION        0x01

#define WPC_TBS_AUTH_PREFIX             0x41
#define WPC_CONST_N_RH                  ATCA_SHA256_DIGEST_SIZE
#define WPC_CONST_OS_MC                 (2 + WPC_CONST_N_RH)

/* WPC Header Format Macro */
#define WPC_HEADER(x)                   ((WPC_PROTOCOL_VERSION << 4) | x)

/* WPC Message Definitions */

/* Requests */
#define WPC_GET_DIGESTS_TYPE            0x09
#define WPC_GET_DIGESTS_HEADER          WPC_HEADER(WPC_GET_DIGESTS_TYPE)
#define WPC_GET_DIGESTS_LENGTH          (2)

#define WPC_GET_CERTIFICATE_TYPE        0x0A
#define WPC_GET_CERTIFICATE_HEADER      WPC_HEADER(WPC_GET_CERTIFICATE_TYPE)
#define WPC_GET_CERTIFICATE_LENGTH      (4)

#define WPC_CHALLENGE_TYPE              0x0B
#define WPC_CHALLENGE_HEADER            WPC_HEADER(WPC_CHALLENGE_TYPE)
#define WPC_CHALLENGE_NONCE_LENGTH      (16)
#define WPC_CHALLENGE_LENGTH            (2 + WPC_CHALLENGE_NONCE_LENGTH)

/* Responses */
#define WPC_DIGESTS_TYPE                0x01
#define WPC_DIGESTS_HEADER              WPC_HEADER(WPC_DIGESTS_TYPE)
#define WPC_DIGESTS_LENGTH(x)           (2 + (ATCA_SHA256_DIGEST_SIZE * x))

#define WPC_CERTIFICATE_TYPE            0x02
#define WPC_CERTIFICATE_HEADER          WPC_HEADER(WPC_CERTIFICATE_TYPE)
#define WPC_CERTIFICATE_LENGTH(x)       (1 + x)

#define WPC_CHALLENGE_AUTH_TYPE         0x03
#define WPC_CHALLENGE_AUTH_HEADER       WPC_HEADER(WPC_CHALLENGE_AUTH_TYPE)
#define WPC_CHALLENGE_AUTH_LENGTH       (67)

#define WPC_ERROR_TYPE                  0x07
#define WPC_ERROR_HEADER                WPC_HEADER(WPC_ERROR_TYPE)
#define WPC_ERROR_LENGTH                (3)
#define WPC_ERROR_INVALID_REQUEST       (0x01)
#define WPC_ERROR_UNSUPPORTED_PROTOCOL  (0x02)
#define WPC_ERROR_BUSY                  (0x03)
#define WPC_ERROR_UNSPECIFIED           (0x04)

extern const uint8_t g_root_ca_digest[];

#if WPC_MSG_PR_EN
ATCA_STATUS wpc_msg_get_digests(uint8_t *const message, uint16_t *const msg_len, const uint8_t slot_mask);
ATCA_STATUS wpc_msg_get_certificate(uint8_t *const message, uint16_t *const msg_len,
                                    const uint8_t slot, const uint16_t offset, const uint16_t length);
ATCA_STATUS wpc_msg_challenge(ATCADevice device, uint8_t *const message, uint16_t *const msg_len, const uint8_t slot);
#endif

#if WPC_MSG_PT_EN
ATCA_STATUS wpc_msg_digests(ATCADevice device, uint8_t *const response,
                            uint16_t *const resp_len, const uint8_t *request);
ATCA_STATUS wpc_msg_certificate(ATCADevice device, uint8_t *const response, uint16_t *const resp_len,
                                const uint8_t *request, uint8_t *buffer, const uint16_t buf_len);
ATCA_STATUS wpc_msg_challenge_auth(ATCADevice device, uint8_t *const response,
                                   uint16_t *const resp_len, const uint8_t *request);
ATCA_STATUS wpc_msg_error(uint8_t *const response, uint16_t *const resp_len, const uint8_t error_code,
                          const uint8_t error_data);
ATCA_STATUS wpc_auth_signature(ATCADevice device, const uint8_t *chain_digest, const uint16_t handle,
                               const uint8_t *request, const uint8_t *other_data, uint8_t *const signature);
#endif

#ifdef __cplusplus
}
#endif

#endif
