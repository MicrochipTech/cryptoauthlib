/**
 * \file
 * \brief PKCS11 Library Slot Handling & Context
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

#ifndef PKCS11_SLOT_H_
#define PKCS11_SLOT_H_

//#include "pkcs11_config.h"
#include "pkcs11_init.h"
#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLOT_STATE_UNINITIALIZED    (0U)
#define SLOT_STATE_CONFIGURED       (1U)
#define SLOT_STATE_READY            (2U)

/** Slot Context */
typedef struct pkcs11_slot_ctx_s
{
    CK_BYTE           slot_state;
    CK_SLOT_ID        slot_id;
    ATCADevice        device_ctx;
    ATCAIfaceCfg      interface_config;
    CK_SESSION_HANDLE session;
#if ATCA_CA_SUPPORT
    atecc608_config_t cfg_zone;
#endif
#if ((defined(ATCA_HAL_KIT_BRIDGE) && defined(PKCS11_TESTING_ENABLE)) || \
    (defined(__linux__) && (defined(ATCA_HAL_SWI_UART) || defined(ATCA_HAL_KIT_UART))))
    uint8_t devpath[24];
#endif
    CK_FLAGS flags;
    uint16_t user_pin_handle;
    uint16_t so_pin_handle;
#ifndef PKCS11_LABEL_IS_SERNUM
    CK_UTF8CHAR label[PKCS11_MAX_LABEL_SIZE + 1];
#endif
    CK_BBOOL logged_in;
    CK_BYTE  read_key[32];                      /**< Accepted through C_Login as the user pin */
} pkcs11_slot_ctx;

#ifdef __cplusplus
}
#endif

CK_RV pkcs11_slot_init(CK_SLOT_ID slotID);
CK_RV pkcs11_slot_config(CK_SLOT_ID slotID);
CK_VOID_PTR pkcs11_slot_initslots(CK_ULONG pulCount);
CK_RV pkcs11_slot_deinitslots(pkcs11_lib_ctx_ptr lib_ctx);
pkcs11_slot_ctx_ptr pkcs11_slot_get_context(pkcs11_lib_ctx_ptr lib_ctx, CK_SLOT_ID slotID);
pkcs11_slot_ctx_ptr pkcs11_slot_get_new_context(pkcs11_lib_ctx_ptr lib_ctx);

CK_RV pkcs11_slot_get_list(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
CK_RV pkcs11_slot_get_info(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);

#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
extern CK_RV pkcs11_trust_load_objects(pkcs11_slot_ctx_ptr pSlot);
#endif

#endif /* PKCS11_SLOT_H_ */
