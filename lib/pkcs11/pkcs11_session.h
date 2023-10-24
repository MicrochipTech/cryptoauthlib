/**
 * \file
 * \brief PKCS11 Library Session Management & Context
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

#ifndef PKCS11_SESSION_H_
#define PKCS11_SESSION_H_

#include "cryptoki.h"
#include "pkcs11_config.h"
#include "cal_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Some mechanism require the context to be initialized first and it is done
   in a previous command than the target operation */
typedef struct pkcs11_session_mech_ctx_s
{
#ifdef PKCS11_HARDWARE_SHA256
    atca_hmac_sha256_ctx_t hmac;
    atca_sha256_ctx_t      sha256;
#else
    atcac_hmac_ctx_t     hmac;
    atcac_sha2_256_ctx_t sha256;
#endif
    atca_aes_cmac_ctx_t cmac;
    atca_aes_cbc_ctx_t  cbc;
#ifdef ATCA_ATECC608_SUPPORT
    struct
    {
        atca_aes_gcm_ctx_t context;
        CK_BYTE            tag_len;
    } gcm;
#endif
#if ATCA_TA_SUPPORT
    struct
    {
        uint8_t iv[TA_AES_GCM_IV_LENGTH];
        uint8_t aad[ATCA_AES128_BLOCK_SIZE];
        CK_BYTE aad_len;
    } gcm_single;
#endif
} pkcs11_session_mech_ctx, *pkcs11_session_mech_ctx_ptr;

/** Session Context */
typedef struct pkcs11_session_ctx_s
{
    CK_BBOOL                initialized;
    pkcs11_slot_ctx_ptr     slot;
    CK_SESSION_HANDLE       handle;
    CK_STATE                state;
    CK_ULONG                error;
    CK_ATTRIBUTE_PTR        attrib_list;
    CK_ULONG                attrib_count;
    CK_ULONG                object_index;
    CK_ULONG                object_count;
    CK_OBJECT_HANDLE        active_object;
    CK_MECHANISM_TYPE       active_mech;
    pkcs11_session_mech_ctx active_mech_data;
} pkcs11_session_ctx, *pkcs11_session_ctx_ptr;

#ifdef __cplusplus
}
#endif
//pkcs11_session_ctx_ptr pkcs11_get_session_context(CK_SESSION_HANDLE hSession);
CK_RV pkcs11_session_check(pkcs11_session_ctx_ptr * pSession, CK_SESSION_HANDLE hSession);

CK_RV pkcs11_session_get_info(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
CK_RV pkcs11_session_open(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession);
CK_RV pkcs11_session_close(CK_SESSION_HANDLE hSession);
CK_RV pkcs11_session_closeall(CK_SLOT_ID slotID);

CK_RV pkcs11_session_login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
CK_RV pkcs11_session_logout(CK_SESSION_HANDLE hSession);

CK_RV pkcs11_reserve_resource(pkcs11_lib_ctx_ptr pContext, pkcs11_session_ctx_ptr pSession, uint8_t resource);
CK_RV pkcs11_release_resource(pkcs11_lib_ctx_ptr pContext, pkcs11_session_ctx_ptr pSession, uint8_t resource);


#endif /* PKCS11_SESSION_H_ */
