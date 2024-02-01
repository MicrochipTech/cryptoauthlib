/**
 * \file
 * \brief PKCS11 Library Object Handling
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

#ifndef PKCS11_OBJECT_H_
#define PKCS11_OBJECT_H_

#include "cryptoauthlib.h"

#include "cryptoki.h"
#include "pkcs11_config.h"
#include "pkcs11_attrib.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pkcs11_object_s
{
    /** The Class Identifier */
    CK_OBJECT_CLASS class_id;
    /** The Class Type */
    CK_ULONG class_type;
    /** List of attribute models this object possesses */
    pkcs11_attrib_model const * attributes;
    /** Count of attribute models */
    CK_ULONG    count;
    CK_ULONG    size;
    uint16_t    slot;
    CK_FLAGS    flags;
    CK_UTF8CHAR name[PKCS11_MAX_LABEL_SIZE + 1];
#if ATCA_CA_SUPPORT
    CK_VOID_PTR config;
#endif
    CK_VOID_PTR data;
#if ATCA_TA_SUPPORT
    ta_element_attributes_t handle_info;
#endif
} pkcs11_object;

typedef struct pkcs11_object_cache_s
{
    /** Arbitrary (but unique) non-null identifier for an object */
    CK_OBJECT_HANDLE handle;
    /* Owner of the object */
    CK_SLOT_ID slotid;
    /** The actual object  */
    pkcs11_object_ptr object;
} pkcs11_object_cache_t;

extern pkcs11_object_cache_t pkcs11_object_cache[];

extern const pkcs11_attrib_model pkcs11_object_monotonic_attributes[];
extern const CK_ULONG pkcs11_object_monotonic_attributes_count;

#define PKCS11_OBJECT_FLAG_DESTROYABLE      (0x01U)
#define PKCS11_OBJECT_FLAG_MODIFIABLE       (0x02U)
#define PKCS11_OBJECT_FLAG_DYNAMIC          (0x04U)
#define PKCS11_OBJECT_FLAG_SENSITIVE        (0x08U)
#define PKCS11_OBJECT_FLAG_TA_TYPE          (0x10U)
#define PKCS11_OBJECT_FLAG_TRUST_TYPE       (0x20U)
#define PKCS11_OBJECT_FLAG_CERT_CACHE       (0x40U)
#define PKCS11_OBJECT_FLAG_KEY_CACHE        (0x80U)
#define PKCS11_OBJECT_FLAG_KEY_CACHE_COMPLEMENT    ~(PKCS11_OBJECT_FLAG_KEY_CACHE & 0xffu)
#define PKCS11_OBJECT_FLAG_CERT_CACHE_COMPLEMENT   ~(PKCS11_OBJECT_FLAG_CERT_CACHE & 0xffu)

/* Object System Access */
CK_RV pkcs11_object_alloc(CK_SLOT_ID slotId, pkcs11_object_ptr * ppObject);
CK_RV pkcs11_object_free(pkcs11_object_ptr pObject);
CK_RV pkcs11_object_check(pkcs11_object_ptr * ppObject, CK_OBJECT_HANDLE hObject);
CK_RV pkcs11_object_find(CK_SLOT_ID slotId, pkcs11_object_ptr * ppObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV pkcs11_object_is_private(pkcs11_object_ptr pObject, CK_BBOOL* is_private, pkcs11_session_ctx_ptr pSession);
CK_RV pkcs11_object_deinit(pkcs11_lib_ctx_ptr pContext);
CK_RV pkcs11_object_get_owner(pkcs11_object_ptr pObject, CK_SLOT_ID_PTR pSlotId);

#if ATCA_TA_SUPPORT
ATCA_STATUS pkcs11_object_load_handle_info(ATCADevice device, pkcs11_lib_ctx_ptr pContext);
#endif

/* Object Attributes */
CK_RV pkcs11_object_get_class(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession);
CK_RV pkcs11_object_get_name(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession);
CK_RV pkcs11_object_get_type(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession);
CK_RV pkcs11_object_get_destroyable(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession);
CK_RV pkcs11_object_get_size(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
CK_RV pkcs11_object_get_handle(pkcs11_object_ptr pObject, CK_OBJECT_HANDLE_PTR phObject);

/* PKCS11 API */
CK_RV pkcs11_object_create(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
CK_RV pkcs11_object_destroy(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

#ifdef __cplusplus
}
#endif

#endif /* PKCS11_OBJECT_H_ */
