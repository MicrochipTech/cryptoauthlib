/**
 * \file
 * \brief PKCS11 Library Object Handling Base
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
#include "cryptoauthlib.h"
#include "atcacert/atcacert_def.h"

#include "cryptoki.h"
#include "pkcs11_config.h"
#include "pkcs11_debug.h"
#include "pkcs11_init.h"
#include "pkcs11_slot.h"
#include "pkcs11_session.h"
#include "pkcs11_util.h"
#include "pkcs11_object.h"
#include "pkcs11_os.h"
#include "pkcs11_find.h"
#include "pkcs11_key.h"
#include "pkcs11_cert.h"

/**
 * \defgroup pkcs11 Object (pkcs11_object_)
   @{ */

#ifdef ATCA_NO_HEAP
static pkcs11_object pkcs11_object_store[PKCS11_MAX_OBJECTS_ALLOWED];
#endif

pkcs11_object_cache_t pkcs11_object_cache[PKCS11_MAX_OBJECTS_ALLOWED];

/** For object handle tracking */
static CK_OBJECT_HANDLE pkcs11_object_alloc_handle(void)
{
    static CK_OBJECT_HANDLE pkcs11_object_last_handle = 1;

    if (0u != pkcs11_object_last_handle)
    {
        pkcs11_object_last_handle++;
    }

    return pkcs11_object_last_handle;
}

/**
 * CKA_CLASS == CKO_HW_FEATURE_TYPE
 * CKA_HW_FEATURE_TYPE == CKH_MONOTONIC_COUNTER
 */
const pkcs11_attrib_model pkcs11_object_monotonic_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,           pkcs11_object_get_class },
    /** Hardware Feature Type - CK_HW_FEATURE_TYPE */
    { CKA_HW_FEATURE_TYPE, pkcs11_object_get_type  },
    /** Counter will reset to a previously returned value if the token is
        initialized using C_InitToken. */
    { CKA_RESET_ON_INIT,   pkcs11_attrib_false     },
    /** Counter has been reset at least once at some point in time. */
    { CKA_HAS_RESET,       pkcs11_attrib_false     },
    /** Current value of the monotonic counter. Big endian order. */
    { CKA_VALUE,           NULL_PTR                },
};

/* coverity[misra_c_2012_rule_5_1_violation:FALSE] C99 limit is 63 characters */
const CK_ULONG pkcs11_object_monotonic_attributes_count = (CK_ULONG)(PKCS11_UTIL_ARRAY_SIZE(pkcs11_object_monotonic_attributes));

#if 0
/**
 * Mandatory Object Identification Fields for All objects not identified
 * as CKA_CLASS == CKO_HW_FEATURE
 */
const pkcs11_attrib_model const pkcs11_object_storage_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,       pkcs11_object_get_class    },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,       pkcs11_attrib_true         },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,     pkcs11_key_get_access_type },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,  NULL_PTR                   },
    /** Description of the object(default empty). */
    { CKA_LABEL,       pkcs11_object_get_name     },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,    pkcs11_attrib_false        },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE, pkcs11_attrib_false        },
};

/**
 * CKO_DATA - Object Attribute Model
 * Other than providing access to it, Cryptoki does not attach any special meaning to a data object.
 */
const pkcs11_attrib_model pkcs11_object_data_attributes[] = {
    /** Description of the application that manages the object(default empty) */
    { CKA_APPLICATION, NULL_PTR },
    /** DER - encoding of the object identifier indicating the data object type(default empty) */
    { CKA_OBJECT_ID,   NULL_PTR },
    /** Value of the object(default empty) */
    { CKA_VALUE,       NULL_PTR }

};
#endif

CK_RV pkcs11_object_alloc(CK_SLOT_ID slotId, pkcs11_object_ptr *ppObject)
{
    CK_ULONG i = 0;
    CK_RV rv = CKR_OK;

    if (NULL == ppObject)
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else
    {
        *ppObject = NULL;
    }

    for (i = 0; i < (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        if (CKR_OK == rv)
        {
            if (NULL == pkcs11_object_cache[i].object)
            {
#ifdef ATCA_NO_HEAP
                *ppObject = &pkcs11_object_store[i];
#else
                *ppObject = pkcs11_os_malloc(sizeof(pkcs11_object));
#endif
                if (NULL != *ppObject)
                {
                    (void)memset(*ppObject, 0, sizeof(pkcs11_object));
                    pkcs11_object_cache[i].handle = pkcs11_object_alloc_handle();
                    pkcs11_object_cache[i].slotid = slotId;
                    pkcs11_object_cache[i].object = *ppObject;
                }
                else
                {
                    rv = CKR_HOST_MEMORY;
                }

                break;
            }
        }
        else
        {
            break;
        }
    }

    if ((CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED == i)
    {
        rv = CKR_HOST_MEMORY;
    }

    return rv;
}

CK_RV pkcs11_object_free(pkcs11_object_ptr pObject)
{
    CK_ULONG i;

    for (i = 0; i < (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        if (pObject == pkcs11_object_cache[i].object)
        {
            /* Delink it */
            pkcs11_object_cache[i].object = NULL;
            pkcs11_object_cache[i].handle = 0;
        }
    }

    if (NULL != pObject)
    {
        if (NULL != pObject->data)
        {
            if (PKCS11_OBJECT_FLAG_CERT_CACHE == (pObject->flags & PKCS11_OBJECT_FLAG_CERT_CACHE))
            {
                (void)pkcs11_cert_clear_object_cache(pObject);
                pObject->flags &= PKCS11_OBJECT_FLAG_CERT_CACHE_COMPLEMENT;
            }
            if (PKCS11_OBJECT_FLAG_KEY_CACHE == (pObject->flags & PKCS11_OBJECT_FLAG_KEY_CACHE))
            {
                (void)pkcs11_key_clear_object_cache(pObject);
                pObject->flags &= PKCS11_OBJECT_FLAG_KEY_CACHE_COMPLEMENT;
            }
            if (PKCS11_OBJECT_FLAG_SENSITIVE == (pObject->flags & PKCS11_OBJECT_FLAG_SENSITIVE))
            {
                (void)pkcs11_util_memset((CK_VOID_PTR)pObject->data, pObject->size, 0, pObject->size);
            }
        }

        (void)pkcs11_util_memset(pObject, sizeof(pkcs11_object), 0, sizeof(pkcs11_object));

#ifdef ATCA_HEAP
        pkcs11_os_free(pObject);
#endif
    }

    return CKR_OK;
}

CK_RV pkcs11_object_check(pkcs11_object_ptr *ppObject, CK_OBJECT_HANDLE hObject)
{
    CK_ULONG i;

    if (0u == hObject)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    for (i = 0; i < (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        if (hObject == pkcs11_object_cache[i].handle)
        {
            break;
        }
    }
    if (i == (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    else if (NULL != ppObject)
    {
        *ppObject = pkcs11_object_cache[i].object;
    }
    else
    {
        /* do nothing */
    }

    return CKR_OK;
}

CK_RV pkcs11_object_get_handle(pkcs11_object_ptr pObject, CK_OBJECT_HANDLE_PTR phObject)
{
    CK_ULONG i;

    if (NULL == phObject || NULL == pObject)
    {
        return CKR_ARGUMENTS_BAD;
    }

    for (i = 0; i < (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        if (pObject == pkcs11_object_cache[i].object)
        {
            *phObject = pkcs11_object_cache[i].handle;
            break;
        }
    }
    if (i == (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    return CKR_OK;
}

CK_RV pkcs11_object_get_owner(pkcs11_object_ptr pObject, CK_SLOT_ID_PTR pSlotId)
{
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != pObject && NULL != pSlotId)
    {
        CK_ULONG i;
        for (i = 0; i < (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED; i++)
        {
            if (pObject == pkcs11_object_cache[i].object)
            {
                *pSlotId = pkcs11_object_cache[i].slotid;
                break;
            }
        }

        if ((CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED == i)
        {
            rv = CKR_OBJECT_HANDLE_INVALID;
        }
        else
        {
            rv = CKR_OK;
        }
    }

    return rv;
}

CK_RV pkcs11_object_get_name(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession)
{
    ((void)pSession);

    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL == obj_ptr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    return pkcs11_attrib_fill(pAttribute, (const CK_VOID_PTR)obj_ptr->name, (CK_ULONG)((strlen((char*)obj_ptr->name)) & UINT32_MAX));
}

CK_RV pkcs11_object_get_class(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession)
{
    ((void)pSession);
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL == obj_ptr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    return pkcs11_attrib_fill(pAttribute, &obj_ptr->class_id, (CK_ULONG)sizeof(obj_ptr->class_id));
}

CK_RV pkcs11_object_get_type(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession)
{
    ((void)pSession);

    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL == obj_ptr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    return pkcs11_attrib_fill(pAttribute, &obj_ptr->class_type, (CK_ULONG)sizeof(obj_ptr->class_type));
}

CK_RV pkcs11_object_get_destroyable(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession)
{
    ((void)pSession);

    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL == obj_ptr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (PKCS11_OBJECT_FLAG_DESTROYABLE == (obj_ptr->flags & PKCS11_OBJECT_FLAG_DESTROYABLE))
    {
        return pkcs11_attrib_true(pObject, pAttribute, NULL);
    }
    else
    {
        return pkcs11_attrib_false(pObject, pAttribute, NULL);
    }
}

CK_RV pkcs11_object_get_size(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
    pkcs11_object_ptr pObject;
    CK_RV rv;

    rv = pkcs11_init_check(NULL, FALSE);

    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pulSize)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(NULL, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pObject, hObject);
    if (CKR_OK != rv)
    {
        return rv;
    }

    *pulSize = pObject->size;

    return CKR_OK;
}

CK_RV pkcs11_object_find(CK_SLOT_ID slotId, pkcs11_object_ptr *ppObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    CK_ULONG i;
    CK_ATTRIBUTE_PTR pName = NULL;
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;    /* Unless specified assume private key object */

    if (NULL == ppObject || NULL == pTemplate || 0u == ulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    /* Match Name and Class */
    for (i = 0; i < ulCount; i++)
    {
        switch (pTemplate->type)
        {
        case CKA_LABEL:
            pName = pTemplate;
            break;
        case CKA_CLASS:
            class = *((CK_OBJECT_CLASS_PTR)pTemplate->pValue);
            break;
        default:
            pName = NULL;
            class = CKO_PRIVATE_KEY;
            break;
        }
        pTemplate++;
    }

    if (NULL != pName)
    {
        for (i = 0; i < (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED; i++)
        {
            pkcs11_object_ptr pObj = pkcs11_object_cache[i].object;
            if (NULL != pObj && (pkcs11_object_cache[i].slotid == slotId))
            {
                if ((pObj->class_id == class) && (strlen((char*)pObj->name) == pName->ulValueLen))
                {
                    if (0 == strncmp((char*)pObj->name, (char*)pName->pValue, pName->ulValueLen))
                    {
                        *ppObject = pObj;
                        break;
                    }
                }
            }
        }
    }

    return CKR_OK;
}

/**
 * \brief Create a new object on the token in the specified session using the given attribute template
 */
CK_RV pkcs11_object_create(
    CK_SESSION_HANDLE       hSession,
    CK_ATTRIBUTE_PTR        pTemplate,
    CK_ULONG                ulCount,
    CK_OBJECT_HANDLE_PTR    phObject)
{
    CK_RV rv;
    pkcs11_object_ptr pObject = NULL;
    CK_ATTRIBUTE_PTR pLabel = NULL;
    CK_OBJECT_CLASS_PTR pClass = NULL;
    CK_ATTRIBUTE_PTR pData = NULL;
    CK_KEY_TYPE *pKeyType = NULL;
    CK_ATTRIBUTE_PTR pEC_OID_Data = NULL;
    CK_ULONG i;
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession = NULL;
#if ATCA_TA_SUPPORT
    CK_BBOOL matched = false;
    CK_ULONG keyTableIdx = 0;
#endif

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    /* Look for supported/mandatory attributes */
    for (i = 0; i < ulCount; i++)
    {
        switch (pTemplate[i].type)
        {
        case CKA_LABEL:
            pLabel = &pTemplate[i];
            break;
        case CKA_CLASS:
            pClass = pTemplate[i].pValue;
            break;
        case CKA_KEY_TYPE:
            pKeyType = pTemplate[i].pValue;
            break;
        case CKA_VALUE:
        case CKA_EC_POINT:
        case CKA_MODULUS:
            pData = &pTemplate[i];
            break;
        case CKA_EC_PARAMS:
            pEC_OID_Data = &pTemplate[i];
            break;
        default:
            break;
        }
    }

    //Data to be supplied by user for the certificate/ecc/rsa key object data to be written to device
    if (NULL == pData)
    {
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if (CKO_PUBLIC_KEY == *pClass || CKO_PRIVATE_KEY == *pClass)
    {
        //Mandatory attributes for ECC KEY objects as per PKCS11 v2.40 standards
        if (NULL == pKeyType)
        {
            return CKR_TEMPLATE_INCOMPLETE;
        }

        if ((CKK_EC != *pKeyType) && (CKK_RSA != *pKeyType))
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }

        if ((CKK_EC == *pKeyType) && (NULL == pEC_OID_Data))
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
    }

    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        if (NULL != pLabel && NULL != pClass)
        {
            if (CKR_OK != (rv = pkcs11_object_find(pSession->slot->slot_id, &pObject, pTemplate, ulCount)))
            {   
                (void)pkcs11_unlock_context(pLibCtx);
                return rv;
            }
        }
        else
        {
            (void)pkcs11_unlock_context(pLibCtx);
            return CKR_ARGUMENTS_BAD;
        }

        if (NULL == pObject)
        {
            /* Allocate a new object */
            rv = pkcs11_object_alloc(pSession->slot->slot_id, &pObject);
        }

        if (NULL != pObject)
        {
#if ATCA_TA_SUPPORT
            ATCADeviceType dev_type = atcab_get_device_type_ext(pSession->slot->device_ctx);

            if (atcab_is_ta_device(dev_type) && (CKO_PUBLIC_KEY == *pClass || CKO_PRIVATE_KEY == *pClass))
            {
                if (CKK_EC == *pKeyType)
                { 
                    CK_BYTE keyTableSz = (CK_BYTE)(sizeof(ec_key_data_table) / sizeof(ec_key_data_table[0]));
                    for (i = 0; i < keyTableSz; i++)
                    {
                        /* coverity[misra_c_2012_rule_21_16_violation:FALSE] CK_VOID_PTR is a pointer type */
                        if ((0 == memcmp(pEC_OID_Data->pValue, ec_key_data_table[i].curve_oid, pEC_OID_Data->ulValueLen)))
                        {
                            //Key OID matched and we got the private key type
                            keyTableIdx = i;
                            matched = true;
                            break;
                        }
                    }
                }
#if PKCS11_RSA_SUPPORT_ENABLE
                else
                {
                    CK_BYTE keyTableSz = (CK_BYTE)(sizeof(rsa_key_data_table) / sizeof(rsa_key_data_table[0]));
                    for (i = 0; i < keyTableSz; i++)
                    {
                        if (pData->ulValueLen == rsa_key_data_table[i].pubkey_sz)
                        {
                            //Modulus size matched and we got the private key type
                            keyTableIdx = i;
                            matched = true;
                            break;
                        }
                    }
                }
#endif
            }
#endif

            switch (*pClass)
            {
                case CKO_CERTIFICATE:
                    rv = pkcs11_config_cert(pLibCtx, pSession->slot, pObject, pLabel);
                    if (CKR_OK == rv)
                    {
                        if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                        {
                            rv = pkcs11_cert_x509_write(pObject, pData, pSession);
                            (void)pkcs11_unlock_device(pLibCtx);
                        }
                    }
                    break;
                case CKO_PUBLIC_KEY:
                    pObject->class_id = CKO_PUBLIC_KEY;
                    pObject->class_type = (CKK_EC == *pKeyType) ? (CKK_EC) : (CKK_RSA);
#if ATCA_TA_SUPPORT
                    if(atcab_is_ta_device(dev_type))
                    {
                        if (false == matched)
                        {
                            return CKR_ARGUMENTS_BAD;
                        }
                        else
                        {
                            if (CKK_EC == *pKeyType)
                            {
                                (void)talib_handle_init_public_key(&pObject->handle_info, ec_key_data_table[keyTableIdx].ec_key_type, TA_ALG_MODE_ECC_ECDSA, TA_PROP_NO_SIGN_GENERATION, TA_PROP_NO_KEY_AGREEMENT);
                            }
#if PKCS11_RSA_SUPPORT_ENABLE
                            else if (CKK_RSA == *pKeyType)
                            {
                                (void)talib_handle_init_public_key(&pObject->handle_info, rsa_key_data_table[keyTableIdx].rsa_key_type, TA_ALG_MODE_RSA_SSA_1_5, TA_PROP_NO_SIGN_GENERATION, TA_PROP_NO_KEY_AGREEMENT);
                            }
#endif
                            else
                            {
                                return CKR_KEY_TYPE_INCONSISTENT;
                            }
                        }
                    }
#endif
                    if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                    {
                        if (CKR_OK == (rv = pkcs11_config_key(pLibCtx, pSession->slot, pObject, pLabel)))
                        {
                            rv = pkcs11_key_write(pSession, pObject, pData);
                            if (CKR_OK != rv)
                            {
#if !PKCS11_USE_STATIC_CONFIG
                                (void)pkcs11_config_remove_object(pLibCtx, pSession->slot, pObject);
#endif
                            }
                        }
                        (void)pkcs11_unlock_device(pLibCtx);
                    }
                    break;
                case CKO_PRIVATE_KEY:
                    pObject->class_id = CKO_PRIVATE_KEY;
                    pObject->class_type = (CKK_EC == *pKeyType) ? (CKK_EC) : (CKK_RSA);
#if ATCA_TA_SUPPORT
                    if(atcab_is_ta_device(dev_type))
                    {
                        if (false == matched)
                        {
                            return CKR_ARGUMENTS_BAD;
                        }
                        else
                        {
                            if (CKK_EC == *pKeyType)
                            {
                                (void)talib_handle_init_private_key(&pObject->handle_info, ec_key_data_table[keyTableIdx].ec_key_type, TA_ALG_MODE_ECC_ECDSA, TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_NO_KEY_AGREEMENT);
                            }
#if PKCS11_RSA_SUPPORT_ENABLE
                            else if (CKK_RSA == *pKeyType)
                            {
                                (void)talib_handle_init_private_key(&pObject->handle_info, rsa_key_data_table[keyTableIdx].rsa_key_type, TA_ALG_MODE_RSA_SSA_1_5, TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_KEY_AGREEMENT_OUT_BUFF);
                            }
#endif
                            else
                            {
                                return CKR_KEY_TYPE_INCONSISTENT;
                            }
                        }
                        /* coverity[cert_int31_c_violation] signed to unsigned casting */
                        pObject->handle_info.property &= (uint16_t)(~TA_PROP_EXECUTE_ONLY_KEY_GEN_MASK);              
                    }
#endif
                    if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                    {
                        if (CKR_OK == (rv = pkcs11_config_key(pLibCtx, pSession->slot, pObject, pLabel)))
                        {
                            rv = pkcs11_key_write(pSession, pObject, pData);
                            if (CKR_OK != rv)
                            {
#if !PKCS11_USE_STATIC_CONFIG
                                (void)pkcs11_config_remove_object(pLibCtx, pSession->slot, pObject);
#endif                      
                            }
                        }
                        (void)pkcs11_unlock_device(pLibCtx);
                    }
                    break;
                default:
                    /* Do Nothing*/
                    break;
            }
    
            if (CKR_OK == rv)
            {
                rv = pkcs11_object_get_handle(pObject, phObject);
            }
            else
            {
                (void)pkcs11_object_free(pObject);
            }
        }
        (void)pkcs11_unlock_context(pLibCtx);
    }

    return rv;
}

/**
 * \brief Destroy the specified object
 */
CK_RV pkcs11_object_destroy(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
    pkcs11_object_ptr pObject;
    CK_RV rv;
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession = NULL;

    if (CKR_OK != (rv = pkcs11_init_check(&pLibCtx, FALSE)))
    {
        return rv;
    }

    if (CKR_OK != (rv = pkcs11_session_check(&pSession, hSession)))
    {
        return rv;
    }

    if (CKR_OK != (rv = pkcs11_object_check(&pObject, hObject)))
    {
        return rv;
    }

    if (PKCS11_OBJECT_FLAG_DESTROYABLE == (pObject->flags & PKCS11_OBJECT_FLAG_DESTROYABLE))
    {
        if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
        {
#if !PKCS11_USE_STATIC_CONFIG
            (void)pkcs11_config_remove_object(pLibCtx, pSession->slot, pObject);
#endif
            rv = pkcs11_object_free(pObject);
            (void)pkcs11_unlock_context(pLibCtx);
        }
    }
    else
    {
        rv = CKR_ACTION_PROHIBITED;
    }
    return rv;
}

/* Interal function to clean up resources */
CK_RV pkcs11_object_deinit(pkcs11_lib_ctx_ptr pContext)
{
    CK_RV rv = CKR_OK;
    uint8_t i;

    ((void)pContext);

    for (i = 0; i < (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        pkcs11_object_ptr pObj = pkcs11_object_cache[i].object;
        if (NULL != pObj)
        {
            CK_RV tmp = pkcs11_object_free(pObj);
            if (CKR_OK == rv)
            {
                rv = tmp;
            }
        }
    }
    return rv;
}

#if ATCA_TA_SUPPORT
ATCA_STATUS pkcs11_object_load_handle_info(ATCADevice device, pkcs11_lib_ctx_ptr pContext)
{
    ATCA_STATUS status = ATCA_GEN_FAIL;
    ta_handle_info handle_info;
    bool bHandleinfosuccess = false;

    ((void)pContext);

    for (uint8_t i = 0; i < (CK_ULONG)PKCS11_MAX_OBJECTS_ALLOWED; i++)
    {
        pkcs11_object_ptr pObj = pkcs11_object_cache[i].object;
        if (NULL != pObj)
        {
            if (pObj->slot > 15u)
            {
                pObj->flags |= PKCS11_OBJECT_FLAG_TA_TYPE;
                if (ATCA_SUCCESS == talib_info_get_handle_info(device, pObj->slot, &handle_info))
                {
                    (void)memcpy(&pObj->handle_info, &handle_info.attributes, sizeof(ta_element_attributes_t));

                    if (CKO_PRIVATE_KEY == pObj->class_id || CKO_PUBLIC_KEY == pObj->class_id)
                    {
                        (void)pkcs11_config_set_key_size(pObj);
                    }
                    bHandleinfosuccess = true;
                }
                else
                {
                    status = ATCA_GEN_FAIL;
                    (void)memset(&pObj->handle_info, 0, sizeof(ta_element_attributes_t));
                }
            }
        }
    }

    if (true == bHandleinfosuccess)
    {
        status = ATCA_SUCCESS;
    }

    return status;
}
#endif

/** \brief Checks the attributes of the underlying cryptographic asset to
    determine if it is a private key - this changes the way the associated
    public key is referenced */
CK_RV pkcs11_object_is_private(pkcs11_object_ptr pObject, CK_BBOOL *is_private, pkcs11_session_ctx_ptr pSession)
{
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != pObject && NULL != is_private && NULL != pSession)
    {
        ATCADeviceType dev_type = atcab_get_device_type_ext(pSession->slot->device_ctx);

        *is_private = false;
        rv = CKR_GENERAL_ERROR;

        if (atcab_is_ca_device(dev_type))
        {
#if ATCA_CA_SUPPORT
            atecc508a_config_t *cfg_ptr = (atecc508a_config_t*)pObject->config;

            if (NULL != cfg_ptr)
            {
                *is_private = (ATCA_KEY_CONFIG_PRIVATE_MASK == (cfg_ptr->KeyConfig[pObject->slot] & ATCA_KEY_CONFIG_PRIVATE_MASK)) ? true : false;
                rv = CKR_OK;
            }
#endif
        }
        else if (atcab_is_ta_device(dev_type))
        {
#if ATCA_TA_SUPPORT
            *is_private = (TA_CLASS_PRIVATE_KEY == (pObject->handle_info.element_CKA & 0x7u));
            rv = CKR_OK;
#endif
        }
        else
        {
            /* do nothing */
        }
    }

    return rv;
}

/** @} */
