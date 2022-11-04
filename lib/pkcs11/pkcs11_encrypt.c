/**
 * \file
 * \brief PKCS11 Library Encrypt Support
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

#include "pkcs11_config.h"
#include "pkcs11_encrypt.h"
#include "pkcs11_debug.h"
#include "pkcs11_init.h"
#include "pkcs11_object.h"
#include "pkcs11_session.h"
#include "pkcs11_util.h"


/**
 * \defgroup pkcs11 Encrypt (pkcs11_encrypt_)
   @{ */

CK_RV pkcs11_encrypt_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
    pkcs11_lib_ctx_ptr pLibCtx;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pObject;
    CK_RV rv;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pObject, hObject);
    if (rv)
    {
        return rv;
    }

    if (CKM_VENDOR_DEFINED == pSession->active_mech)
    {
        switch (pMechanism->mechanism)
        {
        case CKM_AES_ECB:
            rv = CKR_OK;
            break;
        case CKM_AES_CBC_PAD:
            /* fallthrough */
        case CKM_AES_CBC:
            rv = pkcs11_util_convert_rv(atcab_aes_cbc_init(&pSession->active_mech_data.cbc, pObject->slot, 0, pMechanism->pParameter));
            break;
        case CKM_AES_GCM:
            if (pMechanism->pParameter && sizeof(CK_GCM_PARAMS) == pMechanism->ulParameterLen)
            {
                CK_GCM_PARAMS_PTR pParams = (CK_GCM_PARAMS_PTR)pMechanism->pParameter;

                if (pParams->ulTagBits % 8 == 0)
                {
                    if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
                    {
                        if(atcab_is_ca_device(atcab_get_device_type()))
                        {
#ifdef ATCA_ATECC608_SUPPORT
                            pSession->active_mech_data.gcm.tag_len = pParams->ulTagBits / 8;
                            if (CKR_OK == (rv = pkcs11_util_convert_rv(atcab_aes_gcm_init(&pSession->active_mech_data.gcm.context,
                                                                                        pObject->slot, 0, pParams->pIv, pParams->ulIvLen))))
                            {
                                rv = pkcs11_util_convert_rv(atcab_aes_gcm_aad_update(&pSession->active_mech_data.gcm.context, pParams->pAAD, pParams->ulAADLen));
                            }
#else
                            rv = CKR_MECHANISM_INVALID;
#endif
                        }
#ifdef ATCA_TA100_SUPPORT
                        if(atcab_is_ta_device(atcab_get_device_type()))
                        {
                            if (pParams->ulIvLen > sizeof(pSession->active_mech_data.gcm_single.iv))
                            {
                                rv = CKR_ARGUMENTS_BAD;
                            }
                            else
                            {
                                memcpy(pSession->active_mech_data.gcm_single.iv, pParams->pIv, pParams->ulIvLen);
                            }
                            if (pParams->ulAADLen > sizeof(pSession->active_mech_data.gcm_single.aad))
                            {
                                rv = CKR_ARGUMENTS_BAD;
                            }
                            else
                            {
                                memcpy(pSession->active_mech_data.gcm_single.aad, pParams->pAAD, pParams->ulAADLen);
                            }
                        }
#endif
                        (void)pkcs11_unlock_both(pLibCtx);
                    }
                }
                else
                {
                    rv = CKR_ARGUMENTS_BAD;
                }
            }
            else
            {
                rv = CKR_ARGUMENTS_BAD;
            }

            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
    }
    else
    {
        rv = CKR_OPERATION_ACTIVE;
    }

    if (CKR_OK == rv)
    {
        pSession->active_object = hObject;
        pSession->active_mech = pMechanism->mechanism;
    }

    return rv;
}

CK_RV pkcs11_encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                     CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;
    ATCA_STATUS status = ATCA_SUCCESS;
    CK_BBOOL padding = FALSE;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pData || !ulDataLen || !pEncryptedData || !pulEncryptedDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (rv)
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            if (ulDataLen == ATCA_AES128_BLOCK_SIZE && *pulEncryptedDataLen >= ATCA_AES128_BLOCK_SIZE)
            {
                status = atcab_aes_encrypt(pKey->slot, 0, pData, pEncryptedData);
                *pulEncryptedDataLen = ATCA_AES128_BLOCK_SIZE;
            }
            else
            {
                rv = CKR_ARGUMENTS_BAD;
            }
            break;
        case CKM_AES_CBC_PAD:
            padding = TRUE;
            /* fallthrough */
        case CKM_AES_CBC:
            {
                size_t length = *pulEncryptedDataLen;
                if (ATCA_SUCCESS == (status = atcab_aes_cbc_encrypt_update(&pSession->active_mech_data.cbc, pData, ulDataLen, pEncryptedData, &length)))
                {
                    pEncryptedData += length;
                    length = *pulEncryptedDataLen - length;
                    status = atcab_aes_cbc_encrypt_finish(&pSession->active_mech_data.cbc, pEncryptedData, &length, padding);
                }
                *pulEncryptedDataLen = length;
            }
            break;
        case CKM_AES_GCM:
            if(atcab_is_ca_device(atcab_get_device_type()))
            {
    #ifdef ATCA_ATECC608_SUPPORT
                if (ATCA_SUCCESS == (status = atcab_aes_gcm_encrypt_update(&pSession->active_mech_data.gcm.context, pData, ulDataLen, pEncryptedData)))
                {
                    status = atcab_aes_gcm_encrypt_finish(&pSession->active_mech_data.gcm.context, &pEncryptedData[ulDataLen],
                                                        pSession->active_mech_data.gcm.tag_len);
                    *pulEncryptedDataLen = ulDataLen + pSession->active_mech_data.gcm.tag_len;
                }
    #else
                rv = CKR_GENERAL_ERROR;
    #endif
            }
    #ifdef ATCA_TA100_SUPPORT
            if(atcab_is_ta_device(atcab_get_device_type()))
            {
                if(ATCA_SUCCESS == (status = talib_aes_gcm_keyload(atcab_get_device(), pKey->slot, 0)))
                {
                    if (ATCA_SUCCESS == (status = talib_aes_gcm_encrypt(atcab_get_device(), pSession->active_mech_data.gcm_single.aad, 
                                                    pSession->active_mech_data.gcm_single.aad_len, pSession->active_mech_data.gcm_single.iv, 
                                                    pData, (uint16_t)ulDataLen, pEncryptedData, &pEncryptedData[ulDataLen])))
                    {
                        *pulEncryptedDataLen = ulDataLen + TA_AES_GCM_TAG_LENGTH;
                    }
                    else
                    {
                        rv = CKR_DATA_LEN_RANGE;
                    }
                }
            }
    #endif
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
        (void)pkcs11_unlock_both(pLibCtx);
    }
    pSession->active_mech = CKM_VENDOR_DEFINED;

    if (ATCA_SUCCESS != status && CKR_OK == rv)
    {
        rv = pkcs11_util_convert_rv(status);
    }

    return rv;
}

CK_RV pkcs11_encrypt_update
(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pData,
    CK_ULONG          ulDataLen,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG_PTR      pulEncryptedDataLen
)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;
    ATCA_STATUS status = ATCA_SUCCESS;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pData || !ulDataLen || !pEncryptedData || !pulEncryptedDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (rv)
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            if (ulDataLen == ATCA_AES128_BLOCK_SIZE && *pulEncryptedDataLen >= ATCA_AES128_BLOCK_SIZE)
            {
                status = atcab_aes_encrypt(pKey->slot, 0, pData, pEncryptedData);
                *pulEncryptedDataLen = ATCA_AES128_BLOCK_SIZE;
            }
            else
            {
                rv = CKR_ARGUMENTS_BAD;
            }
            break;
        case CKM_AES_CBC_PAD:
            /* fallthrough */
        case CKM_AES_CBC:
            {
                size_t length = *pulEncryptedDataLen;
                status = atcab_aes_cbc_encrypt_update(&pSession->active_mech_data.cbc, pData, ulDataLen, pEncryptedData, &length);
                *pulEncryptedDataLen = length;
            }
            break;
        case CKM_AES_GCM:
            if(atcab_is_ca_device(atcab_get_device_type()))
            {
    #ifdef ATCA_ATECC608_SUPPORT
                status = atcab_aes_gcm_encrypt_update(&pSession->active_mech_data.gcm.context, pData, ulDataLen, pEncryptedData);
    #endif
            }
    #ifdef ATCA_TA100_SUPPORT
            if(atcab_is_ta_device(atcab_get_device_type()))
            {
                rv = CKR_FUNCTION_NOT_SUPPORTED;
            }
    #endif
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
        (void)pkcs11_unlock_both(pLibCtx);
    }

    if (ATCA_SUCCESS != status && CKR_OK == rv)
    {
        rv = pkcs11_util_convert_rv(status);
    }

    return rv;
}

/**
 * \brief Finishes a multiple-part encryption operation
 */
CK_RV pkcs11_encrypt_final(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;
    ATCA_STATUS status = ATCA_SUCCESS;
    CK_BBOOL padding = FALSE;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pEncryptedData || !pulEncryptedDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (rv)
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            break;
        case CKM_AES_CBC_PAD:
            padding = TRUE;
            /* fallthrough */
        case CKM_AES_CBC:
            {
                size_t length = *pulEncryptedDataLen;
                status = atcab_aes_cbc_encrypt_finish(&pSession->active_mech_data.cbc, pEncryptedData, &length, padding);
                *pulEncryptedDataLen = length;
            }
            break;
        case CKM_AES_GCM:
            if(atcab_is_ca_device(atcab_get_device_type()))
            {
    #ifdef ATCA_ATECC608_SUPPORT
                status = atcab_aes_gcm_encrypt_finish(&pSession->active_mech_data.gcm.context, pEncryptedData,
                                                    pSession->active_mech_data.gcm.tag_len);
                *pulEncryptedDataLen = pSession->active_mech_data.gcm.tag_len;
    #endif
            }
    #ifdef ATCA_TA100_SUPPORT
            if(atcab_is_ta_device(atcab_get_device_type()))
            {
                rv = CKR_FUNCTION_NOT_SUPPORTED;
            }
    #endif
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
        (void)pkcs11_unlock_both(pLibCtx);
    }

    if (ATCA_SUCCESS != status && CKR_OK == rv)
    {
        rv = pkcs11_util_convert_rv(status);
    }

    pSession->active_mech = CKM_VENDOR_DEFINED;

    return rv;
}

CK_RV pkcs11_decrypt_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
    pkcs11_lib_ctx_ptr pLibCtx;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pObject;
    CK_RV rv;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pObject, hObject);
    if (rv)
    {
        return rv;
    }

    if (CKM_VENDOR_DEFINED == pSession->active_mech)
    {
        switch (pMechanism->mechanism)
        {
        case CKM_AES_ECB:
            rv = CKR_OK;
            break;
        case CKM_AES_CBC_PAD:
            /* fallthrough */
        case CKM_AES_CBC:
            rv = pkcs11_util_convert_rv(atcab_aes_cbc_init(&pSession->active_mech_data.cbc, pObject->slot, 0, pMechanism->pParameter));
            break;
        case CKM_AES_GCM:
            if (pMechanism->pParameter && sizeof(CK_GCM_PARAMS) == pMechanism->ulParameterLen)
            {
                CK_GCM_PARAMS_PTR pParams = (CK_GCM_PARAMS_PTR)pMechanism->pParameter;

                if (pParams->ulTagBits % 8 == 0)
                {
                    if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
                    {
                        if(atcab_is_ca_device(atcab_get_device_type()))
                        {
    #ifdef ATCA_ATECC608_SUPPORT
                            pSession->active_mech_data.gcm.tag_len = pParams->ulTagBits / 8;
                            if (CKR_OK == (rv = pkcs11_util_convert_rv(atcab_aes_gcm_init(&pSession->active_mech_data.gcm.context,
                                                                                        pObject->slot, 0, pParams->pIv, pParams->ulIvLen))))
                            {
                                rv = pkcs11_util_convert_rv(atcab_aes_gcm_aad_update(&pSession->active_mech_data.gcm.context, pParams->pAAD, pParams->ulAADLen));
                            }
    #else
                            rv = CKR_MECHANISM_INVALID;
    #endif
                        }
    #ifdef ATCA_TA100_SUPPORT
                        if(atcab_is_ta_device(atcab_get_device_type()))
                        {
                            if (pParams->ulIvLen > sizeof(pSession->active_mech_data.gcm_single.iv))
                            {
                                rv = CKR_ARGUMENTS_BAD;
                            }
                            else
                            {
                                memcpy(pSession->active_mech_data.gcm_single.iv, pParams->pIv, pParams->ulIvLen);
                            }
                            if (pParams->ulAADLen > sizeof(pSession->active_mech_data.gcm_single.aad))
                            {
                                rv = CKR_ARGUMENTS_BAD;
                            }
                            else
                            {
                                memcpy(pSession->active_mech_data.gcm_single.aad, pParams->pAAD, pParams->ulAADLen);
                            }
                        }
    #endif
                    (void)pkcs11_unlock_both(pLibCtx);
                    }
                }
                else
                {
                    rv = CKR_ARGUMENTS_BAD;
                }
            }
            else
            {
                rv = CKR_ARGUMENTS_BAD;
            }

            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
    }
    else
    {
        rv = CKR_OPERATION_ACTIVE;
    }

    if (CKR_OK == rv)
    {
        pSession->active_object = hObject;
        pSession->active_mech = pMechanism->mechanism;
    }

    return rv;
}

CK_RV pkcs11_decrypt
(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG          ulEncryptedDataLen,
    CK_BYTE_PTR       pData,
    CK_ULONG_PTR      pulDataLen
)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;
    ATCA_STATUS status = ATCA_SUCCESS;
    CK_BBOOL padding = FALSE;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pEncryptedData || !ulEncryptedDataLen || !pData || !pulDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (rv)
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            if (ulEncryptedDataLen == ATCA_AES128_BLOCK_SIZE && *pulDataLen >= ATCA_AES128_BLOCK_SIZE)
            {
                status = atcab_aes_decrypt(pKey->slot, 0, pEncryptedData, pData);
                *pulDataLen = ATCA_AES128_BLOCK_SIZE;
            }
            else
            {
                rv = CKR_ARGUMENTS_BAD;
            }
            break;
        case CKM_AES_CBC_PAD:
            padding = TRUE;
            /* fallthrough */
        case CKM_AES_CBC:
            {
                size_t length = *pulDataLen;
                if (ATCA_SUCCESS == (status = atcab_aes_cbc_decrypt_update(&pSession->active_mech_data.cbc, pEncryptedData, ulEncryptedDataLen, pData, &length)))
                {
                    pData += length;
                    length = *pulDataLen - length;
                    status = atcab_aes_cbc_decrypt_finish(&pSession->active_mech_data.cbc, pData, &length, padding);
                }
                *pulDataLen = length;
            }
            break;
        case CKM_AES_GCM:
            if(atcab_is_ca_device(atcab_get_device_type()))
            {
    #ifdef ATCA_ATECC608_SUPPORT
                *pulDataLen = ulEncryptedDataLen - pSession->active_mech_data.gcm.tag_len;
                if (ATCA_SUCCESS == (status = atcab_aes_gcm_decrypt_update(&pSession->active_mech_data.gcm.context, pEncryptedData,
                                                                        *pulDataLen, pData)))
                {
                    bool is_verified = FALSE;
                    status = atcab_aes_gcm_decrypt_finish(&pSession->active_mech_data.gcm.context, &pEncryptedData[*pulDataLen],
                                                        pSession->active_mech_data.gcm.tag_len, &is_verified);
                    if (!is_verified)
                    {
                        rv = CKR_ENCRYPTED_DATA_INVALID;
                    }
                }
    #endif
            }
    #ifdef ATCA_TA100_SUPPORT
            if(atcab_is_ta_device(atcab_get_device_type()))
            {
                if(ATCA_SUCCESS == (status = talib_aes_gcm_keyload(atcab_get_device(), pKey->slot, 0)))
                {
                    *pulDataLen = ulEncryptedDataLen - TA_AES_GCM_TAG_LENGTH;
                    if (ATCA_SUCCESS != (status = talib_aes_gcm_decrypt(atcab_get_device(), pSession->active_mech_data.gcm_single.aad, 
                                                    pSession->active_mech_data.gcm_single.aad_len, pSession->active_mech_data.gcm_single.iv,
                                                    &pEncryptedData[*pulDataLen], pEncryptedData, *pulDataLen, pData)))
                    {
                        rv = CKR_ENCRYPTED_DATA_INVALID;
                    }
                }
            }
    #endif
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
        (void)pkcs11_unlock_both(pLibCtx);
    }

    pSession->active_mech = CKM_VENDOR_DEFINED;

    if (ATCA_SUCCESS != status && CKR_OK == rv)
    {
        rv = pkcs11_util_convert_rv(status);
    }

    return rv;
}

CK_RV pkcs11_decrypt_update
(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG          ulEncryptedDataLen,
    CK_BYTE_PTR       pData,
    CK_ULONG_PTR      pulDataLen
)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;
    ATCA_STATUS status = ATCA_SUCCESS;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pEncryptedData || !ulEncryptedDataLen || !pData || !pulDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (rv)
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            if (ulEncryptedDataLen == ATCA_AES128_BLOCK_SIZE && *pulDataLen >= ATCA_AES128_BLOCK_SIZE)
            {
                status = atcab_aes_decrypt(pKey->slot, 0, pEncryptedData, pData);
                *pulDataLen = ATCA_AES128_BLOCK_SIZE;
            }
            else
            {
                rv = CKR_ARGUMENTS_BAD;
            }
            break;
        case CKM_AES_CBC_PAD:
            /* fallthrough */
        case CKM_AES_CBC:
            {
                size_t length = *pulDataLen;
                status = atcab_aes_cbc_decrypt_update(&pSession->active_mech_data.cbc, pEncryptedData, ulEncryptedDataLen, pData, &length);
                *pulDataLen = length;
            }
            break;
        case CKM_AES_GCM:
            if(atcab_is_ca_device(atcab_get_device_type()))
            {
    #ifdef ATCA_ATECC608_SUPPORT
                status = atcab_aes_gcm_decrypt_update(&pSession->active_mech_data.gcm.context, pEncryptedData,
                                                *pulDataLen, pData);
    #endif
            }
    #ifdef ATCA_TA100_SUPPORT
            if(atcab_is_ta_device(atcab_get_device_type()))
            {
                rv = CKR_FUNCTION_NOT_SUPPORTED;
            }
    #endif
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
        (void)pkcs11_unlock_both(pLibCtx);
    }

    if (ATCA_SUCCESS != status && CKR_OK == rv)
    {
        rv = pkcs11_util_convert_rv(status);
    }

    return rv;
}

/**
 * \brief Finishes a multiple-part decryption operation
 */
CK_RV pkcs11_decrypt_final(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;
    ATCA_STATUS status = ATCA_SUCCESS;
    CK_BBOOL padding = FALSE;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (rv)
    {
        return rv;
    }

    if (!pData || !pulDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (rv)
    {
        return rv;
    }

    switch (pSession->active_mech)
    {
    case CKM_AES_ECB:
        break;
    case CKM_AES_CBC_PAD:
        padding = TRUE;
        /* fallthrough */
    case CKM_AES_CBC:
        {
            size_t length = *pulDataLen;
            status = atcab_aes_cbc_decrypt_finish(&pSession->active_mech_data.cbc, pData, &length, padding);
            *pulDataLen = length;
        }
        break;
    case CKM_AES_GCM:
        if(atcab_is_ca_device(atcab_get_device_type()))
        {
#ifdef ATCA_ATECC608_SUPPORT
            if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
            {
                bool is_verified = FALSE;
                status = atcab_aes_gcm_decrypt_finish(&pSession->active_mech_data.gcm.context, pData,
                                                    pSession->active_mech_data.gcm.tag_len, &is_verified);
                if (!is_verified)
                {
                    rv = CKR_ENCRYPTED_DATA_INVALID;
                }
                (void)pkcs11_unlock_both(pLibCtx);
            }
#endif
        }
#ifdef ATCA_TA100_SUPPORT
        if(atcab_is_ta_device(atcab_get_device_type()))
        {
            rv = CKR_FUNCTION_NOT_SUPPORTED;
        }
#endif
    break;
    default:
        rv = CKR_MECHANISM_INVALID;
        break;
    }

    pSession->active_mech = CKM_VENDOR_DEFINED;

    if (ATCA_SUCCESS != status && CKR_OK == rv)
    {
        rv = pkcs11_util_convert_rv(status);
    }

    return rv;
}

/** @} */
