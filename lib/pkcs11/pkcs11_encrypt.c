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
#include <limits.h>
#include "pkcs11_config.h"
#include "pkcs11_encrypt.h"
#include "pkcs11_debug.h"
#include "pkcs11_init.h"
#include "pkcs11_object.h"
#include "pkcs11_session.h"
#include "pkcs11_util.h"
#include "pkcs11_slot.h"
#include "pkcs11_key.h"

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "MISRA C-2012 Rule 16.1" "Implementation is correct and has good readablity") \
    (deviate "MISRA C-2012 Rule 16.3" "Implementation is correct and has good readablity")
#endif

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
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pObject, hObject);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (CKR_OK != (rv = pkcs11_reserve_resource(pLibCtx, pSession, PKCS11_AES_OP)))
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        if (CKM_VENDOR_DEFINED == pSession->active_mech)
        {
            switch (pMechanism->mechanism)
            {
            case CKM_AES_ECB:
                rv = CKR_OK;
                break;
            case CKM_AES_CBC_PAD:
                rv = pkcs11_util_convert_rv(atcab_aes_cbc_init_ext(pSession->slot->device_ctx, &pSession->active_mech_data.cbc, pObject->slot, 0, (uint8_t*)pMechanism->pParameter, 1));
                break;
            case CKM_AES_CBC:
                rv = pkcs11_util_convert_rv(atcab_aes_cbc_init_ext(pSession->slot->device_ctx, &pSession->active_mech_data.cbc, pObject->slot, 0, (uint8_t*)pMechanism->pParameter, 0));
                break;
            case CKM_AES_GCM:
                if ((NULL != pMechanism->pParameter) && sizeof(CK_GCM_PARAMS) == pMechanism->ulParameterLen)
                {
                    CK_GCM_PARAMS_PTR pParams = (CK_GCM_PARAMS_PTR)pMechanism->pParameter;

                    if (pParams->ulTagBits % 8u == 0u)
                    {
                        if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
                        {
#ifdef ATCA_ATECC608_SUPPORT
                            /* coverity[misra_c_2012_rule_10_1_violation] False positive - coverity bug with stdint.h definitions */
                            pSession->active_mech_data.gcm.tag_len = (CK_BYTE)((pParams->ulTagBits / 8u) & UINT8_MAX);
                            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                            {
                                if (CKR_OK == (rv = pkcs11_util_convert_rv(atcab_aes_gcm_init_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context,
                                                                                                  pObject->slot, 0, pParams->pIv, pParams->ulIvLen))))
                                {
                                    /* coverity[misra_c_2012_rule_10_1_violation] False positive - coverity bug with stdint.h definitions */
                                    rv = pkcs11_util_convert_rv(atcab_aes_gcm_aad_update_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, pParams->pAAD, (uint32_t)(pParams->ulAADLen) & UINT32_MAX));
                                }
                                (void)pkcs11_unlock_device(pLibCtx);
                            }
#else
                            rv = CKR_MECHANISM_INVALID;
#endif
                        }
#if ATCA_TA_SUPPORT
                        if (atcab_is_ta_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
                        {
                            if (pParams->ulIvLen > sizeof(pSession->active_mech_data.gcm_single.iv))
                            {
                                rv = CKR_ARGUMENTS_BAD;
                            }
                            else
                            {
                                (void)memcpy(pSession->active_mech_data.gcm_single.iv, pParams->pIv, pParams->ulIvLen);
                            }
                            if (pParams->ulAADLen > sizeof(pSession->active_mech_data.gcm_single.aad))
                            {
                                rv = CKR_ARGUMENTS_BAD;
                            }
                            else
                            {
                                (void)memcpy(pSession->active_mech_data.gcm_single.aad, pParams->pAAD, pParams->ulAADLen);
                            }
                        }
#endif
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
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
            case CKM_RSA_PKCS_OAEP:
                // pMechanism->pParameter should point to CK_RSA_PKCS_OAEP_PARAMS
                if ((NULL != pMechanism->pParameter) && sizeof(CK_RSA_PKCS_OAEP_PARAMS) == pMechanism->ulParameterLen)
                {
                    rv = CKR_OK;
                }
                else
                {
                    rv = CKR_ARGUMENTS_BAD;
                }
                break;
#endif
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
        (void)pkcs11_unlock_context(pLibCtx);
    }

    if (CKR_OK != rv)
    {
        (void)pkcs11_release_resource(pLibCtx, pSession, PKCS11_AES_OP);
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
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
    CK_BBOOL is_private = false;
#endif

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pData || 0u == ulDataLen || NULL == pEncryptedData || NULL == pulEncryptedDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (CKR_OK != rv)
    {
        return rv;
    }

    /* need lock both for encrypt*/
    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            if (ulDataLen == ATCA_AES128_BLOCK_SIZE && *pulEncryptedDataLen >= ATCA_AES128_BLOCK_SIZE)
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    status = atcab_aes_encrypt_ext(pSession->slot->device_ctx, pKey->slot, 0, pData, pEncryptedData);
                    (void)pkcs11_unlock_device(pLibCtx);
                }
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
            size_t final = 0;

            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {
                if (ATCA_SUCCESS == (status = atcab_aes_cbc_encrypt_update(&pSession->active_mech_data.cbc, pData, ulDataLen, pEncryptedData, &length)))
                {
                    pEncryptedData += length;
                    final = *pulEncryptedDataLen - length;
                    status = atcab_aes_cbc_encrypt_finish(&pSession->active_mech_data.cbc, pEncryptedData, &final);
                }
                (void)pkcs11_unlock_device(pLibCtx);
            }
            /* coverity[misra_c_2012_rule_10_1_violation] False positive - coverity bug with stdint.h definitions */
            if (length <= UINT32_MAX)
            {
                if ((UINT32_MAX - length) >= final)
                {
                    *pulEncryptedDataLen = (CK_ULONG)(length + final);
                }
            }
        }
        break;
        case CKM_AES_GCM:
            if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
#ifdef ATCA_ATECC608_SUPPORT
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    /* coverity[misra_c_2012_rule_10_1_violation] False positive - coverity bug with stdint.h definitions */
                    if (ATCA_SUCCESS == (status = atcab_aes_gcm_encrypt_update_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, pData, (uint32_t)(ulDataLen & UINT32_MAX), pEncryptedData)))
                    {
                        status = atcab_aes_gcm_encrypt_finish_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, &pEncryptedData[ulDataLen],
                                                                  pSession->active_mech_data.gcm.tag_len);
                        *pulEncryptedDataLen = ulDataLen + pSession->active_mech_data.gcm.tag_len;
                    }
                    (void)pkcs11_unlock_device(pLibCtx);
                }
#else
                rv = CKR_GENERAL_ERROR;
#endif
            }
#if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(atcab_get_device_type()))
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    if (ATCA_SUCCESS == (status = talib_aes128_gcm_keyload(pSession->slot->device_ctx, pKey->slot, 0)))
                    {
                        cal_buffer aad_buf = CAL_BUF_INIT(pSession->active_mech_data.gcm_single.aad_len, pSession->active_mech_data.gcm_single.aad);
                        cal_buffer iv_buf = CAL_BUF_INIT(TA_AES_GCM_IV_LENGTH, pSession->active_mech_data.gcm_single.iv);
                        cal_buffer data_buf = CAL_BUF_INIT(ulDataLen, pData);
                        cal_buffer ciphertext_buf = CAL_BUF_INIT(*pulEncryptedDataLen, pEncryptedData);
                        cal_buffer tag_buf = CAL_BUF_INIT(TA_AES_GCM_TAG_LENGTH, &pEncryptedData[ulDataLen]);
                        if (ATCA_SUCCESS == (status = talib_aes_gcm_encrypt(pSession->slot->device_ctx, &aad_buf, &iv_buf,
                                                                            &data_buf, &ciphertext_buf, &tag_buf)))
                        {
                            *pulEncryptedDataLen = ulDataLen + TA_AES_GCM_TAG_LENGTH;
                        }
                        else
                        {
                            rv = CKR_DATA_LEN_RANGE;
                        }
                    }
                    (void)pkcs11_unlock_device(pLibCtx);
                }
            }
#endif
            break;
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
        case CKM_RSA_PKCS_OAEP:
            if (CKR_OK == (rv = pkcs11_object_is_private(pKey, &is_private, pSession)))
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    ATCADeviceType dev_type = atcab_get_device_type_ext(pSession->slot->device_ctx);
                    if (atcab_is_ta_device(dev_type))
                    {
                        cal_buffer plaintext_buf = CAL_BUF_INIT(ulDataLen, pData);
                        cal_buffer ciphertext_buf = CAL_BUF_INIT(*pulEncryptedDataLen, pEncryptedData);
                        const pkcs11_key_info_t* key_data = pkcs11_get_object_key_type(pSession->slot->device_ctx, pKey);

                        if (NULL != key_data && NULL != key_data->rsa_key_info)
                        {
                            if (true == is_private)
                            {
                                uint8_t pub_key[PKCS11_MAX_RSA_PB_KEY_SIZE];
                                cal_buffer rsa_pubkey_buf = CAL_BUF_INIT(key_data->rsa_key_info->pubkey_sz, pub_key);

                                if (CKR_OK == (rv = pkcs11_ta_get_pubkey(pKey, &rsa_pubkey_buf, pSession)))
                                {
                                    rv = pkcs11_util_convert_rv(talib_rsaenc_encrypt(pSession->slot->device_ctx, key_data->rsa_key_info->rsa_encrypt_mode, TA_HANDLE_INPUT_BUFFER,
                                                                                     &plaintext_buf, &rsa_pubkey_buf, &ciphertext_buf));
                                }
                            }
                            else
                            {
                                /* Assume Public Key has been stored properly and encrypt against whatever is stored */
                                rv = pkcs11_util_convert_rv(talib_rsaenc_encrypt(pSession->slot->device_ctx, key_data->rsa_key_info->rsa_encrypt_mode, pKey->slot,
                                                                                 &plaintext_buf, NULL, &ciphertext_buf));
                            }
                        }
                    }
                    (void)pkcs11_unlock_device(pLibCtx);
                }
            }
            break;
#endif
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
        (void)pkcs11_unlock_context(pLibCtx);
    }

    (void)pkcs11_release_resource(pLibCtx, pSession, PKCS11_AES_OP);

    pSession->active_mech = CKM_VENDOR_DEFINED;

    if (ATCA_SUCCESS != status && CKR_OK == rv)
    {
        rv = pkcs11_util_convert_rv(status);
    }

    return rv;
}

CK_RV pkcs11_encrypt_update(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pData,
    CK_ULONG          ulDataLen,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG_PTR      pulEncryptedDataLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;
    ATCA_STATUS status = ATCA_SUCCESS;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pData || 0u == ulDataLen || NULL == pEncryptedData || NULL == pulEncryptedDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (CKR_OK != rv)
    {
        return rv;
    }

    /* need lock both for encrypt update*/
    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            if (ulDataLen == ATCA_AES128_BLOCK_SIZE && *pulEncryptedDataLen >= ATCA_AES128_BLOCK_SIZE)
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    status = atcab_aes_encrypt_ext(pSession->slot->device_ctx, pKey->slot, 0, pData, pEncryptedData);
                    (void)pkcs11_unlock_device(pLibCtx);
                }
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
            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {
                status = atcab_aes_cbc_encrypt_update(&pSession->active_mech_data.cbc, pData, ulDataLen, pEncryptedData, &length);
                (void)pkcs11_unlock_device(pLibCtx);
            }

            *pulEncryptedDataLen = (CK_ULONG)(length & UINT32_MAX);
        }
        break;
        case CKM_AES_GCM:
            if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
#ifdef ATCA_ATECC608_SUPPORT
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    /* coverity[misra_c_2012_rule_10_1_violation] False positive - coverity bug with stdint.h definitions */
                    status = atcab_aes_gcm_encrypt_update_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, pData, (uint32_t)(ulDataLen & UINT32_MAX), pEncryptedData);
                    (void)pkcs11_unlock_device(pLibCtx);
                }
#endif
            }
#if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(atcab_get_device_type()))
            {
                rv = CKR_FUNCTION_NOT_SUPPORTED;
            }
#endif
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
        (void)pkcs11_unlock_context(pLibCtx);
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

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pEncryptedData || NULL == pulEncryptedDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (CKR_OK != rv)
    {
        return rv;
    }
    /* need lock both for encrypt final*/
    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            break;
        case CKM_AES_CBC_PAD:
        /* fallthrough */
        case CKM_AES_CBC:
        {
            size_t length = *pulEncryptedDataLen;

            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {
                status = atcab_aes_cbc_encrypt_finish(&pSession->active_mech_data.cbc, pEncryptedData, &length);
                (void)pkcs11_unlock_device(pLibCtx);
            }

            *pulEncryptedDataLen = (CK_ULONG)(length & UINT32_MAX);
        }
        break;
        case CKM_AES_GCM:
            if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
#ifdef ATCA_ATECC608_SUPPORT
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    status = atcab_aes_gcm_encrypt_finish_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, pEncryptedData,
                                                              pSession->active_mech_data.gcm.tag_len);
                    (void)pkcs11_unlock_device(pLibCtx);
                }
                *pulEncryptedDataLen = pSession->active_mech_data.gcm.tag_len;
#endif
            }
#if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(atcab_get_device_type()))
            {
                rv = CKR_FUNCTION_NOT_SUPPORTED;
            }
#endif
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        (void)pkcs11_unlock_context(pLibCtx);
    }

    (void)pkcs11_release_resource(pLibCtx, pSession, PKCS11_AES_OP);

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
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pMechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pObject, hObject);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (CKR_OK != (rv = pkcs11_reserve_resource(pLibCtx, pSession, PKCS11_AES_OP)))
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        if (CKM_VENDOR_DEFINED == pSession->active_mech)
        {
            switch (pMechanism->mechanism)
            {
            case CKM_AES_ECB:
                rv = CKR_OK;
                break;
            case CKM_AES_CBC_PAD:
                rv = pkcs11_util_convert_rv(atcab_aes_cbc_init_ext(pSession->slot->device_ctx, &pSession->active_mech_data.cbc, pObject->slot, 0, (uint8_t*)pMechanism->pParameter, 1));
                break;
            case CKM_AES_CBC:
                rv = pkcs11_util_convert_rv(atcab_aes_cbc_init_ext(pSession->slot->device_ctx, &pSession->active_mech_data.cbc, pObject->slot, 0, (uint8_t*)pMechanism->pParameter, 0));
                break;
            case CKM_AES_GCM:
                if ((NULL != pMechanism->pParameter) && sizeof(CK_GCM_PARAMS) == pMechanism->ulParameterLen)
                {
                    CK_GCM_PARAMS_PTR pParams = (CK_GCM_PARAMS_PTR)pMechanism->pParameter;

                    if (pParams->ulTagBits % 8u == 0u)
                    {

                        if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
                        {
#ifdef ATCA_ATECC608_SUPPORT
                            /* coverity[misra_c_2012_rule_10_1_violation] False positive - coverity bug with stdint.h definitions */
                            pSession->active_mech_data.gcm.tag_len = (CK_BYTE)((pParams->ulTagBits / 8u) & UINT8_MAX);

                            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                            {
                                if (CKR_OK == (rv = pkcs11_util_convert_rv(atcab_aes_gcm_init_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context,
                                                                                                  pObject->slot, 0, pParams->pIv, pParams->ulIvLen))))
                                {
                                    rv = pkcs11_util_convert_rv(atcab_aes_gcm_aad_update_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, pParams->pAAD, (uint32_t)(pParams->ulAADLen)));
                                }
                                (void)pkcs11_unlock_device(pLibCtx);
                            }
#else
                            rv = CKR_MECHANISM_INVALID;
#endif
                        }
#if ATCA_TA_SUPPORT
                        if (atcab_is_ta_device(atcab_get_device_type()))
                        {
                            if (pParams->ulIvLen > sizeof(pSession->active_mech_data.gcm_single.iv))
                            {
                                rv = CKR_ARGUMENTS_BAD;
                            }
                            else
                            {
                                (void)memcpy(pSession->active_mech_data.gcm_single.iv, pParams->pIv, pParams->ulIvLen);
                            }
                            if (pParams->ulAADLen > sizeof(pSession->active_mech_data.gcm_single.aad))
                            {
                                rv = CKR_ARGUMENTS_BAD;
                            }
                            else
                            {
                                (void)memcpy(pSession->active_mech_data.gcm_single.aad, pParams->pAAD, pParams->ulAADLen);
                            }
                        }
#endif

                        else
                        {
                            rv = CKR_ARGUMENTS_BAD;
                        }
                    }
                    else
                    {
                        rv = CKR_ARGUMENTS_BAD;
                    }
                }
                break;
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
            case CKM_RSA_PKCS_OAEP:
                // pMechanism->pParameter should point to CK_RSA_PKCS_OAEP_PARAMS
                if ((NULL != pMechanism->pParameter) && sizeof(CK_RSA_PKCS_OAEP_PARAMS) == pMechanism->ulParameterLen)
                {
                    rv = CKR_OK;
                }
                break;
#endif
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
        (void)pkcs11_unlock_context(pLibCtx);
    }

    if (CKR_OK != rv)
    {
        (void)pkcs11_release_resource(pLibCtx, pSession, PKCS11_AES_OP);
    }

    return rv;
}

CK_RV pkcs11_decrypt(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG          ulEncryptedDataLen,
    CK_BYTE_PTR       pData,
    CK_ULONG_PTR      pulDataLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;
    ATCA_STATUS status = ATCA_SUCCESS;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pEncryptedData || 0u == ulEncryptedDataLen || NULL == pData || NULL == pulDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }
 #if (ULONG_MAX > UINT32_MAX)
    if (*pulDataLen > UINT32_MAX)
    {
        return CKR_ARGUMENTS_BAD;
    }
#endif

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            if (ulEncryptedDataLen == ATCA_AES128_BLOCK_SIZE && *pulDataLen >= ATCA_AES128_BLOCK_SIZE)
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    status = atcab_aes_decrypt_ext(pSession->slot->device_ctx, pKey->slot, 0, pEncryptedData, pData);
                    (void)pkcs11_unlock_device(pLibCtx);
                }
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
            size_t final = 0;
            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {
                if (ATCA_SUCCESS == (status = atcab_aes_cbc_decrypt_update(&pSession->active_mech_data.cbc, pEncryptedData, ulEncryptedDataLen, pData, &length)))
                {
                    pData += length;
                    final = *pulDataLen - length;
                    status = atcab_aes_cbc_decrypt_finish(&pSession->active_mech_data.cbc, pData, &final);
                }
                (void)pkcs11_unlock_device(pLibCtx);
            }

            /* coverity[misra_c_2012_rule_10_1_violation] False positive - coverity bug with stdint.h definitions */
            if ((UINT32_MAX - length) >= final)
            {
                *pulDataLen = (CK_ULONG)(length + final);
            }
        }
        break;
        case CKM_AES_GCM:
            if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
#ifdef ATCA_ATECC608_SUPPORT
                *pulDataLen = ulEncryptedDataLen - pSession->active_mech_data.gcm.tag_len;
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    if (ATCA_SUCCESS == (status = atcab_aes_gcm_decrypt_update_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, pEncryptedData,
                                                                                   (uint32_t)(*pulDataLen & UINT32_MAX), pData)))
                    {
                        bool is_verified = FALSE;
                        status = atcab_aes_gcm_decrypt_finish_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, &pEncryptedData[*pulDataLen],
                                                                  pSession->active_mech_data.gcm.tag_len, &is_verified);
                        if (!is_verified)
                        {
                            rv = CKR_ENCRYPTED_DATA_INVALID;
                        }
                    }
                    (void)pkcs11_unlock_device(pLibCtx);
                }
#endif
            }
#if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(atcab_get_device_type()))
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    if (ATCA_SUCCESS == (status = talib_aes128_gcm_keyload(pSession->slot->device_ctx, pKey->slot, 0)))
                    {
                        *pulDataLen = ulEncryptedDataLen - TA_AES_GCM_TAG_LENGTH;
                        cal_buffer aad_buf = CAL_BUF_INIT(pSession->active_mech_data.gcm_single.aad_len, pSession->active_mech_data.gcm_single.aad);
                        cal_buffer iv_buf = CAL_BUF_INIT(TA_AES_GCM_IV_LENGTH, pSession->active_mech_data.gcm_single.iv);
                        cal_buffer ciphertext_buf = CAL_BUF_INIT(*pulDataLen, pEncryptedData);
                        cal_buffer data_buf = CAL_BUF_INIT(ulEncryptedDataLen, pData);
                        cal_buffer tag_buf = CAL_BUF_INIT(TA_AES_GCM_TAG_LENGTH, &pEncryptedData[*pulDataLen]);
                        if (ATCA_SUCCESS != (status = talib_aes_gcm_decrypt(pSession->slot->device_ctx, &aad_buf, &iv_buf, &tag_buf,
                                                                            &ciphertext_buf, &data_buf)))
                        {
                            rv = CKR_ENCRYPTED_DATA_INVALID;
                        }
                    }
                }
                (void)pkcs11_unlock_device(pLibCtx);
            }
#endif
            break;
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
        case CKM_RSA_PKCS_OAEP:
            if (atcab_is_ta_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {   
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    cal_buffer ciphertext_buf = CAL_BUF_INIT(ulEncryptedDataLen, pEncryptedData);
                    cal_buffer plaintext_buf = CAL_BUF_INIT(*pulDataLen, pData);
                    const pkcs11_key_info_t* key_data = pkcs11_get_object_key_type(pSession->slot->device_ctx, pKey);

                    if (NULL != key_data && NULL != key_data->rsa_key_info)
                    {
                        rv = pkcs11_util_convert_rv(talib_rsaenc_decrypt(pSession->slot->device_ctx, key_data->rsa_key_info->rsa_decrypt_mode, pKey->slot,
                                                                         &ciphertext_buf, &plaintext_buf));
                    }
                    (void)pkcs11_unlock_device(pLibCtx);
                }
            }
            break;  
#endif
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        (void)pkcs11_unlock_context(pLibCtx);
    }
    (void)pkcs11_release_resource(pLibCtx, pSession, PKCS11_AES_OP);

    pSession->active_mech = CKM_VENDOR_DEFINED;

    if (ATCA_SUCCESS != status && CKR_OK == rv)
    {
        rv = pkcs11_util_convert_rv(status);
    }

    return rv;
}

CK_RV pkcs11_decrypt_update(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG          ulEncryptedDataLen,
    CK_BYTE_PTR       pData,
    CK_ULONG_PTR      pulDataLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;
    ATCA_STATUS status = ATCA_SUCCESS;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pEncryptedData || 0u == ulEncryptedDataLen || NULL == pData || NULL == pulDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

#if (ULONG_MAX > UINT32_MAX)
    if (*pulDataLen > UINT32_MAX)
    {
        return CKR_ARGUMENTS_BAD;
    }
#endif

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            if (ulEncryptedDataLen == ATCA_AES128_BLOCK_SIZE && *pulDataLen >= ATCA_AES128_BLOCK_SIZE)
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    status = atcab_aes_decrypt_ext(pSession->slot->device_ctx, pKey->slot, 0, pEncryptedData, pData);
                    (void)pkcs11_unlock_device(pLibCtx);
                }
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
            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {
                status = atcab_aes_cbc_decrypt_update(&pSession->active_mech_data.cbc, pEncryptedData, ulEncryptedDataLen, pData, &length);
                (void)pkcs11_unlock_device(pLibCtx);
            }
            *pulDataLen = (CK_ULONG)(length & UINT32_MAX);
        }
        break;
        case CKM_AES_GCM:
            if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
#ifdef ATCA_ATECC608_SUPPORT
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    status = atcab_aes_gcm_decrypt_update_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, pEncryptedData,
                                                              (uint32_t)*pulDataLen, pData);
                    (void)pkcs11_unlock_device(pLibCtx);
                }
#endif
            }
#if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(atcab_get_device_type()))
            {
                rv = CKR_FUNCTION_NOT_SUPPORTED;
            }
#endif
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }
        (void)pkcs11_unlock_context(pLibCtx);
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

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pData || NULL == pulDataLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_AES_ECB:
            break;
        case CKM_AES_CBC_PAD:
        /* fallthrough */
        case CKM_AES_CBC:
        {
            size_t length = *pulDataLen;
            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {
                status = atcab_aes_cbc_decrypt_finish(&pSession->active_mech_data.cbc, pData, &length);
                (void)pkcs11_unlock_device(pLibCtx);
            }
            /* coverity[misra_c_2012_rule_10_1_violation] False positive - coverity bug with stdint.h definitions */
            *pulDataLen = (CK_ULONG)(length & UINT32_MAX);
        }
        break;
        case CKM_AES_GCM:
            if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
#ifdef ATCA_ATECC608_SUPPORT

                bool is_verified = FALSE;
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    status = atcab_aes_gcm_decrypt_finish_ext(pSession->slot->device_ctx, &pSession->active_mech_data.gcm.context, pData,
                                                              pSession->active_mech_data.gcm.tag_len, &is_verified);
                    (void)pkcs11_unlock_device(pLibCtx);
                }
                if (!is_verified)
                {
                    rv = CKR_ENCRYPTED_DATA_INVALID;
                }

#endif
            }
#if ATCA_TA_SUPPORT
            if (atcab_is_ta_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
                rv = CKR_FUNCTION_NOT_SUPPORTED;
            }
#endif
            break;
        default:
            rv = CKR_MECHANISM_INVALID;
            break;
        }

        (void)pkcs11_unlock_context(pLibCtx);
    }
    (void)pkcs11_release_resource(pLibCtx, pSession, PKCS11_AES_OP);

    pSession->active_mech = CKM_VENDOR_DEFINED;

    if (ATCA_SUCCESS != status && CKR_OK == rv)
    {
        rv = pkcs11_util_convert_rv(status);
    }

    return rv;
}

#ifdef __COVERITY__
#pragma coverity compliance end_block "MISRA C-2012 Rule 16.1" \
    "MISRA C-2012 Rule 16.3"
#endif

/** @} */
