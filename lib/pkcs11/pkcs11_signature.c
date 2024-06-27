/**
 * \file
 * \brief PKCS11 Library Sign/Verify Handling
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

#include "pkcs11_config.h"
#include "pkcs11_debug.h"
#include "pkcs11_init.h"
#include "pkcs11_signature.h"
#include "pkcs11_object.h"
#include "pkcs11_session.h"
#include "pkcs11_util.h"
#include "cryptoauthlib.h"
#include "pkcs11_slot.h"
#include "pkcs11_key.h"

#if ATCA_CA_SUPPORT
#include "atcacert/atcacert_der.h"
#endif

/**
 * \defgroup pkcs11 Signature (pkcs11_signature_)
   @{ */

/** \brief Check if the mechanism and parameters will be able to be used with
 *   the sign or verify operation
 *
 *   Asumptions:
 *       pMechanism is a valid pointer
 */
static CK_RV pkcs11_signature_check_key(
    pkcs11_object_ptr   pKey,       /**< [in] Key object */
    CK_MECHANISM_PTR    pMechanism, /**< [in] Mechanism parameters from C_SignInit */
    CK_BBOOL            verify      /**< [in] true if verify is being performed */
    )
{
    CK_RV rv = CKR_MECHANISM_INVALID;

    switch (pMechanism->mechanism)
    {
    case CKM_SHA256_HMAC:
        if (CKO_SECRET_KEY == pKey->class_id)
        {
            rv = CKR_OK;
        }
        break;
    case CKM_ECDSA:
        if (CKO_PRIVATE_KEY == pKey->class_id)
        {
            rv = CKR_OK;
        }
        else if (verify && (CKO_PUBLIC_KEY == pKey->class_id))
        {
            rv = CKR_OK;
        }
        else
        {
            /* do nothing */
        }
        break;
    default:
        rv = CKR_MECHANISM_INVALID;
        break;
    }
    return rv;
}

/** \brief Get the sign of expected size of a signature based on the private key
 * Assumptions:
 *       pKey is a valid pointer
 *
 * \return signature length in bytes
 */
static CK_ULONG pkcs11_signature_get_len(
    ATCADeviceType dev_type, /**<[in] Device type */
    pkcs11_object_ptr pKey   /**< [in] Key object */
    )
{   
    CK_ULONG ulSiglen = 0u;
    if (NULL != pKey)
    {   
        if (atcab_is_ca_device(dev_type))
        {
            ulSiglen = ATCA_ECCP256_SIG_SIZE;
        }
        else if (atcab_is_ta_device(dev_type))
        {
#if ATCA_TA_SUPPORT
            uint8_t key_type = ((pKey->handle_info.element_CKA & TA_HANDLE_INFO_KEY_TYPE_MASK) >> TA_HANDLE_INFO_KEY_TYPE_SHIFT);
            ulSiglen = (CK_ULONG)ec_key_data_table[key_type].sig_sz;
#endif
        }
        else
        {
            /* do nothing */
        }
    }
    return ulSiglen;
}

/** \brief Check the parameters for a sign operation
 *
 * Assumptions:
 *       pulSignatureLen is a valid pointer
 */
static CK_RV pkcs11_signature_check_params(
    CK_BYTE_PTR     pSignature,         /**< [in] signature buffer - only checked if it non-null */
    CK_ULONG_PTR    pulSignatureLen,    /**< [in/out] input: size of pSignature, output: required signature size */
    CK_ULONG        ulSignatureLen      /**< [in] Required signature length */
    )
{
    CK_RV rv = CKR_OK;

    if (NULL != pSignature)
    {
        if (*pulSignatureLen < ulSignatureLen)
        {
            rv = CKR_BUFFER_TOO_SMALL;
        }
    }
    else
    {
        rv = CKR_VENDOR_DEFINED;
    }

    *pulSignatureLen = ulSignatureLen;

    return rv;
}

/**
 * \brief Initialize a signing operation using the specified key and mechanism
 */
CK_RV pkcs11_signature_sign_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pObject;
    CK_RV rv;

    rv = pkcs11_init_check(NULL, FALSE);
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

    rv = pkcs11_object_check(&pObject, hKey);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (CKM_VENDOR_DEFINED == pSession->active_mech)
    {
        if (CKR_OK == (rv = pkcs11_signature_check_key(pObject, pMechanism, FALSE)))
        {
            pSession->active_object = hKey;
            pSession->active_mech = pMechanism->mechanism;
        }
    }
    else
    {
        rv = CKR_OPERATION_ACTIVE;
    }

    return rv;
}

/**
 * \brief Sign the data in a single pass operation
 */
CK_RV pkcs11_signature_sign(
    CK_SESSION_HANDLE   hSession,
    CK_BYTE_PTR         pData,
    CK_ULONG            ulDataLen,
    CK_BYTE_PTR         pSignature,
    CK_ULONG_PTR        pulSignatureLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession = NULL;
    pkcs11_object_ptr pKey = NULL;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    /* Check parameters */
    if (NULL == pData || NULL == pulSignatureLen)
    {
        return rv;
    }

    if (0u == ulDataLen)
    {
        return CKR_DATA_LEN_RANGE;
    }

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

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {   
        ATCADeviceType dev_type = atcab_get_device_type_ext(pSession->slot->device_ctx);

        switch (pSession->active_mech)
        {
        //Key type is symmetric
        case CKM_SHA256_HMAC:
            if (CKR_OK == (rv = pkcs11_signature_check_params(pSignature, pulSignatureLen, ATCA_SHA256_DIGEST_SIZE)))
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    rv =
                        pkcs11_util_convert_rv(atcab_sha_hmac_ext(pSession->slot->device_ctx, pData, ulDataLen, pKey->slot, pSignature,
                                                                  SHA_MODE_TARGET_OUT_ONLY));

                    (void)pkcs11_unlock_device(pLibCtx);
                }
            }
            break;
        case CKM_ECDSA:
            if (CKR_OK == (rv = pkcs11_signature_check_params(pSignature, pulSignatureLen, pkcs11_signature_get_len(dev_type, pKey))))
            {   
                if (atcab_is_ca_device(dev_type))
                {
                    if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                    {

#if ATCA_CA_SUPPORT
                        rv = pkcs11_util_convert_rv(atcab_sign_ext(pSession->slot->device_ctx, pKey->slot, pData, pSignature));
#endif              
                        (void)pkcs11_unlock_device(pLibCtx);
                    }
                }
                else if (atcab_is_ta_device(dev_type))
                {   
                    if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                    {
#if ATCA_TA_SUPPORT     
                        uint8_t key_type = ((pKey->handle_info.element_CKA & TA_HANDLE_INFO_KEY_TYPE_MASK) >> TA_HANDLE_INFO_KEY_TYPE_SHIFT);
                        cal_buffer msg_buf = CAL_BUF_INIT(ulDataLen, pData);
                        cal_buffer sign_buf = CAL_BUF_INIT(*pulSignatureLen, pSignature);
                        //EC CURVE type depend on minium message size constraints for signing external messages in TA devices
                        if (ulDataLen >= ec_key_data_table[key_type].min_msg_sz)
                        {
                            rv = pkcs11_util_convert_rv(talib_sign_external(pSession->slot->device_ctx, key_type, pKey->slot, TA_HANDLE_INPUT_BUFFER, &msg_buf,
                                                                           &sign_buf));
                        }
#endif              
                        (void)pkcs11_unlock_device(pLibCtx);
                    }
                }
                else
                {
                    /* do nothing */
                }
            }
            break;
        default:
            /* An irrationality occured */
            rv = CKR_GENERAL_ERROR;
            break;
        }

        (void)pkcs11_unlock_context(pLibCtx);

        if (CKR_VENDOR_DEFINED == rv)
        {
            /* Made it through the pSignature buffer check so pulSignatureLen is populated */
            rv = CKR_OK;
        }
        else
        {
            /* Any other condition resets the sign operation */
            pSession->active_mech = CKM_VENDOR_DEFINED;
        }
    }

    return rv;
}

/**
 * \brief Continues a multiple-part signature operation
 */
CK_RV pkcs11_signature_sign_continue(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    ((void)hSession);
    ((void)pPart);
    ((void)ulPartLen);

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * \brief Finishes a multiple-part signature operation
 */
CK_RV pkcs11_signature_sign_finish(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    ((void)hSession);
    ((void)pSignature);
    ((void)pulSignatureLen);

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * \brief Initializes a verification operation using the specified key and mechanism
 */
CK_RV pkcs11_signature_verify_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pObject;
    CK_RV rv;

    rv = pkcs11_init_check(NULL, FALSE);
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

    rv = pkcs11_object_check(&pObject, hKey);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (CKM_VENDOR_DEFINED == pSession->active_mech)
    {
        if (CKR_OK == (rv = pkcs11_signature_check_key(pObject, pMechanism, TRUE)))
        {
            pSession->active_object = hKey;
            pSession->active_mech = pMechanism->mechanism;
        }
    }
    else
    {
        rv = CKR_OPERATION_ACTIVE;
    }

    return rv;
}

/**
 * \brief Verifies a signature on single-part data
 */
CK_RV pkcs11_signature_verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession = NULL;
    pkcs11_object_ptr pKey = NULL;
    CK_BBOOL is_private = FALSE;

    /*
        A successful call to C_Verify should return either the value CKR_OK (indicating that the supplied signature is valid) or CKR_SIGNATURE_INVALID (indicating that the supplied signature is invalid).
        If the signature can be seen to be invalid purely on the basis of its length, then CKR_SIGNATURE_LEN_RANGE should be returned.
        In any of these cases, the active signing operation is terminated.
     */
    CK_RV rv = CKR_ARGUMENTS_BAD;
    bool verified = FALSE;

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

    rv = pkcs11_object_check(&pKey, pSession->active_object);
    if (CKR_OK != rv)
    {
        return rv;
    }

    /* Check parameters */
    if (NULL == pData || NULL == pSignature)
    {
        return rv;
    }

    const pkcs11_ecc_key_info_t *ec_key_data = pkcs11_get_object_key_type(pSession->slot->device_ctx, pKey);

    if (CKR_OK != (rv = pkcs11_lock_context(pLibCtx)))
    {
        return rv;
    }

    switch (pSession->active_mech)
    {
    case CKM_SHA256_HMAC:
    {
        uint8_t buf[ATCA_SHA256_DIGEST_SIZE];

        /* Checking Data length */
        if (0u == ulDataLen)
        {
            (void)pkcs11_unlock_context(pLibCtx);
            return CKR_DATA_LEN_RANGE;
        }

        /* Checking Signature length */
        if (ulSignatureLen != ATCA_SHA256_DIGEST_SIZE)
        {
            (void)pkcs11_unlock_context(pLibCtx);
            return CKR_SIGNATURE_LEN_RANGE;
        }

        if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
        {
            if (CKR_OK ==
                (rv = pkcs11_util_convert_rv(atcab_sha_hmac_ext(pSession->slot->device_ctx, pData, ulDataLen, pKey->slot, buf, SHA_MODE_TARGET_OUT_ONLY))))
            {
                if (0 == memcmp(pSignature, buf, ATCA_SHA256_DIGEST_SIZE))
                {
                    verified = TRUE;
                }
            }

            (void)pkcs11_unlock_device(pLibCtx);
        }
    }
    break;
    case CKM_ECDSA:
        if (NULL == ec_key_data)
        {
            return CKR_ARGUMENTS_BAD;
        }
        
        /* Checking data length */
        if (ulDataLen < ec_key_data->min_msg_sz)
        {
            (void)pkcs11_unlock_context(pLibCtx);
            return CKR_DATA_LEN_RANGE;
        }

        /* Checking Signature length */
        if (ulSignatureLen < ec_key_data->sig_sz)
        {
            (void)pkcs11_unlock_context(pLibCtx);
            return CKR_SIGNATURE_LEN_RANGE;
        }

        if (CKR_OK == (rv = pkcs11_object_is_private(pKey, &is_private, pSession)))
        {
            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {

                ATCADeviceType dev_type = atcab_get_device_type_ext(pSession->slot->device_ctx);

                /* Device can't verify against a private key so ask the device for
                   the public key first then perform an external verify */
                uint8_t pub_key[PKCS11_MAX_ECC_PB_KEY_SIZE];
                if (is_private)
                {
                    if (atcab_is_ca_device(dev_type))
                    {
#if ATCA_CA_SUPPORT
                        if (CKR_OK == (rv = pkcs11_util_convert_rv(atcab_get_pubkey_ext(pSession->slot->device_ctx, pKey->slot, pub_key))))
                        {
                            rv = pkcs11_util_convert_rv(atcab_verify_extern_ext(pSession->slot->device_ctx, pData, pSignature, pub_key, &verified));
                        }
#endif
                    }
                    else if (atcab_is_ta_device(dev_type))
                    {
#if ATCA_TA_SUPPORT
                        cal_buffer ec_pubkey_buf = CAL_BUF_INIT(ec_key_data->pubkey_sz, pub_key);
                        if (CKR_OK == (rv = pkcs11_ta_get_pubkey(pKey, &ec_pubkey_buf, pSession)))
                        {
                            uint8_t key_type = ((pKey->handle_info.element_CKA & TA_HANDLE_INFO_KEY_TYPE_MASK) >> TA_HANDLE_INFO_KEY_TYPE_SHIFT);
                            cal_buffer sign_buf = CAL_BUF_INIT(ulSignatureLen, pSignature);
                            cal_buffer pbkey_buf = CAL_BUF_INIT(ec_key_data->pubkey_sz, pub_key);
                            cal_buffer msg_buf = CAL_BUF_INIT(ulDataLen, pData);
#if TALIB_VERIFY_EXTERN_EN
                            rv = pkcs11_util_convert_rv(talib_verify_extern(pSession->slot->device_ctx, key_type, TA_HANDLE_INPUT_BUFFER, &pbkey_buf, &sign_buf,
                                                                           &msg_buf, &verified));
#endif
                        }
#endif
                    }
                    else
                    {
                        /* do nothing */
                    }
                }
                else
                {
                    /* Assume Public Key has been stored properly and verify against
                        whatever is stored */
                    if (atcab_is_ca_device(dev_type))
                    {
#if ATCA_CA_SUPPORT
                        rv = pkcs11_util_convert_rv(atcab_verify_stored_ext(pSession->slot->device_ctx, pData, pSignature, pKey->slot, &verified));
#endif
                    }
                    else if (atcab_is_ta_device(dev_type))
                    {
#if ATCA_TA_SUPPORT
                        uint8_t key_type = ((pKey->handle_info.element_CKA & TA_HANDLE_INFO_KEY_TYPE_MASK) >> TA_HANDLE_INFO_KEY_TYPE_SHIFT);
                        cal_buffer sign_buf = CAL_BUF_INIT(ulSignatureLen, pSignature);
                        cal_buffer msg_buf = CAL_BUF_INIT(ulDataLen, pData);
#if TALIB_VERIFY_STORED_EN
                        rv = pkcs11_util_convert_rv(talib_verify_stored(pSession->slot->device_ctx, key_type, TA_HANDLE_INPUT_BUFFER, pKey->slot, &sign_buf,
                                                                       &msg_buf, &verified));
#endif
#endif
                    }
                    else
                    {
                        /* do nothing */
                    }

                }
                (void)pkcs11_unlock_device(pLibCtx);
            }
        }
        break;
    default:
        break;
    }

    pSession->active_mech = CKM_VENDOR_DEFINED;
    (void)pkcs11_unlock_context(pLibCtx);

    if ((CKR_OK != rv || TRUE != verified))
    {
        rv = CKR_SIGNATURE_INVALID;
    }

    return rv;
}

/**
 * \brief Continues a multiple-part verification operation
 */
CK_RV pkcs11_signature_verify_continue(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    ((void)hSession);
    ((void)pPart);
    ((void)ulPartLen);

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/**
 * \brief Finishes a multiple-part verification operation
 */
CK_RV pkcs11_signature_verify_finish(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
    ((void)hSession);
    ((void)pSignature);
    ((void)ulSignatureLen);

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/** @} */
