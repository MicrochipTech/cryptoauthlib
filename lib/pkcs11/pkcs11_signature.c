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
    pkcs11_object_ptr pKey,       /**< [in] Key object */
    CK_MECHANISM_PTR  pMechanism, /**< [in] Mechanism parameters from C_SignInit */
    CK_BBOOL          verify      /**< [in] true if verify is being performed */
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
 *
 * Assumptions:
 *       pKey is a valid pointer
 *
 * \return signature length in bytes
 */
static CK_ULONG pkcs11_signature_get_len(
    pkcs11_object_ptr pKey /**< [in] Key object */
    )
{
    /** \todo Support other key types (RSA, P384, etc) */
    ((void)pKey);

    return ATCA_ECCP256_SIG_SIZE;
}

/** \brief Check the parameters for a sign operation
 *
 * Assumptions:
 *       pulSignatureLen is a valid pointer
 */
static CK_RV pkcs11_signature_check_params(
    CK_BYTE_PTR  pSignature,      /**< [in] signature buffer - only checked if it non-null */
    CK_ULONG_PTR pulSignatureLen, /**< [in/out] input: size of pSignature, output: required signature size */
    CK_ULONG     ulSignatureLen   /**< [in] Required signature length */
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
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR       pData,
    CK_ULONG          ulDataLen,
    CK_BYTE_PTR       pSignature,
    CK_ULONG_PTR      pulSignatureLen)
{
    pkcs11_lib_ctx_ptr pLibCtx = NULL;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_RV rv;

    /* Check parameters */
    if (NULL == pData || NULL == pulSignatureLen)
    {
        return CKR_ARGUMENTS_BAD;
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
        switch (pSession->active_mech)
        {
        case CKM_SHA256_HMAC:
            if (CKR_OK == (rv = pkcs11_signature_check_params(pSignature, pulSignatureLen, ATCA_SHA256_DIGEST_SIZE)))
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    rv = pkcs11_util_convert_rv(atcab_sha_hmac_ext(pSession->slot->device_ctx, pData, ulDataLen, pKey->slot, pSignature, SHA_MODE_TARGET_OUT_ONLY));

                    (void)pkcs11_unlock_device(pLibCtx);
                }
            }
            break;
        case CKM_ECDSA:
            if (CKR_OK == (rv = pkcs11_signature_check_params(pSignature, pulSignatureLen, pkcs11_signature_get_len(pKey))))
            {
                if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
                {
                    rv = pkcs11_util_convert_rv(atcab_sign_ext(pSession->slot->device_ctx, pKey->slot, pData, pSignature));
                    (void)pkcs11_unlock_device(pLibCtx);
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
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey;
    CK_BBOOL is_private;
    CK_RV rv;
    ATCA_STATUS status = ATCA_GEN_FAIL;
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
        return CKR_ARGUMENTS_BAD;
    }

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
            if (ATCA_SUCCESS == (status = atcab_sha_hmac_ext(pSession->slot->device_ctx, pData, ulDataLen, pKey->slot, buf, SHA_MODE_TARGET_OUT_ONLY)))
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
        /* Checking data length */
        if (ulDataLen != ATCA_SHA256_DIGEST_SIZE)
        {
            (void)pkcs11_unlock_context(pLibCtx);
            return CKR_DATA_LEN_RANGE;
        }

        /* Checking Signature length */
        if (ulSignatureLen != ATCA_ECCP256_SIG_SIZE)
        {
            (void)pkcs11_unlock_context(pLibCtx);
            return CKR_SIGNATURE_LEN_RANGE;
        }

        if (CKR_OK == (rv = pkcs11_object_is_private(pKey, &is_private, pSession)))
        {
            if (CKR_OK == (rv = pkcs11_lock_device(pLibCtx)))
            {
                if (is_private)
                {
                    /* Device can't verify against a private key so ask the device for
                        the public key first then perform an external verify */
                    uint8_t pub_key[ATCA_ECCP256_PUBKEY_SIZE];

                    if (ATCA_SUCCESS == (status = atcab_get_pubkey_ext(pSession->slot->device_ctx, pKey->slot, pub_key)))
                    {
                        status = atcab_verify_extern_ext(pSession->slot->device_ctx, pData, pSignature, pub_key, &verified);
                    }
                }
                else
                {
                    /* Assume Public Key has been stored properly and verify against
                        whatever is stored */
                    status = atcab_verify_stored_ext(pSession->slot->device_ctx, pData, pSignature, pKey->slot, &verified);
                }

                (void)pkcs11_unlock_device(pLibCtx);
            }
        }
        break;
    default:
        status = ATCA_GEN_FAIL;
        break;
    }
    pSession->active_mech = CKM_VENDOR_DEFINED;
    (void)pkcs11_unlock_context(pLibCtx);

    if (ATCA_SUCCESS == status)
    {
        rv = verified ? CKR_OK : CKR_SIGNATURE_INVALID;
    }
    else
    {
        rv = CKR_DEVICE_ERROR;
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
