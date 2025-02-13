#include "cryptoauthlib.h"
#include "pkcs11_init.h"
#include "pkcs11_digest.h"
#include "pkcs11_mech.h"
#include "pkcs11_object.h"
#include "pkcs11_session.h"
#include "pkcs11_util.h"

/**
 * \brief Initializes a message-digesting operation using the specified mechanism in the specified session
 */
CK_RV pkcs11_digest_init(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
    pkcs11_session_ctx_ptr pSession;
    pkcs11_lib_ctx_ptr pLibCtx;
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

    if ((CKM_SHA256 != pMechanism->mechanism) && (CKM_SHA384 != pMechanism->mechanism) && (CKM_SHA512 != pMechanism->mechanism))
    {
        return CKR_MECHANISM_INVALID;
    }
    else if (CKM_VENDOR_DEFINED != pSession->active_mech)
    {
        return CKR_OPERATION_ACTIVE;
    }
    else
    {
        /* do nothing */
    }

#ifdef PKCS11_HARDWARE_SHA256
    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        switch (pMechanism->mechanism)
        {
        case CKM_SHA256:
#if (ATCAC_SHA256_EN)
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_256_init(&pSession->active_mech_data.sha256));

            if (CKR_OK == rv)
            {
                pSession->active_mech = CKM_SHA256;
            }
#else
            rv = CKR_FUNCTION_NOT_SUPPORTED;
#endif            
            break;

        case CKM_SHA384:
#if (ATCAC_SHA384_EN)
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_384_init(&pSession->active_mech_data.sha384));

            if (CKR_OK == rv)
            {
                pSession->active_mech = CKM_SHA384;
            }
#else
            rv = CKR_FUNCTION_NOT_SUPPORTED;
#endif
            break;

        case CKM_SHA512:
#if (ATCAC_SHA512_EN)
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_512_init(&pSession->active_mech_data.sha512));

            if (CKR_OK == rv)
            {
                pSession->active_mech = CKM_SHA512;
            }
#else
            rv = CKR_FUNCTION_NOT_SUPPORTED;
#endif
            break;

        default:
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        } 
        
        (void)pkcs11_unlock_context(pLibCtx);
    }

    return rv;
#endif
}

/**
 * \brief Digest the specified data in a one-pass operation and return the resulting digest
 */
CK_RV pkcs11_digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    pkcs11_session_ctx_ptr pSession;
    pkcs11_lib_ctx_ptr pLibCtx;
    CK_RV rv;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pData || 0u == ulDataLen || NULL == pulDigestLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

#ifdef PKCS11_HARDWARE_SHA256
    ((void)hSession);
    ((void)pData);
    ((void)ulDataLen);
    ((void)pDigest);
    ((void)pulDigestLen);

    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    switch (pSession->active_mech)
    {
    case CKM_SHA256:
        if (NULL == pDigest)
        {
            *pulDigestLen = ATCA_SHA2_256_DIGEST_SIZE;
            rv = CKR_OK;
            break;
        }
        else if (ATCA_SHA2_256_DIGEST_SIZE > *pulDigestLen)
        {
            rv = CKR_BUFFER_TOO_SMALL;
            break;
        }
        else
        {
            /* do nothing */
        }
#if (ATCAC_SHA256_EN)
        if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
        {
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_256_update(&pSession->active_mech_data.sha256, pData, ulDataLen));
            if (CKR_OK == rv)
            {
                rv = pkcs11_util_convert_rv(atcac_sw_sha2_256_finish(&pSession->active_mech_data.sha256, pDigest));
            }
        }
        pSession->active_mech = CKM_VENDOR_DEFINED;
        (void)pkcs11_unlock_context(pLibCtx);
#endif
        break;

    case CKM_SHA384:
        if (NULL == pDigest)
        {
            *pulDigestLen = ATCA_SHA2_384_DIGEST_SIZE;
            rv = CKR_OK;
            break;
        }
        else if (ATCA_SHA2_384_DIGEST_SIZE > *pulDigestLen)
        {
            rv = CKR_BUFFER_TOO_SMALL;
            break;
        }
        else
        {
            /* do nothing */
        }
#if (ATCAC_SHA384_EN)
        if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
        {
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_384_update(&pSession->active_mech_data.sha384, pData, ulDataLen));
            if (CKR_OK == rv)
            {
                rv = pkcs11_util_convert_rv(atcac_sw_sha2_384_finish(&pSession->active_mech_data.sha384, pDigest));
            }
        }
        pSession->active_mech = CKM_VENDOR_DEFINED;
        (void)pkcs11_unlock_context(pLibCtx);
#endif
        break; 

    case CKM_SHA512:
        if (NULL == pDigest)
        {
            *pulDigestLen = ATCA_SHA2_512_DIGEST_SIZE;
            rv = CKR_OK;
            break;
        }
        else if (ATCA_SHA2_512_DIGEST_SIZE > *pulDigestLen)
        {
            rv = CKR_BUFFER_TOO_SMALL;
            break;
        }
        else
        {
            /* do nothing */
        }
#if (ATCAC_SHA512_EN)
        if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
        {
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_512_update(&pSession->active_mech_data.sha512, pData, ulDataLen));
            if (CKR_OK == rv)
            {
                rv = pkcs11_util_convert_rv(atcac_sw_sha2_512_finish(&pSession->active_mech_data.sha512, pDigest));
            }
        }    
        pSession->active_mech = CKM_VENDOR_DEFINED;
        (void)pkcs11_unlock_context(pLibCtx);
#endif
        break;     
        
    default:
        rv = CKR_OPERATION_NOT_INITIALIZED;
        break;
    }

    return rv;
#endif
}

/**
 * \brief Continues a multiple-part digesting operation
 */
CK_RV pkcs11_digest_update(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
    pkcs11_session_ctx_ptr pSession;
    pkcs11_lib_ctx_ptr pLibCtx;
    CK_RV rv;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pPart || 0u == ulPartLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

#ifdef PKCS11_HARDWARE_SHA256
    ((void)hSession);
    ((void)pPart);
    ((void)ulPartLen);

    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
    {
        switch (pSession->active_mech)
        {
        case CKM_SHA256:
#if (ATCAC_SHA256_EN)
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_256_update(&pSession->active_mech_data.sha256, pPart, ulPartLen));
#endif
            break;

        case CKM_SHA384:
#if (ATCAC_SHA384_EN)
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_384_update(&pSession->active_mech_data.sha384, pPart, ulPartLen));
#endif
            break;    

        case CKM_SHA512:
#if (ATCAC_SHA512_EN)
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_512_update(&pSession->active_mech_data.sha512, pPart, ulPartLen));
#endif
            break;    
        
        default:
            rv = CKR_OPERATION_NOT_INITIALIZED;
            break;
        }

        (void)pkcs11_unlock_context(pLibCtx);
    }
    return rv;
#endif
}

/**
 * \brief Finishes a multiple-part digesting operation
 */
CK_RV pkcs11_digest_final(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
    pkcs11_session_ctx_ptr pSession;
    pkcs11_lib_ctx_ptr pLibCtx;
    CK_RV rv;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pulDigestLen)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

#ifdef PKCS11_HARDWARE_SHA256
    ((void)hSession);
    ((void)pDigest);
    ((void)pulDigestLen);

    return CKR_FUNCTION_NOT_SUPPORTED;
#else
    switch (pSession->active_mech)
    {
    case CKM_SHA256:
        if (NULL == pDigest)
        {
            *pulDigestLen = ATCA_SHA2_256_DIGEST_SIZE;
            rv = CKR_OK;
            break;
        }
        else if (ATCA_SHA2_256_DIGEST_SIZE > *pulDigestLen)
        {
            rv = CKR_BUFFER_TOO_SMALL;
            break;
        }
        else
        {
            /* do nothing */
        }
#if (ATCAC_SHA256_EN)
        if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
        {
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_256_finish(&pSession->active_mech_data.sha256, pDigest));
        }
        pSession->active_mech = CKM_VENDOR_DEFINED;
        (void)pkcs11_unlock_context(pLibCtx);
#endif
        break;

    case CKM_SHA384:
        if (NULL == pDigest)
        {
            *pulDigestLen = ATCA_SHA2_384_DIGEST_SIZE;
            rv = CKR_OK;
            break;
        }
        else if (ATCA_SHA2_384_DIGEST_SIZE > *pulDigestLen)
        {
            rv = CKR_BUFFER_TOO_SMALL;
            break;
        }
        else
        {
            /* do nothing */
        }
#if (ATCAC_SHA384_EN)
        if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
        {
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_384_finish(&pSession->active_mech_data.sha384, pDigest));
        }
        pSession->active_mech = CKM_VENDOR_DEFINED;
        (void)pkcs11_unlock_context(pLibCtx);
#endif
        break;   

    case CKM_SHA512:
        if (NULL == pDigest)
        {
            *pulDigestLen = ATCA_SHA2_512_DIGEST_SIZE;
            rv = CKR_OK;
            break;
        }
        else if (ATCA_SHA2_512_DIGEST_SIZE > *pulDigestLen)
        {
            rv = CKR_BUFFER_TOO_SMALL;
            break;
        }
        else
        {
            /* do nothing */
        }
#if (ATCAC_SHA512_EN)
        if (CKR_OK == (rv = pkcs11_lock_context(pLibCtx)))
        {
            rv = pkcs11_util_convert_rv(atcac_sw_sha2_512_finish(&pSession->active_mech_data.sha512, pDigest));
        }
        pSession->active_mech = CKM_VENDOR_DEFINED;
        (void)pkcs11_unlock_context(pLibCtx);
#endif
        break;     
    
    default:
        rv = CKR_OPERATION_NOT_INITIALIZED;
        break;
    }

    return rv;
#endif
}
