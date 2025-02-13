/**
 * \file
 * \brief PKCS11 Library Certificate Handling
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

#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
#include "tng_atca.h"
#endif

#include "atcacert/atcacert_def.h"
#include "atcacert/atcacert_client.h"

#include "pkcs11_config.h"
#include "pkcs11_debug.h"
#include "pkcs11_token.h"
#include "pkcs11_cert.h"
#include "pkcs11_os.h"
#include "pkcs11_util.h"
#include "pkcs11_slot.h"

/**
 * \defgroup pkcs11 Key (pkcs11_key_)
   @{ */

#if defined(ATCA_HEAP) && (FEATURE_ENABLED == ATCACERT_INTEGRATION_EN)
typedef struct pkcs11_cert_cache_s
{
    CK_ATTRIBUTE            cert_x509_parse;
    pkcs11_session_ctx_ptr  pSession_cert;
    pkcs11_object_ptr       pObject_cert;
    atcacert_def_t *        pSession_cert_def;
    CK_BBOOL                in_use;
    void *                  pCert_parsed;
} pkcs11_cert_cache;

static pkcs11_cert_cache pkcs11_cert_cache_list[PKCS11_MAX_CERTS_CACHED];
#endif


#if (defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)) && ATCACERT_COMPCERT_EN
static CK_RV pkcs11_cert_check_trust_data(pkcs11_object_ptr pObject, pkcs11_session_ctx_ptr pSession)
{
    CK_RV rv = CKR_ARGUMENTS_BAD;
    if ((PKCS11_OBJECT_FLAG_TRUST_TYPE == (PKCS11_OBJECT_FLAG_TRUST_TYPE & pObject->flags)) && (NULL == pObject->data) && (NULL != pSession))
    {
        const atcacert_def_t * cert_def = NULL;
        rv = pkcs11_util_convert_rv(tng_get_device_cert_def_ext(pSession->slot->device_ctx, &cert_def));

        if (NULL != cert_def)
        {
            if (CK_CERTIFICATE_CATEGORY_AUTHORITY == pObject->class_type)
            {
                /* coverity[cert_exp40_c_violation] The system understands how to use the certificate definition properly */
                /* coverity[misra_c_2012_rule_11_8_violation] The system understands how to use the certificate definition properly */
                pObject->data = (void*)cert_def->ca_cert_def;
            }
            else
            {
                /* coverity[cert_exp40_c_violation] The system understands how to use the certificate definition properly */
                /* coverity[misra_c_2012_rule_11_8_violation] The system understands how to use the certificate definition properly */
                pObject->data = (void*)cert_def;
            }
        }
    }
    return rv;
}
#endif

/* Loads cert into cache list */
static CK_RV pkcs11_cert_load_cache(const pkcs11_session_ctx_ptr pSession, const pkcs11_object_ptr pObject)
{
    CK_RV rv = CKR_GENERAL_ERROR;

    UNUSED_VAR(pSession);

    if ((pObject->class_id == CKO_CERTIFICATE) &&
        (pObject->class_type == CK_CERTIFICATE_CATEGORY_TOKEN_USER))
    {
#if defined(ATCA_HEAP) && (FEATURE_ENABLED == ATCACERT_INTEGRATION_EN)
        if (NULL == pObject->data)
        {
            /* Find free cert cache slot*/
            CK_ULONG i;
            for (i = 0; i < PKCS11_MAX_CERTS_CACHED; i++)
            {
                if (FALSE == pkcs11_cert_cache_list[i].in_use)
                {
                    break;
                }
            }

            if (i < PKCS11_MAX_CERTS_CACHED)
            {
                /* Allocate cert object memory */
                atcacert_def_t* cert_def = pkcs11_os_malloc(sizeof(atcacert_def_t));

                if (NULL != cert_def)
                {
                    cert_def->type = CERTTYPE_X509_FULL_STORED;
                    cert_def->comp_cert_dev_loc.zone = (atcacert_device_zone_t)ATCA_ZONE_DATA;
                    cert_def->comp_cert_dev_loc.slot = pObject->slot;
                    cert_def->parsed = (struct atcac_x509_ctx**)(&pkcs11_cert_cache_list[i].pCert_parsed);
                    pObject->data = cert_def;
                    pObject->flags |= PKCS11_OBJECT_FLAG_CERT_CACHE;


                    /* Get the buffer size required first */
                    rv = pkcs11_cert_load(pObject, &pkcs11_cert_cache_list[i].cert_x509_parse, pSession->slot->device_ctx);
                    if (CKR_OK == rv)
                    {
                        pkcs11_cert_cache_list[i].cert_x509_parse.pValue = pkcs11_os_malloc(pkcs11_cert_cache_list[i].cert_x509_parse.ulValueLen);
                        /* Link x509 parsed certificate to object */
                        rv = pkcs11_cert_load(pObject, &pkcs11_cert_cache_list[i].cert_x509_parse, pSession->slot->device_ctx);
                        pkcs11_cert_cache_list[i].in_use = TRUE;
                        pkcs11_cert_cache_list[i].pSession_cert = pSession;
                        pkcs11_cert_cache_list[i].pObject_cert = pObject;
                        pkcs11_cert_cache_list[i].pSession_cert_def = cert_def;
                    }
                }
                else
                {
                    rv = CKR_HOST_MEMORY;
                }
            }
            else
            {
                rv = CKR_GENERAL_ERROR;
            }
        }
        else
        {
            CK_ULONG i;
            for (i = 0; i < PKCS11_MAX_CERTS_CACHED; i++)
            {
                if ((pkcs11_cert_cache_list[i].pSession_cert == pSession) &&
                    (pkcs11_cert_cache_list[i].pObject_cert == pObject))
                {
                    return CKR_OK;
                }
            }
        }
#endif
    }

    return rv;
}

#if ATCA_CA_SUPPORT
static CK_RV pkcs11_cert_load_ca(pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pAttribute, ATCADevice device)
{
    int cert_status;

    if (NULL != pObject->data)
    {
        atcacert_def_t * cert_cfg = (atcacert_def_t*)pObject->data;

        /* Load Certificate */
        if ((NULL != pAttribute->pValue) && (0u != pAttribute->ulValueLen))
        {
            size_t temp = pAttribute->ulValueLen;

#if (FEATURE_ENABLED == ATCACERT_INTEGRATION_EN)
            cert_status = atcacert_read_cert_ext(device, (atcacert_def_t*)pObject->data, NULL, (uint8_t*)pAttribute->pValue, &temp);
#else
            ATCA_STATUS status = ATCA_SUCCESS;
            uint8_t ca_key[64] = { 0 };
            cal_buffer ca_key_buf = CAL_BUF_INIT(sizeof(ca_key), ca_key);

            if (NULL != cert_cfg->ca_cert_def)
            {
                if (cert_cfg->ca_cert_def->public_key_dev_loc.is_genkey == 1u)
                {
                    status = atcab_get_pubkey_ext(device, cert_cfg->ca_cert_def->public_key_dev_loc.slot, ca_key);
                }
                else
                {
                    status = atcab_read_pubkey_ext(device, cert_cfg->ca_cert_def->public_key_dev_loc.slot, ca_key);
                }
            }

            if (ATCA_SUCCESS != status)
            {
                return CKR_DEVICE_ERROR;
            }

            cert_status = atcacert_read_cert_ext(device, (atcacert_def_t*)pObject->data, (cert_cfg->ca_cert_def != NULL) ? &ca_key_buf : NULL,
                                                 (uint8_t*)pAttribute->pValue, &temp);
#endif
            pAttribute->ulValueLen = (uint32_t)(temp & 0xffffffffu);

            if (ATCACERT_E_DECODING_ERROR == cert_status)
            {
                return CKR_DATA_INVALID;
            }
            if (ATCACERT_E_SUCCESS != cert_status)
            {
                return CKR_DEVICE_ERROR;
            }
        }
        else
        {
            size_t cert_size = 0u;

            if (ATCACERT_E_SUCCESS != atcacert_read_cert_size_ext(device, cert_cfg, &cert_size))
            {
                return CKR_DEVICE_ERROR;
            }

            pAttribute->ulValueLen = (CK_ULONG)cert_size;
        }
        return CKR_OK;
    }
    else
    {
        return pkcs11_attrib_empty(NULL, pAttribute, NULL);
    }
}
#endif

#if ATCA_TA_SUPPORT
static CK_RV pkcs11_cert_load_ta(pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pAttribute, ATCADevice device)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != pObject->data)
    {
        atcacert_def_t * cert_def = (atcacert_def_t*)pObject->data;
        if ((NULL == pAttribute->pValue) && (0u == pAttribute->ulValueLen))
        {
            size_t cert_size = 0x00;
            if (ATCACERT_E_SUCCESS != (status = atcacert_read_cert_ext(device, cert_def, NULL, NULL, &cert_size)))
            {
                return pkcs11_util_convert_rv(status);
            }
            //Full certificate size
            pAttribute->ulValueLen = cert_size;
        }
        else if ((NULL != pAttribute->pValue) && (0u != pAttribute->ulValueLen))
        {
            uint8_t* cert = (uint8_t*)pAttribute->pValue;
            size_t cert_size = pAttribute->ulValueLen;
            if (ATCACERT_E_SUCCESS != (status = atcacert_read_cert_ext(device, cert_def, NULL, cert, &cert_size)))
            {
                return pkcs11_util_convert_rv(status);
            }
        }
        else
        {
            status = ATCA_SUCCESS;
        }
    }
    else
    {
        (void)pkcs11_attrib_empty(NULL, pAttribute, NULL);
    }

    return pkcs11_util_convert_rv(status);
}
#endif

CK_RV pkcs11_cert_load(pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pAttribute, ATCADevice device)
{
    CK_RV ret = CKR_GENERAL_ERROR;
    ATCADeviceType dev_type = atcab_get_device_type_ext(device);

    if (atcab_is_ca_device(dev_type))
    {
#if ATCA_CA_SUPPORT
        ret = pkcs11_cert_load_ca(pObject, pAttribute, device);
#endif
    }
    else if (atcab_is_ta_device(dev_type))
    {
#if ATCA_TA_SUPPORT
        ret = pkcs11_cert_load_ta(pObject, pAttribute, device);
#endif
    }
    else
    {
        ret = CKR_FUNCTION_NOT_SUPPORTED;
    }
    return ret;
}

static CK_RV pkcs11_cert_get_encoded(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != psession)
    {
        if (PKCS11_OBJECT_FLAG_TRUST_TYPE == (PKCS11_OBJECT_FLAG_TRUST_TYPE & obj_ptr->flags))
        {
#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
            rv = pkcs11_cert_check_trust_data(obj_ptr, psession);
            if (CKR_OK == rv)
            {
                return pkcs11_cert_load(obj_ptr, pAttribute, psession->slot->device_ctx);
            }
#endif
        }
        #if defined(ATCA_HEAP) && (FEATURE_ENABLED == ATCACERT_INTEGRATION_EN)
        rv = pkcs11_cert_load_cache(psession, obj_ptr);
        if (CKR_OK == rv)
        {
            CK_ULONG i;
            for (i = 0; i < PKCS11_MAX_CERTS_CACHED; i++)
            {
                if ((pkcs11_cert_cache_list[i].pSession_cert == psession) &&
                    (pkcs11_cert_cache_list[i].pObject_cert == pObject))
                {
                    return pkcs11_attrib_fill(pAttribute, pkcs11_cert_cache_list[i].cert_x509_parse.pValue,
                                            pkcs11_cert_cache_list[i].cert_x509_parse.ulValueLen);
                }
            }
        }
        #else
        return pkcs11_cert_load(obj_ptr, pAttribute, psession->slot->device_ctx);
        #endif      
    }
    return rv;
}

#if ATCA_CA_SUPPORT
static CK_RV pkcs11_cert_get_type_ca(pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != pObject)
    {
        if (PKCS11_OBJECT_FLAG_TRUST_TYPE == (PKCS11_OBJECT_FLAG_TRUST_TYPE & pObject->flags))
        {
#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
            (void)pkcs11_cert_check_trust_data(pObject, psession);
#endif
        }

        if (NULL != pObject->data)
        {
            atcacert_def_t* cert_cfg = (atcacert_def_t*)pObject->data;

            if (CERTTYPE_X509 == cert_cfg->type)
            {
                return pkcs11_attrib_value(pAttribute, CKC_X_509, (CK_ULONG)sizeof(CK_CERTIFICATE_TYPE));
            }
            else
            {
                return pkcs11_attrib_value(pAttribute, CKC_VENDOR_DEFINED, (CK_ULONG)sizeof(CK_CERTIFICATE_TYPE));
            }
        }
        else
        {
            rv = pkcs11_attrib_empty(NULL, pAttribute, NULL);
        }
    }

    return rv;
}
#endif

static CK_RV pkcs11_cert_get_type(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    CK_RV rv = CKR_GENERAL_ERROR;

    if (NULL != psession)
    {
        if (atcab_is_ca_device(atcab_get_device_type_ext(psession->slot->device_ctx)))
        {
#if ATCA_CA_SUPPORT
            rv = pkcs11_cert_get_type_ca((pkcs11_object_ptr)pObject, pAttribute, psession);
#else
            ((void)pObject);
#endif
        }
        else
        {
            rv = pkcs11_attrib_value(pAttribute, CKC_X_509, (CK_ULONG)sizeof(CK_CERTIFICATE_TYPE));
        }
    }

    return rv;
}

static CK_RV pkcs11_cert_get_subject(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != psession)
    {
        if (PKCS11_OBJECT_FLAG_TRUST_TYPE == (PKCS11_OBJECT_FLAG_TRUST_TYPE & obj_ptr->flags))
        {
#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
            (void)pkcs11_cert_check_trust_data(obj_ptr, psession);
#endif
        }
        else
        {
            rv = pkcs11_cert_load_cache(psession, obj_ptr);
        }

        if (NULL != obj_ptr->data)
        {
            if ((NULL != pAttribute->pValue) && (0u != pAttribute->ulValueLen))
            {
                atcacert_def_t* cert_def = (atcacert_def_t*)obj_ptr->data;
                if (CKR_OK == rv)
                {
                    uint8_t subject[128] = { 0 };
                    cal_buffer subject_buf = CAL_BUF_INIT(sizeof(subject), subject);

                    if (ATCA_SUCCESS == (atcacert_get_subject(cert_def, NULL, 0, &subject_buf)))
                    {
                        return pkcs11_attrib_fill(pAttribute, subject, (CK_ULONG)cal_buf_get_used(&subject_buf));
                    }
                    else
                    {
                        return CKR_DEVICE_ERROR;
                    }
                }
                #if defined(ATCA_HEAP) && ATCA_CA_SUPPORT
                else
                {
                    const atcacert_cert_element_t * subj_element = NULL;

                    if (NULL != cert_def->cert_elements)
                    {
                        uint8_t i;
                        for (i = 0; i < cert_def->cert_elements_count; i++)
                        {
                            if (0 == strcmp(cert_def->cert_elements[i].id, "subject"))
                            {
                                subj_element = &cert_def->cert_elements[i];
                                break;
                            }
                        }
                    }

                    if (NULL != subj_element)
                    {
                        CK_ATTRIBUTE cert_attr = { 0, NULL, 0 };

                        /* Get the buffer size required first */
                        rv = pkcs11_cert_load(obj_ptr, &cert_attr, psession->slot->device_ctx);

                        if (CKR_OK == rv)
                        {
                            cert_attr.pValue = pkcs11_os_malloc(cert_attr.ulValueLen);
                            rv = pkcs11_cert_load(obj_ptr, &cert_attr, psession->slot->device_ctx);
                        }

                        if (CKR_OK == rv)
                        {
                            if (NULL != cert_attr.pValue)
                            {
                                rv = pkcs11_attrib_fill(pAttribute, &((uint8_t*)cert_attr.pValue)[subj_element->cert_loc.offset],
                                                        subj_element->cert_loc.count);
                            }
                        }

                        if (NULL != cert_attr.pValue)
                        {
                            pkcs11_os_free(cert_attr.pValue);
                        }
                    }
                }
                #endif
            }
            else
            {
                pAttribute->ulValueLen = 128;
                if (pAttribute->pValue == NULL)
                {
                    return CKR_OK;
                }
            }
        }
        else
        {
            return pkcs11_attrib_empty(NULL, pAttribute, NULL);
        }
    }
    else
    {
        return pkcs11_attrib_empty(pObject, pAttribute, NULL);
    }

    return rv;
}

static CK_RV pkcs11_cert_get_issuer(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != psession)
    {
        CK_RV read_cache = CKR_GENERAL_ERROR;

        read_cache = pkcs11_cert_load_cache(psession, obj_ptr);

        if (NULL != obj_ptr->data)
        {
            if ((NULL != pAttribute->pValue) && (0u != pAttribute->ulValueLen))
            {
                atcacert_def_t * cert_cfg = (atcacert_def_t*)obj_ptr->data;
                if (CKR_OK == read_cache)
                {
                    uint8_t issuer_name[128] = { 0 };

                    if (ATCA_SUCCESS == (atcacert_get_issuer(cert_cfg, NULL, 0, issuer_name)))
                    {
                        return pkcs11_attrib_fill(pAttribute, issuer_name, (CK_ULONG)sizeof(issuer_name));
                    }
                    else
                    {
                        return CKR_DEVICE_ERROR;
                    }
                }
            }
            else
            {
                pAttribute->ulValueLen = 128;
                if (pAttribute->pValue == NULL)
                {
                    return CKR_OK;
                }
            }
        }
        else
        {
            return pkcs11_attrib_empty(NULL, pAttribute, NULL);
        }
    }
    else
    {
        return pkcs11_attrib_empty(pObject, pAttribute, NULL);
    }

    return rv;
}

static CK_RV pkcs11_cert_get_subject_key_id(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    CK_RV read_cache = CKR_GENERAL_ERROR;
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr)
    {
        if (PKCS11_OBJECT_FLAG_TRUST_TYPE == (PKCS11_OBJECT_FLAG_TRUST_TYPE & obj_ptr->flags))
        {
#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
            (void)pkcs11_cert_check_trust_data(obj_ptr, psession);
#endif
        }
        else
        {
            read_cache = pkcs11_cert_load_cache(psession, obj_ptr);
        }

        if (NULL != obj_ptr->data)
        {
            if ((NULL != pAttribute->pValue) && (0u != pAttribute->ulValueLen))
            {
                atcacert_def_t * cert_cfg = (atcacert_def_t*)obj_ptr->data;
                uint8_t subj_key_id[20] = { 0 };
                ATCA_STATUS cert_status = (ATCA_STATUS)CKR_DEVICE_ERROR;

                if (CKR_OK == read_cache)
                {
                    cert_status = atcacert_get_subj_key_id(cert_cfg, NULL, 0, subj_key_id);
                }
                else
                {
#if ATCACERT_COMPCERT_EN
                    cert_status = atcacert_read_subj_key_id(cert_cfg, subj_key_id);
#endif
                }

                if (ATCA_SUCCESS != (ATCA_STATUS)cert_status)
                {
                    return CKR_DEVICE_ERROR;
                }

                return pkcs11_attrib_fill(pAttribute, subj_key_id, (CK_ULONG)sizeof(subj_key_id));
            }
            else
            {
                pAttribute->ulValueLen = 20;
                if (pAttribute->pValue == NULL)
                {
                    return CKR_OK;
                }
            }
        }
        else
        {
            return pkcs11_attrib_empty(NULL, pAttribute, NULL);
        }
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV pkcs11_cert_get_serial_num(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr && NULL != psession)
    {
        (void)pkcs11_cert_load_cache(psession, obj_ptr);

        if (NULL != obj_ptr->data)
        {
            if ((NULL != pAttribute->pValue) && (0u != pAttribute->ulValueLen))
            {
                atcacert_def_t * cert_cfg = (atcacert_def_t*)obj_ptr->data;
                uint8_t cert_sn[32] = { 0 };
                size_t cert_sn_size = sizeof(cert_sn);
                int sn_status;

                sn_status = atcacert_get_cert_sn(cert_cfg, NULL, 0, cert_sn, &cert_sn_size);

                if (ATCA_SUCCESS != (ATCA_STATUS)sn_status)
                {
                    return CKR_DEVICE_ERROR;
                }

                return pkcs11_attrib_fill(pAttribute, cert_sn, (CK_ULONG)cert_sn_size);
            }
            else
            {
                pAttribute->ulValueLen = 32;
                if (pAttribute->pValue == NULL)
                {
                    return CKR_OK;
                }
            }
        }
        else
        {
            return pkcs11_attrib_empty(NULL, pAttribute, NULL);
        }
    }

    return CKR_ARGUMENTS_BAD;
}


static CK_RV pkcs11_cert_get_authority_key_id(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr)
    {
        if (PKCS11_OBJECT_FLAG_TRUST_TYPE == (PKCS11_OBJECT_FLAG_TRUST_TYPE & obj_ptr->flags))
        {
#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
            (void)pkcs11_cert_check_trust_data(obj_ptr, psession);
#endif
        }
        else
        {
            (void)pkcs11_cert_load_cache(psession, obj_ptr);
        }

        if (NULL != obj_ptr->data)
        {
            if ((NULL != pAttribute->pValue) && (0u != pAttribute->ulValueLen))
            {
                atcacert_def_t * cert_cfg = (atcacert_def_t*)obj_ptr->data;
                uint8_t auth_key_id[20] = { 0 };

                if (ATCA_SUCCESS == (atcacert_get_auth_key_id(cert_cfg, NULL, 0, auth_key_id)))
                {
                    return pkcs11_attrib_fill(pAttribute, auth_key_id, (CK_ULONG)sizeof(auth_key_id));
                }
                else
                {
                    return CKR_DEVICE_ERROR;
                }
            }
            else
            {
                pAttribute->ulValueLen = 20;
                if (pAttribute->pValue == NULL)
                {
                    return CKR_OK;
                }
            }
        }
        else
        {
            return pkcs11_attrib_empty(NULL, pAttribute, NULL);
        }
    }

    return CKR_ARGUMENTS_BAD;
}


static CK_RV pkcs11_get_issue_date(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr && NULL != psession)
    {
        if (NULL != obj_ptr->data)
        {
            if ((NULL != pAttribute->pValue) && (0u != pAttribute->ulValueLen))
            {
                atcacert_def_t * cert_cfg = (atcacert_def_t*)obj_ptr->data;
                atcacert_tm_utc_t timestamp;

                (void)memset(&timestamp, 0, sizeof(atcacert_tm_utc_t));

                if (ATCA_SUCCESS == (atcacert_get_issue_date(cert_cfg, NULL, 0, &timestamp)))
                {
                    return pkcs11_attrib_fill(pAttribute, &timestamp, (CK_ULONG)sizeof(timestamp));
                }
                else
                {
                    return CKR_DEVICE_ERROR;
                }
            }
            else
            {
                pAttribute->ulValueLen = 0;
                if (pAttribute->pValue == NULL)
                {
                    return CKR_OK;
                }
            }
        }
        else
        {
            return pkcs11_attrib_empty(NULL, pAttribute, NULL);
        }
    }

    return CKR_ARGUMENTS_BAD;
}


static CK_RV pkcs11_get_expire_date(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr && NULL != psession)
    {
        if (NULL != obj_ptr->data)
        {
            if ((NULL != pAttribute->pValue) && (0u != pAttribute->ulValueLen))
            {
                atcacert_def_t * cert_cfg = (atcacert_def_t*)obj_ptr->data;
                atcacert_tm_utc_t timestamp;

                (void)memset(&timestamp, 0, sizeof(atcacert_tm_utc_t));

                if (ATCA_SUCCESS == (atcacert_get_expire_date(cert_cfg, NULL, 0, &timestamp)))
                {
                    return pkcs11_attrib_fill(pAttribute, &timestamp, (CK_ULONG)sizeof(timestamp));
                }
                else
                {
                    return CKR_DEVICE_ERROR;
                }
            }
            else
            {
                pAttribute->ulValueLen = 0;
                if (pAttribute->pValue == NULL)
                {
                    return CKR_OK;
                }
            }
        }
        else
        {
            return pkcs11_attrib_empty(NULL, pAttribute, NULL);
        }
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV pkcs11_cert_get_trusted_flag(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    ((void)psession);

    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr)
    {
        if (CK_CERTIFICATE_CATEGORY_AUTHORITY == obj_ptr->class_type)
        {
            return pkcs11_attrib_true(NULL, pAttribute, NULL);
        }
        else
        {
            return pkcs11_attrib_false(NULL, pAttribute, NULL);
        }
    }
    return CKR_ARGUMENTS_BAD;
}

static CK_RV pkcs11_cert_get_subj_key(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
#if PKCS11_AUTO_ID_ENABLE
    return pkcs11_cert_get_subject_key_id(pObject, pAttribute, psession);
#elif ATCA_CA_SUPPORT || ATCA_TA_SUPPORT
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr)
    {
        CK_RV read_cache = CKR_GENERAL_ERROR;
        if (PKCS11_OBJECT_FLAG_TRUST_TYPE == (PKCS11_OBJECT_FLAG_TRUST_TYPE & obj_ptr->flags))
        {
#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)
            (void)pkcs11_cert_check_trust_data(obj_ptr, psession);
#endif
        }
        else
        {
            read_cache = pkcs11_cert_load_cache(psession, obj_ptr);
        }
        if (NULL != obj_ptr->data)
        {
            atcacert_def_t * cert_cfg = (atcacert_def_t*)obj_ptr->data;

            if (CKR_OK == read_cache)
            {
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
                uint8_t subj_public_key[PKCS11_MAX_ECC_RSA_PB_KEY_SIZE] = { 0 };
#else
                uint8_t subj_public_key[PKCS11_MAX_ECC_PB_KEY_SIZE] = { 0 };
#endif

                cal_buffer subj_pubkey = CAL_BUF_INIT(sizeof(subj_public_key), subj_public_key);

                if (ATCA_SUCCESS == (atcacert_get_subj_public_key(cert_cfg, NULL, 0, &subj_pubkey)))
                {
                    rv = pkcs11_attrib_fill(pAttribute, subj_public_key, (CK_ULONG)subj_pubkey.len);
                }
                else
                {
                    rv = CKR_DEVICE_ERROR;
                }
            }
            else
            {
                uint16_t key_id = ATCA_UINT16_HOST_TO_BE(cert_cfg->public_key_dev_loc.slot);
                rv = pkcs11_attrib_fill(pAttribute, &key_id, sizeof(uint16_t));
            }
        }
        else
        {
            rv = pkcs11_attrib_empty(pObject, pAttribute, NULL);
        }
    }
    return rv;
#else
    return pkcs11_attrib_empty(pObject, pAttribute, NULL);
#endif
}

/**
 * CKO_CERTIFICATE (Type: CKC_X_509) - X509 Public Key Certificate Model
 */
const pkcs11_attrib_model pkcs11_cert_x509public_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,                      pkcs11_object_get_class          },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,                      pkcs11_attrib_true               },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,                    pkcs11_token_get_access_type     },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,                 pkcs11_token_get_writable        },
    /** Description of the object(default empty). */
    { CKA_LABEL,                      pkcs11_object_get_name           },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,                   pkcs11_attrib_false              },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,                pkcs11_object_get_destroyable    },
    /** Type of certificate */
    { CKA_CERTIFICATE_TYPE,           pkcs11_cert_get_type             },
    /** The certificate can be trusted for the application that it was created. */
    { CKA_TRUSTED,                    pkcs11_cert_get_trusted_flag     },
    /** Default CK_CERTIFICATE_CATEGORY_UNSPECIFIED) */
    { CKA_CERTIFICATE_CATEGORY,       pkcs11_object_get_type           },
    /** Checksum */
    { CKA_CHECK_VALUE,                NULL_PTR                         },
    /** Start date for the certificate (default empty) */
    { CKA_START_DATE,                 pkcs11_get_issue_date            },
    /** End date for the certificate (default empty) */
    { CKA_END_DATE,                   pkcs11_get_expire_date           },
    /** ALL: DER-encoding of the SubjectPublicKeyInfo for the public key
       contained in this certificate (default empty)
       SubjectPublicKeyInfo ::= SEQUENCE {
       algorithm AlgorithmIdentifier,
       subjectPublicKey BIT_STRING } */
    { CKA_PUBLIC_KEY_INFO,            pkcs11_attrib_empty              },
    /** DER-encoded Certificate subject name */
    { CKA_SUBJECT,                    pkcs11_cert_get_subject          },
    /** Key identifier for public/private key pair (default empty) */
    { CKA_ID,                         pkcs11_cert_get_subj_key         },
    /** DER-encoded Certificate issuer name (default empty)*/
    { CKA_ISSUER,                     pkcs11_cert_get_issuer           },
    /** DER-encoding of the certificate serial number (default empty) */
    { CKA_SERIAL_NUMBER,              pkcs11_cert_get_serial_num       },
    /** BER-encoded Complete Certificate */
    { CKA_VALUE,                      pkcs11_cert_get_encoded          },
    /** If not empty this attribute gives the URL where the complete
       certificate can be obtained (default empty) */
    { CKA_URL,                        pkcs11_attrib_empty              },
    /** Hash of the subject public key (default empty). Hash algorithm is
       defined by CKA_NAME_HASH_ALGORITHM */
    { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, pkcs11_cert_get_subject_key_id   },
    /** Hash of the issuer public key (default empty). Hash algorithm is
       defined by CKA_NAME_HASH_ALGORITHM */
    { CKA_HASH_OF_ISSUER_PUBLIC_KEY,  pkcs11_cert_get_authority_key_id },
    /** Java MIDP security domain. (default CK_SECURITY_DOMAIN_UNSPECIFIED) */
    { CKA_JAVA_MIDP_SECURITY_DOMAIN,  NULL_PTR                         },
    /** Defines the mechanism used to calculate CKA_HASH_OF_SUBJECT_PUBLIC_KEY
       and CKA_HASH_OF_ISSUER_PUBLIC_KEY. If the attribute is not present then
       the type defaults to SHA-1. */
    { CKA_NAME_HASH_ALGORITHM,        pkcs11_attrib_empty              },
};

/* coverity[misra_c_2012_rule_5_1_violation:FALSE] C99 limit is 63 characters */
const CK_ULONG pkcs11_cert_x509public_attributes_count = (CK_ULONG)(PKCS11_UTIL_ARRAY_SIZE(pkcs11_cert_x509public_attributes));

/**
 * CKO_CERTIFICATE (Type: CKC_WTLS) - WTLS Public Key Certificate Model
 */
const pkcs11_attrib_model pkcs11_cert_wtlspublic_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,                      pkcs11_object_get_class        },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,                      pkcs11_attrib_true             },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,                    pkcs11_token_get_access_type   },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,                 NULL_PTR                       },
    /** Description of the object(default empty). */
    { CKA_LABEL,                      pkcs11_object_get_name         },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,                   pkcs11_attrib_false            },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,                pkcs11_object_get_destroyable  },
    /** Type of certificate */
    { CKA_CERTIFICATE_TYPE,           pkcs11_cert_get_type           },
    /** The certificate can be trusted for the application that it was created. */
    { CKA_TRUSTED,                    NULL_PTR                       },
    /** Default CK_CERTIFICATE_CATEGORY_UNSPECIFIED) */
    { CKA_CERTIFICATE_CATEGORY,       pkcs11_object_get_type         },
    /** Checksum */
    { CKA_CHECK_VALUE,                NULL_PTR                       },
    /** Start date for the certificate (default empty) */
    { CKA_START_DATE,                 pkcs11_attrib_empty            },
    /** End date for the certificate (default empty) */
    { CKA_END_DATE,                   pkcs11_attrib_empty            },
    /** ALL: DER-encoding of the SubjectPublicKeyInfo for the public key
       contained in this certificate (default empty)
       SubjectPublicKeyInfo ::= SEQUENCE {
       algorithm AlgorithmIdentifier,
       subjectPublicKey BIT_STRING } */
    { CKA_PUBLIC_KEY_INFO,            pkcs11_attrib_empty            },
    /** WTLS-encoded Certificate subject name */
    { CKA_SUBJECT,                    pkcs11_attrib_empty            },
    /** WTLS-encoded Certificate issuer name (default empty)*/
    { CKA_ISSUER,                     pkcs11_attrib_empty            },
    /** WTLS-encoded Complete Certificate */
    { CKA_VALUE,                      pkcs11_cert_get_encoded        },
    /** If not empty this attribute gives the URL where the complete
       certificate can be obtained (default empty) */
    { CKA_URL,                        pkcs11_attrib_empty            },
    /** Hash of the subject public key (default empty). Hash algorithm is
       defined by CKA_NAME_HASH_ALGORITHM */
    { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, pkcs11_cert_get_subject_key_id },
    /** Hash of the issuer public key (default empty). Hash algorithm is
       defined by CKA_NAME_HASH_ALGORITHM */
    { CKA_HASH_OF_ISSUER_PUBLIC_KEY,  pkcs11_attrib_empty            },
    /** Defines the mechanism used to calculate CKA_HASH_OF_SUBJECT_PUBLIC_KEY
       and CKA_HASH_OF_ISSUER_PUBLIC_KEY. If the attribute is not present then
       the type defaults to SHA-1. */
    { CKA_NAME_HASH_ALGORITHM,        pkcs11_attrib_empty            },
};

/* coverity[misra_c_2012_rule_5_1_violation:FALSE] C99 limit is 63 characters */
const CK_ULONG pkcs11_cert_wtlspublic_attributes_count = (CK_ULONG)(PKCS11_UTIL_ARRAY_SIZE(pkcs11_cert_wtlspublic_attributes));

/**
 * CKO_CERTIFICATE (Type: CKC_X_509_ATTR_CERT) - X509 Attribute Certificate Model
 */
const pkcs11_attrib_model pkcs11_cert_x509_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,                pkcs11_object_get_class       },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,                pkcs11_attrib_true            },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,              pkcs11_token_get_access_type  },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,           NULL_PTR                      },
    /** Description of the object(default empty). */
    { CKA_LABEL,                pkcs11_object_get_name        },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,             pkcs11_attrib_false           },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,          pkcs11_object_get_destroyable },
    /** Type of certificate */
    { CKA_CERTIFICATE_TYPE,     pkcs11_cert_get_type          },
    /** The certificate can be trusted for the application that it was created. */
    { CKA_TRUSTED,              NULL_PTR                      },
    /** Default CK_CERTIFICATE_CATEGORY_UNSPECIFIED) */
    { CKA_CERTIFICATE_CATEGORY, pkcs11_object_get_type        },
    /** Checksum */
    { CKA_CHECK_VALUE,          NULL_PTR                      },
    /** Start date for the certificate (default empty) */
    { CKA_START_DATE,           pkcs11_attrib_empty           },
    /** End date for the certificate (default empty) */
    { CKA_END_DATE,             pkcs11_attrib_empty           },
    /** ALL: DER-encoding of the SubjectPublicKeyInfo for the public key
       contained in this certificate (default empty)
       SubjectPublicKeyInfo ::= SEQUENCE {
       algorithm AlgorithmIdentifier,
       subjectPublicKey BIT_STRING } */
    { CKA_PUBLIC_KEY_INFO,      pkcs11_attrib_empty           },
    /** X509: DER-encoding of the attribute certificate's subject field. This
       is distinct from the CKA_SUBJECT attribute contained in CKC_X_509
       certificates because the ASN.1 syntax and encoding are different. */
    { CKA_OWNER,                pkcs11_attrib_empty           },
    /** X509: DER-encoding of the attribute certificate's issuer field. This
       is distinct from the CKA_ISSUER attribute contained in CKC_X_509
       certificates because the ASN.1 syntax and encoding are different.
       (default empty) */
    { CKA_AC_ISSUER,            pkcs11_attrib_empty           },
    /** DER-encoding of the certificate serial number (default empty) */
    { CKA_SERIAL_NUMBER,        pkcs11_attrib_empty           },
    /** X509: BER-encoding of a sequence of object identifier values corresponding
       to the attribute types contained in the certificate. When present, this
       field offers an opportunity for applications to search for a particular
       attribute certificate without fetching and parsing the certificate itself.
       (default empty) */
    { CKA_ATTR_TYPES,           pkcs11_attrib_empty           },
    /** BER-encoded Complete Certificate */
    { CKA_VALUE,                pkcs11_cert_get_encoded       },
};

const CK_ULONG pkcs11_cert_x509_attributes_count = (CK_ULONG)(PKCS11_UTIL_ARRAY_SIZE(pkcs11_cert_x509_attributes));

CK_RV pkcs11_cert_x509_write(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    ATCA_STATUS status;

    if (NULL == obj_ptr || NULL == pAttribute || NULL == pAttribute->pValue || pAttribute->type != CKA_VALUE)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
    {
#if ATCA_CA_SUPPORT
        status = (ATCA_STATUS)atcacert_write_cert_ext(pSession->slot->device_ctx, (atcacert_def_t*)obj_ptr->data, (uint8_t*)pAttribute->pValue,
                                                      pAttribute->ulValueLen);
#else
        status = ATCA_NO_DEVICES;
#endif
    }
    else
    {
#if ATCA_TA_SUPPORT
        ATCADevice device = pSession->slot->device_ctx;
        ta_handle_info handle_info;
        status = talib_info_get_handle_info(device, obj_ptr->slot, &handle_info);

        if ((ATCA_STATUS)TA_HANDLE_EXIST_ERROR == status)
        {
            /* Create a new handle */
            (void)talib_handle_init_data(&handle_info.attributes, (uint16_t)(pAttribute->ulValueLen & UINT16_MAX));
            status = talib_create_element_with_handle(device, obj_ptr->slot, &handle_info.attributes);
        }

        if (ATCA_SUCCESS == status)
        {
            cal_buffer sAttribute = CAL_BUF_INIT(pAttribute->ulValueLen, pAttribute->pValue);
            status = talib_write_X509_cert(device, obj_ptr->slot, &sAttribute);
        }
#else
        status = ATCA_NO_DEVICES;
#endif
    }

    if (ATCA_SUCCESS == status)
    {
        return CKR_OK;
    }
    else
    {
        return CKR_GENERAL_ERROR;
    }
}

/* Called from auth session to clear the certificate */
CK_RV pkcs11_cert_clear_session_cache(pkcs11_session_ctx_ptr session_ctx)
{
    CK_RV rv = CKR_GENERAL_ERROR;

    UNUSED_VAR(session_ctx);

#if defined(ATCA_HEAP) && (FEATURE_ENABLED == ATCACERT_INTEGRATION_EN)
    CK_ULONG i;

    for (i = 0; i < PKCS11_MAX_CERTS_CACHED; i++)
    {
        if (session_ctx == pkcs11_cert_cache_list[i].pSession_cert)
        {
            if (NULL != *pkcs11_cert_cache_list[i].pSession_cert_def->parsed)
            {
#if defined(ATCA_OPENSSL) || defined(ATCA_WOLFSSL) || defined(ATCA_MBEDTLS)
                atcac_x509_free(*pkcs11_cert_cache_list[i].pSession_cert_def->parsed);
#else
                pkcs11_os_free(*pkcs11_cert_cache_list[i].pSession_cert_def->parsed);
#endif
                *pkcs11_cert_cache_list[i].pSession_cert_def->parsed = NULL;
            }

            if (NULL != pkcs11_cert_cache_list[i].pSession_cert_def)
            {
                pkcs11_os_free(pkcs11_cert_cache_list[i].pSession_cert_def);
                pkcs11_cert_cache_list[i].pSession_cert_def = NULL;
            }

            if (NULL != pkcs11_cert_cache_list[i].cert_x509_parse.pValue)
            {
                pkcs11_os_free(pkcs11_cert_cache_list[i].cert_x509_parse.pValue);
                pkcs11_cert_cache_list[i].cert_x509_parse.pValue = NULL;
            }

            pkcs11_cert_cache_list[i].in_use = FALSE;
            pkcs11_cert_cache_list[i].pSession_cert = NULL;
            pkcs11_cert_cache_list[i].pObject_cert = NULL;
            rv = CKR_OK;
            break;
        }
    }
#endif

    return rv;
}

/* Called to free certificate object */
CK_RV pkcs11_cert_clear_object_cache(pkcs11_object_ptr pObject)
{
    CK_RV rv = CKR_GENERAL_ERROR;

    UNUSED_VAR(pObject);

#if defined(ATCA_HEAP) && (FEATURE_ENABLED == ATCACERT_INTEGRATION_EN)
    CK_ULONG i;
    atcacert_def_t *cert_def = pObject->data;

    for (i = 0; i < PKCS11_MAX_CERTS_CACHED; i++)
    {
        if (cert_def == pkcs11_cert_cache_list[i].pSession_cert_def)
        {
            if (NULL != *cert_def->parsed)
            {
#if defined(ATCA_OPENSSL) || defined (ATCA_WOLFSSL) || defined(ATCA_MBEDTLS)
                atcac_x509_free(*cert_def->parsed);
#else
                pkcs11_os_free(*cert_def->parsed);
#endif
                *cert_def->parsed = NULL;
            }

            if (NULL != pObject->data)
            {
                pkcs11_os_free(pObject->data);
                pObject->data = NULL;
            }

            if (NULL != pkcs11_cert_cache_list[i].cert_x509_parse.pValue)
            {
                pkcs11_os_free(pkcs11_cert_cache_list[i].cert_x509_parse.pValue);
                pkcs11_cert_cache_list[i].cert_x509_parse.pValue = NULL;
            }

            pkcs11_cert_cache_list[i].in_use = FALSE;
            pkcs11_cert_cache_list[i].pSession_cert = NULL;
            pkcs11_cert_cache_list[i].pObject_cert = NULL;
            pkcs11_cert_cache_list[i].pSession_cert_def = NULL;
            rv = CKR_OK;
            break;
        }
    }
#endif

    return rv;
}


/** @} */
