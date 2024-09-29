/**
 * \file
 * \brief PKCS11 Trust Platform Configuration
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
#include "pkcs11/pkcs11_object.h"
#include "pkcs11/pkcs11_slot.h"

#if defined(ATCA_TNGTLS_SUPPORT) || defined(ATCA_TNGLORA_SUPPORT) || defined(ATCA_TFLEX_SUPPORT)

#include "tng_root_cert.h"


static const char pkcs11_trust_device_label[] = "device";
static const char pkcs11_trust_signer_label[] = "signer";
static const char pkcs11_trust_root_label[] = "root";


/* Per PKCS11 ECDSA private keys must have a matching public key. It is
   consider best practice for these keys to have the same label and the
   library will create the matching public key object whenever a private
   key is specified in the configuration or is created with the genkey
   mechanism. However in a static configuration it is possible to
   circumvent this alignment by defining PKCS11_TNG_NONMATCHING_LABELS */
#ifdef PKCS11_TNG_NONMATCHING_LABELS
static const char pkcs11_trust_device_private_key_label[] = "device private";
static const char pkcs11_trust_device_public_key_label[] = "device public";
#else
static const char pkcs11_trust_device_private_key_label[] = "device";
static const char pkcs11_trust_device_public_key_label[] = "device";
#endif

/* Helper function to assign the proper fields to an certificate object from a cert def */
static CK_RV pkcs11_trust_config_cert(pkcs11_lib_ctx_ptr pLibCtx, pkcs11_slot_ctx_ptr pSlot, pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pLabel)
{
    CK_RV rv = CKR_OK;

    (void)pLibCtx;
    (void)pSlot;

    if ((NULL == pObject) || (NULL == pLabel))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (pLabel->ulValueLen >= PKCS11_MAX_LABEL_SIZE)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (0 == strncmp(pkcs11_trust_device_label, (char*)pLabel->pValue, pLabel->ulValueLen))
    {
        /* Slot 10 - Device Cert for Slot 0*/
        (void)pkcs11_config_init_cert(pObject, (char*)pLabel->pValue, pLabel->ulValueLen);
        pObject->slot = 10;
        pObject->flags |= PKCS11_OBJECT_FLAG_TRUST_TYPE;
        pObject->class_type = CK_CERTIFICATE_CATEGORY_TOKEN_USER;

    }
    else if (0 == strncmp(pkcs11_trust_signer_label, (char*)pLabel->pValue, pLabel->ulValueLen))
    {
        /* Slot 12 - Signer Cert for Slot 10 */
        (void)pkcs11_config_init_cert(pObject, (char*)pLabel->pValue, pLabel->ulValueLen);
        pObject->slot = 12;
        pObject->flags |= PKCS11_OBJECT_FLAG_TRUST_TYPE;
        pObject->class_type = CK_CERTIFICATE_CATEGORY_AUTHORITY;
    }
    else if (0 == strncmp(pkcs11_trust_root_label, (char*)pLabel->pValue, pLabel->ulValueLen))
    {
        /* Slot 12 - Signer Cert for Slot 10 */
        (void)pkcs11_config_init_cert(pObject, (char*)pLabel->pValue, pLabel->ulValueLen);
        pObject->slot = 0xFFFF;
        pObject->flags |= PKCS11_OBJECT_FLAG_TRUST_TYPE;
        /* coverity[cert_str30_c_violation] Implementation treats input attributes as constants */
        pObject->data = (CK_VOID_PTR)&g_cryptoauth_root_ca_002_cert;
        pObject->size = (CK_ULONG)g_cryptoauth_root_ca_002_cert_size;
        pObject->class_type = CK_CERTIFICATE_CATEGORY_AUTHORITY;
    }
    else
    {
        rv = CKR_ARGUMENTS_BAD;
    }

#if ATCA_CA_SUPPORT
    if (CKR_OK == rv)
    {
        pObject->config = &pSlot->cfg_zone;
    }
#endif


    return rv;
}

#if PKCS11_USE_STATIC_CONFIG
/* Helper function to assign the proper fields to a key object */
static CK_RV pkcs11_trust_config_key(pkcs11_lib_ctx_ptr pLibCtx, pkcs11_slot_ctx_ptr pSlot, pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pLabel)
{
    CK_RV rv = CKR_OK;

    (void)pLibCtx;

    if ((NULL == pObject) || (NULL == pLabel) || (NULL == pSlot))
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (pLabel->ulValueLen >= PKCS11_MAX_LABEL_SIZE)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (0 == strncmp(pkcs11_trust_device_private_key_label, (char*)pLabel->pValue, pLabel->ulValueLen))
    {
        /* slot 0 - Device Private Key */
        (void)pkcs11_config_init_private(pObject, pLabel->pValue, pLabel->ulValueLen);
        pObject->slot = 0;
        pObject->flags |= PKCS11_OBJECT_FLAG_TRUST_TYPE;
        pObject->config = &pSlot->cfg_zone;
    }
    else if (0 == strncmp(pkcs11_trust_device_public_key_label, (char*)pLabel->pValue, pLabel->ulValueLen))
    {
        /* slot 0 - Device Public Key */
        (void)pkcs11_config_init_public(pObject, pLabel->pValue, pLabel->ulValueLen);
        pObject->slot = 0;
        pObject->flags |= PKCS11_OBJECT_FLAG_TRUST_TYPE;
        pObject->config = &pSlot->cfg_zone;
    }
    else
    {
        rv = CKR_ARGUMENTS_BAD;
    }

    return rv;
}
#endif

CK_RV pkcs11_trust_load_objects(pkcs11_slot_ctx_ptr pSlot)
{
    pkcs11_object_ptr pObject;
    CK_RV rv = CKR_OK;
    CK_ATTRIBUTE xLabel;

    if (NULL == pSlot)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if (CKR_OK == rv)
    {
        rv = pkcs11_object_alloc(pSlot->slot_id, &pObject);
        if (NULL != pObject)
        {
            /* Slot 0 - Device Private Key */
            (void)pkcs11_config_init_private(pObject, pkcs11_trust_device_private_key_label, strlen(pkcs11_trust_device_private_key_label));
            pObject->slot = 0;
            pObject->flags |= PKCS11_OBJECT_FLAG_TRUST_TYPE;
            pObject->config = &pSlot->cfg_zone;
        }
    }

    if (CKR_OK == rv)
    {
        rv = pkcs11_object_alloc(pSlot->slot_id, &pObject);
        if (NULL != pObject)
        {
            /* Slot 0 - Device Public Key */
            (void)pkcs11_config_init_public(pObject, pkcs11_trust_device_public_key_label, strlen(pkcs11_trust_device_public_key_label));
            pObject->slot = 0;
            pObject->flags |= PKCS11_OBJECT_FLAG_TRUST_TYPE;
            pObject->config = &pSlot->cfg_zone;
        }
    }

    if (CKR_OK == rv)
    {
        rv = pkcs11_object_alloc(pSlot->slot_id, &pObject);
        if (NULL != pObject)
        {
            /* Device Certificate */
            /* coverity[cert_exp40_c_violation] Implementation treats input attributes as constants */
            /* coverity[cert_str30_c_violation] Implementation treats input attributes as constants */
            /* coverity[misra_c_2012_rule_11_8_violation] Implementation treats input attributes as constants */
            xLabel.pValue = (CK_VOID_PTR)pkcs11_trust_device_label;
            xLabel.ulValueLen = (CK_ULONG)strlen(pkcs11_trust_device_label);
            xLabel.type = CKA_LABEL;
            (void)pkcs11_trust_config_cert(NULL, pSlot, pObject, &xLabel);
        }
    }

    if (CKR_OK == rv)
    {
        rv = pkcs11_object_alloc(pSlot->slot_id, &pObject);
        if (NULL != pObject)
        {
            /* Signer Certificate */
            /* coverity[cert_exp40_c_violation] Implementation treats input attributes as constants */
            /* coverity[cert_str30_c_violation] Implementation treats input attributes as constants */
            /* coverity[misra_c_2012_rule_11_8_violation] Implementation treats input attributes as constants */
            xLabel.pValue = (CK_VOID_PTR)pkcs11_trust_signer_label;
            xLabel.ulValueLen = (CK_ULONG)strlen(pkcs11_trust_signer_label);
            xLabel.type = CKA_LABEL;
            (void)pkcs11_trust_config_cert(NULL, pSlot, pObject, &xLabel);
        }
    }

    return rv;
}

#if PKCS11_USE_STATIC_CONFIG
CK_RV pkcs11_config_cert(pkcs11_lib_ctx_ptr pLibCtx, pkcs11_slot_ctx_ptr pSlot, pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pLabel)
{
    return pkcs11_trust_config_cert(pLibCtx, pSlot, pObject, pLabel);
}

CK_RV pkcs11_config_key(pkcs11_lib_ctx_ptr pLibCtx, pkcs11_slot_ctx_ptr pSlot, pkcs11_object_ptr pObject, CK_ATTRIBUTE_PTR pLabel)
{
    return pkcs11_trust_config_key(pLibCtx, pSlot, pObject, pLabel);
}

CK_RV pkcs11_config_load_objects(pkcs11_slot_ctx_ptr pSlot)
{
    return pkcs11_trust_load_objects(pSlot);
}
#endif

#endif
