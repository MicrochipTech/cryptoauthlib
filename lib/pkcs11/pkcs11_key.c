/**
 * \file
 * \brief PKCS11 Library Key Object Handling
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
#include "crypto/atca_crypto_sw_sha1.h"

#include "pkcs11_config.h"
#include "pkcs11_debug.h"
#include "pkcs11_token.h"
#include "pkcs11_attrib.h"
#include "pkcs11_key.h"
#include "pkcs11_session.h"
#include "pkcs11_slot.h"
#include "pkcs11_util.h"
#include "pkcs11_os.h"


/**
 * \defgroup pkcs11 Key (pkcs11_key_)
   @{ */

static CK_RV pkcs11_key_get_derivekey_flag(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr && NULL != pSession)
    {
        if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
        {
        #if ATCA_CA_SUPPORT
            atecc508a_config_t * pConfig = (atecc508a_config_t*)obj_ptr->config;

            if (NULL == pConfig)
            {
                return CKR_GENERAL_ERROR;
            }

            if (ATCA_SLOT_CONFIG_ECDH_MASK == (ATCA_SLOT_CONFIG_ECDH_MASK & pConfig->SlotConfig[obj_ptr->slot]))
            {
                return pkcs11_attrib_true(NULL, pAttribute, NULL);
            }
            else
            {
                return pkcs11_attrib_false(NULL, pAttribute, NULL);
            }
        #endif
        }
        else
        {
            return pkcs11_attrib_false(NULL, pAttribute, NULL);
        }
    }

    return CKR_ARGUMENTS_BAD;
}

#if ATCA_TA_SUPPORT
static ATCA_STATUS pkcs11_ta_get_pubkey(CK_VOID_PTR pObject, uint8_t buffer[ATCA_ECCP256_PUBKEY_SIZE], pkcs11_session_ctx_ptr session_ctx)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    pkcs11_slot_ctx_ptr slot_ctx;
    CK_SLOT_ID owner_id;
    uint16_t auth_handle;
    uint16_t publickey_slot = 0;
    ATCA_STATUS status = ATCA_GEN_FAIL;
    ta_handle_info pubkey_field_handle_info;
    bool allowed = false;

    if (CKR_OK != pkcs11_object_get_owner(obj_ptr, &owner_id))
    {
        return ATCA_GEN_FAIL;
    }

    if (NULL == (slot_ctx = pkcs11_slot_get_context(NULL, owner_id)))
    {
        return ATCA_GEN_FAIL;
    }

    if (NULL == session_ctx || NULL == session_ctx->slot)
    {
        return ATCA_GEN_FAIL;
    }

    ATCADevice device = session_ctx->slot->device_ctx;

    /* Get the handle that is expected to be used for logging in */
    auth_handle = slot_ctx->user_pin_handle;

    /* Get the pubkey slot value from property of handleinfo */
    publickey_slot = TA_HANDLE_LINKED_SHARED_DATA | (obj_ptr->handle_info.property & TA_PROP_PUB_KEY_MASK);

    status = talib_info_get_handle_info(device, publickey_slot, &pubkey_field_handle_info);

    if (ATCA_SUCCESS == status)
    {
        /* If the Pub_Key field of the handleinfo references a valid public key, read the public key
           from the referenced handle */
        if ( ((pubkey_field_handle_info.attributes.element_CKA & TA_HANDLE_INFO_CLASS_MASK) == TA_CLASS_PUBLIC_KEY)
             && ((pubkey_field_handle_info.attributes.property & TA_PROP_ROOT_MASK) != TA_PROP_ROOT_MASK))
        {
            (void)talib_handle_can_read(device, auth_handle, &pubkey_field_handle_info.attributes, &allowed);
            if (allowed)
            {
                status = atcab_read_pubkey_ext(device, publickey_slot, buffer);
            }
            else
            {
                status = ATCA_GEN_FAIL;
            }
        }
        else
        {
            status = TA_HANDLE_EXIST_ERROR;
        }
    }

    /* Use the genkey feature to get the public key if handle does not exist or is not a valid public key */
    if (TA_HANDLE_EXIST_ERROR == status)
    {
        (void)talib_handle_can_use(device, auth_handle, &obj_ptr->handle_info, &allowed);
        if (allowed)
        {
            status = atcab_get_pubkey_ext(device, obj_ptr->slot, buffer);
        }
        else
        {
            status = ATCA_GEN_FAIL;
        }
    }

    return status;
}
#endif

static CK_RV pkcs11_key_get_local_flag(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr session_ctx)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr && NULL != session_ctx)
    {
        if (atcab_is_ca_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)))
        {
        #if ATCA_CA_SUPPORT
            atecc508a_config_t * pConfig = (atecc508a_config_t*)obj_ptr->config;

            if (NULL == pConfig)
            {
                return CKR_GENERAL_ERROR;
            }

            if (ATCA_SLOT_CONFIG_WRITE_CONFIG(2u) == (ATCA_SLOT_CONFIG_WRITE_CONFIG_MASK & pConfig->SlotConfig[obj_ptr->slot]))
            {
                return pkcs11_attrib_true(NULL, pAttribute, NULL);
            }
            else
            {
                return pkcs11_attrib_false(NULL, pAttribute, NULL);
            }
        #endif
        }
        else
        {
            return pkcs11_attrib_false(NULL, pAttribute, NULL);
        }
    }

    return CKR_ARGUMENTS_BAD;
}

#if 0
static CK_RV pkcs11_key_get_gen_mechanism(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    ((void)pObject);
    ((void)pAttribute);
    return CKR_FUNCTION_NOT_SUPPORTED;
}
#endif

static const CK_MECHANISM_TYPE pkcs11_key_508_public_mech[] = {
    CKM_ECDSA,
    CKM_ECDSA_SHA256
};

static const CK_MECHANISM_TYPE pkcs11_key_508_private_mech[] = {
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256
};

#if ATCA_CA_SUPPORT
static const CK_MECHANISM_TYPE pkcs11_key_508_secret_mech[] = {
    CKM_SHA256_HMAC,
//    CKM_SHA256_HMAC_GENERAL
};
#endif

static const CK_MECHANISM_TYPE pkcs11_key_608_secret_mech[] = {
    CKM_SHA256_HMAC,
//    CKM_SHA256_HMAC_GENERAL,
    CKM_AES_ECB,
    CKM_AES_CBC,
//    CKM_AES_CTR,
    CKM_AES_GCM,
//    CKM_AES_CCM,
//    CKM_AES_CMAC,
//    CKM_AES_CMAC_GENERAL,
//    CKM_AES_ECB_ENCRYPT_DATA,
//    CKM_AES_CBC_ENCRYPT_DATA
};

#if ATCA_CA_SUPPORT
static CK_RV pkcs11_key_fill_ca_mech(atecc508a_config_t* pConfig, uint16_t slot, CK_ATTRIBUTE_PTR pAttribute)
{
    CK_RV rv = CKR_GENERAL_ERROR;

    if (NULL != pConfig)
    {
        if (ATCA_KEY_CONFIG_KEY_TYPE(4u) == (ATCA_KEY_CONFIG_KEY_TYPE_MASK & pConfig->KeyConfig[slot]))
        {
            if (ATCA_KEY_CONFIG_PRIVATE_MASK == (ATCA_KEY_CONFIG_PRIVATE_MASK & pConfig->KeyConfig[slot]))
            {
                rv = pkcs11_attrib_fill(pAttribute, pkcs11_key_508_private_mech,
                                        (CK_ULONG)sizeof(pkcs11_key_508_private_mech));
            }
            else
            {
                rv = pkcs11_attrib_fill(pAttribute, pkcs11_key_508_public_mech,
                                        (CK_ULONG)sizeof(pkcs11_key_508_public_mech));
            }
        }
        else
        {
            switch (((uint8_t*)&pConfig->RevNum)[2])
            {
            case 0x60:
                rv = pkcs11_attrib_fill(pAttribute, pkcs11_key_608_secret_mech,
                                        (CK_ULONG)sizeof(pkcs11_key_608_secret_mech));
                break;
            case 0x50:
                rv = pkcs11_attrib_fill(pAttribute, pkcs11_key_508_secret_mech,
                                        (CK_ULONG)sizeof(pkcs11_key_508_secret_mech));
                break;
            default:
                /* Do nothing */
                break;
            }
        }
    }

    return rv;
}
#endif

#if ATCA_TA_SUPPORT
static CK_RV pkcs11_key_fill_ta_mech(pkcs11_object_ptr obj_ptr, CK_ATTRIBUTE_PTR pAttribute)
{
    CK_RV rv = CKR_GENERAL_ERROR;

    switch (obj_ptr->class_id)
    {
    case CKO_PRIVATE_KEY:
        rv = pkcs11_attrib_fill(pAttribute, pkcs11_key_508_private_mech,
                                (CK_ULONG)sizeof(pkcs11_key_508_private_mech));
        break;
    case CKO_PUBLIC_KEY:
        rv = pkcs11_attrib_fill(pAttribute, pkcs11_key_508_public_mech,
                                (CK_ULONG)sizeof(pkcs11_key_508_public_mech));
        break;
    case CKO_SECRET_KEY:
        rv = pkcs11_attrib_fill(pAttribute, pkcs11_key_608_secret_mech,
                                (CK_ULONG)sizeof(pkcs11_key_608_secret_mech));
        break;
    default:
        /* Do nothing */
        break;
    }
    return rv;
}
#endif


static CK_RV pkcs11_key_get_allowed_mechanisms(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr session_ctx)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != session_ctx)
    {
        ATCADeviceType devtype = atcab_get_device_type_ext(session_ctx->slot->device_ctx);
#if ATCA_CA_SUPPORT
        if (atcab_is_ca_device(devtype))
        {
            rv = pkcs11_key_fill_ca_mech((atecc508a_config_t*)obj_ptr->config, obj_ptr->slot, pAttribute);
        }
#endif
#if ATCA_TA_SUPPORT
        if (atcab_is_ta_device(devtype))
        {
            rv = pkcs11_key_fill_ta_mech(obj_ptr, pAttribute);
        }
#endif
    }

    return rv;
}

/** ASN.1 Header for SECP256R1 public keys */
static const uint8_t ec_pubkey_asn1_header[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
    0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00, 0x04
};

/** X.962 ASN.1 Header for EC public keys */
static const uint8_t ec_x962_asn1_header[] = {
    0x04, 0x41, 0x04
};

/**
 * \brief Extract a public key and convert it to the asn.1 format
 */
static CK_RV pkcs11_key_get_public_key(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr session_ctx)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != session_ctx)
    {
        CK_BBOOL is_private = false;

        if (CKR_OK == (rv = pkcs11_object_is_private(obj_ptr, &is_private, session_ctx)))
        {
            CK_UTF8CHAR ec_asn1_key[sizeof(ec_pubkey_asn1_header) + ATCA_ECCP256_PUBKEY_SIZE];
            ATCA_STATUS status = ATCA_GEN_FAIL;

            (void)memcpy(ec_asn1_key, ec_pubkey_asn1_header, sizeof(ec_pubkey_asn1_header));


            if (is_private)
            {
                ATCADeviceType dev_type = atcab_get_device_type_ext(session_ctx->slot->device_ctx);

                if (atcab_is_ca_device(dev_type))
                {
#if ATCA_CA_SUPPORT
                    status = atcab_get_pubkey_ext(session_ctx->slot->device_ctx, obj_ptr->slot, &ec_asn1_key[sizeof(ec_pubkey_asn1_header)]);
                    PKCS11_DEBUG("atcab_get_pubkey: %x\r\n", status);
#endif
                }
                else if (atcab_is_ta_device(dev_type))
                {
#if ATCA_TA_SUPPORT
                    status = pkcs11_ta_get_pubkey(pObject, &ec_asn1_key[sizeof(ec_pubkey_asn1_header)], session_ctx);
#endif
                }
                else
                {
                    /* do nothing */
                }
            }
            else
            {
                status = atcab_read_pubkey_ext(session_ctx->slot->device_ctx, obj_ptr->slot, &ec_asn1_key[sizeof(ec_pubkey_asn1_header)]);
                PKCS11_DEBUG("atcab_read_pubkey: %x\r\n", status);

            }

            if (ATCA_SUCCESS == status)
            {
                rv = pkcs11_attrib_fill(pAttribute, ec_asn1_key, (CK_ULONG)sizeof(ec_asn1_key));
            }
            else
            {
                (void)pkcs11_attrib_empty(pObject, pAttribute, NULL);
                PKCS11_DEBUG("Couldnt generate public key\r\n", status);
                rv = CKR_OK;

            }
        }
    }

    return rv;
}

static const uint8_t pkcs11_key_ec_params[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

static CK_RV pkcs11_key_get_ec_params(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    ((void)pObject);
    ((void)psession);

    return pkcs11_attrib_fill(pAttribute, pkcs11_key_ec_params, (CK_ULONG)sizeof(pkcs11_key_ec_params));
}

static CK_RV pkcs11_key_get_ec_point(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != psession)
    {
        ATCA_STATUS status = ATCA_SUCCESS;
        CK_UTF8CHAR ec_asn1_key[3 + ATCA_ECCP256_PUBKEY_SIZE] = { 0x04, 0x41, 0x04, 0x0,  0x0,  0x0, 0x0, 0x0,
                                                                  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0,
                                                                  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0,
                                                                  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0,
                                                                  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0,
                                                                  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0,
                                                                  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0,
                                                                  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0, 0x0,
                                                                  0x0,  0x0,  0x0 };

        if (NULL != pAttribute->pValue)
        {
            CK_BBOOL is_private;

            if (CKR_OK == (rv = pkcs11_object_is_private(obj_ptr, &is_private, psession)))
            {
                if (is_private)
                {
                    ATCADeviceType dev_type = atcab_get_device_type_ext(psession->slot->device_ctx);

                    if (atcab_is_ca_device(dev_type))
                    {
#if ATCA_CA_SUPPORT
                        status = atcab_get_pubkey_ext(psession->slot->device_ctx, obj_ptr->slot, &ec_asn1_key[3]);
                        PKCS11_DEBUG("atcab_get_pubkey: %x\r\n", status);
#endif
                    }
                    else if (atcab_is_ta_device(dev_type))
                    {
#if ATCA_TA_SUPPORT
                        status = pkcs11_ta_get_pubkey(pObject, &ec_asn1_key[3], psession);
#endif
                    }
                    else
                    {
                        /* do nothing */
                    }
                }
                else
                {
                    status = atcab_read_pubkey_ext(psession->slot->device_ctx, obj_ptr->slot, &ec_asn1_key[3]);
                    PKCS11_DEBUG("atcab_read_pubkey: %x\r\n", status);

                }
            }
        }

        if (ATCA_SUCCESS == status)
        {
            rv = pkcs11_attrib_fill(pAttribute, ec_asn1_key, (CK_ULONG)sizeof(ec_asn1_key));
        }
        else
        {
            (void)pkcs11_attrib_empty(pObject, pAttribute, NULL);
            PKCS11_DEBUG("Couldnt generate public key\r\n", status);
            rv = CKR_OK;
        }
    }

    return rv;
}

static CK_RV pkcs11_key_get_secret(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession)
{
    ((void)pSession);
#if ATCA_CA_SUPPORT
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr)
    {
        return pkcs11_attrib_fill(pAttribute, (const CK_VOID_PTR)obj_ptr->data, obj_ptr->size);
    }
    else
    {
        return CKR_ARGUMENTS_BAD;
    }
#else
    return pkcs11_attrib_empty(pObject, pAttribute, NULL);
#endif
}

static CK_RV pkcs11_key_get_secret_length(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession)
{
    ((void)pSession);
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr)
    {
        return pkcs11_attrib_fill(pAttribute, &obj_ptr->size, (CK_ULONG)sizeof(CK_ULONG));
    }
    else
    {
        return CKR_ARGUMENTS_BAD;
    }
}

static CK_RV pkcs11_key_get_check_value(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr pSession)
{
    ((void)pObject);
    ((void)pSession);
    return pkcs11_attrib_empty(NULL, pAttribute, NULL);
#if 0
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (obj_ptr)
    {
        uint8_t sha1_digest[ATCA_SHA1_DIGEST_SIZE];
        if (ATCA_SUCCESS == atcac_sw_sha1(obj_ptr->data, obj_ptr->size, sha1_digest))
        {
            return pkcs11_attrib_fill(pAttribute, sha1_digest, 3);
        }
        else
        {
            return CKR_GENERAL_ERROR;
        }
    }
    else
    {
        return CKR_ARGUMENTS_BAD;
    }
#endif
}

static CK_RV pkcs11_key_auth_required(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr session_ctx)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != session_ctx)
    {
        if (atcab_is_ca_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)))
        {
#if ATCA_CA_SUPPORT
            ((void)pAttribute);
#endif
        }
        else
        {
#if ATCA_TA_SUPPORT
            if (TA_PERM_ALWAYS != (obj_ptr->handle_info.permission & TA_PERM_USAGE_MASK) >> TA_PERM_USAGE_SHIFT)
            {
                rv = pkcs11_attrib_true(pObject, pAttribute, NULL);
            }
            else
            {
                rv = pkcs11_attrib_false(pObject, pAttribute, NULL);
            }
#endif
        }
    }
    return rv;
}

static CK_RV pkcs11_key_get_id(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr session_ctx)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != session_ctx)
    {
#if PKCS11_AUTO_ID_ENABLE
        if (NULL != pAttribute->pValue)
        {
            CK_BBOOL is_private;

            if (CKR_OK == (rv = pkcs11_object_is_private(obj_ptr, &is_private, session_ctx)))
            {
                ATCA_STATUS status = ATCA_GEN_FAIL;
                uint8_t buffer[1 + ATCA_ECCP256_PUBKEY_SIZE] = { 0x0 };
                buffer[0] = 0x04;

                if (is_private)
                {
                    ATCADeviceType dev_type = atcab_get_device_type_ext(session_ctx->slot->device_ctx);
                    if (atcab_is_ca_device(dev_type))
                    {
#if ATCA_CA_SUPPORT
                        status = atcab_get_pubkey_ext(session_ctx->slot->device_ctx, obj_ptr->slot, &buffer[1]);
                        PKCS11_DEBUG("atcab_get_pubkey: %x\r\n", status);
#endif
                    }
                    else if (atcab_is_ta_device(dev_type))
                    {
#if ATCA_TA_SUPPORT
                        status = pkcs11_ta_get_pubkey(pObject, &buffer[1], session_ctx);
#endif
                    }
                    else
                    {
                        /* do nothing */
                    }
                }
                else
                {
                    status = atcab_read_pubkey_ext(session_ctx->slot->device_ctx, obj_ptr->slot, &buffer[1]);
                    PKCS11_DEBUG("atcab_read_pubkey: %x\r\n", status);
                }

                if (ATCA_SUCCESS == status)
                {
                    status = (ATCA_STATUS)atcac_sw_sha1(buffer, sizeof(buffer), buffer);
                }

                if (ATCA_SUCCESS == status)
                {
                    rv = pkcs11_attrib_fill(pAttribute, buffer, ATCA_SHA1_DIGEST_SIZE);
                }
                else
                {
                    (void)pkcs11_attrib_empty(pObject, pAttribute, NULL);
                    PKCS11_DEBUG("Couldnt generate public key\r\n", status);
                    rv = CKR_OK;
                }
            }
        }
        else
        {
            rv = pkcs11_attrib_fill(pAttribute, NULL, ATCA_SHA1_DIGEST_SIZE);
        }
#else
        uint16_t key_id = ATCA_UINT16_HOST_TO_BE(obj_ptr->slot);
        rv = pkcs11_attrib_fill(pAttribute, &key_id, sizeof(uint16_t));
#endif
    }
    return rv;
}

/**
 * CKO_PUBLIC_KEY - Public Key Object Model
 */
const pkcs11_attrib_model pkcs11_key_public_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,              pkcs11_object_get_class                                                                                                                                                                                                           },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,              pkcs11_attrib_true                                                                                                                                                                                                                },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,            pkcs11_attrib_false                                                                                                                                                                                                               },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,         pkcs11_token_get_writable                                                                                                                                                                                                         },
    /** Description of the object(default empty). */
    { CKA_LABEL,              pkcs11_object_get_name                                                                                                                                                                                                            },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,           pkcs11_attrib_false                                                                                                                                                                                                               },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,        pkcs11_object_get_destroyable                                                                                                                                                                                                     },
    /** Type of key */
    { CKA_KEY_TYPE,           pkcs11_object_get_type                                                                                                                                                                                                            },
    /** Key identifier for key (default empty) */
    { CKA_ID,                 pkcs11_key_get_id                                                                                                                                                                                                                 },
    /** Start date for the key (default empty) */
    { CKA_START_DATE,         pkcs11_attrib_empty                                                                                                                                                                                                               },
    /** End date for the key (default empty) */
    { CKA_END_DATE,           pkcs11_attrib_empty                                                                                                                                                                                                               },
    /** CK_TRUE if key supports key derivation (i.e., if other keys can be derived from this one (default CK_FALSE) */
    { CKA_DERIVE,             pkcs11_key_get_derivekey_flag                                                                                                                                                                                                     },
    /** CK_TRUE only if key was either generated locally (i.e., on the token)
       with a C_GenerateKey or C_GenerateKeyPair call created with a C_CopyObject
       call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE */
    { CKA_LOCAL,              pkcs11_attrib_true                                                                                                                                                                                                                },
    /** Identifier of the mechanism used to generate the key material. */
    { CKA_KEY_GEN_MECHANISM,  NULL_PTR                                                                                                                                                                                                                          },
    /** A list of mechanisms allowed to be used with this key. The number of
       mechanisms in the array is the ulValueLen component of the attribute
       divided by the size of CK_MECHANISM_TYPE. */
    { CKA_ALLOWED_MECHANISMS, pkcs11_key_get_allowed_mechanisms                                                                                                                                                                                                 },
    /** DER-encoding of the key subject name (default empty) */
    { CKA_SUBJECT,            pkcs11_attrib_empty                                                                                                                                                                                                               },
    /** CK_TRUE if key supports encryption */
    { CKA_ENCRYPT,            NULL_PTR                                                                                                                                                                                                                          },
    /** CK_TRUE if key supports verification where the signature is an appendix to the data */
    { CKA_VERIFY,             pkcs11_attrib_true                                                                                                                                                                                                                },
    /** CK_TRUE if key supports verification where the data is recovered from the signature */
    { CKA_VERIFY_RECOVER,     NULL_PTR                                                                                                                                                                                                                          },
    /** CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys) */
    { CKA_WRAP,               NULL_PTR                                                                                                                                                                                                                          },
    /** The key can be trusted for the application that it was created. The
        wrapping key can be used to wrap keys with CKA_WRAP_WITH_TRUSTED set
        to CK_TRUE. */
    { CKA_TRUSTED,            NULL_PTR                                                                                                                                                                                                                          },
    /** For wrapping keys. The attribute template to match against any keys
        wrapped using this wrapping key. Keys that do not match cannot be
        wrapped. The number of attributes in the array is the ulValueLen
        component of the attribute divided by the size of CK_ATTRIBUTE. */
    { CKA_WRAP_TEMPLATE,      NULL_PTR                                                                                                                                                                                                                          },
    /** DER-encoding of the SubjectPublicKeyInfo for this public key.
        (MAY be empty, DEFAULT derived from the underlying public key data)
        SubjectPublicKeyInfo ::= SEQUENCE {
            algorithm AlgorithmIdentifier,
            subjectPublicKey BIT_STRING } */
    { CKA_PUBLIC_KEY_INFO,    pkcs11_key_get_public_key                                                                                                                                                                                                         },

    /** DER - encoding of an ANSI X9.62 Parameters value
        Parameters ::= CHOICE {
            ecParameters ECParameters,
            namedCurve CURVES.&id({CurveNames}),
            implicitlyCA NULL } */
    { CKA_EC_PARAMS,          pkcs11_key_get_ec_params                                                                                                                                                                                                          },
    /** DER - encoding of ANSI X9.62 ECPoint value Q */
    { CKA_EC_POINT,           pkcs11_key_get_ec_point                                                                                                                                                                                                           },
};

const CK_ULONG pkcs11_key_public_attributes_count = (CK_ULONG)(PKCS11_UTIL_ARRAY_SIZE(pkcs11_key_public_attributes));

#if 0
/**
 * CKO_PUBLIC_KEY (Type: CKK_EC) - EC/ECDSA Public Key Object Model
 */
const pkcs11_attrib_model pkcs11_key_ec_public_attributes[] = {
    /** DER - encoding of an ANSI X9.62 Parameters value
        Parameters ::= CHOICE {
            ecParameters ECParameters,
            namedCurve CURVES.&id({CurveNames}),
            implicitlyCA NULL } */
    { CKA_EC_PARAMS, pkcs11_key_get_ec_params                              },
    /** DER - encoding of ANSI X9.62 ECPoint value Q */
    { CKA_EC_POINT,  pkcs11_key_get_ec_point                               },
};
#endif
/**
 * CKO_PRIVATE_KEY - Private Key Object Base Model
 */
const pkcs11_attrib_model pkcs11_key_private_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,               pkcs11_object_get_class                                                                                                                                                                                                                                       },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,               pkcs11_attrib_true                                                                                                                                                                                                                                            },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,             pkcs11_attrib_true                                                                                                                                                                                                                                            },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,          pkcs11_token_get_writable                                                                                                                                                                                                                                     },
    /** Description of the object(default empty). */
    { CKA_LABEL,               pkcs11_object_get_name                                                                                                                                                                                                                                        },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,            pkcs11_attrib_false                                                                                                                                                                                                                                           },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,         pkcs11_object_get_destroyable                                                                                                                                                                                                                                 },
    /** Type of key */
    { CKA_KEY_TYPE,            pkcs11_object_get_type                                                                                                                                                                                                                                        },
    /** Key identifier for key (default empty) */
    { CKA_ID,                  pkcs11_key_get_id                                                                                                                                                                                                                                             },
    /** Start date for the key (default empty) */
    { CKA_START_DATE,          pkcs11_attrib_empty                                                                                                                                                                                                                                           },
    /** End date for the key (default empty) */
    { CKA_END_DATE,            pkcs11_attrib_empty                                                                                                                                                                                                                                           },
    /** CK_TRUE if key supports key derivation (i.e., if other keys can be derived from this one (default CK_FALSE) */
    { CKA_DERIVE,              pkcs11_key_get_derivekey_flag                                                                                                                                                                                                                                 },
    /** CK_TRUE only if key was either generated locally (i.e., on the token)
       with a C_GenerateKey or C_GenerateKeyPair call created with a C_CopyObject
       call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE */
    { CKA_LOCAL,               pkcs11_key_get_local_flag                                                                                                                                                                                                                                     },
    /** Identifier of the mechanism used to generate the key material. */
    { CKA_KEY_GEN_MECHANISM,   NULL_PTR                                                                                                                                                                                                                                                      },
    /** A list of mechanisms allowed to be used with this key. The number of
       mechanisms in the array is the ulValueLen component of the attribute
       divided by the size of CK_MECHANISM_TYPE. */
    { CKA_ALLOWED_MECHANISMS,  pkcs11_key_get_allowed_mechanisms                                                                                                                                                                                                                             },
    /** DER-encoding of the key subject name (default empty) */
    { CKA_SUBJECT,             pkcs11_attrib_empty                                                                                                                                                                                                                                           },
    /** CK_TRUE if key is sensitive */
    { CKA_SENSITIVE,           pkcs11_token_get_access_type                                                                                                                                                                                                                                  },
    /** CK_TRUE if key supports decryption */
    { CKA_DECRYPT,             NULL_PTR                                                                                                                                                                                                                                                      },
    /** CK_TRUE if key supports signatures where the signature is an appendix to the data */
    { CKA_SIGN,                pkcs11_attrib_true                                                                                                                                                                                                                                            },
    /** CK_TRUE if key supports signatures where the data can be recovered from the signature9 */
    { CKA_SIGN_RECOVER,        NULL_PTR                                                                                                                                                                                                                                                      },
    /** CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys)9 */
    { CKA_UNWRAP,              NULL_PTR                                                                                                                                                                                                                                                      },
    /** CK_TRUE if key is extractable and can be wrapped */
    { CKA_EXTRACTABLE,         pkcs11_attrib_false                                                                                                                                                                                                                                           },
    /** CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE */
    { CKA_ALWAYS_SENSITIVE,    pkcs11_token_get_access_type                                                                                                                                                                                                                                  },
    /** CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE */
    { CKA_NEVER_EXTRACTABLE,   pkcs11_token_get_access_type                                                                                                                                                                                                                                  },
    /** CK_TRUE if the key can only be wrapped with a wrapping key that has CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE. */
    { CKA_WRAP_WITH_TRUSTED,   NULL_PTR                                                                                                                                                                                                                                                      },
    /** For wrapping keys. The attribute template to match against any keys
        wrapped using this wrapping key. Keys that do not match cannot be
        wrapped. The number of attributes in the array is the ulValueLen
        component of the attribute divided by the size of CK_ATTRIBUTE. */
    { CKA_UNWRAP_TEMPLATE,     NULL_PTR                                                                                                                                                                                                                                                      },
    /** If CK_TRUE, the user has to  supply the PIN for each use (sign or decrypt) with the key. Default is CK_FALSE. */
    { CKA_ALWAYS_AUTHENTICATE, pkcs11_key_auth_required                                                                                                                                                                                                                                      },
    /** DER-encoding of the SubjectPublicKeyInfo for the associated public key
        (MAY be empty; DEFAULT derived from the underlying private key data;
        MAY be manually set for specific key types; if set; MUST be consistent
        with the underlying private key data)   */
    { CKA_PUBLIC_KEY_INFO,     pkcs11_key_get_public_key                                                                                                                                                                                                                                     },
    /** DER - encoding of an ANSI X9.62 Parameters value
        Parameters ::= CHOICE {
            ecParameters ECParameters,
            namedCurve CURVES.&id({CurveNames}),
            implicitlyCA NULL } */
    { CKA_EC_PARAMS,           pkcs11_key_get_ec_params                                                                                                                                                                                                                                      },
    /** DER - encoding of ANSI X9.62 ECPoint value Q */
    { CKA_EC_POINT,            pkcs11_key_get_ec_point                                                                                                                                                                                                                                       },
    /** The value of the private key should remain private.  A NULL function pointer is interpreted as a sensitive attribute. */
    { CKA_VALUE,               NULL_PTR                                                                                                                                                                                                                                                      },
};

const CK_ULONG pkcs11_key_private_attributes_count = (CK_ULONG)(PKCS11_UTIL_ARRAY_SIZE(pkcs11_key_private_attributes));


#if 0
/**
 * CKO_PRIVATE_KEY (Type: CKK_RSA) - RSA Private Key Object Model
 */
const pkcs11_attrib_model pkcs11_key_rsa_private_attributes[] = {
    /** Big integer Modulus n */
    { CKA_MODULUS,          NULL_PTR                                                                                                                },
    /** Big integer Public exponent e */
    { CKA_PUBLIC_EXPONENT,  NULL_PTR                                                                                                                },
    /** Big integer Private exponent d */
    { CKA_PRIVATE_EXPONENT, NULL_PTR                                                                                                                },
    /** Big integer Prime p */
    { CKA_PRIME_1,          NULL_PTR                                                                                                                },
    /** Big integer Prime q */
    { CKA_PRIME_2,          NULL_PTR                                                                                                                },
    /** Big integer Private exponent d modulo p - 1 */
    { CKA_EXPONENT_1,       NULL_PTR                                                                                                                },
    /** Big integer Private exponent d modulo q - 1 */
    { CKA_EXPONENT_2,       NULL_PTR                                                                                                                },
    /** Big integer CRT coefficient q - 1 mod p */
    { CKA_COEFFICIENT,      NULL_PTR                                                                                                                },
};

/**
 * CKO_PRIVATE_KEY (Type: CKK_EC) - EC/ECDSA Public Key Object Model
 */
const pkcs11_attrib_model pkcs11_key_ec_private_attributes[] = {
    /** DER - encoding of an ANSI X9.62 Parameters value
        Parameters ::= CHOICE {
            ecParameters ECParameters,
            namedCurve CURVES.&id({CurveNames}),
            implicitlyCA NULL } */
    { CKA_EC_PARAMS, pkcs11_key_get_ec_params                              },
    /** DER - encoding of ANSI X9.62 ECPoint value Q */
    { CKA_EC_POINT,  pkcs11_key_get_ec_point                               },
};
#endif

/**
 * CKO_SECRET_KEY - Secret Key Object Base Model
 */
const pkcs11_attrib_model pkcs11_key_secret_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,              pkcs11_object_get_class                                                                                                                                                                                                    },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,              pkcs11_token_get_storage                                                                                                                                                                                                   },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,            pkcs11_token_get_access_type                                                                                                                                                                                               },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,         pkcs11_token_get_writable                                                                                                                                                                                                  },
    /** Description of the object(default empty). */
    { CKA_LABEL,              pkcs11_object_get_name                                                                                                                                                                                                     },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,           pkcs11_attrib_false                                                                                                                                                                                                        },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,        pkcs11_object_get_destroyable                                                                                                                                                                                              },
    /** Type of key */
    { CKA_KEY_TYPE,           pkcs11_object_get_type                                                                                                                                                                                                     },
    /** Key identifier for key (default empty) */
    { CKA_ID,                 pkcs11_attrib_empty                                                                                                                                                                                                        },
    /** Start date for the key (default empty) */
    { CKA_START_DATE,         pkcs11_attrib_empty                                                                                                                                                                                                        },
    /** End date for the key (default empty) */
    { CKA_END_DATE,           pkcs11_attrib_empty                                                                                                                                                                                                        },
    /** CK_TRUE if key supports key derivation (i.e., if other keys can be derived from this one (default CK_FALSE) */
    { CKA_DERIVE,             pkcs11_attrib_true                                                                                                                                                                                                         },
    /** CK_TRUE only if key was either generated locally (i.e., on the token)
       with a C_GenerateKey or C_GenerateKeyPair call created with a C_CopyObject
       call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE */
    { CKA_LOCAL,              pkcs11_key_get_local_flag                                                                                                                                                                                                  },
    /** Identifier of the mechanism used to generate the key material. */
    { CKA_KEY_GEN_MECHANISM,  NULL_PTR                                                                                                                                                                                                                   },
    /** A list of mechanisms allowed to be used with this key. The number of
       mechanisms in the array is the ulValueLen component of the attribute
       divided by the size of CK_MECHANISM_TYPE. */
    { CKA_ALLOWED_MECHANISMS, pkcs11_key_get_allowed_mechanisms                                                                                                                                                                                          },
    /** CK_TRUE if key is sensitive */
    { CKA_SENSITIVE,          pkcs11_token_get_access_type                                                                                                                                                                                               },
    /** CK_TRUE if key supports encryption */
    { CKA_ENCRYPT,            NULL_PTR                                                                                                                                                                                                                   },
    /** CK_TRUE if key supports decryption */
    { CKA_DECRYPT,            NULL_PTR                                                                                                                                                                                                                   },
    /** CK_TRUE if key supports signatures (i.e., authentication codes) where
        the signature is an appendix to the data */
    { CKA_SIGN,               NULL_PTR                                                                                                                                                                                                                   },
    /** CK_TRUE if key supports verification (i.e., of authentication codes)
        where the signature is an appendix to the data */
    { CKA_VERIFY,             NULL_PTR                                                                                                                                                                                                                   },
    /** CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys)  */
    { CKA_WRAP,               NULL_PTR                                                                                                                                                                                                                   },
    /** CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys) */
    { CKA_UNWRAP,             NULL_PTR                                                                                                                                                                                                                   },
    /** CK_TRUE if key is extractable and can be wrapped */
    { CKA_EXTRACTABLE,        pkcs11_attrib_false                                                                                                                                                                                                        },
    /** CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE */
    { CKA_ALWAYS_SENSITIVE,   pkcs11_token_get_access_type                                                                                                                                                                                               },
    /** CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE  */
    { CKA_NEVER_EXTRACTABLE,  pkcs11_token_get_access_type                                                                                                                                                                                               },
    /** Key checksum */
    { CKA_CHECK_VALUE,        pkcs11_key_get_check_value                                                                                                                                                                                                 },
    /** CK_TRUE if the key can only be wrapped with a wrapping key that has CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE. */
    { CKA_WRAP_WITH_TRUSTED,  NULL_PTR                                                                                                                                                                                                                   },
    /**  The wrapping key can be used to wrap keys with CKA_WRAP_WITH_TRUSTED set to CK_TRUE. */
    { CKA_TRUSTED,            NULL_PTR                                                                                                                                                                                                                   },
    /** For wrapping keys. The attribute template to match against any keys
        wrapped using this wrapping key. Keys that do not match cannot be
        wrapped. The number of attributes in the array is the ulValueLen
        component of the attribute divided by the size of CK_ATTRIBUTE */
    { CKA_WRAP_TEMPLATE,      NULL_PTR                                                                                                                                                                                                                   },
    /** For wrapping keys. The attribute template to apply to any keys unwrapped
        using this wrapping key. Any user supplied template is applied after
        this template as if the object has already been created. The number of
        attributes in the array is the ulValueLen component of the attribute
        divided by the size of CK_ATTRIBUTE.  */
    { CKA_UNWRAP_TEMPLATE,    NULL_PTR                                                                                                                                                                                                                   },
    /* Key value */
    { CKA_VALUE,              pkcs11_key_get_secret                                                                                                                                                                                                      },
    /* Length in bytes of the key */
    { CKA_VALUE_LEN,          pkcs11_key_get_secret_length                                                                                                                                                                                               },
};

const CK_ULONG pkcs11_key_secret_attributes_count = (CK_ULONG)(PKCS11_UTIL_ARRAY_SIZE(pkcs11_key_secret_attributes));


static CK_RV pkcs11_key_privwrite_ca(CK_VOID_PTR pSession, pkcs11_object_ptr pObject, CK_VOID_PTR pValue, CK_ULONG ulValueLen)
{

    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != pSession && NULL != pObject && NULL != pValue && 0u != ulValueLen)
    {
        pkcs11_session_ctx_ptr session_ctx = (pkcs11_session_ctx_ptr)pSession;
        if (atcab_is_ca_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)))
        {
#if ATCA_CA_SUPPORT
            uint8_t key_buf[36] = { 0 };
            uint8_t num_in[32] = { 0, 1, 2, 3, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0, };

            atecc508a_config_t* cfg_ptr = (atecc508a_config_t*)pObject->config;

            uint16_t write_key_id = cfg_ptr->SlotConfig[pObject->slot];
            write_key_id &= ATCA_SLOT_CONFIG_WRITE_KEY_MASK;
            write_key_id >>= ATCA_SLOT_CONFIG_WRITE_KEY_SHIFT;

            (void)memcpy(&key_buf[4], pValue, 32);

            /* Requires the io protection secret to be configured previously and for the
                configuration to support this - should only be enabled for testing purposes.
                Production devices should never have this feature enabled. */
            rv = pkcs11_util_convert_rv(calib_priv_write(session_ctx->slot->device_ctx, pObject->slot, key_buf, write_key_id, session_ctx->slot->read_key, num_in));
#endif
        }
        else
        {
#if ATCA_TA_SUPPORT
            cal_buffer sValue = CAL_BUF_INIT(ulValueLen, pValue);
            rv = pkcs11_util_convert_rv(talib_write_element(session_ctx->slot->device_ctx, pObject->slot, &sValue));
#endif
        }
    }

    return rv;
}


CK_RV pkcs11_key_write(CK_VOID_PTR pSession, CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if ((NULL != obj_ptr) && (NULL != pAttribute) && (NULL != pAttribute->pValue) && (NULL != pSession))
    {
        pkcs11_session_ctx_ptr session_ctx = (pkcs11_session_ctx_ptr)pSession;
        if (obj_ptr->class_id == CKO_PUBLIC_KEY && pAttribute->type == CKA_EC_POINT)
        {
            /* coverity[misra_c_2012_rule_21_16_violation:FALSE] inputs are of pointer type */
            if (0 == memcmp(ec_x962_asn1_header, pAttribute->pValue, sizeof(ec_x962_asn1_header)))
            {
                CK_BBOOL is_private;

                if (CKR_OK == (rv = pkcs11_object_is_private(obj_ptr, &is_private, session_ctx)))
                {
                    if (is_private)
                    {
                        /* Assume it is paired with the private key that is already stored */
                        rv = CKR_OK;
                    }
                    else
                    {
                        /* Actually write the public key into the slot */
                        rv = pkcs11_util_convert_rv(atcab_write_pubkey_ext(session_ctx->slot->device_ctx, obj_ptr->slot, &(((uint8_t*)pAttribute->pValue)[sizeof(ec_x962_asn1_header)])));
                    }
                }
            }
        }
        else if (obj_ptr->class_id == CKO_PRIVATE_KEY && pAttribute->type == CKA_VALUE)
        {
            if (atcab_is_ca_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)))
            {
                rv = pkcs11_key_privwrite_ca(pSession, obj_ptr, pAttribute->pValue, pAttribute->ulValueLen);
            }
        }
        else if (obj_ptr->class_id == CKO_SECRET_KEY && pAttribute->type == CKA_VALUE)
        {
            if (atcab_is_ca_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)) && ((pAttribute->ulValueLen % 32u) != 0u))
            {
                uint8_t buf[64] = { 0 };
                uint16_t buflen = (uint16_t)((0u != (pAttribute->ulValueLen / 32u)) ? 64u : 32u);
                if (pAttribute->ulValueLen > 64u)
                {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                (void)memcpy(buf, pAttribute->pValue, pAttribute->ulValueLen);
                rv = pkcs11_util_convert_rv(atcab_write_bytes_zone_ext(session_ctx->slot->device_ctx, ATCA_ZONE_DATA, obj_ptr->slot, 0, buf, buflen));
            }
            else
            {
                rv = pkcs11_util_convert_rv(atcab_write_bytes_zone_ext(session_ctx->slot->device_ctx, ATCA_ZONE_DATA, obj_ptr->slot, 0, (uint8_t*)pAttribute->pValue, pAttribute->ulValueLen));
            }
        }
        else
        {
            /* do nothing */
        }
    }

    return rv;
}

CK_RV pkcs11_key_generate
(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    CK_ATTRIBUTE_PTR pName = NULL;
    pkcs11_lib_ctx_ptr pLibCtx;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pKey = NULL;
    CK_ULONG i;
    CK_RV rv = CKR_OK;
    ATCA_STATUS status = ATCA_SUCCESS;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pMechanism || NULL == pTemplate || 0u == ulCount || NULL == phKey)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    /* @todo Perform the various mechanism and key attribute checks */

    if ((CKM_AES_KEY_GEN != pMechanism->mechanism) &&
        (CKM_SHA256_HMAC != pMechanism->mechanism))
    {
        return CKR_MECHANISM_INVALID;
    }


    for (i = 0; i < ulCount; i++)
    {
        if (CKA_LABEL == pTemplate[i].type)
        {
            pName = &pTemplate[i];
            break;
        }
    }

    if (NULL == pName || pName->ulValueLen > (CK_ULONG)PKCS11_MAX_LABEL_SIZE)
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }

    /* Must create two new objects - a public and private key */

    rv = pkcs11_object_alloc(pSession->slot->slot_id, &pKey);

    if (CKR_OK == rv)
    {
        pKey->class_id = CKO_SECRET_KEY;
        rv = pkcs11_config_key(pLibCtx, pSession->slot, pKey, pName);
    }

    if (CKR_OK == rv)
    {
        if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
        {
            if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
#if ATCA_CA_SUPPORT
                uint8_t buf[32] = { 0 };
                atecc508a_config_t * pConfig = (atecc508a_config_t*)pKey->config;

                if ((0x0010u == (pConfig->KeyConfig[pKey->slot] & 0x0018u)) || (0x0008u == (pConfig->KeyConfig[pKey->slot] & 0x0018u)))
                {
                    if (0x2000u == (pConfig->SlotConfig[pKey->slot] & 0x2000u))
                    {
                        if (ATCA_SUCCESS == (status = atcab_nonce_rand_ext(pSession->slot->device_ctx, buf, NULL)))
                        {
                            status = atcab_derivekey_ext(pSession->slot->device_ctx, 0, pKey->slot, NULL);
                        }
                    }
                    else
                    {
                        if (ATCA_SUCCESS == (status = atcab_random_ext(pSession->slot->device_ctx, buf)))
                        {
                            status = atcab_write_bytes_zone_ext(pSession->slot->device_ctx, ATCA_ZONE_DATA, pKey->slot, 0, buf, 32);
                        }
                    }
                }
#endif
            }
            else
            {
#if ATCA_TA_SUPPORT
                status = talib_genkey_symmetric_key(pSession->slot->device_ctx, pKey->slot);
#endif
            }
            (void)pkcs11_unlock_both(pLibCtx);
        }
    }

    if (CKR_OK == rv && ATCA_SUCCESS != status)
    {
#if !PKCS11_USE_STATIC_CONFIG
        (void)pkcs11_config_remove_object(pLibCtx, pSession->slot, pKey);
#endif
        rv = pkcs11_util_convert_rv(status);
    }

    if (CKR_OK == rv)
    {
        (void)pkcs11_object_get_handle(pKey, phKey);
    }
    else
    {
        if (NULL != pKey)
        {
            (void)pkcs11_object_free(pKey);
        }
    }

    return rv;
}

CK_RV pkcs11_key_generate_pair
(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
    CK_ULONG             ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
    CK_ULONG             ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
    CK_ATTRIBUTE_PTR pName = NULL;
    pkcs11_lib_ctx_ptr pLibCtx;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pPublic = NULL;
    pkcs11_object_ptr pPrivate = NULL;
    CK_ULONG i;
    CK_RV rv = CKR_OK;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if (NULL == pMechanism || NULL == pPublicKeyTemplate || 0u == ulPublicKeyAttributeCount ||
        NULL == pPrivateKeyTemplate || 0u == ulPrivateKeyAttributeCount ||
        NULL == phPublicKey || NULL == phPrivateKey)
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = pkcs11_session_check(&pSession, hSession);
    if (CKR_OK != rv)
    {
        return rv;
    }

    /* @todo Perform the various mechanism and key attribute checks */

    if (CKM_EC_KEY_PAIR_GEN != pMechanism->mechanism)
    {
        return CKR_MECHANISM_INVALID;
    }


    for (i = 0; i < ulPrivateKeyAttributeCount; i++)
    {
        if (CKA_LABEL == pPrivateKeyTemplate[i].type)
        {
            pName = &pPrivateKeyTemplate[i];
            break;
        }
    }

    if (NULL == pName || pName->ulValueLen > (CK_ULONG)PKCS11_MAX_LABEL_SIZE)
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }

    /* Must create two new objects - a public and private key */

    rv = pkcs11_object_alloc(pSession->slot->slot_id, &pPrivate);

    if (CKR_OK == rv)
    {
        rv = pkcs11_object_alloc(pSession->slot->slot_id, &pPublic);
    }

    if (CKR_OK == rv)
    {
        if (NULL == pPublic || NULL == pPrivate)
        {
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
    }

    if (CKR_OK == rv)
    {
        pPrivate->class_id = CKO_PRIVATE_KEY;
#if ATCA_TA_SUPPORT
        (void)talib_handle_init_private_key(&pPrivate->handle_info, TA_KEY_TYPE_ECCP256,
                                            TA_ALG_MODE_ECC_ECDSA, TA_PROP_SIGN_INT_EXT_DIGEST,
                                            TA_PROP_NO_KEY_AGREEMENT);
#endif

        rv = pkcs11_config_key(pLibCtx, pSession->slot, pPrivate, pName);
    }

    if (CKR_OK == rv)
    {
        pPublic->slot = pPrivate->slot;
        pPublic->flags = pPrivate->flags;
        (void)memcpy(pPublic->name, pName->pValue, pName->ulValueLen);
        pPublic->class_id = CKO_PUBLIC_KEY;
        pPublic->class_type = CKK_EC;
        pPublic->attributes = pkcs11_key_public_attributes;
        pPublic->count = pkcs11_key_public_attributes_count;
        pPublic->size = 64;
#if ATCA_CA_SUPPORT
        pPublic->config = &((pkcs11_slot_ctx_ptr)pSession->slot)->cfg_zone;
#endif

        if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
        {
            rv = pkcs11_util_convert_rv(atcab_genkey_ext(pSession->slot->device_ctx, pPrivate->slot, NULL));
            if (CKR_OK != rv)
            {
#if !PKCS11_USE_STATIC_CONFIG
                (void)pkcs11_config_remove_object(pLibCtx, pSession->slot, pPrivate);
#endif
            }
            (void)pkcs11_unlock_both(pLibCtx);
        }
    }

    if (CKR_OK == rv)
    {
        (void)pkcs11_object_get_handle(pPrivate, phPrivateKey);
        (void)pkcs11_object_get_handle(pPublic, phPublicKey);
    }
    else
    {
        if (NULL != pPrivate)
        {
            (void)pkcs11_object_free(pPrivate);
        }
        if (NULL != pPublic)
        {
            (void)pkcs11_object_free(pPublic);
        }
    }

    return rv;
}

#ifdef ATCA_NO_HEAP
static uint8_t pkcs11_key_cache[32];

static uint8_t pkcs11_key_used(uint8_t * key, size_t keylen)
{
    if (key)
    {
        for (int i = 0; i < keylen; i++)
        {
            if (key[i])
            {
                return 1;
            }
        }
    }
    return 0;
}
#endif

static CK_RV pkcs11_key_derive_ca(pkcs11_session_ctx_ptr pSession, pkcs11_object_ptr pBaseKey, pkcs11_object_ptr pSecretKey, CK_ECDH1_DERIVE_PARAMS_PTR pEcdhParameters)
{
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if ((NULL != pSession) && (NULL != pBaseKey) && (NULL != pSecretKey) && (NULL != pEcdhParameters))
    {
        pSecretKey->attributes = pkcs11_key_secret_attributes;
        pSecretKey->count = pkcs11_key_secret_attributes_count;
        pSecretKey->size = 32;
        pSecretKey->flags = PKCS11_OBJECT_FLAG_DESTROYABLE | PKCS11_OBJECT_FLAG_SENSITIVE;
#ifdef ATCA_NO_HEAP
        if (!pkcs11_key_used(pkcs11_key_cache, sizeof(pkcs11_key_cache)))
        {
            pSecretKey->data = pkcs11_key_cache;
        }
#else
        pSecretKey->data = pkcs11_os_malloc(pSecretKey->size);
#endif
        if (NULL == pSecretKey->data)
        {
            rv = CKR_HOST_MEMORY;
        }
        else
        {
            ATCA_STATUS status = ATCA_SUCCESS;
            if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {

            #if ATCA_CA_SUPPORT
                pkcs11_lib_ctx_ptr pLibCtx = pkcs11_get_context();
                pSecretKey->slot = ATCA_TEMPKEY_KEYID;
                pSecretKey->config = &((pkcs11_slot_ctx_ptr)pSession->slot)->cfg_zone;

                if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
                {
                    /* Because of the number of ECDH options this function unfortunately has a complex bit of logic
                       to walk through to select the proper ECDH command. Normally this would be left up to the user
                       to chose */

                    if (ATCA_TEMPKEY_KEYID == pBaseKey->slot)
                    {
                        if (pSession->slot->logged_in)
                        {
                            status = calib_ecdh_tempkey_ioenc(pSession->slot->device_ctx, &pEcdhParameters->pPublicData[1], (uint8_t*)pSecretKey->data, pSession->slot->read_key);
                        }
                        else
                        {
                            status = calib_ecdh_tempkey(pSession->slot->device_ctx, &pEcdhParameters->pPublicData[1], (uint8_t*)pSecretKey->data);
                        }
                    }
                    else if (16u > pBaseKey->slot)
                    {
                        if (ATCA_SLOT_CONFIG_WRITE_ECDH_MASK == (ATCA_SLOT_CONFIG_WRITE_ECDH_MASK & pSession->slot->cfg_zone.SlotConfig[pBaseKey->slot]))
                        {
                            uint8_t num_in[32] = { 0, 1, 2, 3, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0,
                                                   0, 0, 0, 0, 0, 0, 0, 0 };

                            uint16_t read_key_id = (ATCA_SLOT_CONFIG_READKEY_MASK & pSession->slot->cfg_zone.SlotConfig[pBaseKey->slot | 0x01u])
                                                   >> ATCA_SLOT_CONFIG_READKEY_SHIFT;
                            status = calib_ecdh_enc(pSession->slot->device_ctx, pBaseKey->slot, &pEcdhParameters->pPublicData[1], (uint8_t*)pSecretKey->data,
                                                    pSession->slot->read_key, read_key_id, num_in);
                        }
                        else if ((ATECC508A != pSession->slot->interface_config.devtype) &&
                                 (ATCA_CHIP_OPT_IO_PROT_EN_MASK == (ATCA_CHIP_OPT_IO_PROT_EN_MASK & pSession->slot->cfg_zone.ChipOptions)) &&
                                 pSession->slot->logged_in)
                        {
                            status = calib_ecdh_ioenc(pSession->slot->device_ctx, pBaseKey->slot, &pEcdhParameters->pPublicData[1], (uint8_t*)pSecretKey->data, pSession->slot->read_key);
                        }
                        else
                        {
                            status = calib_ecdh(pSession->slot->device_ctx, pBaseKey->slot, &pEcdhParameters->pPublicData[1], (uint8_t*)pSecretKey->data);
                        }
                    }
                    else
                    {
                        status = ATCA_GEN_FAIL;
                    }
                    (void)pkcs11_unlock_both(pLibCtx);

                }
            #endif
            }
            else
            {
        #if ATCA_TA_SUPPORT
                status = talib_ecdh_compat(pSession->slot->device_ctx, pBaseKey->slot, &pEcdhParameters->pPublicData[1], (uint8_t*)pSecretKey->data);
        #endif
            }
            rv = pkcs11_util_convert_rv(status);
        }
    }

    return rv;
}

CK_RV pkcs11_key_derive
(
    CK_SESSION_HANDLE    hSession,
    CK_MECHANISM_PTR     pMechanism,
    CK_OBJECT_HANDLE     hBaseKey,
    CK_ATTRIBUTE_PTR     pTemplate,
    CK_ULONG             ulCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    pkcs11_session_ctx_ptr pSession = NULL;
    pkcs11_lib_ctx_ptr pLibCtx;
    pkcs11_object_ptr pBaseKey = NULL;
    pkcs11_object_ptr pSecretKey = NULL;
    CK_ECDH1_DERIVE_PARAMS_PTR pEcdhParameters = NULL;
    CK_ULONG i;
    CK_RV rv = CKR_OK;

    rv = pkcs11_init_check(&pLibCtx, FALSE);
    if (CKR_OK != rv)
    {
        return rv;
    }

    if ((0u == hSession) || (NULL == pMechanism) || (0u == hBaseKey) ||
        (NULL == pTemplate) || (0u == ulCount) || (NULL == phKey))
    {
        return CKR_ARGUMENTS_BAD;
    }

    *phKey = CK_INVALID_HANDLE;

    if (CKM_ECDH1_DERIVE == pMechanism->mechanism || CKM_ECDH1_COFACTOR_DERIVE == pMechanism->mechanism)
    {
        if (sizeof(CK_ECDH1_DERIVE_PARAMS) != pMechanism->ulParameterLen ||
            (NULL == pMechanism->pParameter))
        {
            rv = CKR_ARGUMENTS_BAD;
        }
        else
        {
            pEcdhParameters = (CK_ECDH1_DERIVE_PARAMS_PTR)pMechanism->pParameter;
            if (NULL == pEcdhParameters->pPublicData)
            {
                rv = CKR_ARGUMENTS_BAD;
            }
        }
    }
    else
    {
        rv = CKR_FUNCTION_NOT_SUPPORTED;
    }

    if (CKR_OK == rv)
    {
        rv = pkcs11_session_check(&pSession, hSession);
    }

    if (CKR_OK == rv)
    {
        rv = pkcs11_object_check(&pBaseKey, hBaseKey);
    }

    if (CKR_OK == rv)
    {
        rv = pkcs11_object_alloc(pSession->slot->slot_id, &pSecretKey);
    }

    for (i = 0; (i < ulCount); i++)
    {
        if (CKR_OK == rv)
        {
            if (CKA_LABEL == pTemplate[i].type)
            {
                if ((NULL != pTemplate[i].pValue) && (pTemplate[i].ulValueLen > (CK_ULONG)PKCS11_MAX_LABEL_SIZE))
                {
                    rv = CKR_TEMPLATE_INCONSISTENT;
                }
                else if ((NULL != pTemplate[i].pValue) && (0u != pTemplate[i].ulValueLen))
                {
                    (void)memcpy(pSecretKey->name, pTemplate[i].pValue, pTemplate[i].ulValueLen);
                }
                else
                {
                    /* do nothing */
                }
            }
            else if (CKA_CLASS == pTemplate[i].type)
            {
                if (sizeof(pSecretKey->class_id) != pTemplate[i].ulValueLen)
                {
                    rv = CKR_TEMPLATE_INCONSISTENT;
                }
                else
                {
                    (void)memcpy(&pSecretKey->class_id, pTemplate[i].pValue, sizeof(pSecretKey->class_id));
                }
            }
            else if (CKA_KEY_TYPE == pTemplate[i].type)
            {
                if (sizeof(pSecretKey->class_type) != pTemplate[i].ulValueLen)
                {
                    rv = CKR_TEMPLATE_INCONSISTENT;
                }
                else
                {
                    (void)memcpy(&pSecretKey->class_type, pTemplate[i].pValue, sizeof(pSecretKey->class_type));
                }
            }
            else
            {
                /* do nothing */
            }
        }
        else
        {
            break;
        }
    }

    if (CKR_OK == rv)
    {
        if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
        {
            rv = pkcs11_key_derive_ca(pSession, pBaseKey, pSecretKey, pEcdhParameters);
        }
    }

    if (CKR_OK == rv)
    {
        (void)pkcs11_object_get_handle(pSecretKey, phKey);
    }
    else if (NULL != pSecretKey)
    {
        (void)pkcs11_object_free(pSecretKey);
    }
    else
    {
        /* do nothing */
    }

    return rv;
}

/** @} */
