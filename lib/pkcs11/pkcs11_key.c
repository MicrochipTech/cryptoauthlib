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

#if defined(ATCA_HEAP)
typedef struct pkcs11_key_cache_s
{
    CK_ATTRIBUTE            key_id_hash;
    pkcs11_session_ctx_ptr  pSession_key;
    pkcs11_object_ptr       pObject_key;
    CK_BBOOL                in_use;
} pkcs11_key_cache_fields_t;

static pkcs11_key_cache_fields_t pkcs11_key_cache_list[PKCS11_MAX_KEYS_CACHED];
#endif

//All below data taken from: https://asecuritysite.com/ecc/sigs3

/** ASN.1 Header for SECP256R1 public keys */
CK_BYTE pkcs11_ec_pbkey_asn1_hdr_p256[] = {
    0x30, 0x59,                                                 // a SEQUENCE of 89 bytes follows
    0x30, 0x13,                                                 // a SEQUENCE of 19 bytes follows
    0x06, 0x07,                                                 // an OBJECT IDENTIFIER of 7 bytes follows
    0x2A, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,                   //ID algorithm: 1.2.840.10045.2.1 ECC (ecPublicKey)
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, //ID algorithm: 1.2.840.10045.3.1.7 secp256r1
    0x03, 0x42, 0x00,                                           // a BIT STRING of 66 bytes follows (including the 0x00 padding byte)
    0x04                                                        // Uncompressed indicator
};

/** X.962 ASN.1 Header for EC256 public keys */
CK_BYTE pkcs11_x962_asn1_hdr_ec256[] = {
    0x04, 0x41, 0x04
};

CK_BYTE pkcs11_key_ec_params_p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

#if ATCA_TA_SUPPORT
/** ASN.1 Header for SECP224R1 public keys */
CK_BYTE pkcs11_ec_pbkey_asn1_hdr_p224[] = {
    0x30, 0x4e,                                 // a SEQUENCE of 78 bytes follows
    0x30, 0x10,                                 // a SEQUENCE of 16 bytes follows
    0x06, 0x07,                                 // an OBJECT IDENTIFIER of 7 bytes follows
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,   //ID algorithm: 1.2.840.10045.2.1 ECC (ecPublicKey)
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21,   //ID algorithm: 1.3.132.0.33 secp224r1
    0x03, 0x3a, 0x00,                           // a BIT STRING of 58 bytes follows (including the 0x00 padding byte)
    0x04                                        // Uncompressed indicator
};

/** X.962 ASN.1 Header for EC224 public keys */
CK_BYTE pkcs11_x962_asn1_hdr_ec224[] = {
    0x04, 0x39, 0x04
};

CK_BYTE pkcs11_key_ec_params_p224[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21 };

/** ASN.1 Header for SECP384R1 public keys */
CK_BYTE pkcs11_ec_pbkey_asn1_hdr_p384[] = {
    0x30, 0x76,                                 // a SEQUENCE of 118 bytes follows
    0x30, 0x10,                                 // a SEQUENCE of 16 bytes follows
    0x06, 0x07,                                 // an OBJECT IDENTIFIER of 7 bytes follows
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,   // OID 1.2.840.10045.2.1 (ecPublicKey)
    0x06, 0x05,                                 // an OBJECT IDENTIFIER of 5 bytes follows
    0x2b, 0x81, 0x04, 0x00, 0x22,               // OID 1.3.132.0.34 (secp384r1)
    0x03, 0x62, 0x00,                           // a BIT STRING of 98 bytes follows (including the 0x00 padding byte)
    0x04                                        // Uncompressed indicator
};

CK_BYTE pkcs11_key_ec_params_p384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };

/** X.962 ASN.1 Header for EC384 public keys */
CK_BYTE pkcs11_x962_asn1_hdr_ec384[] = {
    0x04, 0x61, 0x04
};

/** ASN.1 Header for SECP521R1 public keys */
CK_BYTE pkcs11_ec_pbkey_asn1_hdr_p521[] = {
    0x30, 0x81, 0x9b,                           // a SEQUENCE of 155 bytes follows
    0x30, 0x10,                                 // a SEQUENCE of 16 bytes follows
    0x06, 0x07,                                 // an OBJECT IDENTIFIER of 7 bytes follows
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,   // OID 1.2.840.10045.2.1 (ecPublicKey)
    0x06, 0x05,                                 // an OBJECT IDENTIFIER of 5 bytes follows
    0x2b, 0x81, 0x04, 0x00, 0x23,               // OID 1.3.132.0.35 (secp521r1)
    0x03, 0x81, 0x86, 0x00,                     // a BIT STRING of 134 bytes follows (including the 0x00 padding byte)
    0x04                                        //Uncompressed indicator
};

/** X.962 ASN.1 Header for EC521 public keys */
CK_BYTE pkcs11_x962_asn1_hdr_ec521[] = {
    0x04, 0x85, 0x04
};

CK_BYTE pkcs11_key_ec_params_p521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

#if PKCS11_RSA_SUPPORT_ENABLE
/* ASN.1 header for RSA-1024 public keys */
CK_BYTE pkcs11_pbkey_asn1_hdr_rsa1024[] = {
    0x30, 0x81, 0x9F,                                          // a SEQUENCE of 159 bytes follows
    0x30, 0x0D,                                                // a SEQUENCE of 13 bytes follows
    0x06, 0x09,                                                // an OBJECT IDENTIFIER of 9 bytes follows
    0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,      // ID algorithm: 1.2.840.113549.1.1.1 (RSA)
    0x05, 0x00,                                                // No paramters for this algorithm
    0x03, 0x81, 0x8D, 0x00,                                    // a BIT STRING of 141 bytes follows (including the 0x00 padding byte)
    0x30, 0x81, 0x89,                                          // a SEQUENCE of 137 bytes follows
    0x02, 0x81, 0x81,                                          // a INTEGER VALUE of 129 bytes follows
    0x00                                                       // Leading zero for MODULUS
};

/* ASN.1 header for RSASSA_PSS-1024 public keys */
CK_BYTE pkcs11_pbkey_asn1_hdr_rsapss1024[] = {
    0x30, 0x81, 0x9D,                                          // a SEQUENCE of 157 bytes follows
    0x30, 0x0B,                                                // a SEQUENCE of 11 bytes follows
    0x06, 0x09,                                                // an OBJECT IDENTIFIER of 9 bytes follows
    0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,      // ID algorithm: 1.2.840.113549.1.1.10 (RSASSA-PSS)
    0x03, 0x81, 0x8D, 0x00,                                    // a BIT STRING of 141 bytes follows (including the 0x00 padding byte)
    0x30, 0x81, 0x89,                                          // a SEQUENCE of 137 bytes follows
    0x02, 0x81, 0x81,                                          // a INTEGER VALUE of 129 bytes follows
    0x00                                                       // Leading zero for MODULUS
};

/* ASN.1 header for RSA-2048 public keys */
CK_BYTE pkcs11_pbkey_asn1_hdr_rsa2048[] = {
    0x30, 0x82, 0x01, 0x22,                                    // a SEQUENCE of 290 bytes follows
    0x30, 0x0D,                                                // a SEQUENCE of 13 bytes follows
    0x06, 0x09,                                                // an OBJECT IDENTIFIER of 9 bytes follows
    0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,      // ID algorithm: 1.2.840.113549.1.1.1 (RSA)
    0x05, 0x00,                                                // No paramters for this algorithm
    0x03, 0x82, 0x01, 0x0F, 0x00,                              // a BIT STRING of 271 bytes follows (including the 0x00 padding byte)
    0x30, 0x82, 0x01, 0x0A,                                    // a SEQUENCE of 266 bytes follows
    0x02, 0x82, 0x01, 0x01,                                    // a INTEGER VALUE of 257 bytes follows
    0x00                                                       // Leading zero for MODULUS
};

/* ASN.1 header for RSASSA_PSS-2048  public keys */
CK_BYTE pkcs11_pbkey_asn1_hdr_rsapss2048[] = {
    0x30, 0x82, 0x01, 0x20,                                    // a SEQUENCE of 288 bytes follows
    0x30, 0x0B,                                                // a SEQUENCE of 11 bytes follows
    0x06, 0x09,                                                // an OBJECT IDENTIFIER of 9 bytes follows
    0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,      // ID algorithm: 1.2.840.113549.1.1.10 (RSASSA-PSS)
    0x03, 0x82, 0x01, 0x0F, 0x00,                              // a BIT STRING of 271 bytes follows (including the 0x00 padding byte)
    0x30, 0x82, 0x01, 0x0A,                                    // a SEQUENCE of 266 bytes follows
    0x02, 0x82, 0x01, 0x01,                                    // a INTEGER VALUE of 257 bytes follows
    0x00                                                       // Leading zero for MODULUS
};

/* ASN.1 header for RSA-3072 public keys */
CK_BYTE pkcs11_pbkey_asn1_hdr_rsa3072[] = {
    0x30, 0x82, 0x01, 0xA2,                                    // a SEQUENCE of 418 bytes follows
    0x30, 0x0D,                                                // a SEQUENCE of 13 bytes follows
    0x06, 0x09,                                                // an OBJECT IDENTIFIER of 9 bytes follows
    0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,      // ID algorithm: 1.2.840.113549.1.1.1 (RSA)
    0x05, 0x00,                                                // No paramters for this algorithm
    0x03, 0x82, 0x01, 0x8F, 0x00,                              // a BIT STRING of 399 bytes follows (including the 0x00 padding byte)
    0x30, 0x82, 0x01, 0x8A,                                    // a SEQUENCE of 394 bytes follows
    0x02, 0x82, 0x01, 0x81,                                    // a INTEGER VALUE of 385 bytes follows
    0x00                                                       // Leading zero for MODULUS
};

/* ASN.1 header for RSASSA_PSS-3072 public keys */
CK_BYTE pkcs11_pbkey_asn1_hdr_rsapss3072[] = {
    0x30, 0x82, 0x01, 0xA0,                                    // a SEQUENCE of 416 bytes follows
    0x30, 0x0B,                                                // a SEQUENCE of 11 bytes follows
    0x06, 0x09,                                                // an OBJECT IDENTIFIER of 9 bytes follows
    0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,      // ID algorithm: 1.2.840.113549.1.1.10 (RSASSA-PSS)
    0x03, 0x82, 0x01, 0x8F, 0x00,                              // a BIT STRING of 399 bytes follows (including the 0x00 padding byte)
    0x30, 0x82, 0x01, 0x8A,                                    // a SEQUENCE of 394 bytes follows
    0x02, 0x82, 0x01, 0x81,                                    // a INTEGER VALUE of 385 bytes follows
    0x00                                                       // Leading zero for MODULUS
};

/* ASN.1 header for RSA-4096 public keys */
CK_BYTE pkcs11_pbkey_asn1_hdr_rsa4096[] = {
    0x30, 0x82, 0x02, 0x22,                                    // a SEQUENCE of 546 bytes follows
    0x30, 0x0D,                                                // a SEQUENCE of 13 bytes follows
    0x06, 0x09,                                                // an OBJECT IDENTIFIER of 9 bytes follows
    0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,      // ID algorithm: 1.2.840.113549.1.1.1 (RSA)
    0x05, 0x00,                                                // No paramters for this algorithm
    0x03, 0x82, 0x02, 0x0F, 0x00,                              // a BIT STRING of 527 bytes follows (including the 0x00 padding byte)
    0x30, 0x82, 0x02, 0x0A,                                    // a SEQUENCE of 522 bytes follows
    0x02, 0x82, 0x02, 0x01,                                    // a INTEGER VALUE of 513 bytes follows
    0x00                                                       // Leading zero for MODULUS
};

/* ASN.1 header for RSASSA_PSS-4096 public keys */
CK_BYTE pkcs11_pbkey_asn1_hdr_rsapss4096[] = {
    0x30, 0x82, 0x02, 0x20,                                    // a SEQUENCE of 544 bytes follows
    0x30, 0x0B,                                                // a SEQUENCE of 11 bytes follows
    0x06, 0x09,                                                // an OBJECT IDENTIFIER of 9 bytes follows
    0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,      // ID algorithm: 1.2.840.113549.1.1.10 (RSASSA-PSS)
    0x03, 0x82, 0x02, 0x0F, 0x00,                              // a BIT STRING of 527 bytes follows (including the 0x00 padding byte)
    0x30, 0x82, 0x02, 0x0A,                                    // a SEQUENCE of 522 bytes follows
    0x02, 0x82, 0x02, 0x01,                                    // a INTEGER VALUE of 513 bytes follows
    0x00                                                       // Leading zero for MODULUS
};

/* ASN.1 header for SHA-256 Hash */
CK_BYTE pkcs11_sha256_asn1_hdr[19] = {
    0x30, 0x31,                                                // a SEQUENCE of 49 bytes follows
    0x30, 0x0D,                                                // a SEQUENCE of 13 bytes follows
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  // ID algorithm: 2.16.840.1.101.3.4.2.1 (SHA-256)
    0x05, 0x00,                                                // No paramters for this algorithm
    0x04, 0x20                                                 // a OCTET STRING of 32 bytes follows
};

/* ASN.1 Header for rsa public exponent */
CK_BYTE pkcs11_rsa_public_exp_asn1_hdr[] = {0x02, 0x03};       // an INTEGER VALUE of 3 bytes follows

/* Public Exponent for RSA Private and Public Keys */
CK_BYTE pkcs11_rsa_public_exp[] = {0x01, 0x00, 0x01};          // Default value of 65537
#endif
#endif

//Fixing the lookup table size to support max of 4 ECC curves
//Note: Add more ECC key type info based on support required

const pkcs11_ecc_key_info_t ec_key_data_table[4] = {
    { ATCA_KEY_TYPE_ECCP256, (CK_BYTE)ATCA_ECCP256_OID_SIZE, pkcs11_key_ec_params_p256, pkcs11_ec_pbkey_asn1_hdr_p256,
      pkcs11_x962_asn1_hdr_ec256, (uint16_t)ATCA_ECCP256_ASN1_HDR_SIZE, ATCA_ECCP256_PUBKEY_SIZE, ATCA_ECCP256_MSG_SIZE, ATCA_ECCP256_SIG_SIZE }
#if ATCA_TA_SUPPORT
    ,{ TA_KEY_TYPE_ECCP224, (CK_BYTE)TA_ECC224_OID_SIZE, pkcs11_key_ec_params_p224, pkcs11_ec_pbkey_asn1_hdr_p224,
      pkcs11_x962_asn1_hdr_ec224, (uint16_t)TA_ECC224_ASN1_HDR_SIZE, TA_ECC224_PUB_KEY_SIZE, TA_SIGN_P224_MSG_SIZE, TA_SIGN_P224_SIG_SIZE },

    { TA_KEY_TYPE_ECCP384, (CK_BYTE)TA_ECC384_OID_SIZE, pkcs11_key_ec_params_p384, pkcs11_ec_pbkey_asn1_hdr_p384,
      pkcs11_x962_asn1_hdr_ec384, (uint16_t)TA_ECC384_ASN1_HDR_SIZE, TA_ECC384_PUB_KEY_SIZE, TA_SIGN_P384_MSG_SIZE, TA_SIGN_P384_SIG_SIZE },

    { TA_KEY_TYPE_ECCP521, (CK_BYTE)TA_ECC521_OID_SIZE, pkcs11_key_ec_params_p521, pkcs11_ec_pbkey_asn1_hdr_p521,
      pkcs11_x962_asn1_hdr_ec521, (uint16_t)TA_ECC521_ASN1_HDR_SIZE, TA_ECC521_PUB_KEY_SIZE, TA_SIGN_P521_MSG_SIZE, TA_SIGN_P521_SIG_SIZE },
#endif
};

const pkcs11_rsa_key_info_t rsa_key_data_table[4] = {
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
    { TA_KEY_TYPE_RSA1024, TA_RSAENC_MODE_ENCRYPT1024, TA_RSAENC_MODE_DECRYPT1024, TA_RSA1024_ASN1_HDR_SIZE, TA_RSA1024_PSS_ASN1_HDR_SIZE,
      pkcs11_pbkey_asn1_hdr_rsa1024, pkcs11_pbkey_asn1_hdr_rsapss1024, pkcs11_rsa_public_exp_asn1_hdr, pkcs11_rsa_public_exp,
      TA_RSAENC_PUB_KEY_SIZE1024_BITS, TA_RSAENC_PUB_KEY_SIZE1024, TA_SIGN_OTHER_KEY_TYPE_MSG_SIZE, TA_SIGN_RSA1024_SIG_SIZE },

    { TA_KEY_TYPE_RSA2048, TA_RSAENC_MODE_ENCRYPT2048, TA_RSAENC_MODE_DECRYPT2048, TA_RSA2048_ASN1_HDR_SIZE, TA_RSA2048_PSS_ASN1_HDR_SIZE,
      pkcs11_pbkey_asn1_hdr_rsa2048, pkcs11_pbkey_asn1_hdr_rsapss2048, pkcs11_rsa_public_exp_asn1_hdr, pkcs11_rsa_public_exp,
      TA_RSAENC_PUB_KEY_SIZE2048_BITS, TA_RSAENC_PUB_KEY_SIZE2048, TA_SIGN_OTHER_KEY_TYPE_MSG_SIZE, TA_SIGN_RSA2048_SIG_SIZE },

    { TA_KEY_TYPE_RSA3072, TA_RSAENC_MODE_ENCRYPT3072, TA_RSAENC_MODE_DECRYPT3072, TA_RSA3072_ASN1_HDR_SIZE, TA_RSA3072_PSS_ASN1_HDR_SIZE,
      pkcs11_pbkey_asn1_hdr_rsa3072, pkcs11_pbkey_asn1_hdr_rsapss3072,pkcs11_rsa_public_exp_asn1_hdr, pkcs11_rsa_public_exp,
      TA_RSAENC_PUB_KEY_SIZE3072_BITS, TA_RSAENC_PUB_KEY_SIZE3072, TA_SIGN_OTHER_KEY_TYPE_MSG_SIZE, TA_SIGN_RSA3072_SIG_SIZE },

    { TA_KEY_TYPE_RSA4096, TA_RSAENC_MODE_ENCRYPT4096, TA_RSAENC_MODE_DECRYPT4096, TA_RSA4096_ASN1_HDR_SIZE, TA_RSA4096_PSS_ASN1_HDR_SIZE,
      pkcs11_pbkey_asn1_hdr_rsa4096, pkcs11_pbkey_asn1_hdr_rsapss4096, pkcs11_rsa_public_exp_asn1_hdr, pkcs11_rsa_public_exp,
      TA_RSAENC_PUB_KEY_SIZE4096_BITS, TA_RSAENC_PUB_KEY_SIZE4096, TA_SIGN_OTHER_KEY_TYPE_MSG_SIZE, TA_SIGN_RSA4096_SIG_SIZE },
#endif
};

const pkcs11_key_info_t key_data_table[] = {
    // ECC keys
    { &ec_key_data_table[0], NULL },
#if ATCA_TA_SUPPORT
    { &ec_key_data_table[1], NULL },
    { &ec_key_data_table[2], NULL },
    { &ec_key_data_table[3], NULL },
#if PKCS11_RSA_SUPPORT_ENABLE
    // RSA keys
    { NULL, &rsa_key_data_table[0] },
    { NULL, &rsa_key_data_table[1] },
    { NULL, &rsa_key_data_table[2] },
    { NULL, &rsa_key_data_table[3] },
#endif
#endif
};

const pkcs11_key_info_t* pkcs11_get_object_key_type(ATCADevice device_ctx, pkcs11_object_ptr obj_ptr)
{
    CK_BYTE key_type = 0u;

    ATCADeviceType dev_type = atcab_get_device_type_ext(device_ctx);

    if (NULL != obj_ptr)
    {
        if (atcab_is_ca_device(dev_type))
        {
#if ATCA_CA_SUPPORT
            key_type = ATCA_KEY_TYPE_ECCP256;
            return &key_data_table[key_type];
#endif
        }
        else if (atcab_is_ta_device(dev_type))
        {
#if ATCA_TA_SUPPORT
            key_type = ((obj_ptr->handle_info.element_CKA & TA_HANDLE_INFO_KEY_TYPE_MASK) >> TA_HANDLE_INFO_KEY_TYPE_SHIFT);
            if (key_type >= (sizeof(key_data_table) / sizeof(key_data_table[0])))
            {
                return NULL;
            }
            return &key_data_table[key_type];
#endif
        }
        else
        {
            /* do nothing*/
        }
    }

    /* If reached here means object not valid*/
    return NULL;
}

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
CK_RV pkcs11_ta_get_pubkey(CK_VOID_PTR pObject, cal_buffer *key_buffer, pkcs11_session_ctx_ptr session_ctx)
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
        return CKR_FUNCTION_FAILED;
    }

    if (NULL == (slot_ctx = pkcs11_slot_get_context(NULL, owner_id)))
    {
        return CKR_FUNCTION_FAILED;
    }

    if (NULL == session_ctx || NULL == session_ctx->slot)
    {
        return CKR_FUNCTION_FAILED;
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
        if (((pubkey_field_handle_info.attributes.element_CKA & TA_HANDLE_INFO_CLASS_MASK) == TA_CLASS_PUBLIC_KEY)
            && ((pubkey_field_handle_info.attributes.property & TA_PROP_ROOT_MASK) != TA_PROP_ROOT_MASK))
        {
            (void)talib_handle_can_read(device, auth_handle, &pubkey_field_handle_info.attributes, &allowed);
            if (allowed)
            {
                status = talib_read_element(device, publickey_slot, key_buffer);
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
            status = talib_get_pubkey(device, obj_ptr->slot, key_buffer);
        }
        else
        {
            status = ATCA_GEN_FAIL;
        }
    }

    return pkcs11_util_convert_rv(status);
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

#if ATCA_CA_SUPPORT
static const CK_MECHANISM_TYPE pkcs11_key_508_public_mech[] = {
    CKM_ECDSA,
    CKM_ECDSA_SHA256
};
#endif

#if ATCA_TA_SUPPORT
static const CK_MECHANISM_TYPE pkcs11_key_ta_public_mech[] = {
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS,
    CKM_RSA_PKCS_OAEP
};
#endif

#if ATCA_CA_SUPPORT
static const CK_MECHANISM_TYPE pkcs11_key_508_private_mech[] = {
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256
};
#endif

#if ATCA_TA_SUPPORT
static const CK_MECHANISM_TYPE pkcs11_key_ta_private_mech[] = {
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_PSS,
    CKM_RSA_PKCS_OAEP
};
#endif

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
        rv = pkcs11_attrib_fill(pAttribute, pkcs11_key_ta_private_mech,
                                (CK_ULONG)sizeof(pkcs11_key_ta_private_mech));
        break;
    case CKO_PUBLIC_KEY:
        rv = pkcs11_attrib_fill(pAttribute, pkcs11_key_ta_public_mech,
                                (CK_ULONG)sizeof(pkcs11_key_ta_public_mech));
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
        const pkcs11_key_info_t *key_data = pkcs11_get_object_key_type(session_ctx->slot->device_ctx, obj_ptr);

        if (NULL == key_data)
        {
            return rv;
        }

        if (CKR_OK == (rv = pkcs11_object_is_private(obj_ptr, &is_private, session_ctx)))
        {
            ATCADeviceType dev_type = atcab_get_device_type_ext(session_ctx->slot->device_ctx);
            CK_ULONG asn1_key_size = 0u;
            CK_ULONG asn1_header_size = (CKK_EC == obj_ptr->class_type) ? key_data->ecc_key_info->asn1_header_sz : 0u;
            //Keeping to max size
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
            CK_UTF8CHAR asn1_key[PKCS11_MAX_ECC_RSA_ASN1_HDR_SIZE + PKCS11_MAX_ECC_RSA_PB_KEY_SIZE] = { 0 };
#else
            CK_UTF8CHAR asn1_key[PKCS11_MAX_ECC_ASN1_HDR_SIZE + PKCS11_MAX_ECC_PB_KEY_SIZE] = { 0 };
#endif
            CK_ULONG pubkey_size = PKCS11_MAX_ECC_RSA_PB_KEY_SIZE;

            if (CKK_EC == obj_ptr->class_type)
            {
                if (NULL == key_data->ecc_key_info)
                {
                    return rv;
                }
                pubkey_size = key_data->ecc_key_info->pubkey_sz;
                (void)memcpy(asn1_key, key_data->ecc_key_info->ec_asn1_header, key_data->ecc_key_info->asn1_header_sz);
            }
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
            else
            {
                CK_BYTE_PTR asn1_rsa_header = NULL;
                ta_handle_info handle_info;
                CK_BYTE alg_mode = 0u;

                if (NULL == key_data->rsa_key_info)
                {
                    return rv;
                }
                // Update the public key size for RSA curves
                pubkey_size = key_data->rsa_key_info->pubkey_sz;
                if (CKR_OK == (rv = pkcs11_util_convert_rv(talib_info_get_handle_info(session_ctx->slot->device_ctx, obj_ptr->slot, &handle_info))))
                {
                    alg_mode = handle_info.attributes.element_CKA & TA_HANDLE_INFO_ALG_MODE_MASK;
                    asn1_rsa_header = ((CK_BYTE)TA_ALG_MODE_RSA_SSA_1_5 == alg_mode) ? (key_data->rsa_key_info->rsa_asn1_header)
                                                                                     : (key_data->rsa_key_info->rsa_pss_asn1_header);
                    asn1_header_size = ((CK_BYTE)TA_ALG_MODE_RSA_SSA_1_5 == alg_mode) ? (key_data->rsa_key_info->rsa_asn1_header_size)
                                                                                      : (key_data->rsa_key_info->rsa_pss_asn1_header_size);
                    (void)memcpy(asn1_key, asn1_rsa_header, asn1_header_size);
                }
            }
#endif

            if (true == is_private)
            {
                if (atcab_is_ca_device(dev_type))
                {
#if ATCA_CA_SUPPORT
                    rv = pkcs11_util_convert_rv(atcab_get_pubkey_ext(session_ctx->slot->device_ctx, obj_ptr->slot,
                                                                        &asn1_key[key_data->ecc_key_info->asn1_header_sz]));
                    PKCS11_DEBUG("atcab_get_pubkey_ext: %x\r\n", rv);
#endif
                }
                else if (atcab_is_ta_device(dev_type))
                {
#if ATCA_TA_SUPPORT
#if PKCS11_RSA_SUPPORT_ENABLE
                    CK_UTF8CHAR pubkey_gen[PKCS11_MAX_RSA_PB_KEY_SIZE] = { 0 };
#else
                    CK_UTF8CHAR pubkey_gen[PKCS11_MAX_ECC_PB_KEY_SIZE] = { 0 };
#endif
                    cal_buffer pubkey_buf = CAL_BUF_INIT(pubkey_size, pubkey_gen);

                    if (CKR_OK == (rv = pkcs11_ta_get_pubkey(pObject, &pubkey_buf, session_ctx)))
                    {
                        (void)memcpy(&asn1_key[asn1_header_size], pubkey_gen, pubkey_size);
                    }
                    PKCS11_DEBUG("pkcs11_ta_get_pubkey: %x\r\n", rv);
#endif
                }
                else
                {
                    rv = CKR_GENERAL_ERROR;
                }
            }
            else
            {
                if (atcab_is_ca_device(dev_type))
                {
#if ATCA_CA_SUPPORT
                    rv = pkcs11_util_convert_rv(atcab_read_pubkey_ext(session_ctx->slot->device_ctx, obj_ptr->slot,
                                                                        &asn1_key[key_data->ecc_key_info->asn1_header_sz]));
                    PKCS11_DEBUG("atcab_read_pubkey_ext: %x\r\n", rv);
#endif
                }
                else if (atcab_is_ta_device(dev_type))
                {
#if ATCA_TA_SUPPORT
#if PKCS11_RSA_SUPPORT_ENABLE
                    CK_UTF8CHAR pubkey_rd[PKCS11_MAX_RSA_PB_KEY_SIZE] = { 0 };
#else
                    CK_UTF8CHAR pubkey_rd[PKCS11_MAX_ECC_PB_KEY_SIZE] = { 0 };
#endif
                    cal_buffer pubkey_buf = CAL_BUF_INIT(pubkey_size, pubkey_rd);
                    if (CKR_OK == (rv = pkcs11_util_convert_rv(talib_read_element(session_ctx->slot->device_ctx, obj_ptr->slot, &pubkey_buf))))
                    {
                        (void)memcpy(&asn1_key[asn1_header_size], pubkey_rd, pubkey_size);
                    }
                    PKCS11_DEBUG("talib_read_element: %x\r\n", rv);
#endif
                }
                else
                {
                    rv = CKR_GENERAL_ERROR;
                }
            }
            if (CKR_OK == rv)
            {
                if (CKK_EC == obj_ptr->class_type)
                {
                    asn1_key_size = asn1_header_size + pubkey_size;
                }
            #if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
                else
                {
                    CK_BYTE rsa_pubexp_hdr_size = (CK_BYTE)sizeof(pkcs11_rsa_public_exp_asn1_hdr);
                    CK_BYTE rsa_pubkey_exp_size = (CK_BYTE)sizeof(pkcs11_rsa_public_exp);

                    (void)memcpy(&asn1_key[asn1_header_size + pubkey_size], pkcs11_rsa_public_exp_asn1_hdr, rsa_pubexp_hdr_size);
                    (void)memcpy(&asn1_key[asn1_header_size + pubkey_size + rsa_pubexp_hdr_size], pkcs11_rsa_public_exp, rsa_pubkey_exp_size);
                    asn1_key_size = asn1_header_size + pubkey_size + rsa_pubexp_hdr_size + rsa_pubkey_exp_size;
                }
            #endif

                rv = pkcs11_attrib_fill(pAttribute, asn1_key, asn1_key_size);
            }
            else
            {
                (void)pkcs11_attrib_empty(pObject, pAttribute, NULL);
                PKCS11_DEBUG("Couldnt generate public key\r\n", rv);
                rv = CKR_OK;
            }
        }
        else
        {
            rv = CKR_KEY_SIZE_RANGE;
        }
    }
    else
    {
        rv = CKR_ARGUMENTS_BAD;
    }

    return rv;
}

static CK_RV pkcs11_key_get_ec_params(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    ((void)psession);
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;
    if (NULL != obj_ptr && NULL != psession)
    {
        const pkcs11_key_info_t *ec_key_data = pkcs11_get_object_key_type(psession->slot->device_ctx, obj_ptr);

        if (NULL != ec_key_data)
        {
            rv = pkcs11_attrib_fill(pAttribute, ec_key_data->ecc_key_info->curve_oid, (CK_ULONG)(ec_key_data->ecc_key_info->oid_size));
        }
        else
        {
            (void)pkcs11_attrib_empty(pObject, pAttribute, NULL);
        }

    }
    return rv;
}

static CK_RV pkcs11_key_get_ec_point(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != psession)
    {
        const pkcs11_key_info_t *ec_key_data = pkcs11_get_object_key_type(psession->slot->device_ctx, obj_ptr);

        if (NULL == ec_key_data)
        {
            return rv;
        }

        //EC point attribute length need to be set before fetching the actual attribute data
        //Hence by default, return value is CKR_OK
        rv = CKR_OK;

        if (ec_key_data->ecc_key_info->pubkey_sz <= PKCS11_MAX_ECC_PB_KEY_SIZE)
        {
            CK_UTF8CHAR ec_asn1_key[PKCS11_X962_ASN1_HEADER_SZ + PKCS11_MAX_ECC_PB_KEY_SIZE];
            (void)memcpy(ec_asn1_key, ec_key_data->ecc_key_info->ec_x962_asn1_header, PKCS11_X962_ASN1_HEADER_SZ);

            if (NULL != pAttribute->pValue)
            {
                CK_BBOOL is_private;
                ATCADeviceType dev_type = atcab_get_device_type_ext(psession->slot->device_ctx);

                if (CKR_OK == (rv = pkcs11_object_is_private(obj_ptr, &is_private, psession)))
                {
                    if (is_private)
                    {
                        if (atcab_is_ca_device(dev_type))
                        {
#if ATCA_CA_SUPPORT
                            rv = pkcs11_util_convert_rv(atcab_get_pubkey_ext(psession->slot->device_ctx, obj_ptr->slot, &ec_asn1_key[PKCS11_X962_ASN1_HEADER_SZ]));
                            PKCS11_DEBUG("atcab_get_pubkey: %x\r\n", rv);
#endif
                        }
                        else if (atcab_is_ta_device(dev_type))
                        {
#if ATCA_TA_SUPPORT
                            CK_UTF8CHAR ec_pubkey_gen[PKCS11_MAX_ECC_PB_KEY_SIZE];
                            cal_buffer ec_pubkey_buf = CAL_BUF_INIT(ec_key_data->ecc_key_info->pubkey_sz, ec_pubkey_gen);
                            if (CKR_OK == (rv = pkcs11_ta_get_pubkey(pObject, &ec_pubkey_buf, psession)))
                            {
                                (void)memcpy(&ec_asn1_key[PKCS11_X962_ASN1_HEADER_SZ], ec_pubkey_gen, ec_key_data->ecc_key_info->pubkey_sz);
                            }
                            PKCS11_DEBUG("pkcs11_ta_get_pubkey: %x\r\n", rv);
#endif
                        }
                        else
                        {
                            rv = CKR_GENERAL_ERROR;
                        }
                    }
                    else
                    {
                        if (atcab_is_ca_device(dev_type))
                        {
#if ATCA_CA_SUPPORT
                            rv = pkcs11_util_convert_rv(atcab_read_pubkey_ext(psession->slot->device_ctx, obj_ptr->slot, &ec_asn1_key[PKCS11_X962_ASN1_HEADER_SZ]));
                            PKCS11_DEBUG("atcab_read_pubkey: %x\r\n", rv);
#endif
                        }
                        else if (atcab_is_ta_device(dev_type))
                        {
#if ATCA_TA_SUPPORT
                            CK_UTF8CHAR ec_pubkey_rd[PKCS11_MAX_ECC_PB_KEY_SIZE];
                            cal_buffer ec_pubkey_buf = CAL_BUF_INIT(ec_key_data->ecc_key_info->pubkey_sz, ec_pubkey_rd);
                            if (CKR_OK == (rv = pkcs11_util_convert_rv(talib_read_element(psession->slot->device_ctx, obj_ptr->slot, &ec_pubkey_buf))))
                            {
                                (void)memcpy(&ec_asn1_key[PKCS11_X962_ASN1_HEADER_SZ], ec_pubkey_rd, ec_key_data->ecc_key_info->pubkey_sz);
                            }
                            PKCS11_DEBUG("talib_read_element: %x\r\n", rv);
#endif
                        }
                        else
                        {
                            rv = CKR_GENERAL_ERROR;
                        }

                    }
                }
            }

            if (CKR_OK == rv)
            {
                rv = pkcs11_attrib_fill(pAttribute, ec_asn1_key, (ec_key_data->ecc_key_info->pubkey_sz + PKCS11_X962_ASN1_HEADER_SZ));
            }
            else
            {
                (void)pkcs11_attrib_empty(pObject, pAttribute, NULL);
                PKCS11_DEBUG("Couldnt generate public key\r\n", rv);
                rv = CKR_OK;
            }
        }
        else
        {
            rv = CKR_KEY_SIZE_RANGE;
        }
    }
    else
    {
        rv = CKR_ARGUMENTS_BAD;
    }

    return rv;
}

#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
static CK_RV pkcs11_key_get_public_exponent(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    ((void)psession);
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != psession)
    {
        if (CKK_RSA == obj_ptr->class_type)
        {
            rv = pkcs11_attrib_fill(pAttribute, pkcs11_rsa_public_exp, (CK_ULONG)(sizeof(pkcs11_rsa_public_exp)));
        }
        else
        {
            (void)pkcs11_attrib_empty(pObject, pAttribute, NULL);
        }
    }
    else
    {
        return CKR_ARGUMENTS_BAD;
    }

    return rv;
}

static CK_RV pkcs11_key_get_modulus_bits(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    ((void)psession);
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != psession)
    {
        if (CKK_RSA == obj_ptr->class_type)
        {
            const pkcs11_key_info_t *rsa_key_data = pkcs11_get_object_key_type(psession->slot->device_ctx, obj_ptr);

            if (NULL == rsa_key_data)
            {
                return rv;
            }
            rv = pkcs11_attrib_fill(pAttribute, &rsa_key_data->rsa_key_info->rsa_modulus_bits, sizeof(CK_ULONG));
        }
        else
        {
            (void)pkcs11_attrib_empty(pObject, pAttribute, NULL);
        }
    }
    else
    {
        return CKR_ARGUMENTS_BAD;
    }

    return rv;
}

static CK_RV pkcs11_key_get_modulus(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr psession)
{
    ((void)psession);
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != obj_ptr && NULL != psession)
    {
        if (CKK_RSA == obj_ptr->class_type)
        {
            CK_BBOOL is_private;
            CK_BYTE pubkey_buffer[PKCS11_MAX_RSA_PB_KEY_SIZE];
            const pkcs11_key_info_t *rsa_key_data = pkcs11_get_object_key_type(psession->slot->device_ctx, obj_ptr);

            if (NULL == rsa_key_data || NULL == rsa_key_data->rsa_key_info)
            {
                return rv;
            }

            if (CKR_OK == (rv = pkcs11_object_is_private(obj_ptr, &is_private, psession)))
            {
                cal_buffer rsa_pubkey_buf = CAL_BUF_INIT(rsa_key_data->rsa_key_info->pubkey_sz, pubkey_buffer);

                if (is_private)
                {
                    rv = pkcs11_ta_get_pubkey(pObject, &rsa_pubkey_buf, psession);
                    PKCS11_DEBUG("pkcs11_ta_get_pubkey: %x\r\n", rv);
                }
                else
                {
                    rv = pkcs11_util_convert_rv(talib_read_element(psession->slot->device_ctx, obj_ptr->slot, &rsa_pubkey_buf));
                    PKCS11_DEBUG("talib_read_element: %x\r\n", rv);
                }
            }

            if (CKR_OK == rv)
            {
                rv = pkcs11_attrib_fill(pAttribute, pubkey_buffer, rsa_key_data->rsa_key_info->pubkey_sz);
            }
        }
        else
        {
            (void)pkcs11_attrib_empty(pObject, pAttribute, NULL);
        }
    }

    return rv;
}
#endif

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

static CK_RV pkcs11_key_calc_key_id(const pkcs11_session_ctx_ptr pSession, const pkcs11_object_ptr pObject, CK_BYTE_PTR key_id_buffer)
{
    CK_BBOOL is_private = FALSE;
    CK_RV rv = CKR_ARGUMENTS_BAD;
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;

    if (NULL != obj_ptr && NULL != pSession)
    {
        const pkcs11_key_info_t *key_data = pkcs11_get_object_key_type(pSession->slot->device_ctx, obj_ptr);

        if (NULL == key_data)
        {
            return rv;
        }

        if (CKR_OK == (rv = pkcs11_object_is_private(pObject, &is_private, pSession)))
        {
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
            CK_UTF8CHAR pubkey_buffer[PKCS11_MAX_ECC_RSA_PB_KEY_SIZE] = { 0 };
#else
            CK_UTF8CHAR pubkey_buffer[ATCA_ECC_UNCOMPRESSED_TYPE_OFFSET + PKCS11_MAX_ECC_PB_KEY_SIZE] = { 0 };
#endif
            CK_ULONG pubkey_size = sizeof(pubkey_buffer);
            ATCADeviceType dev_type = atcab_get_device_type_ext(pSession->slot->device_ctx);

            if (CKK_EC == obj_ptr->class_type)
            {
                if (NULL == key_data->ecc_key_info)
                {
                    return rv;
                }
                pubkey_size = key_data->ecc_key_info->pubkey_sz;
                pubkey_buffer[0] = ATCA_ECC_UNCOMPRESSED_TYPE;
            }
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
            else
            {
                if (NULL == key_data->rsa_key_info)
                {
                    return rv;
                }
                pubkey_size = key_data->rsa_key_info->pubkey_sz;
            }
#endif

            if (TRUE == is_private)
            {
                if (atcab_is_ca_device(dev_type))
                {
#if ATCA_CA_SUPPORT
                    rv = pkcs11_util_convert_rv(atcab_get_pubkey_ext(pSession->slot->device_ctx, pObject->slot, &pubkey_buffer[1]));
#endif
                }
                else if (atcab_is_ta_device(dev_type))
                {
#if ATCA_TA_SUPPORT
#if PKCS11_RSA_SUPPORT_ENABLE
                    CK_UTF8CHAR pubkey_gen[PKCS11_MAX_RSA_PB_KEY_SIZE] = { 0 };
#else
                    CK_UTF8CHAR pubkey_gen[PKCS11_MAX_ECC_PB_KEY_SIZE] = { 0 };
#endif
                    cal_buffer pubkey_buf = CAL_BUF_INIT(pubkey_size, pubkey_gen);
                    CK_BYTE_PTR pubkey_buf_ptr = (CKK_EC == obj_ptr->class_type) ? &pubkey_buffer[1] : &pubkey_buffer[0];

                    if (CKR_OK == (rv = pkcs11_ta_get_pubkey(pObject, &pubkey_buf, pSession)))
                    {
                        (void)memcpy(pubkey_buf_ptr, pubkey_gen, pubkey_size);
                    }
                    PKCS11_DEBUG("pkcs11_ta_get_pubkey: %x\r\n", rv);
#endif
                }
                else
                {
                    rv = CKR_GENERAL_ERROR;
                }
            }
            else
            {
                if (atcab_is_ca_device(dev_type))
                {
#if ATCA_CA_SUPPORT
                    rv = pkcs11_util_convert_rv(atcab_read_pubkey_ext(pSession->slot->device_ctx, obj_ptr->slot, &pubkey_buffer[1]));
                    PKCS11_DEBUG("atcab_read_pubkey_ext: %x\r\n", rv);
#endif
                }
                else if (atcab_is_ta_device(dev_type))
                {
#if ATCA_TA_SUPPORT
#if PKCS11_RSA_SUPPORT_ENABLE
                    CK_UTF8CHAR pubkey_rd[PKCS11_MAX_RSA_PB_KEY_SIZE] = { 0 };
#else
                    CK_UTF8CHAR pubkey_rd[PKCS11_MAX_ECC_PB_KEY_SIZE] = { 0 };
#endif
                    cal_buffer pubkey_buf = CAL_BUF_INIT(pubkey_size, pubkey_rd);
                    CK_BYTE_PTR pubkey_buf_ptr = (CKK_EC == obj_ptr->class_type) ? &pubkey_buffer[1] : &pubkey_buffer[0];

                    if (CKR_OK == (rv = pkcs11_util_convert_rv(talib_read_element(pSession->slot->device_ctx, obj_ptr->slot, &pubkey_buf))))
                    {
                        (void)memcpy(pubkey_buf_ptr, pubkey_rd, pubkey_size);
                    }
                    PKCS11_DEBUG("talib_read_element: %x\r\n", rv);
#endif
                }
                else
                {
                    rv = CKR_GENERAL_ERROR;
                }
            }
            if (CKR_OK == rv)
            {
                rv = pkcs11_util_convert_rv(atcac_sw_sha1(pubkey_buffer, (CKK_EC == obj_ptr->class_type) ? (ATCA_ECC_UNCOMPRESSED_TYPE_OFFSET + pubkey_size) : (pubkey_size), key_id_buffer));
            }
        }
        else
        {
            rv = CKR_ARGUMENTS_BAD;
        }

    }
    return rv;
}

#if defined(ATCA_HEAP)
/* Loads keys into cache list*/
static CK_RV pkcs11_key_load_key_id_cache(const pkcs11_session_ctx_ptr pSession, const pkcs11_object_ptr pObject,
                                          pkcs11_key_cache_fields_t** pkcs11_key_cache_item)
{
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if ((NULL != pkcs11_key_cache_item) && (pObject->class_type == CKK_EC || pObject->class_type == CKK_RSA))
    {
        CK_ULONG i;

        //Check if KEY ID has been cached already for the public key object
        if (NULL == pObject->data)
        {
            rv = CKR_HOST_MEMORY;
            /* Find free key ID cache slot*/
            for (i = 0U; i < PKCS11_MAX_KEYS_CACHED; i++)
            {
                //Check for free slots
                if (FALSE == pkcs11_key_cache_list[i].in_use)
                {
                    break;
                }
            }

            if (i < PKCS11_MAX_KEYS_CACHED)
            {
                /* Allocate key ID object memory */
                uint8_t *key_id_object_ptr = pkcs11_os_malloc(ATCA_SHA1_DIGEST_SIZE);

                if (NULL != key_id_object_ptr)
                {
                    (void)memset(key_id_object_ptr, 0, ATCA_SHA1_DIGEST_SIZE);
                    //Read public key from device
                    //calculate SHA1
                    rv = pkcs11_key_calc_key_id(pSession, pObject, key_id_object_ptr);
                    if (CKR_OK == rv)
                    {
                        pObject->data = key_id_object_ptr;
                        /* Link key ID buffer to cache list and object */
                        pkcs11_key_cache_list[i].key_id_hash.pValue = pkcs11_os_malloc(ATCA_SHA1_DIGEST_SIZE);
                        pkcs11_key_cache_list[i].key_id_hash.ulValueLen = ATCA_SHA1_DIGEST_SIZE;
                        (void)memcpy(pkcs11_key_cache_list[i].key_id_hash.pValue, key_id_object_ptr, ATCA_SHA1_DIGEST_SIZE);
                        pkcs11_key_cache_list[i].in_use = TRUE;
                        pkcs11_key_cache_list[i].pSession_key = pSession;
                        pkcs11_key_cache_list[i].pObject_key = pObject;
                        *pkcs11_key_cache_item = &pkcs11_key_cache_list[i];
                    }
                    else
                    {
                        pkcs11_os_free(key_id_object_ptr);
                    }
                }
            }
        }
        else
        {
            rv = CKR_GENERAL_ERROR;
            for (i = 0U; i < PKCS11_MAX_KEYS_CACHED; i++)
            {
                if ((pkcs11_key_cache_list[i].pSession_key == pSession) &&
                    (pkcs11_key_cache_list[i].pObject_key == pObject))
                {
                    *pkcs11_key_cache_item = &pkcs11_key_cache_list[i];
                    rv = CKR_OK;
                    break;
                }
            }
        }
    }
    return rv;
}
#endif

static CK_RV pkcs11_key_get_key_id(CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, pkcs11_session_ctx_ptr session_ctx)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    //Check if object allocated and a valid session
    if (NULL != obj_ptr && NULL != session_ctx)
    {
#if PKCS11_AUTO_ID_ENABLE
        //Check if attribute fields are valid and required buffer allocated
        if (NULL != pAttribute->pValue)
        {
#ifdef ATCA_HEAP
            pkcs11_key_cache_fields_t *pkcs11_key_cache_item = NULL;
            //Check if calculated key ID can be read from cache list
            if (CKR_OK == (rv = pkcs11_key_load_key_id_cache(session_ctx, obj_ptr, &pkcs11_key_cache_item)))
            {
                return pkcs11_attrib_fill(pAttribute, pkcs11_key_cache_item->key_id_hash.pValue, pkcs11_key_cache_item->key_id_hash.ulValueLen);
            }
            else
#endif
            {
                CK_BYTE key_id[ATCA_SHA1_DIGEST_SIZE] = { 0x0 };

                //Read public key from device and calculate key id
                if (CKR_OK == pkcs11_key_calc_key_id(session_ctx, obj_ptr, key_id))
                {
                    rv = pkcs11_attrib_fill(pAttribute, key_id, (CK_BYTE)ATCA_SHA1_DIGEST_SIZE);
                }
                else
                {
                    rv = pkcs11_attrib_empty(pObject, pAttribute, NULL);
                }
            }
        }
        else
        {
            rv = pkcs11_attrib_fill(pAttribute, NULL, (CK_BYTE)ATCA_SHA1_DIGEST_SIZE);
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
    { CKA_CLASS,              pkcs11_object_get_class                                           },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,              pkcs11_attrib_true                                                },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,            pkcs11_attrib_false                                               },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,         pkcs11_token_get_writable                                         },
    /** Description of the object(default empty). */
    { CKA_LABEL,              pkcs11_object_get_name                                            },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,           pkcs11_attrib_false                                               },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,        pkcs11_object_get_destroyable                                     },
    /** Type of key */
    { CKA_KEY_TYPE,           pkcs11_object_get_type                                            },
    /** Key identifier for key (default empty) */
    { CKA_ID,                 pkcs11_key_get_key_id                                             },
    /** Start date for the key (default empty) */
    { CKA_START_DATE,         pkcs11_attrib_empty                                               },
    /** End date for the key (default empty) */
    { CKA_END_DATE,           pkcs11_attrib_empty                                               },
    /** CK_TRUE if key supports key derivation (i.e., if other keys can be derived from this one (default CK_FALSE) */
    { CKA_DERIVE,             pkcs11_key_get_derivekey_flag                                     },
    /** CK_TRUE only if key was either generated locally (i.e., on the token)
       with a C_GenerateKey or C_GenerateKeyPair call created with a C_CopyObject
       call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE */
    { CKA_LOCAL,              pkcs11_attrib_true                                                },
    /** Identifier of the mechanism used to generate the key material. */
    { CKA_KEY_GEN_MECHANISM,  NULL_PTR                                                          },
    /** A list of mechanisms allowed to be used with this key. The number of
       mechanisms in the array is the ulValueLen component of the attribute
       divided by the size of CK_MECHANISM_TYPE. */
    { CKA_ALLOWED_MECHANISMS, pkcs11_key_get_allowed_mechanisms                                 },
    /** DER-encoding of the key subject name (default empty) */
    { CKA_SUBJECT,            pkcs11_attrib_empty                                               },
    /** CK_TRUE if key supports encryption */
    { CKA_ENCRYPT,            NULL_PTR                                                          },
    /** CK_TRUE if key supports verification where the signature is an appendix to the data */
    { CKA_VERIFY,             pkcs11_attrib_true                                                },
    /** CK_TRUE if key supports verification where the data is recovered from the signature */
    { CKA_VERIFY_RECOVER,     NULL_PTR                                                          },
    /** CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys) */
    { CKA_WRAP,               NULL_PTR                                                          },
    /** The key can be trusted for the application that it was created. The
        wrapping key can be used to wrap keys with CKA_WRAP_WITH_TRUSTED set
        to CK_TRUE. */
    { CKA_TRUSTED,            NULL_PTR                                                          },
    /** For wrapping keys. The attribute template to match against any keys
        wrapped using this wrapping key. Keys that do not match cannot be
        wrapped. The number of attributes in the array is the ulValueLen
        component of the attribute divided by the size of CK_ATTRIBUTE. */
    { CKA_WRAP_TEMPLATE,      NULL_PTR                                                          },
    /** DER-encoding of the SubjectPublicKeyInfo for this public key.
        (MAY be empty, DEFAULT derived from the underlying public key data)
        SubjectPublicKeyInfo ::= SEQUENCE {
            algorithm AlgorithmIdentifier,
            subjectPublicKey BIT_STRING } */
    { CKA_PUBLIC_KEY_INFO,    pkcs11_key_get_public_key                                         },

    /** DER - encoding of an ANSI X9.62 Parameters value
        Parameters ::= CHOICE {
            ecParameters ECParameters,
            namedCurve CURVES.&id({CurveNames}),
            implicitlyCA NULL } */
    { CKA_EC_PARAMS,          pkcs11_key_get_ec_params                                          },
    /** DER - encoding of ANSI X9.62 ECPoint value Q */
    { CKA_EC_POINT,           pkcs11_key_get_ec_point                                           },
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
    /** Big integer - Modulus n */
    { CKA_MODULUS,            pkcs11_key_get_modulus                                            },
    /** CK_ULONG - Length in bits of modulus n */
    { CKA_MODULUS_BITS,       pkcs11_key_get_modulus_bits                                       },
    /** Big integer - Public exponent e */
    { CKA_PUBLIC_EXPONENT,    pkcs11_key_get_public_exponent                                    },
#endif
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
    { CKA_EC_PARAMS, pkcs11_key_get_ec_params   },
    /** DER - encoding of ANSI X9.62 ECPoint value Q */
    { CKA_EC_POINT,  pkcs11_key_get_ec_point    },
};
#endif
/**
 * CKO_PRIVATE_KEY - Private Key Object Base Model
 */
const pkcs11_attrib_model pkcs11_key_private_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,               pkcs11_object_get_class                                             },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,               pkcs11_attrib_true                                                  },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,             pkcs11_attrib_true                                                  },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,          pkcs11_token_get_writable                                           },
    /** Description of the object(default empty). */
    { CKA_LABEL,               pkcs11_object_get_name                                              },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,            pkcs11_attrib_false                                                 },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,         pkcs11_object_get_destroyable                                       },
    /** Type of key */
    { CKA_KEY_TYPE,            pkcs11_object_get_type                                              },
    /** Key identifier for key (default empty) */
    { CKA_ID,                  pkcs11_key_get_key_id                                               },
    /** Start date for the key (default empty) */
    { CKA_START_DATE,          pkcs11_attrib_empty                                                 },
    /** End date for the key (default empty) */
    { CKA_END_DATE,            pkcs11_attrib_empty                                                 },
    /** CK_TRUE if key supports key derivation (i.e., if other keys can be derived from this one (default CK_FALSE) */
    { CKA_DERIVE,              pkcs11_key_get_derivekey_flag                                       },
    /** CK_TRUE only if key was either generated locally (i.e., on the token)
       with a C_GenerateKey or C_GenerateKeyPair call created with a C_CopyObject
       call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE */
    { CKA_LOCAL,               pkcs11_key_get_local_flag                                           },
    /** Identifier of the mechanism used to generate the key material. */
    { CKA_KEY_GEN_MECHANISM,   NULL_PTR                                                            },
    /** A list of mechanisms allowed to be used with this key. The number of
       mechanisms in the array is the ulValueLen component of the attribute
       divided by the size of CK_MECHANISM_TYPE. */
    { CKA_ALLOWED_MECHANISMS,  pkcs11_key_get_allowed_mechanisms                                   },
    /** DER-encoding of the key subject name (default empty) */
    { CKA_SUBJECT,             pkcs11_attrib_empty                                                 },
    /** CK_TRUE if key is sensitive */
    { CKA_SENSITIVE,           pkcs11_token_get_access_type                                        },
    /** CK_TRUE if key supports decryption */
    { CKA_DECRYPT,             NULL_PTR                                                            },
    /** CK_TRUE if key supports signatures where the signature is an appendix to the data */
    { CKA_SIGN,                pkcs11_attrib_true                                                  },
    /** CK_TRUE if key supports signatures where the data can be recovered from the signature9 */
    { CKA_SIGN_RECOVER,        NULL_PTR                                                            },
    /** CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys)9 */
    { CKA_UNWRAP,              NULL_PTR                                                            },
    /** CK_TRUE if key is extractable and can be wrapped */
    { CKA_EXTRACTABLE,         pkcs11_attrib_false                                                 },
    /** CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE */
    { CKA_ALWAYS_SENSITIVE,    pkcs11_token_get_access_type                                        },
    /** CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE */
    { CKA_NEVER_EXTRACTABLE,   pkcs11_token_get_access_type                                        },
    /** CK_TRUE if the key can only be wrapped with a wrapping key that has CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE. */
    { CKA_WRAP_WITH_TRUSTED,   NULL_PTR                                                            },
    /** For wrapping keys. The attribute template to match against any keys
        wrapped using this wrapping key. Keys that do not match cannot be
        wrapped. The number of attributes in the array is the ulValueLen
        component of the attribute divided by the size of CK_ATTRIBUTE. */
    { CKA_UNWRAP_TEMPLATE,     NULL_PTR                                                            },
    /** If CK_TRUE, the user has to  supply the PIN for each use (sign or decrypt) with the key. Default is CK_FALSE. */
    { CKA_ALWAYS_AUTHENTICATE, pkcs11_key_auth_required                                            },
    /** DER-encoding of the SubjectPublicKeyInfo for the associated public key
        (MAY be empty; DEFAULT derived from the underlying private key data;
        MAY be manually set for specific key types; if set; MUST be consistent
        with the underlying private key data)   */
    { CKA_PUBLIC_KEY_INFO,     pkcs11_key_get_public_key                                           },
    /** DER - encoding of an ANSI X9.62 Parameters value
        Parameters ::= CHOICE {
            ecParameters ECParameters,
            namedCurve CURVES.&id({CurveNames}),
            implicitlyCA NULL } */
    { CKA_EC_PARAMS,           pkcs11_key_get_ec_params                                            },
    /** DER - encoding of ANSI X9.62 ECPoint value Q */
    { CKA_EC_POINT,            pkcs11_key_get_ec_point                                             },
    /** The value of the private key should remain private.  A NULL function pointer is interpreted as a sensitive attribute. */
    { CKA_VALUE,               NULL_PTR                                                            },
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
    /** Big integer - Modulus n */
    { CKA_MODULUS,             pkcs11_key_get_modulus                                              },
    /** Big integer - Public exponent e */
    { CKA_PUBLIC_EXPONENT,     pkcs11_key_get_public_exponent                                      },
    /** Big integer - Private exponent d */
    { CKA_PRIVATE_EXPONENT,    NULL_PTR                                                            },
    /** Big integer - Prime p */
    { CKA_PRIME_1,             NULL_PTR                                                            },
    /** Big integer - Prime q */
    { CKA_PRIME_2,             NULL_PTR                                                            },
    /** Big integer - Private exponent d modulo p-1 */
    { CKA_EXPONENT_1,          NULL_PTR                                                            },
    /** Big integer - Private exponent d modulo q-1 */
    { CKA_EXPONENT_2,          NULL_PTR                                                            },
    /** Big integer -  CRT coefficient q-1 mod p */
    { CKA_COEFFICIENT,         NULL_PTR                                                            },
#endif
};

const CK_ULONG pkcs11_key_private_attributes_count = (CK_ULONG)(PKCS11_UTIL_ARRAY_SIZE(pkcs11_key_private_attributes));

/**
 * CKO_SECRET_KEY - Secret Key Object Base Model
 */
const pkcs11_attrib_model pkcs11_key_secret_attributes[] = {
    /** Object Class - CK_OBJECT_CLASS */
    { CKA_CLASS,              pkcs11_object_get_class                                           },
    /** CK_TRUE if object is a token object; CK_FALSE if object is a session object. Default is CK_FALSE. */
    { CKA_TOKEN,              pkcs11_token_get_storage                                          },
    /** CK_TRUE if object is a private object; CK_FALSE if object is a public object. */
    { CKA_PRIVATE,            pkcs11_token_get_access_type                                      },
    /** CK_TRUE if object can be modified. Default is CK_TRUE. */
    { CKA_MODIFIABLE,         pkcs11_token_get_writable                                         },
    /** Description of the object(default empty). */
    { CKA_LABEL,              pkcs11_object_get_name                                            },
    /** CK_TRUE if object can be copied using C_CopyObject.Defaults to CK_TRUE. */
    { CKA_COPYABLE,           pkcs11_attrib_false                                               },
    /** CK_TRUE if the object can be destroyed using C_DestroyObject. Default is CK_TRUE. */
    { CKA_DESTROYABLE,        pkcs11_object_get_destroyable                                     },
    /** Type of key */
    { CKA_KEY_TYPE,           pkcs11_object_get_type                                            },
    /** Key identifier for key (default empty) */
    { CKA_ID,                 pkcs11_attrib_empty                                               },
    /** Start date for the key (default empty) */
    { CKA_START_DATE,         pkcs11_attrib_empty                                               },
    /** End date for the key (default empty) */
    { CKA_END_DATE,           pkcs11_attrib_empty                                               },
    /** CK_TRUE if key supports key derivation (i.e., if other keys can be derived from this one (default CK_FALSE) */
    { CKA_DERIVE,             pkcs11_attrib_true                                                },
    /** CK_TRUE only if key was either generated locally (i.e., on the token)
       with a C_GenerateKey or C_GenerateKeyPair call created with a C_CopyObject
       call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE */
    { CKA_LOCAL,              pkcs11_key_get_local_flag                                         },
    /** Identifier of the mechanism used to generate the key material. */
    { CKA_KEY_GEN_MECHANISM,  NULL_PTR                                                          },
    /** A list of mechanisms allowed to be used with this key. The number of
       mechanisms in the array is the ulValueLen component of the attribute
       divided by the size of CK_MECHANISM_TYPE. */
    { CKA_ALLOWED_MECHANISMS, pkcs11_key_get_allowed_mechanisms                                 },
    /** CK_TRUE if key is sensitive */
    { CKA_SENSITIVE,          pkcs11_token_get_access_type                                      },
    /** CK_TRUE if key supports encryption */
    { CKA_ENCRYPT,            NULL_PTR                                                          },
    /** CK_TRUE if key supports decryption */
    { CKA_DECRYPT,            NULL_PTR                                                          },
    /** CK_TRUE if key supports signatures (i.e., authentication codes) where
        the signature is an appendix to the data */
    { CKA_SIGN,               NULL_PTR                                                          },
    /** CK_TRUE if key supports verification (i.e., of authentication codes)
        where the signature is an appendix to the data */
    { CKA_VERIFY,             NULL_PTR                                                          },
    /** CK_TRUE if key supports wrapping (i.e., can be used to wrap other keys)  */
    { CKA_WRAP,               NULL_PTR                                                          },
    /** CK_TRUE if key supports unwrapping (i.e., can be used to unwrap other keys) */
    { CKA_UNWRAP,             NULL_PTR                                                          },
    /** CK_TRUE if key is extractable and can be wrapped */
    { CKA_EXTRACTABLE,        pkcs11_attrib_false                                               },
    /** CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE */
    { CKA_ALWAYS_SENSITIVE,   pkcs11_token_get_access_type                                      },
    /** CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE  */
    { CKA_NEVER_EXTRACTABLE,  pkcs11_token_get_access_type                                      },
    /** Key checksum */
    { CKA_CHECK_VALUE,        pkcs11_key_get_check_value                                        },
    /** CK_TRUE if the key can only be wrapped with a wrapping key that has CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE. */
    { CKA_WRAP_WITH_TRUSTED,  NULL_PTR                                                          },
    /**  The wrapping key can be used to wrap keys with CKA_WRAP_WITH_TRUSTED set to CK_TRUE. */
    { CKA_TRUSTED,            NULL_PTR                                                          },
    /** For wrapping keys. The attribute template to match against any keys
        wrapped using this wrapping key. Keys that do not match cannot be
        wrapped. The number of attributes in the array is the ulValueLen
        component of the attribute divided by the size of CK_ATTRIBUTE */
    { CKA_WRAP_TEMPLATE,      NULL_PTR                                                          },
    /** For wrapping keys. The attribute template to apply to any keys unwrapped
        using this wrapping key. Any user supplied template is applied after
        this template as if the object has already been created. The number of
        attributes in the array is the ulValueLen component of the attribute
        divided by the size of CK_ATTRIBUTE.  */
    { CKA_UNWRAP_TEMPLATE,    NULL_PTR                                                          },
    /* Key value */
    { CKA_VALUE,              pkcs11_key_get_secret                                             },
    /* Length in bytes of the key */
    { CKA_VALUE_LEN,          pkcs11_key_get_secret_length                                      },
};

const CK_ULONG pkcs11_key_secret_attributes_count = (CK_ULONG)(PKCS11_UTIL_ARRAY_SIZE(pkcs11_key_secret_attributes));

#if ATCA_CA_SUPPORT
static CK_RV pkcs11_key_privwrite_ca(CK_VOID_PTR pSession, pkcs11_object_ptr pObject, CK_VOID_PTR pValue, CK_ULONG ulValueLen)
{

    CK_RV rv = CKR_ARGUMENTS_BAD;

    if (NULL != pSession && NULL != pObject && NULL != pValue && 0u != ulValueLen)
    {
        pkcs11_session_ctx_ptr session_ctx = (pkcs11_session_ctx_ptr)pSession;
        if (atcab_is_ca_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)))
        {
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
            rv = pkcs11_util_convert_rv(calib_priv_write(session_ctx->slot->device_ctx, pObject->slot, key_buf, write_key_id, session_ctx->slot->read_key,
                                                         num_in));
        }
    }

    return rv;
}
#endif

CK_RV pkcs11_key_write(CK_VOID_PTR pSession, CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute)
{
    pkcs11_object_ptr obj_ptr = (pkcs11_object_ptr)pObject;
    CK_RV rv = CKR_ARGUMENTS_BAD;

    if ((NULL != obj_ptr) && (NULL != pAttribute) && (NULL != pAttribute->pValue) && (NULL != pSession))
    {
        pkcs11_session_ctx_ptr session_ctx = (pkcs11_session_ctx_ptr)pSession;
        if (obj_ptr->class_id == CKO_PUBLIC_KEY && (pAttribute->type == CKA_EC_POINT || pAttribute->type == CKA_MODULUS))
        {
            const pkcs11_key_info_t *key_data = pkcs11_get_object_key_type(session_ctx->slot->device_ctx, obj_ptr);

            if (NULL != key_data)
            {
                CK_BBOOL is_private;

                /* coverity[misra_c_2012_rule_21_16_violation:FALSE] CK_VOID_PTR is a pointer type */
                if ((CKK_EC == obj_ptr->class_type) && (0 != memcmp((CK_BYTE_PTR)key_data->ecc_key_info->ec_x962_asn1_header, (CK_BYTE_PTR)pAttribute->pValue, PKCS11_X962_ASN1_HEADER_SZ)))
                {
                    return CKR_ARGUMENTS_BAD;
                }

                if (CKR_OK == (rv = pkcs11_object_is_private(obj_ptr, &is_private, session_ctx)))
                {
                    if (is_private)
                    {
                        /* Assume it is paired with the private key that is already stored */
                        rv = CKR_OK;
                    }
                    else
                    {
                        ATCADeviceType device_type = atcab_get_device_type_ext(session_ctx->slot->device_ctx);

                        /* Actually write the public key into the slot */
                        if (atcab_is_ca_device(device_type))
                        {
#if ATCA_CA_SUPPORT
                            rv = pkcs11_util_convert_rv(atcab_write_pubkey_ext(session_ctx->slot->device_ctx, obj_ptr->slot,
                                                                                &(((uint8_t*)pAttribute->pValue)[PKCS11_X962_ASN1_HEADER_SZ])));
#endif
                        }
                        else if (atcab_is_ta_device(device_type))
                        {
#if ATCA_TA_SUPPORT
#if PKCS11_RSA_SUPPORT_ENABLE
                            CK_UTF8CHAR pubkey[PKCS11_MAX_RSA_PB_KEY_SIZE] = { 0 };
#else
                            CK_UTF8CHAR pubkey[PKCS11_MAX_ECC_PB_KEY_SIZE] = { 0 };
#endif

                            cal_buffer pbkey_buf = {0u, pubkey};

                            if (CKK_EC == obj_ptr->class_type)
                            {
                                pbkey_buf.len = key_data->ecc_key_info->pubkey_sz;
                            }
#if PKCS11_RSA_SUPPORT_ENABLE
                            else
                            {
                                pbkey_buf.len = key_data->rsa_key_info->pubkey_sz;
                            }
#endif
                            (void)memcpy(pubkey, &(((CK_BYTE_PTR)pAttribute->pValue)[0]), pAttribute->ulValueLen);
                            rv = pkcs11_util_convert_rv(talib_write_element(session_ctx->slot->device_ctx, obj_ptr->slot, &pbkey_buf));
#endif
                        }
                        else
                        {
                            rv = CKR_KEY_SIZE_RANGE;
                        }
                    }
                }
            }
        }
        else if (obj_ptr->class_id == CKO_PRIVATE_KEY && (pAttribute->type == CKA_VALUE || pAttribute->type == CKA_MODULUS))
        {
#if ATCA_CA_SUPPORT
            if (atcab_is_ca_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)))
            {
                rv = pkcs11_key_privwrite_ca(pSession, obj_ptr, pAttribute->pValue, pAttribute->ulValueLen);
            }
            else
#endif
            {
                rv = CKR_OK;
            }
        }
        else if (obj_ptr->class_id == CKO_SECRET_KEY && pAttribute->type == CKA_VALUE)
        {
            if (atcab_is_ca_device(atcab_get_device_type_ext(session_ctx->slot->device_ctx)) && ((pAttribute->ulValueLen % 32u) != 0u))
            {
#if ATCA_CA_SUPPORT
                uint8_t buf[64] = { 0 };
                uint16_t buflen = (uint16_t)((0u != (pAttribute->ulValueLen / 32u)) ? 64u : 32u);
                if (pAttribute->ulValueLen > 64u)
                {
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                (void)memcpy(buf, pAttribute->pValue, pAttribute->ulValueLen);
                rv = pkcs11_util_convert_rv(atcab_write_bytes_zone_ext(session_ctx->slot->device_ctx, ATCA_ZONE_DATA, obj_ptr->slot, 0, buf, buflen));
#endif
            }
            else
            {
                rv = pkcs11_util_convert_rv(atcab_write_bytes_zone_ext(session_ctx->slot->device_ctx, ATCA_ZONE_DATA, obj_ptr->slot, 0,
                                                                       (uint8_t*)pAttribute->pValue,
                                                                       pAttribute->ulValueLen));
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
    CK_SESSION_HANDLE       hSession,
    CK_MECHANISM_PTR        pMechanism,
    CK_ATTRIBUTE_PTR        pTemplate,
    CK_ULONG                ulCount,
    CK_OBJECT_HANDLE_PTR    phKey
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

    /* Must create object for secret key*/

    rv = pkcs11_object_alloc(pSession->slot->slot_id, &pKey);

    if (CKR_OK == rv)
    {
        pKey->class_id = CKO_SECRET_KEY;
        #if ATCA_TA_SUPPORT
        status = talib_handle_init_symmetric_key(&pKey->handle_info, TA_KEY_TYPE_AES128, TA_PROP_SYMM_KEY_USAGE_ANY);
        #endif
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
    CK_SESSION_HANDLE       hSession,
    CK_MECHANISM_PTR        pMechanism,
    CK_ATTRIBUTE_PTR        pPublicKeyTemplate,
    CK_ULONG                ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR        pPrivateKeyTemplate,
    CK_ULONG                ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR    phPublicKey,
    CK_OBJECT_HANDLE_PTR    phPrivateKey
)
{
    CK_ATTRIBUTE_PTR pLabel = NULL;
    CK_OBJECT_CLASS_PTR pClass = NULL;
    CK_ATTRIBUTE_PTR pData = NULL;
    pkcs11_lib_ctx_ptr pLibCtx;
    pkcs11_session_ctx_ptr pSession;
    pkcs11_object_ptr pPublic = NULL;
    pkcs11_object_ptr pPrivate = NULL;
    CK_ULONG i;
    CK_RV rv = CKR_OK;
    CK_BBOOL isRsa = false;
    CK_ULONG keyTableIdx = 0;
    CK_BBOOL matched = false;

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

    if ((CKM_EC_KEY_PAIR_GEN != pMechanism->mechanism) && (CKM_RSA_PKCS_KEY_PAIR_GEN != pMechanism->mechanism))
    {
        return CKR_MECHANISM_INVALID;
    }

    isRsa = (CKM_RSA_PKCS_KEY_PAIR_GEN == pMechanism->mechanism) ? true : false;

    /* Look for supported/mandatory attributes */
    for (i = 0; i < ulPrivateKeyAttributeCount; i++)
    {
        switch (pPrivateKeyTemplate[i].type)
        {
        case CKA_LABEL:
            pLabel = &pPrivateKeyTemplate[i];
            break;
        case CKA_CLASS:
            pClass = pPrivateKeyTemplate[i].pValue;
            break;
        case CKA_EC_PARAMS:
            pData = &pPrivateKeyTemplate[i];
            break;
        default:
            break;
        }
    }

#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
    if (true == isRsa)
    {
        for (i = 0; i < ulPublicKeyAttributeCount; i++)
        {
            if (CKA_MODULUS_BITS == pPublicKeyTemplate[i].type)
            {
                pData = &pPublicKeyTemplate[i];
                break;
            }
        }
    }
#endif

    if (NULL == pLabel || pLabel->ulValueLen > (CK_ULONG)PKCS11_MAX_LABEL_SIZE)
    {
        PKCS11_DEBUG("pLabel is NULL\r\n");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    if (NULL == pClass || (CKO_PRIVATE_KEY) != *pClass)
    {
        PKCS11_DEBUG("pClass is NULL\r\n");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    if (NULL == pData || pData->ulValueLen == 0u)
    {
        PKCS11_DEBUG("pData is NULL\r\n");
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
        if(false == isRsa)
        {
            CK_BYTE keyTableSz = (CK_BYTE)(sizeof(ec_key_data_table) / sizeof(ec_key_data_table[0]));
            for (i = 0; i < keyTableSz; i++)
            {
                /* coverity[misra_c_2012_rule_21_16_violation:FALSE] CK_VOID_PTR is a pointer type */
                if (0 == memcmp((CK_BYTE_PTR)ec_key_data_table[i].curve_oid, (CK_BYTE_PTR)pData->pValue, pData->ulValueLen))
                {
                    //Key OID matched and we got the private key type
                    keyTableIdx = i;
                    matched = true;
                    break;
                }
            }
        }
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
        else
        {
            CK_BYTE keyTableSz = (CK_BYTE)(sizeof(rsa_key_data_table) / sizeof(rsa_key_data_table[0]));
            for (i = 0; i < keyTableSz; i++)
            {
                if (rsa_key_data_table[i].rsa_modulus_bits == *((CK_ULONG_PTR)pData->pValue))
                {
                    //Modulus size in bits matched and we got the private key type
                    keyTableIdx = i;
                    matched = true;
                    break;
                }
            }
        }
#endif

        if (false == matched)
        {
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
#if ATCA_TA_SUPPORT
        else
        {
#if PKCS11_RSA_SUPPORT_ENABLE
            if (true == isRsa)
            {
                if (TA_KEY_TYPE_RSA1024 == rsa_key_data_table[keyTableIdx].rsa_key_type)
                {
                    rv = CKR_DEVICE_ERROR;
                }
                else
                {
                    (void)talib_handle_init_private_key(&pPrivate->handle_info, rsa_key_data_table[keyTableIdx].rsa_key_type, TA_ALG_MODE_RSA_SSA_1_5, TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_KEY_AGREEMENT_OUT_BUFF);
                }
            }
            else
#endif
            {
                (void)talib_handle_init_private_key(&pPrivate->handle_info, ec_key_data_table[keyTableIdx].ec_key_type, TA_ALG_MODE_ECC_ECDSA, TA_PROP_SIGN_INT_EXT_DIGEST, TA_PROP_KEY_AGREEMENT_OUT_BUFF);
            }
        }
#endif
        if (CKR_OK == rv)
        {
            rv = pkcs11_config_key(pLibCtx, pSession->slot, pPrivate, pLabel);
        }
    }

    if (CKR_OK == rv)
    {
        pPublic->slot = pPrivate->slot;
        pPublic->flags = pPrivate->flags;
        (void)memcpy(pPublic->name, pLabel->pValue, pLabel->ulValueLen);
        pPublic->class_id = CKO_PUBLIC_KEY;
        pPublic->attributes = pkcs11_key_public_attributes;
        pPublic->count = pkcs11_key_public_attributes_count;
#if ATCA_CA_SUPPORT
        pPublic->config = &((pkcs11_slot_ctx_ptr)pSession->slot)->cfg_zone;
#endif
#if ATCA_TA_SUPPORT && PKCS11_RSA_SUPPORT_ENABLE
        if (true == isRsa)
        {
            pPublic->class_type = CKK_RSA;
            pPublic->size = rsa_key_data_table[keyTableIdx].pubkey_sz;
        }
        else
#endif
        {
            pPublic->class_type = CKK_EC;
            pPublic->size = ec_key_data_table[keyTableIdx].pubkey_sz;
        }

        if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
        {
            ATCADeviceType dev_type = atcab_get_device_type_ext(pSession->slot->device_ctx);
            if (atcab_is_ca_device(dev_type))
            {
#if ATCA_CA_SUPPORT
                rv = pkcs11_util_convert_rv(atcab_genkey_ext(pSession->slot->device_ctx, pPrivate->slot, NULL));
#endif
            }
            else if (atcab_is_ta_device(dev_type))
            {
#if ATCA_TA_SUPPORT
                rv = pkcs11_util_convert_rv(talib_genkey(pSession->slot->device_ctx, pPrivate->slot, NULL));
#endif
            }
            else
            {
                /* do nothing */
            }

            //If public key generation is success , means corresponding private key is good
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

#if defined(ATCA_NO_HEAP) && ATCA_CA_SUPPORT
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

#if ATCA_CA_SUPPORT
static CK_RV pkcs11_key_derive_ca(pkcs11_session_ctx_ptr pSession, pkcs11_object_ptr pBaseKey, pkcs11_object_ptr pSecretKey,
                                  CK_ECDH1_DERIVE_PARAMS_PTR pEcdhParameters)
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
            pkcs11_lib_ctx_ptr pLibCtx = pkcs11_get_context();

            if (atcab_is_ca_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
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
                            status = calib_ecdh_tempkey_ioenc(pSession->slot->device_ctx, &pEcdhParameters->pPublicData[1], (uint8_t*)pSecretKey->data,
                                                              pSession->slot->read_key);
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
                            status = calib_ecdh_ioenc(pSession->slot->device_ctx, pBaseKey->slot, &pEcdhParameters->pPublicData[1], (uint8_t*)pSecretKey->data,
                                                      pSession->slot->read_key);
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
            }
            rv = pkcs11_util_convert_rv(status);
        }
    }

    return rv;
}
#endif

#if ATCA_TA_SUPPORT
static CK_RV pkcs11_key_derive_ta(pkcs11_session_ctx_ptr pSession, pkcs11_object_ptr pBaseKey, pkcs11_object_ptr pSecretKey,
                                  CK_ECDH1_DERIVE_PARAMS_PTR pEcdhParameters)
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
            pkcs11_lib_ctx_ptr pLibCtx = pkcs11_get_context();
            if (atcab_is_ta_device(atcab_get_device_type_ext(pSession->slot->device_ctx)))
            {
                if (CKR_OK == (rv = pkcs11_lock_both(pLibCtx)))
                {
                    status = talib_ecdh_compat(pSession->slot->device_ctx, pBaseKey->slot, &pEcdhParameters->pPublicData[1], (uint8_t*)pSecretKey->data);
                    (void)pkcs11_unlock_both(pLibCtx);
                }
            }
            rv = pkcs11_util_convert_rv(status);
        }
    }

    return rv;
}
#endif

CK_RV pkcs11_key_derive
(
    CK_SESSION_HANDLE       hSession,
    CK_MECHANISM_PTR        pMechanism,
    CK_OBJECT_HANDLE        hBaseKey,
    CK_ATTRIBUTE_PTR        pTemplate,
    CK_ULONG                ulCount,
    CK_OBJECT_HANDLE_PTR    phKey
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
#if ATCA_CA_SUPPORT
            rv = pkcs11_key_derive_ca(pSession, pBaseKey, pSecretKey, pEcdhParameters);
#endif
        }
        else
        {
#if ATCA_TA_SUPPORT
            rv = pkcs11_key_derive_ta(pSession, pBaseKey, pSecretKey, pEcdhParameters);
#endif
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

/* Called from auth session to clear the key object */
CK_RV pkcs11_key_clear_session_cache(pkcs11_session_ctx_ptr session_ctx)
{
    CK_RV rv = CKR_GENERAL_ERROR;

#if defined(ATCA_HEAP)
    CK_ULONG i;

    for (i = 0; i < PKCS11_MAX_KEYS_CACHED; i++)
    {
        if (session_ctx == pkcs11_key_cache_list[i].pSession_key)
        {
            if (NULL != pkcs11_key_cache_list[i].key_id_hash.pValue)
            {
                pkcs11_os_free(pkcs11_key_cache_list[i].key_id_hash.pValue);
                pkcs11_key_cache_list[i].key_id_hash.pValue = NULL;
                pkcs11_key_cache_list[i].in_use = FALSE;
                pkcs11_key_cache_list[i].pSession_key = NULL;
                rv = CKR_OK;
                break;
            }
        }
    }
#endif

    return rv;
}

/* Called to free certificate object */
CK_RV pkcs11_key_clear_object_cache(pkcs11_object_ptr pObject)
{
    CK_RV rv = CKR_GENERAL_ERROR;

#if defined(ATCA_HEAP)
    CK_ULONG i;

    for (i = 0; i < PKCS11_MAX_KEYS_CACHED; i++)
    {
        if (pObject == pkcs11_key_cache_list[i].pObject_key)
        {
            if (NULL != pObject->data)
            {
                pkcs11_os_free(pObject->data);
                pObject->data = NULL;
            }
            if (NULL != pkcs11_key_cache_list[i].key_id_hash.pValue)
            {
                pkcs11_os_free(pkcs11_key_cache_list[i].key_id_hash.pValue);
                pkcs11_key_cache_list[i].key_id_hash.pValue = NULL;
            }
            pkcs11_key_cache_list[i].in_use = FALSE;
            pkcs11_key_cache_list[i].pSession_key = NULL;
            pkcs11_key_cache_list[i].pObject_key = NULL;
            rv = CKR_OK;
            break;
        }
    }
#endif
    return rv;
}

/** @} */
