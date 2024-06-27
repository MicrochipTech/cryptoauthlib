/**
 * \file
 * \brief PKCS11 Library Object Handling
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

#ifndef PKCS11_KEY_H_
#define PKCS11_KEY_H_

#include "pkcs11_object.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

typedef struct pkcs11_ecc_key_info_s
{
    CK_BYTE           ec_key_type;
    CK_BYTE           oid_size;
    CK_BYTE_PTR       curve_oid;
    CK_BYTE_PTR       ec_asn1_header;
    CK_BYTE_PTR       ec_x962_asn1_header;
    uint16_t          asn1_header_sz;
    CK_ULONG          pubkey_sz;
    CK_ULONG          min_msg_sz;
    CK_ULONG          sig_sz;
}pkcs11_ecc_key_info_t;

#define PKCS11_X962_ASN1_HEADER_SZ 3u

//Maximum ASN1 Header size for the supported ECC curves (ECCP256/224/384/521)
//Set to ASN1 header size for ECCP256 which has the max size
#define PKCS11_MAX_ECC_ASN1_HDR_SIZE ATCA_ECCP256_ASN1_HDR_SIZE   

#if ATCA_TA_SUPPORT
//Max public key size supported (ECCP521) in case of TA
    #define PKCS11_MAX_ECC_PB_KEY_SIZE   TA_ECC521_PUB_KEY_SIZE
#else
//Max public key size supported (ECCP256) in case of ECC device
    #define PKCS11_MAX_ECC_PB_KEY_SIZE   ATCA_ECCP256_PUBKEY_SIZE
#endif

extern const pkcs11_ecc_key_info_t ec_key_data_table[4];
extern const pkcs11_attrib_model pkcs11_key_public_attributes[];
extern const CK_ULONG pkcs11_key_public_attributes_count;

extern const pkcs11_attrib_model pkcs11_key_private_attributes[];
extern const CK_ULONG pkcs11_key_private_attributes_count;

extern const pkcs11_attrib_model pkcs11_key_secret_attributes[];
extern const CK_ULONG pkcs11_key_secret_attributes_count;

extern CK_BYTE  pkcs11_ec_pbkey_asn1_hdr_p256[];
extern CK_BYTE  pkcs11_x962_asn1_hdr_ec256[];
extern CK_BYTE  pkcs11_key_ec_params_p256[];

#if ATCA_TA_SUPPORT
extern CK_BYTE  pkcs11_ec_pbkey_asn1_hdr_p224[];
extern CK_BYTE  pkcs11_x962_asn1_hdr_ec224[];
extern CK_BYTE  pkcs11_key_ec_params_p224[];

extern CK_BYTE  pkcs11_ec_pbkey_asn1_hdr_p384[];
extern CK_BYTE  pkcs11_x962_asn1_hdr_ec384[];
extern CK_BYTE  pkcs11_key_ec_params_p384[];

extern CK_BYTE  pkcs11_ec_pbkey_asn1_hdr_p521[];
extern CK_BYTE  pkcs11_x962_asn1_hdr_ec521[];
extern CK_BYTE  pkcs11_key_ec_params_p521[];
#endif
CK_RV pkcs11_key_write(CK_VOID_PTR pSession, CK_VOID_PTR pObject, CK_ATTRIBUTE_PTR pAttribute, const pkcs11_ecc_key_info_t *ec_key_info);
CK_RV pkcs11_key_generate(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
                          CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV pkcs11_key_generate_pair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                               CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
                               CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
                               CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
CK_RV pkcs11_key_derive(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
CK_RV pkcs11_key_clear_session_cache(pkcs11_session_ctx_ptr session_ctx);
CK_RV pkcs11_key_clear_object_cache(pkcs11_object_ptr pObject);
const pkcs11_ecc_key_info_t* pkcs11_get_object_key_type(ATCADevice device_ctx, pkcs11_object_ptr obj_ptr);
#if ATCA_TA_SUPPORT
CK_RV pkcs11_ta_get_pubkey(CK_VOID_PTR pObject, cal_buffer *key_buffer, pkcs11_session_ctx_ptr session_ctx);
#endif
#endif /* PKCS11_KEY_H_ */
