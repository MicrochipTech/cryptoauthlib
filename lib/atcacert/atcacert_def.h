/**
 * \file
 * \brief Declarations for certificates related to ECC CryptoAuthentication devices.
 * These are the definitions required to define a certificate and its various
 * elements with regards to the CryptoAuthentication ECC devices.
 *
 * Only the dynamic elements of a certificate (the parts of the certificate
 * that change from device to device) are stored on the ATECC device. The
 * definitions here describe the form of the certificate, and where the
 * dynamic elements can be found both on the ATECC device itself and in the
 * certificate template.
 *
 * This also defines utility functions for working with the certificates and their definitions.
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


#ifndef ATCACERT_DEF_H
#define ATCACERT_DEF_H

#include <stddef.h>
#include <stdint.h>
#include "atca_compiler.h"
#include "atcacert.h"
#include "atcacert_date.h"
#include "atca_helpers.h"
#include "crypto/atca_crypto_sw.h"
#include "cal_buffer.h"

#define ATCA_MAX_TRANSFORMS 2

#define CA_DEV_SN_SIZE                          9u
#define CA2_DEV_SN_SIZE_PART_1                  4u
#define CA2_DEV_SN_SIZE_PART_2                  5u

#define CA_DEV_SN_CONFIG_ZONE_OFFSET            0u
#define CA2_DEV_SN_CONFIG_ZONE_OFFSET_PART_1    0u
#define CA2_DEV_SN_CONFIG_ZONE_OFFSET_PART_2    8u
#define TA_DEV_SN_DEDICATED_DATA_ZONE_OFFSET    0u

/** \defgroup atcacert_ Certificate manipulation methods (atcacert_)
 *
 * \brief
 * These methods provide convenient ways to perform certification I/O with
 * CryptoAuth chips and perform certificate manipulation in memory
 *
   @{ */

/**
 * Types of certificates.
 */
typedef enum atcacert_cert_type_e
{
    CERTTYPE_X509,              //!< Standard X509 certificate
    CERTTYPE_CUSTOM,            //!< Custom format
    CERTTYPE_X509_FULL_STORED   //!< Full Stored X509 Certificate
} atcacert_cert_type_t;

/**
 * Sources for the certificate serial number.
 */
typedef enum atcacert_cert_sn_src_e
{
    SNSRC_STORED                = 0x0,  //!< Cert serial is stored on the device.
    SNSRC_STORED_DYNAMIC        = 0x7,  //!< Cert serial is stored on the device with the first byte being the DER size (X509 certs only).
    SNSRC_DEVICE_SN             = 0x8,  //!< Cert serial number is 0x40(MSB) + 9-byte device serial number. Only applies to device certificates.
    SNSRC_SIGNER_ID             = 0x9,  //!< Cert serial number is 0x40(MSB) + 2-byte signer ID. Only applies to signer certificates.
    SNSRC_PUB_KEY_HASH          = 0xA,  //!< Cert serial number is the SHA256(Subject public key + Encoded dates), with uppermost 2 bits set to 01.
    SNSRC_DEVICE_SN_HASH        = 0xB,  //!< Cert serial number is the SHA256(Device SN + Encoded dates), with uppermost 2 bits set to 01. Only applies to device certificates.
    SNSRC_PUB_KEY_HASH_POS      = 0xC,  //!< Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates), with MSBit set to 0 to ensure it's positive.
    SNSRC_DEVICE_SN_HASH_POS    = 0xD,  //!< Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates), with MSBit set to 0 to ensure it's positive. Only applies to device certificates.
    SNSRC_PUB_KEY_HASH_RAW      = 0xE,  //!< Depreciated, don't use. Cert serial number is the SHA256(Subject public key + Encoded dates).
    SNSRC_DEVICE_SN_HASH_RAW    = 0xF   //!< Depreciated, don't use. Cert serial number is the SHA256(Device SN + Encoded dates). Only applies to device certificates.
} atcacert_cert_sn_src_t;

/**
 * ATECC device zones. The values match the Zone Encodings as specified in the datasheet.
 */
typedef enum atcacert_device_zone_e
{
    DEVZONE_CONFIG  = 0x00, //!< Configuration zone.
    DEVZONE_OTP     = 0x01, //!< One Time Programmable zone.
    DEVZONE_DATA    = 0x02, //!< Data zone (slots).
    DEVZONE_GENKEY  = 0x03, //!< Data zone - Generate Pubkey (slots).
    DEVZONE_DEDICATED_DATA = 0x04, //!< Dedicated data zone.
    DEVZONE_NONE    = 0x07  //!< Special value used to indicate there is no device location.
} atcacert_device_zone_t;

/** \brief How to transform the data from the device to the certificate.
 */
typedef enum atcacert_transform_e
{
    TF_NONE,                //!< No transform, data is used byte for byte
    TF_REVERSE,             //!< Reverse the bytes (e.g. change endianness)
    TF_BIN2HEX_UC,          //!< Convert raw binary into ASCII hex, uppercase
    TF_BIN2HEX_LC,          //!< Convert raw binary into ASCII hex, lowercase
    TF_HEX2BIN_UC,          //!< Convert ASCII hex, uppercase to binary
    TF_HEX2BIN_LC,          //!< Convert ASCII hex, lowercase to binary
    TF_BIN2HEX_SPACE_UC,    //!< Convert raw binary into ASCII hex, uppercase space between bytes
    TF_BIN2HEX_SPACE_LC,    //!< Convert raw binary into ASCII hex, lowercase space between bytes
    TF_HEX2BIN_SPACE_UC,    //!< Convert ASCII hex, uppercase with spaces between bytes to binary
    TF_HEX2BIN_SPACE_LC,    //!< Convert ASCII hex, lowercase with spaces between bytes to binary
} atcacert_transform_t;

/**
 * Standard dynamic certificate elements.
 */
typedef enum atcacert_std_cert_element_e
{
    STDCERT_PUBLIC_KEY,
    STDCERT_SIGNATURE,
    STDCERT_ISSUE_DATE,
    STDCERT_EXPIRE_DATE,
    STDCERT_SIGNER_ID,
    STDCERT_CERT_SN,
    STDCERT_AUTH_KEY_ID,
    STDCERT_SUBJ_KEY_ID,
    STDCERT_NUM_ELEMENTS    //!< Special item to give the number of elements in this enum
} atcacert_std_cert_element_t;

// Some of these structures may need to be byte-accurate
#ifndef ATCA_NO_PRAGMA_PACK
#pragma pack(push, 1)
#endif

/**
 * Defines a chunk of data in an ATECC device.
 */
typedef struct ATCA_PACKED atcacert_device_loc_s
{
    atcacert_device_zone_t zone;    //!< Zone in the device.
    uint16_t slot;                  //!< Slot within the data zone. Only applies if zone is DEVZONE_DATA.
    uint8_t is_genkey;              //!< If true, use GenKey command to get the contents instead of Read.
    uint16_t offset;                //!< Byte offset in the zone.
    uint16_t count;                 //!< Byte count.
} atcacert_device_loc_t;

/**
 * Defines a chunk of data in a certificate template.
 */
typedef struct ATCA_PACKED atcacert_cert_loc_s
{
    uint16_t offset;    //!< Byte offset in the certificate template.
    uint16_t count;     //!< Byte count. Set to 0 if it doesn't exist.
} atcacert_cert_loc_t;

/**
 * Defines a generic dynamic element for a certificate including the device and template locations.
 */
typedef struct ATCA_PACKED atcacert_cert_element_s
{
    char id[25];                                            //!< ID identifying this element.
    atcacert_device_loc_t device_loc;                       //!< Location in the device for the element.
    atcacert_cert_loc_t cert_loc;                           //!< Location in the certificate template for the element.
    atcacert_transform_t transforms[ATCA_MAX_TRANSFORMS];   //!< List of transforms from device to cert for this element.
} atcacert_cert_element_t;

#ifndef ATCA_NO_PRAGMA_PACK
#pragma pack(pop)
#endif

/**
 * Defines a certificate and all the pieces to work with it.
 *
 * If any of the standard certificate elements (std_cert_elements) are not a part of the certificate
 * definition, set their count to 0 to indicate their absence.
 */
typedef struct atcacert_def_s
{
    atcacert_cert_type_t    type;                                               //!< Certificate type.
    atcacert_device_loc_t   comp_cert_dev_loc;                                  //!< Where on the device the compressed cert can be found.
    uint16_t                private_key_slot;                                   //!< If this is a device certificate template, this is the device slot for the device private key.
#if ATCACERT_COMPCERT_EN
    uint8_t                         template_id;                                //!< ID for the this certificate definition (4-bit value).
    uint8_t                         chain_id;                                   //!< ID for the certificate chain this definition is a part of (4-bit value).
    uint16_t                        std_sig_size;                               //!< Standard signature size of the certificate keytype.
    atcacert_cert_sn_src_t          sn_source;                                  //!< Where the certificate serial number comes from (4-bit value).
    atcacert_device_loc_t           cert_sn_dev_loc;                            //!< Only applies when sn_source is SNSRC_STORED or SNSRC_STORED_DYNAMIC. Describes where to get the certificate serial number on the device.
    atcacert_date_format_t          issue_date_format;                          //!< Format of the issue date in the certificate.
    atcacert_date_format_t          expire_date_format;                         //!< format of the expire date in the certificate.
    atcacert_cert_loc_t             tbs_cert_loc;                               //!< Location in the certificate for the TBS (to be signed) portion.
    uint8_t                         expire_years;                               //!< Number of years the certificate is valid for (5-bit value). 0 means no expiration.
    atcacert_device_loc_t           public_key_dev_loc;                         //!< Where on the device the public key can be found.
    atcacert_cert_loc_t             std_cert_elements[STDCERT_NUM_ELEMENTS];    //!< Where in the certificate template the standard cert elements are inserted.
    const atcacert_cert_element_t*  cert_elements;                              //!< Additional certificate elements outside of the standard certificate contents.
    uint8_t                         cert_elements_count;                        //!< Number of additional certificate elements in cert_elements.
#endif
    const uint8_t*                  cert_template;                              //!< Pointer to the actual certificate template data.
    uint16_t                        cert_template_size;                         //!< Size of the certificate template in cert_template in bytes.
    const struct atcacert_def_s* ca_cert_def;                                   //!< Certificate definition of the CA certificate
#if ATCACERT_INTEGRATION_EN
    struct atcac_x509_ctx** parsed;
#endif
} atcacert_def_t;

/**
 * Tracks the state of a certificate as it's being rebuilt from device information.
 */

typedef struct atcacert_build_state_s
{
    const atcacert_def_t*   cert_def;       //!< Certificate definition for the certificate being rebuilt.
    uint8_t*                cert;           //!< Buffer to contain the rebuilt certificate.
    size_t*                 cert_size;      //!< Current size of the certificate in bytes.
    size_t                  max_cert_size;  //!< Max size of the cert buffer in bytes.
    uint8_t                 is_device_sn;   //!< Indicates the structure contains the device SN.
    ATCADeviceType          devtype;        //!< Device type info for the certificate being rebuilt.
    uint8_t                 device_sn[9];   //!< Storage for the device SN, when it's found.
    uint8_t                 is_comp_cert;   //!< Indicates the structure contains the compressed certificate.
    uint8_t                 comp_cert[ATCACERT_COMP_CERT_MAX_SIZE];   //!< Storage for the compressed certificate when it's found.
} atcacert_build_state_t;

// Inform function naming when compiling in C++
#ifdef __cplusplus
extern "C" {
#endif

#if ATCACERT_COMPCERT_EN

/**
 * \brief Add all the device locations required to rebuild the specified certificate (cert_def) to
 *        a device locations list.
 *
 * The block_size parameter will adjust all added device locations to have a offset and count that
 * aligns with that block size. This allows one to generate a list of device locations that matches
 * specific read or write semantics (e.g. 4 byte or 32 byte reads).
 *
 * \param[in]    device                 Device context
 * \param[in]    cert_def               Certificate definition containing all the device locations
 *                                      to add to the list.
 * \param[in,out] device_locs            List of device locations to add to.
 * \param[in,out] device_locs_count      As input, existing size of the device locations list.
 *                                      As output, the new size of the device locations list.
 * \param[in]    device_locs_max_count  Maximum number of elements device_locs can hold.
 * \param[in]    block_size             Block size to align all offsets and counts to when adding
 *                                      device locations.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_device_locs(ATCADevice             device,
                                     const atcacert_def_t*  cert_def,
                                     atcacert_device_loc_t* device_locs,
                                     size_t*                device_locs_count,
                                     size_t                 device_locs_max_count,
                                     size_t                 block_size);

/**
 * \brief Starts the certificate rebuilding process.
 *
 * \param[in]  device         device context
 * \param[out] build_state    Structure is initialized to start the certificate building process.
 *                            Will be passed to the other certificate building functions.
 * \param[in]  cert_def       Certificate definition for the certificate being built.
 * \param[in]  cert           Buffer to contain the rebuilt certificate.
 * \param[in]  cert_size      As input, the size of the cert buffer in bytes. This value will be
 *                            adjusted to the current/final size of the certificate through the
 *                            building process.
 * \param[in]  ca_public_key  Buffer pointing to ECC P256/P384/P521 public key of the certificate authority
 *                            (issuer) for the certificate being built. Set to NULL if the authority key id
 *                            is not needed, set properly in the cert_def template, or stored on the
 *                            device as specified in the cert_def cert_elements.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_cert_build_start(ATCADevice                device,
                                      atcacert_build_state_t*   build_state,
                                      const atcacert_def_t*     cert_def,
                                      uint8_t*                  cert,
                                      size_t*                   cert_size,
                                      const cal_buffer*         ca_public_key);

/**
 * \brief Process information read from the ATECC device. If it contains information for the
 *        certificate, it will be incorporated into the certificate.
 *
 * \param[in] build_state  Current certificate building state.
 * \param[in] device_loc   Device location structure describing where on the device the following
 *                         data came from.
 * \param[in] device_data  Actual data from the device. It should represent the offset and byte
 *                         count specified in the device_loc parameter.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_cert_build_process(atcacert_build_state_t*         build_state,
                                        const atcacert_device_loc_t*    device_loc,
                                        const uint8_t*                  device_data);

/**
 * \brief Completes any final certificate processing required after all data from the device has
 *        been incorporated.
 *
 * The final certificate and its size in bytes are contained in the cert and cert_size elements
 * of the build_state structure. This will be the same buffers as supplied to the
 * atcacert_cert_build_start function at the beginning of the certificate rebuilding process.
 *
 * \param[in] build_state  Current certificate build state.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_cert_build_finish(atcacert_build_state_t* build_state);

/**
 * \brief Gets the dynamic data that would be saved to the specified device location.  This
 *        function is primarily used to break down a full certificate into the dynamic components
 *        to be saved to a device.
 *
 * The atcacert_add_device_locs function can be used to generate a list of device locations a
 * particular certificate definition requires.
 *
 * \param[in]  cert_def     Certificate definition for the certificate we're getting data from.
 * \param[in]  cert         Certificate to get the device data from.
 * \param[in]  cert_size    Size of the certificate in bytes.
 * \param[in]  device_loc   Device location to request data for.
 * \param[out] device_data  Buffer that represents the device data in device_loc. Required to be
 *                          at least device_loc.count in size.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_device_data(const atcacert_def_t*          cert_def,
                                     const uint8_t*                 cert,
                                     size_t                         cert_size,
                                     const atcacert_device_loc_t*   device_loc,
                                     uint8_t*                       device_data);

#endif /* ATCACERT_COMPCERT_EN */

/**
 * \brief Gets the subject name from a certificate.
 *
 * \param[in]  cert_def         Certificate definition for the certificate.
 * \param[in]  cert             Certificate to get element from.
 * \param[in]  cert_size        Size of the certificate (cert) in bytes.
 * \param[out] subject          Subject name is returned in this buffer.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_subject(const atcacert_def_t*  cert_def,
                                 const uint8_t*         cert,
                                 size_t                 cert_size,
                                 cal_buffer*            cert_subj_buf);


#if ATCACERT_COMPCERT_EN
/**
 * \brief Sets the subject public key and subject key ID in a certificate.
 *
 * \param[in]    cert_def         Certificate definition for the certificate.
 * \param[in,out] cert             Certificate to update.
 * \param[in]    cert_size        Size of the certificate (cert) in bytes.
 * \param[in]    subj_public_key  Buffer pointing to the subject public key as X and Y integers concatenated together.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_set_subj_public_key(const atcacert_def_t*  cert_def,
                                         uint8_t*               cert,
                                         size_t                 cert_size,
                                         const cal_buffer*      subj_public_key);

#endif /* ATCACERT_COMPCERT_EN */

/**
 * \brief Gets the subject public key from a certificate.
 *
 * \param[in]  cert_def         Certificate definition for the certificate.
 * \param[in]  cert             Certificate to get element from.
 * \param[in]  cert_size        Size of the certificate (cert) in bytes.
 * \param[out] subj_public_key  Subject public key is returned in the buffer pointed by subj_public_key
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_subj_public_key(const atcacert_def_t * cert_def,
                                         const uint8_t *        cert,
                                         size_t                 cert_size,
                                         cal_buffer*            subj_public_key);


/**
 * \brief Gets the subject key ID from a certificate.
 *
 * \param[in]  cert_def     Certificate definition for the certificate.
 * \param[in]  cert         Certificate to get element from.
 * \param[in]  cert_size    Size of the certificate (cert) in bytes.
 * \param[out] subj_key_id  Subject key ID is returned in this buffer. 20 bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_subj_key_id(const atcacert_def_t * cert_def,
                                     const uint8_t *        cert,
                                     size_t                 cert_size,
                                     uint8_t                subj_key_id[20]);

#if ATCACERT_COMPCERT_EN
/**
 * \brief Sets the signature in a certificate. This may alter the size of the X.509 certificates.
 *
 * \param[in]    cert_def       Certificate definition for the certificate.
 * \param[in,out] cert          Certificate to update.
 * \param[in,out] cert_size     As input, size of the certificate (cert) in bytes.
 *                              As output, the new size of the certificate.
 * \param[in]    max_cert_size  Maximum size of the cert buffer.
 * \param[in]    signature      Buffer pointing to the signature as R and S integers concatenated together.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_set_signature(const atcacert_def_t*    cert_def,
                                   uint8_t*                 cert,
                                   size_t*                  cert_size,
                                   size_t                   max_cert_size,
                                   const cal_buffer*        signature);

/**
 * \brief Gets the signature from a certificate.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get element from.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] signature  Signature is returned in this buffer. Formatted at R and S integers 
 *                        concatenated together.          
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_signature(const atcacert_def_t *   cert_def,
                                   const uint8_t *          cert,
                                   size_t                   cert_size,
                                   cal_buffer*              signature);

/**
 * \brief Sets the issue date (notBefore) in a certificate. Will be formatted according to the date
 *        format specified in the certificate definition.
 *
 * \param[in]    cert_def   Certificate definition for the certificate.
 * \param[in,out] cert       Certificate to update.
 * \param[in]    cert_size  Size of the certificate (cert) in bytes.
 * \param[in]    timestamp  Issue date.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_set_issue_date(const atcacert_def_t*       cert_def,
                                    uint8_t*                    cert,
                                    size_t                      cert_size,
                                    const atcacert_tm_utc_t*    timestamp);

#endif /* ATCACERT_COMPCERT_EN */

/**
 * \brief Gets the issuer name of a certificate.
 *
 * \param[in]  cert_def         Certificate definition for the certificate.
 * \param[in]  cert             Certificate to get element from.
 * \param[in]  cert_size        Size of the certificate (cert) in bytes.
 * \param[out] cert_issuer      Certificate's issuer is returned in this buffer.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_issuer(const atcacert_def_t*   cert_def,
                                const uint8_t*          cert,
                                size_t                  cert_size,
                                uint8_t                 cert_issuer[128]);

/**
 * \brief Gets the issue date from a certificate. Will be parsed according to the date format
 *        specified in the certificate definition.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get element from.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] timestamp  Issue date is returned in this structure.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_issue_date(const atcacert_def_t*   cert_def,
                                    const uint8_t*          cert,
                                    size_t                  cert_size,
                                    atcacert_tm_utc_t*      timestamp);

#if ATCACERT_COMPCERT_EN
/**
 * \brief Sets the expire date (notAfter) in a certificate. Will be formatted according to the date
 *        format specified in the certificate definition.
 *
 * \param[in]    cert_def   Certificate definition for the certificate.
 * \param[in,out] cert       Certificate to update.
 * \param[in]    cert_size  Size of the certificate (cert) in bytes.
 * \param[in]    timestamp  Expire date.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_set_expire_date(const atcacert_def_t*      cert_def,
                                     uint8_t*                   cert,
                                     size_t                     cert_size,
                                     const atcacert_tm_utc_t*   timestamp);
#endif /* ATCACERT_COMPCERT_EN */

/**
 * \brief Gets the expire date from a certificate. Will be parsed according to the date format
 *        specified in the certificate definition.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get element from.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] timestamp  Expire date is returned in this structure.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_expire_date(const atcacert_def_t*  cert_def,
                                     const uint8_t*         cert,
                                     size_t                 cert_size,
                                     atcacert_tm_utc_t*     timestamp);

#if ATCACERT_COMPCERT_EN
/**
 * \brief Sets the signer ID in a certificate. Will be formatted as 4 upper-case hex digits.
 *
 * \param[in]    cert_def   Certificate definition for the certificate.
 * \param[in,out] cert       Certificate to update.
 * \param[in]    cert_size  Size of the certificate (cert) in bytes.
 * \param[in]    signer_id  Signer ID.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_set_signer_id(const atcacert_def_t*    cert_def,
                                   uint8_t*                 cert,
                                   size_t                   cert_size,
                                   const uint8_t            signer_id[2]);

/**
 * \brief Gets the signer ID from a certificate. Will be parsed as 4 upper-case hex digits.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get element from.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] signer_id  Signer ID will be returned in this buffer. 2 bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_signer_id(const atcacert_def_t *   cert_def,
                                   const uint8_t *          cert,
                                   size_t                   cert_size,
                                   uint8_t                  signer_id[2]);

/**
 * \brief Sets the certificate serial number in a certificate.
 *
 * \param[in]    cert_def      Certificate definition for the certificate.
 * \param[in,out] cert          Certificate to update.
 * \param[in,out] cert_size     Size of the certificate (cert) in bytes.
 * \param[in]    max_cert_size  Maximum size of the cert buffer.
 * \param[in]    cert_sn       Certificate serial number.
 * \param[in]    cert_sn_size  Size of the certificate serial number in bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_set_cert_sn(const atcacert_def_t*  cert_def,
                                 uint8_t*               cert,
                                 size_t*                cert_size,
                                 size_t                 max_cert_size,
                                 const uint8_t*         cert_sn,
                                 size_t                 cert_sn_size);

/**
 * \brief Sets the certificate serial number by generating it from other information in the
 *        certificate using the scheme specified by sn_source in cert_def. See the
 *
 * This method requires certain elements in the certificate be set properly as they're used for
 * generating the serial number. See atcacert_cert_sn_src_t for what elements should be set in the
 * certificate beforehand. If the sn_source is set to SNSRC_STORED or SNSRC_STORED_DYNAMIC, the
 * function will return ATCACERT_E_SUCCESS without making any changes to the certificate.
 *
 * \param[in]    cert_def      Certificate definition for the certificate.
 * \param[in,out] cert          Certificate to update.
 * \param[in]    cert_size     Size of the certificate (cert) in bytes.
 * \param[in]    device_sn     Device serial number, only used if required by the sn_source scheme.
 *                             Can be set to NULL, if not required.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_gen_cert_sn(const atcacert_def_t*  cert_def,
                                 uint8_t*               cert,
                                 size_t                 cert_size,
                                 const uint8_t          device_sn[ATCA_MAX_SERNUM_SIZE]);

/**
 * \brief Generates a serial number for the given serial number source.
 *
 * \param[in]  sn_source  Generation scheme to use.
 * \param[in]  device_sn  Device serial number (9 bytes) to use if required.
 *                        Can be NULL if the sn_source does not use it.
 * \param[in]  public_key Certificate public key to use if required. 
 *                        Can be NULL if the sn_source does not use
 *                        it.
 * \param[in]  comp_cert  Compressed certificate, used for encoded dates
 *                        (including extended dates) or signer ID if required.
 *                        Can be NULL if the sn_source does not use it.
 * \param[in]  sn_size    Size of the certificate serial number to be
 *                        generated. Must be appropriate for the sn_source
 *                        specified.
 * \param[out] sn         Output buffer for the generated serial number.
 *                        Must be at least sn_size bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_generate_sn(atcacert_cert_sn_src_t sn_source,
                                 const uint8_t          device_sn[ATCA_MAX_SERNUM_SIZE],
                                 const cal_buffer*      public_key,
                                 const uint8_t          comp_cert[ATCACERT_COMP_CERT_MAX_SIZE],
                                 size_t                 sn_size,
                                 uint8_t*               sn);

#endif /* ATCACERT_COMPCERT_EN */

/**
 * \brief Gets the certificate serial number from a certificate.
 *
 * \param[in]    cert_def      Certificate definition for the certificate.
 * \param[in]    cert          Certificate to get element from.
 * \param[in]    cert_size     Size of the certificate (cert) in bytes.
 * \param[out]   cert_sn       Certificate SN will be returned in this buffer.
 * \param[in,out] cert_sn_size  As input, the size of the cert_sn buffer.
 *                             As output, the size of the certificate SN (cert_sn) in bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_cert_sn(const atcacert_def_t*  cert_def,
                                 const uint8_t*         cert,
                                 size_t                 cert_size,
                                 uint8_t*               cert_sn,
                                 size_t*                cert_sn_size);

#if ATCACERT_COMPCERT_EN
/**
 * \brief Sets the authority key ID in a certificate. Note that this takes the actual public key
 *        creates a key ID from it.
 *
 * \param[in]    cert_def         Certificate definition for the certificate.
 * \param[in,out] cert             Certificate to update.
 * \param[in]    cert_size        Size of the certificate (cert) in bytes.
 * \param[in]    auth_public_key  Buffer pointing to the authority public key as X and Y integers concatenated together.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_set_auth_key_id(const atcacert_def_t*  cert_def,
                                     uint8_t*               cert,
                                     size_t                 cert_size,
                                     const cal_buffer*      auth_public_key);

/**
 * \brief Sets the authority key ID in a certificate.
 *
 * \param[in]    cert_def         Certificate definition for the certificate.
 * \param[in,out] cert             Certificate to update.
 * \param[in]    cert_size        Size of the certificate (cert) in bytes.
 * \param[in]    auth_key_id      Authority key ID. Same size as defined in the cert_def.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_set_auth_key_id_raw(const atcacert_def_t*  cert_def,
                                         uint8_t*               cert,
                                         size_t                 cert_size,
                                         const uint8_t*         auth_key_id);
#endif /* ATCACERT_COMPCERT_EN */

/**
 * \brief Gets the authority key ID from a certificate.
 *
 * \param[in]  cert_def     Certificate definition for the certificate.
 * \param[in]  cert         Certificate to get element from.
 * \param[in]  cert_size    Size of the certificate (cert) in bytes.
 * \param[out] auth_key_id  Authority key ID is returned in this buffer. 20 bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_auth_key_id(const atcacert_def_t * cert_def,
                                     const uint8_t *        cert,
                                     size_t                 cert_size,
                                     uint8_t                auth_key_id[20]);

#if ATCACERT_COMPCERT_EN
/**
 * \brief Sets the signature, issue date, expire date, and signer ID found in the compressed
 *        certificate. This also checks fields common between the cert_def and the compressed
 *        certificate to make sure they match.
 *
 * \param[in]    cert_def       Certificate definition for the certificate.
 * \param[in,out] cert           Certificate to update.
 * \param[in,out] cert_size      As input, size of the certificate (cert) in bytes.
 *                              As output, the new size of the certificate.
 * \param[in]    max_cert_size  Maximum size of the cert buffer.
 * \param[in]    comp_cert      Compressed certificate.
 *
 * \return ATCACERT_E_SUCCESS on success. ATCACERT_E_WRONG_CERT_DEF if the template ID, chain ID, and/or SN source
 *         don't match between the cert_def and the compressed certificate.
 */
ATCA_STATUS atcacert_set_comp_cert(const atcacert_def_t*    cert_def,
                                   uint8_t*                 cert,
                                   size_t*                  cert_size,
                                   size_t                   max_cert_size,
                                   const uint8_t            comp_cert[ATCACERT_COMP_CERT_MAX_SIZE]);

/**
 * \brief Generate the compressed certificate for the given certificate.
 *
 * If the compressed certificate definition does not indicate a issue date
 * location, then the minimum date supported (2000-01-01 00:00:00) will be
 * used.
 *
 * Likewise, if the definition does not have a signer ID location,
 * then and all-zero (0000) signer ID will be used in the compressed
 * certificate.
 *
 * If the certificate is using encoded date logic (expire date is an even
 * number of years from issue date or max date up to 31 years) then the
 * certificate expire years will be used if it differs from the cert def
 * value.
 *
 * \param[in]  cert_def     Certificate definition for the certificate.
 * \param[in]  cert         Certificate to generate the compressed certificate
 *                          for.
 * \param[in]  cert_size    Size of the certificate (cert) in bytes.
 * \param[out] comp_cert    Compressed certificate is returned in this buffer.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_comp_cert(const atcacert_def_t *   cert_def,
                                   const uint8_t *          cert,
                                   size_t                   cert_size,
                                   uint8_t                  comp_cert[ATCACERT_COMP_CERT_MAX_SIZE]);

/**
 * \brief Generate the compressed certificate for the given certificate with
 *        additional controls for supplying information not in the
 *        certificate.
 *
 * If the compressed certificate definition is missing certificate locations
 * for the issue date or signer id, then the values supplied in the optional
 * issue_date and signer_id arguments will be used.
 *
 * If the certificate is using expire years logic (expire date is a max value
 * or an even number of years from the the issue date up to 31) and the
 * calculcate expire years is different from the value in the cert_def,
 * then is_diff_expire_years controls behaviour. If true, then the calculated
 * value overrides the cert_def value. If false, then an error is returned.
 *
 * \param[in]  cert_def        Certificate definition for the certificate.
 * \param[in]  cert            Certificate to generate the compressed
 *                             certificate for.
 * \param[in]  cert_size       Size of the certificate (cert) in bytes.
 * \param[in]  def_issue_date  If the cert_def is missing an issue date
 *                             certificate location (cert_def->std_cert_elements[STDCERT_ISSUE_DATE].count == 0),
 *                             then the issue date supplied here will be used.
 *                             Otherwise, this argument will be ignored and
 *                             can be set to NULL.
 * \param[in]  def_signer_id   If the cert_def is missing a signer id
 *                             certificate location (cert_def->std_cert_elements[STDCERT_SIGNER_ID].count == 0),
 *                             then the 2 byte signer id supplied here will be
 *                             used. Otherwise, this argument will be ignored
 *                             and can be set to NULL.
 * \param[in]  is_diff_expire_years_ok  If calculcated expire years in cert is
 *                             different from cert_def expire_years, then this
 *                             argument controls the behavior. If true, the
 *                             calculated expire years is used instead of the
 *                             cert_def value. If false, an error would be
 *                             returned due to the mismatch.
 * \param[out] comp_cert       Compressed certificate is returned in this
 *                             buffer.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_comp_cert_ext(const atcacert_def_t*    cert_def,
                                       const uint8_t*           cert,
                                       size_t                   cert_size,
                                       const atcacert_tm_utc_t* def_issue_date,
                                       const uint8_t*           def_signer_id,
                                       bool                     is_diff_expire_years_ok,
                                       uint8_t                  comp_cert[ATCACERT_COMP_CERT_MAX_SIZE]);

/**
 * \brief Get a pointer to the TBS data in a certificate.
 *
 * \param[in]  cert_def   Certificate definition for the certificate.
 * \param[in]  cert       Certificate to get the TBS data pointer for.
 * \param[in]  cert_size  Size of the certificate (cert) in bytes.
 * \param[out] tbs        Pointer to a const pointer that will be set the start of the TBS data.
 * \param[out] tbs_size   Size of the TBS data will be returned here.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_tbs(const atcacert_def_t*  cert_def,
                             const uint8_t*         cert,
                             size_t                 cert_size,
                             const uint8_t**        tbs,
                             size_t*                tbs_size);

/**
 * \brief Get the SHA256 digest of certificate's TBS data.
 *
 * \param[in]  cert_def    Certificate definition for the certificate.
 * \param[in]  cert        Certificate to get the TBS data pointer for.
 * \param[in]  cert_size   Size of the certificate (cert) in bytes.
 * \param[out] tbs_digest  TBS data digest will be returned here. 32 bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_tbs_digest(const atcacert_def_t *  cert_def,
                                    const uint8_t *         cert,
                                    size_t                  cert_size,
                                    cal_buffer*             tbs_digest);

/**
 * \brief Sets an element in a certificate. The data_size must match the size in cert_loc.
 *
 * \param[in]    cert_def       Certificate definition for the certificate.
 * \param[in]    cert_loc       Certificate location for this element.
 * \param[in,out] cert           Certificate to update.
 * \param[in]    cert_size      Size of the certificate (cert) in bytes.
 * \param[in]    data           Element data to insert into the certificate. Buffer must contain
 *                              cert_loc.count bytes to be copied into the certificate.
 * \param[in]    data_size      Size of the data in bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_set_cert_element(const atcacert_def_t*         cert_def,
                                      const atcacert_cert_loc_t*    cert_loc,
                                      uint8_t*                      cert,
                                      size_t                        cert_size,
                                      const uint8_t*                data,
                                      size_t                        data_size);

/**
 * \brief Gets an element from a certificate.
 *
 * \param[in]    cert_def   Certificate definition for the certificate.
 * \param[in]    cert_loc   Certificate location for this element.
 * \param[in]    cert       Certificate to get element from.
 * \param[in]    cert_size  Size of the certificate (cert) in bytes.
 * \param[out]   data       Element data will be returned in this buffer. This buffer must be large
 *                          enough to hold cert_loc.count bytes.
 * \param[in]    data_size  Expected size of the cert element data.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_cert_element(const atcacert_def_t*         cert_def,
                                      const atcacert_cert_loc_t*    cert_loc,
                                      const uint8_t*                cert,
                                      size_t                        cert_size,
                                      uint8_t*                      data,
                                      size_t                        data_size);

// Below are utility functions for dealing with various bits for data conversion and wrangling

/**
 * \brief Calculates the key ID for a given public ECC P256 key.
 *
 * Uses method 1 for calculating the keyIdentifier as specified by RFC 5280, section 4.2.1.2:
 *   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
 *        value of the BIT STRING subjectPublicKey (excluding the tag,
 *        length, and number of unused bits).
 *
 * \param[in] public_key  Buffer pointing to the ECC P256/P384/P521 public key to calculate key key ID for.
 *                        Formatted as the X and Y integers concatenated together.
 * \param[in] key_id      Calculated key ID will be returned in this buffer. 20 bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_get_key_id(const cal_buffer* public_key, uint8_t key_id[20]);

/**
 * \brief Merge a new device location into a list of device locations. If the new location overlaps
 *        with an existing location, the existing one will be modified to encompass both. Otherwise
 *        the new location is appended to the end of the list.
 *
 * The block_size parameter will adjust all added device locations to have an offset and count that
 * aligns with that block size. This allows one to generate a list of device locations that matches
 * specific read/write semantics (e.g. 4 byte or 32 byte reads). Note that this block_size only
 * applies to the device_loc being added. Existing device locations in the list won't be modified
 * to match the block size.
 *
 * \param[in]     device                Device context pointer
 * \param[in,out] device_locs           Existing device location list to merge the new device
 *                                      location into.
 * \param[in,out] device_locs_count     As input, the existing number of items in the device_locs
 *                                      list. As output, the new size of the device_locs list.
 * \param[in]    device_locs_max_count  Maximum number of items the device_locs list can hold.
 * \param[in]    device_loc             New device location to be merged into the device_locs list.
 * \param[in]    block_size             Block size to align all offsets and counts to when adding
 *                                      device location.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_merge_device_loc(ATCADevice                    device,
                                      atcacert_device_loc_t*        device_locs,
                                      size_t*                       device_locs_count,
                                      size_t                        device_locs_max_count,
                                      const atcacert_device_loc_t*  device_loc,
                                      size_t                        block_size);

/** \brief Determines if the two device locations overlap.
 *  \param[in] device_loc1  First device location to check.
 *  \param[in] device_loc2  Second device location o check.
 *  \return 0 (false) if they don't overlap, non-zero if the do overlap.
 */
bool atcacert_is_device_loc_overlap(const atcacert_device_loc_t*    device_loc1,
                                    const atcacert_device_loc_t*    device_loc2);

/**
 * \brief Takes a raw P256 ECC public key and converts it to the padded version used by ATECC
 *        devices. Input and output buffers can point to the same location to do an in-place
 *        transform.
 *
 * \param[in]  raw_key     Public key as X and Y integers concatenated together. 64 bytes.
 * \param[out] padded_key  Padded key is returned in this buffer. X and Y integers are padded
 *                         with 4 bytes of 0 in the MSB. 72 bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
void atcacert_public_key_add_padding(const uint8_t raw_key[64], uint8_t padded_key[72]);

/**
 * \brief Takes a padded public key used by ATECC devices and converts it to a raw P256 ECC public
 *        key. Input and output buffers can point to the same location to do an in-place transform.
 *
 * \param[out] padded_key  X and Y integers are padded with 4 bytes of 0 in the MSB. 72 bytes.
 * \param[in]  raw_key     Raw key is returned in this buffer. Public key as X and Y integers
 *                         concatenated together. 64 bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
void atcacert_public_key_remove_padding(const uint8_t padded_key[72], uint8_t raw_key[64]);

/**
 * \brief Apply the specified transform to the specified data.
 *
 * \param[in]    transform         Transform to be performed.
 * \param[in]    data              Input data to be transformed.
 * \param[in]    data_size         Size of the input data in bytes.
 * \param[out]   destination       Destination buffer to hold the transformed data.
 * \param[in,out] destination_size  As input, the size of the destination buffer.
 *                                 As output the size of the transformed data.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_transform_data(atcacert_transform_t    transform,
                                    const uint8_t*          data,
                                    size_t                  data_size,
                                    uint8_t*                destination,
                                    size_t*                 destination_size);

/** \brief Return the maximum possible certificate size in bytes for a given
 *         cert def. Certificate can be variable size, so this gives an
 *         appropriate buffer size when reading the certificates.
 *
 * \param[in]  cert_def       Certificate definition to find a max size for.
 * \param[out] max_cert_size  Maximum certificate size will be returned here in bytes.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_max_cert_size(const atcacert_def_t*    cert_def,
                                   size_t*                  max_cert_size);

/** \brief
 *
 * \param[in]    cert_def       Certificate definition to find a max size for.
 * \param[in]    cert           Certificate to get element from.
 * \param[in]    cert_size      Size of the certificate (cert) in bytes.
 * \param[in]    issue_tm_year  issue year.
 * \param[out]   expire_years   expire years.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
int atcacert_calc_expire_years(const atcacert_def_t*    cert_def,
                               const uint8_t*           cert,
                               size_t                   cert_size,
                               int                      issue_tm_year,
                               uint8_t*                 expire_years);
#endif /* ATCACERT_COMPCERT_EN */

/** @} */
#ifdef __cplusplus
}
#endif
#endif /* ATCACERT_DEF_H */
