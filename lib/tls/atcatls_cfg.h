/**
 * \file
 *
 * \brief  Collection of functions for hardware abstraction of TLS implementations (e.g. OpenSSL)
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */

#ifndef ATCATLS_CFG_H
#define ATCATLS_CFG_H

#include "cryptoauthlib.h"
#include "atcacert/atcacert_def.h"

/** \defgroup atcatls TLS integration with ATECC (atcatls_)
   @{ */

// Slot definitions for ECC508 used by the default TLS configuration.
#define TLS_SLOT_AUTH_PRIV      ((uint8_t)0x0)     //!< Primary authentication private key
#define TLS_SLOT_AUTH_PMK       ((uint8_t)0x1)     //!< Premaster key for ECDH cipher suites
#define TLS_SLOT_ECDH_PRIV      ((uint8_t)0x2)     //!< ECDH private key
#define TLS_SLOT_ECDHE_PRIV     ((uint8_t)0x2)     //!< ECDHE private key
#define TLS_SLOT_ECDH_PMK       ((uint8_t)0x3)     //!< ECDH/ECDHE pmk slot.  This slot is encrypted with encParentSlot
#define TLS_SLOT_ENC_PARENT     ((uint8_t)0x4)     //!< The parent encryption key.  This is a random key set on a per-platform basis.
#define TLS_SLOT_SHAKEY         ((uint8_t)0x5)     //!< SHA key slot.  Used for SHA use cases
#define TLS_SLOT_HOST_SHAKEY    ((uint8_t)0x6)     //!< Host SHA key slot.  Used for host SHA use cases
#define TLS_SLOT_FEATURE_PRIV   ((uint8_t)0x7)     //!< Feature private key. Used for feature use cases
#define TLS_SLOT8_ENC_STORE     ((uint8_t)0x8)     //!< Encrypted storage for 416 bytes
#define TLS_SLOT9_ENC_STORE     ((uint8_t)0x9)     //!< Encrypted storage for 72 bytes
#define TLS_SLOT_AUTH_CERT      ((uint8_t)0xA)     //!< Compressed certificate information for the authPrivSlot
#define TLS_SLOT_SIGNER_PUBKEY  ((uint8_t)0xB)     //!< Public key of the signer of authCertSlot.
#define TLS_SLOT_SIGNER_CERT    ((uint8_t)0xC)     //!< Compressed certificate information for the signerPubkey
#define TLS_SLOT_FEATURE_CERT   ((uint8_t)0xD)     //!< Compressed certificate information for the featurePrivSlot
#define TLS_SLOT_PKICA_PUBKEY   ((uint8_t)0xE)     //!< Public key for the PKI certificate authority
#define TLS_SLOT_MFRCA_PUBKEY   ((uint8_t)0xF)     //!< Public key for the MFR certificate authority
// Development Only Definitions
#define TLS_SLOT_DEV_SIGNER_PRIV    ((uint8_t)0x2) //!< Signer private key - For Development ONLY
#define TLS_SLOT_DEV_CA_PRIV        ((uint8_t)0x7) //!< Root CA private key - For Development ONLY

typedef struct
{
    uint8_t authPrivSlot;       //!< Primary authentication private key
    uint8_t authPmkSlot;        //!< Premaster key for ECDH cipher suites
    uint8_t ecdhPrivSlot;       //!< ECDH private key
    uint8_t ecdhePrivSlot;      //!< ECDHE private key
    uint8_t ecdhPmkSlot;        //!< ECDH/ECDHE pmk slot.  This slot is encrypted with encParentSlot
    uint8_t encParentSlot;      //!< The parent encryption key.  This is a random key set on a per-platform basis.
    uint8_t shaKeySlot;         //!< SHA key slot.  Used for SHA use cases
    uint8_t hostShaKeySlot;     //!< Host SHA key slot.  Used for host SHA use cases
    uint8_t featurePrivSlot;    //!< Feature private key. Used for feature use cases
    uint8_t encStoreSlot8;      //!< Encrypted storage for 416 bytes
    uint8_t encStoreSlot9;      //!< Encrypted storage for 72 bytes
    uint8_t authCertSlot;       //!< Compressed certificate information for the authPrivSlot
    uint8_t signerPubkeySlot;   //!< Public key of the signer of authCertSlot.
    uint8_t signerCertSlot;     //!< Compressed certificate information for the signerPubkey
    uint8_t featureCertSlot;    //!< Compressed certificate information for the featurePrivSlot
    uint8_t pkiCaPubkeySlot;    //!< Public key for the PKI certificate authority
    uint8_t mfrCaPubkeySlot;    //!< Public key for the MFR certificate authority
} TlsSlotDef;

//////////////////////////////////////////////////////////////////////////
// Function Definitions
ATCA_STATUS device_init_default(void);
ATCA_STATUS device_init(const atcacert_def_t* cert_def_signer, const atcacert_def_t* cert_def_device);

static int build_and_save_cert(
    const atcacert_def_t*    cert_def,
    uint8_t*                 cert,
    size_t*                  cert_size,
    const uint8_t            ca_public_key[64],
    const uint8_t            public_key[64],
    const uint8_t            signer_id[2],
    const atcacert_tm_utc_t* issue_date,
    const uint8_t            config32[32],
    uint8_t                  ca_slot);


//////////////////////////////////////////////////////////////////////////
// I2C address for device communication
#define FACTORY_INIT_I2C    (uint8_t)(0xC0)     // Initial I2C address is set to 0xC0 in the factory
//#define DEVICE_I2C		FACTORY_INIT_I2C	// Device I2C Address.  Initial communication. Before provisioning, use FACTORY_INIT_I2C.
#define DEVICE_I2C          (uint8_t)(0xB0)     // Device I2C Address.  Initial communication. After provisioning, use actual device address.
#define D_I2C               DEVICE_I2C          // Device I2C Address.  Program the device to this address when provisioning

extern const atcacert_def_t g_cert_def_0_signer;
extern const atcacert_def_t g_cert_def_0_device;

/** @} */

#endif // ATCATLS_CFG_H
