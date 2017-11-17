/**
 * \file
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

#ifndef ATCATLS_H
#define ATCATLS_H

#include "cryptoauthlib.h"
#include "atcacert/atcacert_def.h"

/** \defgroup atcatls TLS integration with ATECC (atcatls_)
 *
 * \brief
    Instructions for integrating the ECC508 into a platform:
    1.	Add compiler switch for ECC_HAL
    2.	Define the configuration properties of the secure element in the atcatls_cfg.h file
    3.	Add call to HAL_init() before main loop.
            - This will use the configuration information and replace the private key resource in /oic/sec/cred with a handle to the secure element keys.
    4.	Re-compile the OIC implementation for the target platform
   @{ */

// The number of bytes in a standard ECC508 memory block
//#define MEM_BLOCK_SIZE      ATCA_BLOCK_SIZE
//#define TLS_RANDOM_SIZE     MEM_BLOCK_SIZE
// The number of bytes in ECC keys & signatures
//#define PUB_KEY_SIZE        ATCA_PUB_KEY_SIZE
//#define PRIV_KEY_SIZE       ATCA_PRIV_KEY_SIZE
//#define SIGNATURE_SIZE      ATCA_SIG_SIZE

// Configures the device for tls operations
ATCA_STATUS atcatls_config_default(void);

// TLS API Init/finish
ATCA_STATUS atcatls_init(ATCAIfaceCfg *pCfg);
ATCA_STATUS atcatls_finish(void);

// Core TLS definitions
ATCA_STATUS atcatls_sign(uint8_t slot_id, const uint8_t *message, uint8_t *signature);
ATCA_STATUS atcatls_verify(const uint8_t *message, const uint8_t *signature, const uint8_t *public_key, bool *verified);
ATCA_STATUS atcatls_ecdh(uint8_t slot_id, const uint8_t* public_key, uint8_t* pmk);
ATCA_STATUS atcatls_ecdh_enc(uint8_t slot_id, uint8_t enckeyId, const uint8_t* public_key, uint8_t* pmk);
ATCA_STATUS atcatls_ecdhe(uint8_t slot_id, const uint8_t* public_key, uint8_t* public_key_return, uint8_t* pmk);
ATCA_STATUS atcatls_create_key(uint8_t slot_id, uint8_t *public_key);
ATCA_STATUS atcatls_calc_pubkey(uint8_t slot_id, uint8_t *public_key);
ATCA_STATUS atcatls_write_pubkey(uint8_t slot_id, uint8_t public_key[ATCA_PUB_KEY_SIZE], bool lock);
ATCA_STATUS atcatls_read_pubkey(uint8_t slot_id, uint8_t *public_key);
ATCA_STATUS atcatls_random(uint8_t* randout);
ATCA_STATUS atcatls_get_sn(uint8_t sn_out[ATCA_SERIAL_NUM_SIZE]);

// Certificate Handling
ATCA_STATUS atcatls_get_cert(const atcacert_def_t* cert_def, const uint8_t *ca_public_key, uint8_t *cert_out, size_t* cert_size);
ATCA_STATUS atcatls_get_ca_cert(uint8_t *cert_out, size_t* cert_size);
ATCA_STATUS atcatls_verify_cert(const atcacert_def_t* cert_def, const uint8_t* cert, size_t cert_size, const uint8_t* ca_public_key);
ATCA_STATUS atcatls_read_ca_pubkey(uint8_t slot_id, uint8_t ca_public_key[ATCA_PUB_KEY_SIZE]);

// CSR Handling
ATCA_STATUS atcatls_create_csr(const atcacert_def_t* csr_def, char *csr_out, size_t* csr_size);

// Test Certificates
ATCA_STATUS atcatls_get_device_cert(uint8_t *cert_out, size_t* cert_size);
ATCA_STATUS atcatls_get_signer_cert(uint8_t *cert_out, size_t* cert_size);

// Encrypted Read/Write
ATCA_STATUS atcatls_init_enckey(uint8_t* enc_key_out, uint8_t enckeyId, bool lock);
ATCA_STATUS atcatls_set_enckey(uint8_t* enc_key_in, uint8_t enckeyId, bool lock);
ATCA_STATUS atcatls_get_enckey(uint8_t* enc_key_out);
ATCA_STATUS atcatls_enc_read(uint8_t slot_id, uint8_t block, uint8_t enc_key_id, uint8_t* data, int16_t* buf_size);
ATCA_STATUS atcatls_enc_write(uint8_t slot_id, uint8_t block, uint8_t enc_key_id, uint8_t* data, int16_t buf_size);
ATCA_STATUS atcatls_enc_rsakey_read(uint8_t enckeyId, uint8_t* rsa_key, int16_t* key_size);
ATCA_STATUS atcatls_enc_rsakey_write(uint8_t enckeyId, uint8_t* rsa_key, int16_t key_size);

// Interface to get the encryption key from the platform
typedef ATCA_STATUS (atcatlsfn_get_enckey)(uint8_t* enckey, int16_t key_size);
ATCA_STATUS atcatlsfn_set_get_enckey(atcatlsfn_get_enckey* fn_get_enckey);

/** @} */

#endif // ATCATLS_H
