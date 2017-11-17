/**
 * \file
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

#include <stdlib.h>
#include <stdio.h>
#include "atcatls.h"
#include "atcatls_cfg.h"
#include "basic/atca_basic.h"
#include "atcacert/atcacert_client.h"
#include "atcacert/atcacert_host_hw.h"

// File scope defines
// The RSA key will be written to the upper blocks of slot 8
#define RSA_KEY_SLOT            8
#define RSA_KEY_START_BLOCK     5

// File scope global varibles
uint8_t _enckey[ATCA_KEY_SIZE] = { 0 };
atcatlsfn_get_enckey* _fn_get_enckey = NULL;

///////////////////////////////////////////////////////////////////////////////////////////////////

//#define LOCKABLE_SHA_KEYS

//// Data to be written to each Address
//uint8_t config_data_default[] = {
//	// block 0
//	// Not Written: First 16 bytes are not written
//	0x01, 0x23, 0x00, 0x00,
//	0x00, 0x00, 0x50, 0x00,
//	0x04, 0x05, 0x06, 0x07,
//	0xEE, 0x00, 0x01, 0x00,
//	// I2C, reserved, OtpMode, ChipMode
//	0xC0, 0x00, 0xAA, 0x00,
//	// SlotConfig
//	0x8F, 0x20, 0xC4, 0x44,
//	0x87, 0x20, 0xC4, 0x44,
//#ifdef LOCKABLE_SHA_KEYS
//	0x8F, 0x0F, 0x8F, 0x0F,
//	// block 1
//	0x9F, 0x0F, 0x82, 0x20,
//#else
//	0x8F, 0x0F, 0x8F, 0x8F,
//	// block 1
//	0x9F, 0x8F, 0x82, 0x20,
//#endif
//	0xC4, 0x44, 0xC4, 0x44,
//	0x0F, 0x0F, 0x0F, 0x0F,
//	0x0F, 0x0F, 0x0F, 0x0F,
//	0x0F, 0x0F, 0x0F, 0x0F,
//	// Counters
//	0xFF, 0xFF, 0xFF, 0xFF,
//	0x00, 0x00, 0x00, 0x00,
//	0xFF, 0xFF, 0xFF, 0xFF,
//	// block 2
//	0x00, 0x00, 0x00, 0x00,
//	// Last Key Use
//	0xFF, 0xFF, 0xFF, 0xFF,
//	0xFF, 0xFF, 0xFF, 0xFF,
//	0xFF, 0xFF, 0xFF, 0xFF,
//	0xFF, 0xFF, 0xFF, 0xFF,
//	// Not Written: UserExtra, Selector, LockValue, LockConfig (word offset = 5)
//	0x00, 0x00, 0x00, 0x00,
//	// SlotLock[2], RFU[2]
//	0xFF, 0xFF, 0x00, 0x00,
//	// X.509 Format
//	0x00, 0x00, 0x00, 0x00,
//	// block 3
//	// KeyConfig
//	0x33, 0x00, 0x5C, 0x00,
//	0x13, 0x00, 0x5C, 0x00,
//#ifdef LOCKABLE_SHA_KEYS
//	0x3C, 0x00, 0x3C, 0x00,
//	0x3C, 0x00, 0x33, 0x00,
//#else
//	0x3C, 0x00, 0x1C, 0x00,
//	0x1C, 0x00, 0x33, 0x00,
//#endif
//	0x1C, 0x00, 0x1C, 0x00,
//	0x3C, 0x00, 0x3C, 0x00,
//	0x3C, 0x00, 0x3C, 0x00,
//	0x1C, 0x00, 0x3C, 0x00,
//};

/** \brief Configure the ECC508 for use with TLS API funcitons.
 *		The configuration zone is written and locked.
 *		All GenKey and slot initialization is done and then the data zone is locked.
 *		This configuration needs to be performed before the TLS API functions are called
 *		On a locked ECC508 device, this function will check the configuration against the default and fail if it does not match.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_config_default()
{
    return device_init_default();
    //ATCA_STATUS status = ATCA_SUCCESS;
    //bool isLocked = false;
    //bool sameConfig = false;
    //uint8_t lockRsp[LOCK_RSP_SIZE] = { 0 };
    //uint8_t public_key[ATCA_PUB_KEY_SIZE] = { 0 };

    //do {

    //	// Get the config lock setting
    //	if ((status = atcab_is_locked(LOCK_ZONE_CONFIG, &isLocked)) != ATCA_SUCCESS) BREAK(status, "Read of lock byte failed");

    //	if (isLocked == false) {
    //		// Configuration zone must be unlocked for the write to succeed
    //		if ((status = atcab_write_ecc_config_zone(config_data_default)) != ATCA_SUCCESS) BREAK(status, "Write config zone failed");

    //		// Lock the config zone
    //		if ((status = atcab_lock_config_zone(lockRsp) != ATCA_SUCCESS)) BREAK(status, "Lock config zone failed");

    //		// At this point we have a properly configured and locked config zone
    //		// GenKey all public-private key pairs
    //		if ((status = atcab_genkey(TLS_SLOT_AUTH_PRIV, public_key)) != ATCA_SUCCESS) BREAK(status, "Genkey failed:AUTH_PRIV_SLOT");
    //		if ((status = atcab_genkey(TLS_SLOT_ECDH_PRIV, public_key)) != ATCA_SUCCESS) BREAK(status, "Genkey failed:ECDH_PRIV_SLOT");
    //		if ((status = atcab_genkey(TLS_SLOT_FEATURE_PRIV, public_key)) != ATCA_SUCCESS) BREAK(status, "Genkey failed:FEATURE_PRIV_SLOT");
    //	}else {
    //		// If the config zone is locked, compare the bytes to this configuration
    //		if ((status = atcab_cmp_config_zone(config_data_default, &sameConfig)) != ATCA_SUCCESS) BREAK(status, "Config compare failed");
    //		if (sameConfig == false) {
    //			// The device is locked with the wrong configuration, return an error
    //			status = ATCA_GEN_FAIL;
    //			BREAK(status, "The device is locked with the wrong configuration");
    //		}
    //	}
    //	// Lock the Data zone
    //	// Don't get status since it is ok if it's already locked
    //	atcab_lock_data_zone(lockRsp);

    //} while (0);

    //return status;
}

/** \brief Initialize the ECC508 for use with the TLS API.  Like a constructor
 *  \param[in] pCfg The ATCAIfaceCfg configuration that defines the HAL layer interface
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_init(ATCAIfaceCfg* pCfg)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    // Insert any other constructor code for TLS here.
    status = atcab_init(pCfg);
    return status;
}

/** \brief Finalize the ECC508 when finished.  Like a destructor
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_finish()
{
    ATCA_STATUS status = ATCA_SUCCESS;

    // Insert any other destructor code for TLS here.
    status = atcab_release();
    return status;
}

/** \brief Get the serial number of this device
 *  \param[out] sn_out Pointer to the buffer that will hold the 9 byte serial number read from this device
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_get_sn(uint8_t sn_out[ATCA_SERIAL_NUM_SIZE])
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Call the basic API to get the serial number
        if ((status = atcab_read_serial_number(sn_out)) != ATCA_SUCCESS)
        {
            BREAK(status, "Get serial number failed");
        }

    }
    while (0);

    return status;
}

/** \brief Sign the message with the specified slot and return the signature
 *  \param[in] slot_id The private P256 key slot to use for signing
 *  \param[in] message A pointer to the 32 byte message to be signed
 *  \param[out] signature A pointer that will hold the 64 byte P256 signature
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_sign(uint8_t slot_id, const uint8_t *message, uint8_t *signature)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Check the inputs
        if (message == NULL || signature == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Bad input parameters");
        }
        // Sign the message
        if ((status = atcab_sign(slot_id, message, signature)) != ATCA_SUCCESS)
        {
            BREAK(status, "Sign Failed");
        }

    }
    while (0);

    return status;
}

/** \brief Verify the signature of the specified message using the specified public key
 *  \param[in] message A pointer to the 32 byte message to be verified
 *  \param[in] signature A pointer to the 64 byte P256 signature to be verified
 *  \param[in] public_key A pointer to the 64 byte P256 public key used for verificaion
 *  \param[out] verified A pointer to the boolean result of this verify operation
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_verify(const uint8_t *message, const uint8_t *signature, const uint8_t *public_key, bool *verified)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Check the inputs
        if (message == NULL || signature == NULL || public_key == NULL || verified == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Bad input parameters");
        }
        // Verify the signature of the message
        if ((status = atcab_verify_extern(message, signature, public_key, verified)) != ATCA_SUCCESS)
        {
            BREAK(status, "Verify Failed");
        }

    }
    while (0);

    return status;
}

/**
 * \brief Verify a certificate against its certificate authority's public key using the host's ATECC device for crypto functions.
 * \param[in] cert_def       Certificate definition describing how to extract the TBS and signature components from the certificate specified.
 * \param[in] cert           Certificate to verify.
 * \param[in] cert_size      Size of the certificate (cert) in bytes.
 * \param[in] ca_public_key  The ECC P256 public key of the certificate authority that signed this
 *                           certificate. Formatted as the 32 byte X and Y integers concatenated
 *                           together (64 bytes total).
 * \return ATCA_SUCCESS if the verify succeeds, ATCACERT_VERIFY_FAILED or ATCA_EXECUTION_ERROR if it fails to verify.
 */
ATCA_STATUS atcatls_verify_cert(const atcacert_def_t* cert_def, const uint8_t* cert, size_t cert_size, const uint8_t* ca_public_key)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Check the inputs
        if (cert_def == NULL || cert == NULL || ca_public_key == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Bad input parameters");
        }
        // Verify the certificate
        status = atcacert_verify_cert_hw(cert_def, cert, cert_size, ca_public_key);
        if (status != ATCA_SUCCESS)
        {
            BREAK(status, "Verify Failed");
        }

    }
    while (0);

    return status;
}

/** \brief Generate a pre-master key (pmk) given a private key slot and a public key that will be shared with
 *  \param[in] slot_id slot of key for ECDH computation
 *  \param[in] public_key public to shared with
 *  \param[out] pmk - A pointer to store the computed ECDH key - A buffer with size of ATCA_KEY_SIZE
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_ecdh(uint8_t slot_id, const uint8_t* public_key, uint8_t* pmk)
{
    return atcatls_ecdh_enc(slot_id, TLS_SLOT_ENC_PARENT, public_key, pmk);
}

/** \brief Generate a pre-master key (pmk) given a private key slot and a public key that will be shared with.
 *         This version performs an encrypted read from (slot_id + 1)
 *  \param[in] slot_id Slot of key for ECDH computation
 *  \param[in] enc_key_id Slot of key for the encryption parent
 *  \param[in] public_key Public to shared with
 *  \param[out] pmk - Computed ECDH key - A buffer with size of ATCA_KEY_SIZE
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_ecdh_enc(uint8_t slot_id, uint8_t enc_key_id, const uint8_t* public_key, uint8_t* pmk)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t enc_key[ECDH_KEY_SIZE] = { 0 };

    do
    {
        // Check the inputs
        if (public_key == NULL || pmk == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Bad input parameters");
        }
        // Get the encryption key for this platform
        if ((status = atcatls_get_enckey(enc_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Get enckey Failed");
        }

        if ((status = atcab_ecdh_enc(slot_id, public_key, pmk, enc_key, enc_key_id)) != ATCA_SUCCESS)
        {
            BREAK(status, "ECDH Failed");
        }
    }
    while (0);

    return status;
}

/** \brief Generate a pre-master key (pmk) given a private key slot to create and a public key that will be shared with
 *  \param[in] slot_id Slot of key for ECDHE computation
 *  \param[in] public_key Public to share with
 *  \param[out] public_key_return Public that was created as part of the ECDHE operation
 *  \param[out] pmk - Computed ECDH key - A buffer with size of ATCA_KEY_SIZE
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_ecdhe(uint8_t slot_id, const uint8_t* public_key, uint8_t* public_key_return, uint8_t* pmk)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Check the inputs
        if ((public_key == NULL) || (public_key_return == NULL) || (pmk == NULL))
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Bad input parameters");
        }
        // Create a new key in the ECDH slot
        if ((status = atcab_genkey(slot_id, public_key_return)) != ATCA_SUCCESS)
        {
            BREAK(status, "Create key failed");
        }

        // Send the ECDH command with the public key provided
        if ((status = atcab_ecdh(slot_id, public_key, pmk)) != ATCA_SUCCESS)
        {
            BREAK(status, "ECDH failed");
        }
    }
    while (0);

    return status;
}

/** \brief Create a unique public-private key pair in the specified slot
 *  \param[in] slot_id The slot id to create the ECC private key
 *  \param[out] public_key Pointer the public key bytes that correspond to the private key that was created
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_create_key(uint8_t slot_id, uint8_t* public_key)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Verify input parameters
        if (public_key == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        // Call the Genkey command on the specified slot
        if ((status = atcab_genkey(slot_id, public_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Create key failed");
        }

    }
    while (0);

    return status;
}

/** \brief Get the public key from the specified private key slot
 *  \param[in] slot_id The slot id containing the private key used to calculate the public key
 *  \param[out] public_key Pointer the public key bytes that coorespond to the private key
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_calc_pubkey(uint8_t slot_id, uint8_t *public_key)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Verify input parameters
        if (public_key == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        // Call the GenKey command to return the public key
        if ((status = atcab_get_pubkey(slot_id, public_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Gen public key failed");
        }

    }
    while (0);

    return status;
}

/** \brief reads a pub key from a readable data slot versus atcab_get_pubkey which generates a public_key from a private key slot
 *  \param[in] slot_id Slot number to read, expected value is 0x8 through 0xF
 *  \param[out] public_key Pointer the public key bytes that were read from the slot
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_read_pubkey(uint8_t slot_id, uint8_t *public_key)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Verify input parameters
        if (public_key == NULL || slot_id < 8 || slot_id > 0xF)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "Bad atcatls_read_pubkey() input parameters");
        }
        // Call the GenKey command to return the public key
        if ((status = atcab_read_pubkey(slot_id, public_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Read public key failed");
        }

    }
    while (0);

    return status;
}

/** \brief Get a random number
 *  \param[out] randout Pointer the 32 random bytes that were returned by the Random Command
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_random(uint8_t* randout)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Verify input parameters
        if (randout == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        // Call the random command
        if ((status = atcab_random(randout)) != ATCA_SUCCESS)
        {
            BREAK(status, "Random command failed");
        }

    }
    while (0);

    return status;
}

/** \brief Set the function used to retrieve the unique encryption key for this platform.
 *  \param[in] fn_get_enckey Pointer to a function that will return the platform encryption key
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatlsfn_set_get_enckey(atcatlsfn_get_enckey* fn_get_enckey)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Verify input parameters
        if (fn_get_enckey == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        // Set the get_enckey callback function
        _fn_get_enckey = fn_get_enckey;

    }
    while (0);

    return status;
}

/** \brief Initialize the unique encryption key for this platform.
 *		Write a random number to the parent encryption key slot
 *		Return the random number for storage on platform
 *  \param[out] enc_key_out Pointer to a random 32 byte encryption key that will be stored on the platform and in the device
 *  \param[in] enc_key_id Slot id on the ECC508 to store the encryption key
 *  \param[in] lock If this is set to true, the slot that stores the encryption key will be locked
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_init_enckey(uint8_t* enc_key_out, uint8_t enc_key_id, bool lock)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Verify input parameters
        if (enc_key_out == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        // Get a random number
        if ((status = atcatls_random(enc_key_out)) != ATCA_SUCCESS)
        {
            BREAK(status, "Random command failed");
        }

        // Write the random number as the encryption key
        atcatls_set_enckey(enc_key_out, enc_key_id, lock);

    }
    while (0);

    return status;
}

/** \brief Initialize the unique encryption key for this platform
 *		Write the provided encryption key to the parent encryption key slot
 *		Function optionally lock the parent encryption key slot after it is written
 *  \param[in] enc_key_in Pointer to a 32 byte encryption key that will be stored on the platform and in the device
 *  \param[in] enc_key_id Slot id on the ECC508 to store the encryption key
 *  \param[in] lock If this is set to true, the slot that stores the encryption key will be locked
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_set_enckey(uint8_t* enc_key_in, uint8_t enc_key_id, bool lock)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t block = 0;
    uint8_t offset = 0;

    do
    {
        // Verify input parameters
        if (enc_key_in == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        // Write the random number to specified slot
        if ((status = atcab_write_zone(ATCA_ZONE_DATA, enc_key_id, block, offset, enc_key_in, ATCA_BLOCK_SIZE)) != ATCA_SUCCESS)
        {
            BREAK(status, "Write parent encryption key failed");
        }

        // Optionally lock the key
        if (lock)
        {
            // Send the slot lock command for this slot, ignore the return status
            if ((status = atcab_lock_data_slot(enc_key_id)) != ATCA_SUCCESS)
            {
                BREAK(status, "Slot lock failed.");
            }
        }

    }
    while (0);

    return status;
}

/** \brief Return the random number for storage on platform.
 *		This function reads from platform storage, not the ECC508 device
 *		Therefore, the implementation is platform specific and must be provided at integration
 *  \param[out] enc_key_out Pointer to a 32 byte encryption key that is stored on the platform and in the device
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_get_enckey(uint8_t* enc_key_out)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Verify input parameters
        if (enc_key_out == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        // Memset the output to 0x00
        memset(enc_key_out, 0x00, ATCA_KEY_SIZE);

        // Call the function provided by the platform.  The encryption key must be stored in the platform
        if (_fn_get_enckey != NULL)
        {
            _fn_get_enckey(enc_key_out, ATCA_KEY_SIZE);
        }
        else
        {
            // Get encryption key funciton is not defined.  Return failure.
            status = ATCA_FUNC_FAIL;
        }
    }
    while (0);

    return status;
}

/** \brief Read encrypted bytes from the specified slot
 *  \param[in]  slot_id    The slot id for the encrypted read
 *  \param[in]  block     The block id in the specified slot
 *  \param[in]  enc_key_id  The keyid of the parent encryption key
 *  \param[out] data      The 32 bytes of clear text data that was read encrypted from the slot, then decrypted
 *  \param[inout] buf_size In:Size of data buffer.  Out:Number of bytes read
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_enc_read(uint8_t slot_id, uint8_t block, uint8_t enc_key_id, uint8_t* data, int16_t* buf_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t enc_key[ATCA_KEY_SIZE] = { 0 };

    do
    {
        // Verify input parameters
        if (data == NULL || buf_size == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        // Get the encryption key from the platform
        if ((status = atcatls_get_enckey(enc_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Get encryption key failed");
        }

        // Memset the input data buffer
        memset(data, 0x00, *buf_size);

        // todo: implement to account for the correct block on the ECC508
        if ((status = atcab_read_enc(slot_id, block, data, enc_key, enc_key_id)) != ATCA_SUCCESS)
        {
            BREAK(status, "Read encrypted failed");
        }

    }
    while (0);

    return status;
}

/** \brief Write encrypted bytes to the specified slot
 *  \param[in]  slot_id    The slot id for the encrypted write
 *  \param[in]  block     The block id in the specified slot
 *  \param[in]  enc_key_id  The keyid of the parent encryption key
 *  \param[in] data      The 32 bytes of clear text data that will be encrypted to write to the slot.
 *  \param[in] buf_size    Size of data buffer.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_enc_write(uint8_t slot_id, uint8_t block, uint8_t enc_key_id, uint8_t* data, int16_t buf_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t enc_key[ATCA_KEY_SIZE] = { 0 };

    do
    {
        // Verify input parameters
        if (data == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        // Get the encryption key from the platform
        if ((status = atcatls_get_enckey(enc_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Get encryption key failed");
        }

        // todo: implement to account for the correct block on the ECC508
        if ((status = atcab_write_enc(slot_id, block, data, enc_key, enc_key_id)) != ATCA_SUCCESS)
        {
            BREAK(status, "Write encrypted failed");
        }

    }
    while (0);

    return status;
}

/** \brief Read a private RSA key from the device.  The read will be encrypted
 *  \param[in]  enc_key_id  The keyid of the parent encryption key
 *  \param[out] rsa_key    Pointer to store the read RSA key bytes
 *  \param[inout] key_size Size of RSA key.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_enc_rsakey_read(uint8_t enc_key_id, uint8_t* rsa_key, int16_t* key_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t enc_key[ATCA_KEY_SIZE] = { 0 };
    uint8_t slot_id = RSA_KEY_SLOT;
    uint8_t start_block = RSA_KEY_START_BLOCK;
    uint8_t mem_block = 0;
    uint8_t num_key_blocks = RSA2048_KEY_SIZE / ATCA_BLOCK_SIZE;
    uint8_t block = 0;
    uint8_t mem_loc = 0;

    do
    {
        // Verify input parameters
        if (rsa_key == NULL || key_size == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        if (*key_size < RSA2048_KEY_SIZE)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "RSA key buffer too small");
        }

        // Get the encryption key from the platform
        if ((status = atcatls_get_enckey(enc_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Get encryption key failed");
        }

        // Read the RSA key by blocks
        for (mem_block = 0; mem_block < num_key_blocks; mem_block++)
        {
            block = start_block + mem_block;
            mem_loc = ATCA_BLOCK_SIZE * mem_block;
            if ((status = atcab_read_enc(slot_id, block, &rsa_key[mem_loc], enc_key, enc_key_id)) != ATCA_SUCCESS)
            {
                BREAK(status, "Read RSA failed");
            }
        }
        *key_size = RSA2048_KEY_SIZE;

    }
    while (0);

    return status;
}

/** \brief Write a private RSA key from the device.  The write will be encrypted
 *  \param[in] enc_key_id   The keyid of the parent encryption key
 *  \param[in] rsa_key     Pointer to RSA key bytes
 *  \param[in] key_size    Size of RSA key.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_enc_rsakey_write(uint8_t enc_key_id, uint8_t* rsa_key, int16_t key_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t enc_key[ATCA_KEY_SIZE] = { 0 };
    uint8_t slot_id = RSA_KEY_SLOT;
    uint8_t start_block = RSA_KEY_START_BLOCK;
    uint8_t mem_block = 0;
    uint8_t num_key_blocks = RSA2048_KEY_SIZE / ATCA_BLOCK_SIZE;
    uint8_t block = 0;
    uint8_t mem_loc = 0;

    do
    {
        // Verify input parameters
        if (rsa_key == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }
        if (key_size < RSA2048_KEY_SIZE)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "RSA key buffer too small");
        }

        // Get the encryption key from the platform
        if ((status = atcatls_get_enckey(enc_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Get encryption key failed");
        }

        // Read the RSA key by blocks
        for (mem_block = 0; mem_block < num_key_blocks; mem_block++)
        {
            block = start_block + mem_block;
            mem_loc = ATCA_BLOCK_SIZE * mem_block;
            if ((status = atcab_write_enc(slot_id, block, &rsa_key[mem_loc], enc_key, enc_key_id)) != ATCA_SUCCESS)
            {
                BREAK(status, "Read RSA failed");
            }
        }

    }
    while (0);

    return status;
}

/** \brief Write a public key from the device.
 *  \param[in] slot_id The slot ID to write to
 *  \param[in] public_key The public key bytes
 *  \param[in] lock   If true, lock the slot after writing these bytes.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_write_pubkey(uint8_t slot_id, uint8_t public_key[ATCA_PUB_KEY_SIZE], bool lock)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Write the buffer as a public key into the specified slot
        if ((status = atcab_write_pubkey(slot_id, public_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Write of public key slot failed");
        }


        // Lock the slot if indicated
        if (lock == true)
        {
            if ((status = atcab_lock_data_slot(slot_id)) != ATCA_SUCCESS)
            {
                BREAK(status, "Lock public key slot failed");
            }
        }

    }
    while (0);

    return status;

}

/** \brief Read a public key from the device.
 *  \param[in] slot_id   The slot ID to read from
 *  \param[in] ca_public_key  To store the return public key bytes from device.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_read_ca_pubkey(uint8_t slot_id, uint8_t ca_public_key[ATCA_PUB_KEY_SIZE])
{
    ATCA_STATUS status = ATCA_GEN_FAIL;

    do
    {
        // Read public key from the specified slot and return it in the buffer provided
        if ((status = atcab_read_pubkey(slot_id, ca_public_key)) != ATCA_SUCCESS)
        {
            BREAK(status, "Read of public key slot failed");
        }


    }
    while (0);

    return status;
}

/**
 * \brief Reads the certificate specified by the certificate definition from the ATECC508A device.
 *        This process involves reading the dynamic cert data from the device and combining it
 *        with the template found in the certificate definition. Return the certificate int der format
 * \param[in] cert_def Certificate definition describing where to find the dynamic certificate information
 *                     on the device and how to incorporate it into the template.
 * \param[in] ca_public_key The ECC P256 public key of the certificate authority that signed this certificate.
 *                          Formatted as the 32 byte X and Y integers concatenated together (64 bytes total).
 * \param[out] cert_out Pointer to Buffer to store the received certificate.
 * \param[inout] cert_size As input, the size of the cert buffer in bytes.
 *                         As output, the size of the certificate returned in cert in bytes.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_get_cert(const atcacert_def_t* cert_def, const uint8_t *ca_public_key, uint8_t *cert_out, size_t* cert_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Verify input parameters
        if (cert_out == NULL || cert_size == NULL || cert_def == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }

        // Build a certificate with signature and public key
        status = atcacert_read_cert(cert_def, ca_public_key, cert_out, cert_size);
        if (status != ATCACERT_E_SUCCESS)
        {
            BREAK(status, "Failed to read certificate");
        }

    }
    while (0);

    return status;
}

/**
 * \brief Creates a CSR specified by the CSR definition from the ATECC508A device.
 *        This process involves reading the dynamic CSR data from the device and combining it
 *        with the template found in the CSR definition, then signing it. Return the CSR int der format
 * \param[in] csr_def CSR definition describing where to find the dynamic CSR information
 *                     on the device and how to incorporate it into the template.
 * \param[out] csr_out Pointer to store the received CSR.
 * \param[inout] csr_size As input, the size of the CSR buffer in bytes.
 *                         As output, the size of the CSR returned in cert in bytes.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcatls_create_csr(const atcacert_def_t* csr_def, char *csr_out, size_t* csr_size)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    do
    {
        // Verify input parameters
        if (csr_out == NULL || csr_size == NULL || csr_def == NULL)
        {
            status = ATCA_BAD_PARAM;
            BREAK(status, "NULL inputs");
        }

        // Build a certificate with signature and public key
        status = atcacert_create_csr_pem(csr_def, csr_out, csr_size);
        if (status != ATCACERT_E_SUCCESS)
        {
            BREAK(status, "Failed to create CSR");
        }

    }
    while (0);

    return status;

}

