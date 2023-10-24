/**
 * \file
 * \brief Host side methods to support CryptoAuth computations
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

#include "atca_host.h"
#include "crypto/atca_crypto_sw_sha2.h"
#include "cal_internal.h"

#if ATCA_CA_SUPPORT

/** \brief This function copies otp and sn data into a command buffer.
 *
 * \param[in,out] param pointer to parameter structure
 * \return pointer to command buffer byte that was copied last
 */
#if ATCAH_INCLUDE_DATA
uint8_t *atcah_include_data(struct atca_include_data_in_out *param)
{
    if (MAC_MODE_INCLUDE_OTP_88 == (param->mode & MAC_MODE_INCLUDE_OTP_88))
    {
        (void)memcpy(param->p_temp, param->otp, 11);            // use OTP[0:10], Mode:5 is overridden
        param->p_temp += 11;
    }
    else
    {
        if (MAC_MODE_INCLUDE_OTP_64 == (param->mode & MAC_MODE_INCLUDE_OTP_64))
        {
            (void)memcpy(param->p_temp, param->otp, 8);         // use 8 bytes OTP[0:7] for (6)
        }
        else
        {
            (void)memset(param->p_temp, 0, 8);                  // use 8 zeros for (6)
        }
        param->p_temp += 8;

        (void)memset(param->p_temp, 0, 3);                     // use 3 zeros for (7)
        param->p_temp += 3;
    }

    // (8) 1 byte SN[8]
    *param->p_temp++ = param->sn[8];

    // (9) 4 bytes SN[4:7] or zeros
    if (MAC_MODE_INCLUDE_SN == (param->mode & MAC_MODE_INCLUDE_SN))
    {
        (void)memcpy(param->p_temp, &param->sn[4], 4);           //use SN[4:7] for (9)
    }
    else
    {
        (void)memset(param->p_temp, 0, 4);                       //use zeros for (9)
    }
    param->p_temp += 4;

    // (10) 2 bytes SN[0:1]
    *param->p_temp++ = param->sn[0];
    *param->p_temp++ = param->sn[1];

    // (11) 2 bytes SN[2:3] or zeros
    if (MAC_MODE_INCLUDE_SN == (param->mode & MAC_MODE_INCLUDE_SN))
    {
        (void)memcpy(param->p_temp, &param->sn[2], 2);           //use SN[2:3] for (11)
    }
    else
    {
        (void)memset(param->p_temp, 0, 2);                       //use zeros for (9)
    }
    param->p_temp += 2;

    return param->p_temp;
}
#endif /* ATCAH_INCLUDE_DATA */

/** \brief This function calculates host side nonce with the parameters passed.
 *    \param[in,out] param pointer to parameter structure
 *   \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_NONCE
ATCA_STATUS atcah_nonce(struct atca_nonce_in_out *param)
{
    uint8_t temporary[ATCA_MSG_SIZE_NONCE], nonce_numin_size;
    uint8_t *p_temp;
    uint8_t calc_mode = param->mode & NONCE_MODE_MASK;
    ATCADeviceType device_type = atcab_get_device_type();

    // Check parameters
    if (param->temp_key == NULL || param->num_in == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    (void)calib_get_numin_size(calc_mode, &nonce_numin_size);

    // Calculate or pass-through the nonce to TempKey->Value
    if ((calc_mode == NONCE_MODE_SEED_UPDATE) || (calc_mode == NONCE_MODE_NO_SEED_UPDATE))
    {
        // RandOut is only required for these modes
        if (param->rand_out == NULL)
        {
            return ATCA_BAD_PARAM;
        }

        if ((param->zero & NONCE_ZERO_CALC_MASK) == NONCE_ZERO_CALC_TEMPKEY)
        {
            // Nonce calculation mode. Actual value of TempKey has been returned in RandOut
            (void)memcpy(param->temp_key->value, param->rand_out, 32);

            // TempKey flags aren't changed
        }
        else
        {
            // Calculate nonce using SHA-256 (refer to data sheet)
            p_temp = temporary;

            (void)memcpy(p_temp, param->rand_out, RANDOM_NUM_SIZE);
            p_temp += RANDOM_NUM_SIZE;

            (void)memcpy(p_temp, param->num_in, nonce_numin_size);
            p_temp += nonce_numin_size;

            *p_temp++ = ATCA_NONCE;
            *p_temp++ = param->mode;
            *p_temp++ = 0x00;

            // Calculate SHA256 to get the nonce
            (void)atcac_sw_sha2_256(temporary, ATCA_MSG_SIZE_NONCE, param->temp_key->value);

            // Update TempKey flags
            if ((SHA104 == device_type) || (SHA105 == device_type))
            {
                param->temp_key->source_flag = 0; // Random
            }
            else
            {
                param->temp_key->source_flag = 0; // Random
                param->temp_key->key_id = 0;
                param->temp_key->gen_dig_data = 0;
                param->temp_key->no_mac_flag = 0;
                param->temp_key->valid = 1;
            }
        }

        // Update TempKey to only 32 bytes
        param->temp_key->is_64 = 0;
    }
    else if ((param->mode & NONCE_MODE_MASK) == NONCE_MODE_PASSTHROUGH)
    {

        if ((param->mode & NONCE_MODE_TARGET_MASK) == NONCE_MODE_TARGET_TEMPKEY)
        {
            (void)memcpy(param->temp_key->value, param->num_in, nonce_numin_size);

            // Pass-through mode for TempKey (other targets have no effect on TempKey)
            if ((param->mode & NONCE_MODE_INPUT_LEN_MASK) == NONCE_MODE_INPUT_LEN_64)
            {
                param->temp_key->is_64 = 1;
            }
            else
            {
                param->temp_key->is_64 = 0;
            }

            // Update TempKey flags
            if ((SHA104 == device_type) || (SHA105 == device_type))
            {
                param->temp_key->source_flag = 1; // Not Random
            }
            else
            {
                param->temp_key->source_flag = 1; // Not Random
                param->temp_key->key_id = 0;
                param->temp_key->gen_dig_data = 0;
                param->temp_key->no_mac_flag = 0;
                param->temp_key->valid = 1;
            }
        }
        else //In the case of ECC608, passthrough message may be stored in message digest buffer/ Alternate Key buffer
        {

            // Update TempKey flags
            param->temp_key->source_flag = 1; //Not Random
            param->temp_key->key_id = 0;
            param->temp_key->gen_dig_data = 0;
            param->temp_key->no_mac_flag = 0;
            param->temp_key->valid = 0;

        }
    }
    else if ((NONCE_MODE_GEN_SESSION_KEY == calc_mode) && (param->zero >= 0x8000u))
    {
        // Calculate nonce using SHA-256 (refer to data sheet)
        p_temp = temporary;

        (void)memcpy(p_temp, param->rand_out, RANDOM_NUM_SIZE);
        p_temp += RANDOM_NUM_SIZE;

        (void)memcpy(p_temp, param->num_in, nonce_numin_size);
        p_temp += nonce_numin_size;

        *p_temp++ = ATCA_NONCE;
        *p_temp++ = param->mode;
        *p_temp++ = (uint8_t)((param->zero) & 0xFFu);

        // Calculate SHA256 to get the nonce
        (void)atcac_sw_sha2_256(temporary, ATCA_MSG_SIZE_NONCE, param->temp_key->value);

        if ((SHA104 == device_type) || (SHA105 == device_type))
        {
            param->temp_key->source_flag = 0;
        }
    }
    else
    {
        return ATCA_BAD_PARAM;
    }

    return ATCA_SUCCESS;
}
#endif /* atcah_nonce */

/** \brief Decrypt data that's been encrypted by the IO protection key.
 *          The ECDH and KDF commands on the ATECC608 are the only ones that
 *          support this operation.
 *
 *    \param[in,out] param  Parameters required to perform the operation.
 *
 *   \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_IO_DECRYPT
ATCA_STATUS atcah_io_decrypt(struct atca_io_decrypt_in_out *param)
{
    atcac_sha2_256_ctx_t ctx;
    uint8_t key[ATCA_KEY_SIZE] = { 0 };
    size_t block = 0;
    uint32_t i;

    if (param == NULL || param->io_key == NULL || param->out_nonce == NULL || param->data == NULL)
    {
        return ATCA_BAD_PARAM;
    }
    if (param->data_size % ATCA_BLOCK_SIZE != 0u)
    {
        return ATCA_BAD_PARAM;
    }

    for (block = 0; block < param->data_size / ATCA_BLOCK_SIZE; block++)
    {
        // Calculate key for block
        (void)atcac_sw_sha2_256_init(&ctx);
        (void)atcac_sw_sha2_256_update(&ctx, param->io_key, 32);
        (void)atcac_sw_sha2_256_update(&ctx, &param->out_nonce[block * 16u], 16u);
        (void)atcac_sw_sha2_256_finish(&ctx, key);

        // Decrypt block
        for (i = 0; i < ATCA_BLOCK_SIZE; i++)
        {
            param->data[block * ATCA_BLOCK_SIZE + i] ^= key[i];
        }
    }

    return ATCA_SUCCESS;
}
#endif /* ATCAH_IO_DECRYPT */

/** \brief Calculate the expected MAC on the host side for the Verify command.
 *
 * \param[in,out] param  Data required to perform the operation.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_VERIFY_MAC
ATCA_STATUS atcah_verify_mac(atca_verify_mac_in_out_t *param)
{
    uint8_t verify_mode = (param->mode & VERIFY_MODE_MASK);
    uint8_t verify_source = (param->mode & VERIFY_MODE_SOURCE_MASK);
    atcac_sha2_256_ctx_t ctx;
    uint8_t message[32];
    const uint8_t* nonce = NULL;
    uint8_t input_params[4];
    const uint8_t sign_opcode = ATCA_SIGN;

    // Check parameters
    if (param->signature == NULL || param->msg_dig_buf == NULL || param->io_key == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    // Get the verify message
    if (verify_mode == VERIFY_MODE_VALIDATE || verify_mode == VERIFY_MODE_INVALIDATE)
    {
        if (param->other_data == NULL || param->temp_key == NULL || param->sn == NULL)
        {
            return ATCA_BAD_PARAM;
        }

        // Message is calculated based on TempKey and OtherData
        (void)atcac_sw_sha2_256_init(&ctx);
        (void)atcac_sw_sha2_256_update(&ctx, param->temp_key->value, 32);
        (void)atcac_sw_sha2_256_update(&ctx, &sign_opcode, 1);
        (void)atcac_sw_sha2_256_update(&ctx, &param->other_data[0], 10);
        (void)atcac_sw_sha2_256_update(&ctx, &param->sn[8], 1);
        (void)atcac_sw_sha2_256_update(&ctx, &param->other_data[10], 4);
        (void)atcac_sw_sha2_256_update(&ctx, &param->sn[0], 2);
        (void)atcac_sw_sha2_256_update(&ctx, &param->other_data[14], 5);
        (void)atcac_sw_sha2_256_finish(&ctx, message);
    }
    else if (verify_source == VERIFY_MODE_SOURCE_MSGDIGBUF)
    {
        // Message source is the first 32 bytes of the message digest buffer
        (void)memcpy(message, param->msg_dig_buf, 32);
    }
    else
    {
        // Message source is the first 32 bytes of TempKey
        if (param->temp_key == NULL)
        {
            return ATCA_BAD_PARAM;
        }
        (void)memcpy(message, param->temp_key->value, 32);
    }

    // Get the system nonce
    if (verify_source == VERIFY_MODE_SOURCE_MSGDIGBUF)
    {
        nonce = &param->msg_dig_buf[32];  // System nonce is the second 32 bytes of the message digest buffer
    }
    else
    {
        nonce = &param->msg_dig_buf[0];   // System nonce is the first 32 bytes of the message digest buffer

    }
    // Calculate MAC
    (void)atcac_sw_sha2_256_init(&ctx);
    (void)atcac_sw_sha2_256_update(&ctx, param->io_key, ATCA_KEY_SIZE);  // IO protection key
    (void)atcac_sw_sha2_256_update(&ctx, message, 32);                   // Verify message
    (void)atcac_sw_sha2_256_update(&ctx, nonce, 32);                     // Host (system) nonce
    (void)atcac_sw_sha2_256_update(&ctx, param->signature, 64);          // Signature

    // Add Verify input parameters
    input_params[0] = ATCA_VERIFY;                              // Verify Opcode
    input_params[1] = param->mode;                              // Verify Mode (Param1)
    input_params[2] = (uint8_t)((param->key_id >> 0u) & 0xFFu); // Verify Param2 (LSB)
    input_params[3] = (uint8_t)((param->key_id >> 8u) & 0xFFu); // Verify Param2 (MSB)

    (void)atcac_sw_sha2_256_update(&ctx, input_params, sizeof(input_params));

    // Calculate SHA256 to get mac
    (void)atcac_sw_sha2_256_finish(&ctx, param->mac);

    return ATCA_SUCCESS;
}
#endif

/** \brief Encrypts the digest for the SecureBoot command when using the
 *          encrypted digest / validating mac option.
 *
 * \param[in,out] param  Data required to perform the operation.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_SECUREBOOT_ENC
ATCA_STATUS atcah_secureboot_enc(atca_secureboot_enc_in_out_t* param)
{
    atcac_sha2_256_ctx_t ctx;
    size_t i;

    // Check parameters
    if (param->digest == NULL || param->temp_key == NULL || param->hashed_key == NULL || param->io_key == NULL || param->digest_enc == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    // Calculate key for encrypting digest
    (void)atcac_sw_sha2_256_init(&ctx);
    (void)atcac_sw_sha2_256_update(&ctx, param->io_key, ATCA_KEY_SIZE);
    (void)atcac_sw_sha2_256_update(&ctx, param->temp_key->value, ATCA_KEY_SIZE);
    (void)atcac_sw_sha2_256_finish(&ctx, param->hashed_key);

    // Encrypt digest (XOR with key)
    for (i = 0; i < SECUREBOOT_DIGEST_SIZE; i++)
    {
        param->digest_enc[i] = param->digest[i] ^ param->hashed_key[i];
    }

    return ATCA_SUCCESS;
}
#endif /* ATCAH_SECUREBOOT_ENC */

/** \brief Calculates the expected MAC returned from the SecureBoot command
 *          when verification is a success.
 *
 * The result of this function (param->mac) should be compared with the actual
 * MAC returned to validate the response.
 *
 * \param[in,out] param  Data required to perform the operation.
 *
 *   \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_SECUREBOOT_MAC
ATCA_STATUS atcah_secureboot_mac(atca_secureboot_mac_in_out_t *param)
{
    atcac_sha2_256_ctx_t ctx;
    uint8_t input_params[4];

    if (param->hashed_key == NULL || param->digest == NULL || param->mac == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    // Calculate MAC
    (void)atcac_sw_sha2_256_init(&ctx);
    (void)atcac_sw_sha2_256_update(&ctx, param->hashed_key, ATCA_KEY_SIZE);
    (void)atcac_sw_sha2_256_update(&ctx, param->digest, SECUREBOOT_DIGEST_SIZE);

    // Signature is only skipped when running the SecureBoot command in
    // FullStore mode and SecureBootMode from the configuration zone is set to
    // FullDig
    if (!((param->mode & SECUREBOOT_MODE_MASK) == SECUREBOOT_MODE_FULL_STORE &&
          (param->secure_boot_config & SECUREBOOTCONFIG_MODE_MASK) == SECUREBOOTCONFIG_MODE_FULL_DIG))
    {
        if (param->signature == NULL)
        {
            return ATCA_BAD_PARAM;
        }
        (void)atcac_sw_sha2_256_update(&ctx, param->signature, SECUREBOOT_SIGNATURE_SIZE);
    }

    // Add SecureBoot input parameters
    input_params[0] = ATCA_SECUREBOOT;                          // SecureBoot Opcode
    input_params[1] = param->mode;                              // SecureBoot Mode (Param1)
    input_params[2] = (uint8_t)((param->param2 >> 0u) & 0xFFu); // SecureBoot Param2 (LSB)
    input_params[3] = (uint8_t)((param->param2 >> 8u) & 0xFFu); // SecureBoot Param2 (MSB)
    (void)atcac_sw_sha2_256_update(&ctx, input_params, sizeof(input_params));

    (void)atcac_sw_sha2_256_finish(&ctx, param->mac);

    return ATCA_SUCCESS;
}
#endif /* ATCAH_SECUREBOOT_MAC */


/** \brief This function generates an SHA-256 digest (MAC) of a key, challenge, and other information.

   The resulting digest will match with the one generated by the device when executing a MAC command.
   The TempKey (if used) should be valid (temp_key.valid = 1) before executing this function.

 * \param[in,out] param pointer to parameter structure
 *   \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_MAC
ATCA_STATUS atcah_mac(struct atca_mac_in_out *param)
{
    uint8_t temporary[ATCA_MSG_SIZE_MAC];
    uint8_t *p_temp;
    struct atca_include_data_in_out include_data;
    ATCADeviceType device_type = atcab_get_device_type();

    // Initialize struct
    include_data.otp = param->otp;
    include_data.sn = param->sn;
    include_data.mode = param->mode;

    // Check parameters
    if ((NULL == param->response)
        || ((param->mode & ~MAC_MODE_MASK) > 0u)
        || ((MAC_MODE_BLOCK1_TEMPKEY != (param->mode & MAC_MODE_BLOCK1_TEMPKEY)) && (NULL == param->key))
        || ((MAC_MODE_BLOCK2_TEMPKEY != (param->mode & MAC_MODE_BLOCK2_TEMPKEY)) && (NULL == param->challenge))
        || ((MAC_MODE_USE_TEMPKEY_MASK == (param->mode & MAC_MODE_USE_TEMPKEY_MASK)) && (NULL == param->temp_key))
        || (((MAC_MODE_INCLUDE_OTP_64 == (param->mode & MAC_MODE_INCLUDE_OTP_64))
             || (MAC_MODE_INCLUDE_OTP_88 == (param->mode & MAC_MODE_INCLUDE_OTP_88))) && (NULL == param->otp))
        || ((MAC_MODE_INCLUDE_SN == (param->mode & MAC_MODE_INCLUDE_SN)) && (NULL == param->sn))
        )
    {
        return ATCA_BAD_PARAM;
    }

    if (SHA104 == device_type || SHA105 == device_type)
    {
        // In SHA104 bit 2 of mode parameter must match temp_key.source_flag set by Nonce command or the command will return an error.
        if ((MAC_MODE_SOURCE_FLAG_MATCH != (param->mode & MAC_MODE_SOURCE_FLAG_MATCH)) != (1u != param->temp_key->source_flag))
        {
            return ATCA_EXECUTION_ERROR;
        }
    }
    else
    {
        // Check TempKey fields validity if TempKey is used
        if (((param->mode & MAC_MODE_USE_TEMPKEY_MASK) != 0u)
            // TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
            && ((param->temp_key->no_mac_flag != 0u) || (param->temp_key->valid != 1u)
            // If either mode parameter bit 0 or bit 1 are set, mode parameter bit 2 must match temp_key.source_flag.
            // LHS and RHS expression to be evaluated to TRUE / FALSE first before comparison (!=).
                || ((MAC_MODE_SOURCE_FLAG_MATCH != (param->mode & MAC_MODE_SOURCE_FLAG_MATCH)) != (1u != param->temp_key->source_flag)))
            )
        {
            // Invalidate TempKey, then return
            param->temp_key->valid = 0;
            return ATCA_EXECUTION_ERROR;
        }
    }

    // Start calculation
    p_temp = temporary;

    // (1) first 32 bytes
    (void)memcpy(p_temp, (MAC_MODE_BLOCK1_TEMPKEY == (param->mode & MAC_MODE_BLOCK1_TEMPKEY)) ? param->temp_key->value : param->key, ATCA_KEY_SIZE);                // use Key[KeyID]
    p_temp += ATCA_KEY_SIZE;

    // (2) second 32 bytes
    (void)memcpy(p_temp, (MAC_MODE_BLOCK2_TEMPKEY == (param->mode & MAC_MODE_BLOCK2_TEMPKEY)) ? param->temp_key->value : param->challenge, ATCA_KEY_SIZE);          // use Key[KeyID]
    p_temp += ATCA_KEY_SIZE;

    // (3) 1 byte opcode
    *p_temp++ = ATCA_MAC;

    // (4) 1 byte mode parameter
    *p_temp++ = param->mode;

    // (5) 2 bytes keyID
    *p_temp++ = (uint8_t)(param->key_id & 0xFFu);
    *p_temp++ = (uint8_t)((param->key_id >> 8) & 0xFFu);

    include_data.p_temp = p_temp;
    (void)atcah_include_data(&include_data);

    // Calculate SHA256 to get the MAC digest
    (void)atcac_sw_sha2_256(temporary, ATCA_MSG_SIZE_MAC, param->response);

    // Update TempKey fields
    if (NULL != param->temp_key)
    {
        param->temp_key->valid = 0;
    }

    return ATCA_SUCCESS;
}
#endif /* ATCAH_MAC */



/** \brief This function performs the checkmac operation to generate client response on the host side .
 * \param[in,out] param  Input and output parameters
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_CHECK_MAC
ATCA_STATUS atcah_check_mac(struct atca_check_mac_in_out *param)
{
    uint8_t msg[ATCA_MSG_SIZE_MAC];
    bool is_temp_key_req = false;

    // Check parameters
    if (param == NULL || param->other_data == NULL || param->sn == NULL || param->client_resp == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    if (
        (CHECKMAC_MODE_BLOCK1_TEMPKEY == (param->mode & CHECKMAC_MODE_BLOCK1_TEMPKEY)) ||
        (CHECKMAC_MODE_BLOCK2_TEMPKEY == (param->mode & CHECKMAC_MODE_BLOCK2_TEMPKEY))
        )
    {
        is_temp_key_req = true;  // Message uses TempKey
    }
    if (!is_temp_key_req && ((param->mode == 0x01u || param->mode == 0x05u) && param->target_key != NULL))
    {
        is_temp_key_req = true;  // CheckMac copy will be performed

    }
    if (is_temp_key_req && param->temp_key == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    if ((CHECKMAC_MODE_BLOCK1_TEMPKEY != (param->mode & CHECKMAC_MODE_BLOCK1_TEMPKEY)) && param->slot_key == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    if ((CHECKMAC_MODE_BLOCK2_TEMPKEY != (param->mode & CHECKMAC_MODE_BLOCK2_TEMPKEY)) && param->client_chal == NULL)
    {
        return ATCA_BAD_PARAM;
    }
    if ((CHECKMAC_MODE_INCLUDE_OTP_64 == (param->mode & CHECKMAC_MODE_INCLUDE_OTP_64)) && param->otp == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    if ( (CHECKMAC_MODE_BLOCK1_TEMPKEY == (param->mode & CHECKMAC_MODE_BLOCK1_TEMPKEY)) ||
         (CHECKMAC_MODE_BLOCK2_TEMPKEY == (param->mode & CHECKMAC_MODE_BLOCK2_TEMPKEY)) )
    {
        // This will use TempKey in message, check validity
        if (0u == param->temp_key->valid)
        {
            return ATCA_EXECUTION_ERROR;  // TempKey is not valid
        }
        if (((param->mode >> 2) & 0x01u) != param->temp_key->source_flag)
        {
            return ATCA_EXECUTION_ERROR;  // TempKey SourceFlag doesn't match bit 2 of the mode
        }
    }

    // Build the message
    (void)memset(msg, 0, sizeof(msg));
    if (CHECKMAC_MODE_BLOCK1_TEMPKEY == (param->mode & CHECKMAC_MODE_BLOCK1_TEMPKEY))
    {
        (void)memcpy(&msg[0], param->temp_key->value, 32);
    }
    else
    {
        (void)memcpy(&msg[0], param->slot_key, 32);
    }
    if (CHECKMAC_MODE_BLOCK2_TEMPKEY == (param->mode & CHECKMAC_MODE_BLOCK2_TEMPKEY))
    {
        (void)memcpy(&msg[32], param->temp_key->value, 32);
    }
    else
    {
        (void)memcpy(&msg[32], param->client_chal, 32);
    }
    (void)memcpy(&msg[64], &param->other_data[0], 4);
    if (CHECKMAC_MODE_INCLUDE_OTP_64 == (param->mode & CHECKMAC_MODE_INCLUDE_OTP_64))
    {
        (void)memcpy(&msg[68], param->otp, 8);
    }
    (void)memcpy(&msg[76], &param->other_data[4], 3);
    msg[79] = param->sn[8];
    (void)memcpy(&msg[80], &param->other_data[7], 4);
    (void)memcpy(&msg[84], &param->sn[0], 2);
    (void)memcpy(&msg[86], &param->other_data[11], 2);

    // Calculate the client response
    (void)atcac_sw_sha2_256(msg, sizeof(msg), param->client_resp);

    // Update TempKey fields
    if ((param->mode == 0x01u || param->mode == 0x05u) && param->target_key != NULL)
    {
        // CheckMac Copy will be performed
        (void)memcpy(param->temp_key->value, param->target_key, ATCA_KEY_SIZE);
        param->temp_key->gen_dig_data = 0;
        param->temp_key->source_flag = 1;
        param->temp_key->valid = 1;
    }

    return ATCA_SUCCESS;
}
#endif /* ATCAH_CHECK_MAC */

/** \brief This function performs the checkmac operation and generates output response mac on the host side .
 * \param[in,out] param  Input and output parameters
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_GEN_OUTPUT_RESP_MAC
ATCA_STATUS atcah_gen_output_resp_mac(struct atca_resp_mac_in_out *param)
{
    uint8_t response_mac[ATCA_MSG_SIZE_RESPONSE_MAC];
    uint8_t *p_temp;

    if ((NULL == param->slot_key) || (NULL == param->client_resp) || (NULL == param->sn) || (NULL == param->mac_output))
    {
        return ATCA_BAD_PARAM;
    }

    p_temp = response_mac;

    // (1) 32 bytes of slot key
    (void)memcpy(p_temp, param->slot_key, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    // (2) 0x28
    *p_temp++ = ATCA_CHECKMAC;

    // (3) Param1
    *p_temp++ = param->mode;

    // (4) 0x0003
    *p_temp++ = (uint8_t)(param->key_id & 0xFFu);
    *p_temp++ = (uint8_t)((param->key_id >> 8) & 0xFFu);

    // (5) 1 byte SN[8]
    *p_temp++ = param->sn[8];

    // (6) 2 bytes SN[0:1]
    *p_temp++ = param->sn[0];
    *p_temp++ = param->sn[1];

    // (7) 25 zeros
    (void)memset(p_temp, 0, ATCA_RESP_MAC_ZEROS_SIZE);
    p_temp += ATCA_RESP_MAC_ZEROS_SIZE;

    // (8) 32 bytes mac response generated by client device
    (void)memcpy(p_temp, param->client_resp, 32);
    p_temp += MAC_SIZE;

    // (8) 1 byte Checkmac result
    *p_temp = param->checkmac_result;

    // Calculate SHA256 to generate output response mac
    (void)atcac_sw_sha2_256(response_mac, sizeof(response_mac), param->mac_output);

    return ATCA_SUCCESS;
}
#endif

/** \brief This function generates an HMAC / SHA-256 hash of a key and other information.

   The resulting hash will match with the one generated in the device by an HMAC command.
   The TempKey has to be valid (temp_key.valid = 1) before executing this function.

 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_HMAC
ATCA_STATUS atcah_hmac(struct atca_hmac_in_out *param)
{
    // Local Variables
    struct atca_include_data_in_out include_data;
    uint8_t temporary[ATCA_HMAC_BLOCK_SIZE + ATCA_MSG_SIZE_HMAC];
    uint8_t i = 0;
    uint8_t *p_temp = NULL;

    // Check parameters
    if ((NULL == param->response) || (NULL == param->key) || (NULL == param->temp_key)
        || ((param->mode & ~HMAC_MODE_MASK) > 0u)
        || (((MAC_MODE_INCLUDE_OTP_64 == (param->mode & MAC_MODE_INCLUDE_OTP_64))
             || (MAC_MODE_INCLUDE_OTP_88 == (param->mode & MAC_MODE_INCLUDE_OTP_88))) && (NULL == param->otp))
        || (NULL == param->sn)
        )
    {
        return ATCA_BAD_PARAM;
    }

    // Check TempKey fields validity (TempKey is always used)
    if ( // TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
        (param->temp_key->no_mac_flag == 1u) || (param->temp_key->valid != 1u)
        // The mode parameter bit 2 must match temp_key.source_flag.
        // LHS and RHS expression to be evaluated to TRUE / FALSE first before comparison (!=).
        || ((MAC_MODE_SOURCE_FLAG_MATCH != (param->mode & MAC_MODE_SOURCE_FLAG_MATCH)) != (1u != (param->temp_key->source_flag)))
        )
    {
        // Invalidate TempKey, then return
        param->temp_key->valid = 0;
        return ATCA_EXECUTION_ERROR;
    }

    // Start first calculation (inner)
    p_temp = temporary;

    // XOR key with ipad
    for (i = 0; i < ATCA_KEY_SIZE; i++)
    {
        *p_temp++ = (uint8_t)((param->key[i] ^ 0x36u) & 0xFFu);
    }

    // zero pad key out to block size
    // Refer to fips-198 , length Key = 32 bytes, Block size = 512 bits = 64 bytes.
    // So the Key must be padded with zeros.
    (void)memset(p_temp, 0x36, ATCA_HMAC_BLOCK_SIZE - ATCA_KEY_SIZE);
    p_temp += ATCA_HMAC_BLOCK_SIZE - ATCA_KEY_SIZE;

    // Next append the stream of data 'text'
    (void)memset(p_temp, 0, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    (void)memcpy(p_temp, param->temp_key->value, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    *p_temp++ = ATCA_HMAC;
    *p_temp++ = param->mode;

    *p_temp++ = (uint8_t)((param->key_id >> 0u) & 0xFFu);
    *p_temp++ = (uint8_t)((param->key_id >> 8u) & 0xFFu);

    include_data.otp = param->otp;
    include_data.sn = param->sn;
    include_data.mode = param->mode;
    include_data.p_temp = p_temp;
    (void)atcah_include_data(&include_data);

    // Calculate SHA256
    // H((K0^ipad):text), use param.response for temporary storage
    (void)atcac_sw_sha2_256(temporary, ATCA_HMAC_BLOCK_SIZE + ATCA_MSG_SIZE_HMAC, param->response);


    // Start second calculation (outer)
    p_temp = temporary;

    // XOR K0 with opad
    for (i = 0; i < ATCA_KEY_SIZE; i++)
    {
        *p_temp++ = (uint8_t)((param->key[i] ^ 0x5Cu) & 0xFFu);
    }

    // zero pad key out to block size
    // Refer to fips-198 , length Key = 32 bytes, Block size = 512 bits = 64 bytes.
    // So the Key must be padded with zeros.
    (void)memset(p_temp, 0x5C, ATCA_HMAC_BLOCK_SIZE - ATCA_KEY_SIZE);
    p_temp += ATCA_HMAC_BLOCK_SIZE - ATCA_KEY_SIZE;

    // Append result from last calculation H((K0 ^ ipad) || text)
    (void)memcpy(p_temp, param->response, ATCA_SHA_DIGEST_SIZE);
    p_temp += ATCA_SHA_DIGEST_SIZE;

    // Calculate SHA256 to get the resulting HMAC
    (void)atcac_sw_sha2_256(temporary, ATCA_HMAC_BLOCK_SIZE + ATCA_SHA_DIGEST_SIZE, param->response);

    // Update TempKey fields
    param->temp_key->valid = 0;

    return ATCA_SUCCESS;
}
#endif /* ATCAH_HMAC */

/** \brief This function combines the current TempKey with a stored value.

   The stored value can be a data slot, OTP page, configuration zone, or hardware transport key.
   The TempKey generated by this function will match with the TempKey in the device generated
   when executing a GenDig command.
   The TempKey should be valid (temp_key.valid = 1) before executing this function.
   To use this function, an application first sends a GenDig command with a chosen stored value to the device.
   This stored value must be known by the application and is passed to this GenDig calculation function.
   The function calculates a new TempKey and returns it.

 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_GENDIG
ATCA_STATUS atcah_gen_dig(struct atca_gen_dig_in_out *param)
{
    uint8_t temporary[ATCA_MSG_SIZE_GEN_DIG];
    uint8_t *p_temp;

    // Check parameters
    if (param->sn == NULL || param->temp_key == NULL)
    {
        return ATCA_BAD_PARAM;
    }
    if ((param->zone <= GENDIG_ZONE_DATA) && (param->stored_value == NULL))
    {
        return ATCA_BAD_PARAM;  // Stored value cannot be null for Config,OTP and Data
    }

    if ((param->zone == GENDIG_ZONE_SHARED_NONCE || (param->zone == GENDIG_ZONE_DATA && param->is_key_nomac)) && param->other_data == NULL)
    {
        return ATCA_BAD_PARAM;  // Other data is required in these cases
    }

    if (param->zone > 5u)
    {
        return ATCA_BAD_PARAM;  // Unknown zone

    }
    // Start calculation
    p_temp = temporary;


    // (1) 32 bytes inputKey
    if (param->zone == GENDIG_ZONE_SHARED_NONCE)
    {
        if (GENDIG_USE_TEMPKEY_BIT == (param->key_id & GENDIG_USE_TEMPKEY_BIT))
        {
            (void)memcpy(p_temp, param->temp_key->value, ATCA_KEY_SIZE);  // 32 bytes TempKey
        }
        else
        {
            (void)memcpy(p_temp, param->other_data, ATCA_KEY_SIZE);       // 32 bytes other data

        }
    }
    else if (param->zone == GENDIG_ZONE_COUNTER || param->zone == GENDIG_ZONE_KEY_CONFIG)
    {
        (void)memset(p_temp, 0x00, ATCA_KEY_SIZE);                        // 32 bytes of zero.

    }
    else
    {
        (void)memcpy(p_temp, param->stored_value, ATCA_KEY_SIZE);     // 32 bytes of stored data

    }

    p_temp += ATCA_KEY_SIZE;


    if (param->zone == GENDIG_ZONE_DATA && param->is_key_nomac)
    {
        // If a key has the SlotConfig.NoMac bit set, then opcode and parameters come from OtherData
        (void)memcpy(p_temp, param->other_data, 4);
        p_temp += 4;
    }
    else
    {
        // (2) 1 byte Opcode
        *p_temp++ = ATCA_GENDIG;

        // (3) 1 byte Param1 (zone)
        *p_temp++ = param->zone;

        // (4) 1 byte LSB of Param2 (keyID)
        *p_temp++ = (uint8_t)(param->key_id & 0xFFu);
        if (param->zone == GENDIG_ZONE_SHARED_NONCE)
        {
            //(4) 1 byte zero for shared nonce mode
            *p_temp++ = 0;
        }
        else
        {
            //(4)  1 byte MSB of Param2 (keyID) for other modes
            *p_temp++ = (uint8_t)(param->key_id >> 8);
        }
    }

    // (5) 1 byte SN[8]
    *p_temp++ = param->sn[8];

    // (6) 2 bytes SN[0:1]
    *p_temp++ = param->sn[0];
    *p_temp++ = param->sn[1];


    // (7)
    if (param->zone == GENDIG_ZONE_COUNTER)
    {
        *p_temp++ = 0;
        *p_temp++ = (uint8_t)(param->counter & 0xFFu);   // (7) 4 bytes of counter
        *p_temp++ = (uint8_t)((param->counter >> 8u) & 0xFFu);
        *p_temp++ = (uint8_t)((param->counter >> 16u) & 0xFFu);
        *p_temp++ = (uint8_t)((param->counter >> 24u) & 0xFFu);

        (void)memset(p_temp, 0x00, 20);                       // (7) 20 bytes of zero
        p_temp += 20;

    }
    else if (param->zone == GENDIG_ZONE_KEY_CONFIG)
    {
        *p_temp++ = 0;
        *p_temp++ = (uint8_t)(param->slot_conf & 0xFFu);            // (7) 2 bytes of Slot config
        *p_temp++ = (uint8_t)(param->slot_conf >> 8u);

        *p_temp++ = (uint8_t)(param->key_conf & 0xFFu);
        *p_temp++ = (uint8_t)(param->key_conf >> 8u);  // (7) 2 bytes of key config

        *p_temp++ = param->slot_locked;                // (7) 1 byte of slot locked

        (void)memset(p_temp, 0x00, 19);                // (7) 19 bytes of zero
        p_temp += 19;

    }
    else
    {

        (void)memset(p_temp, 0, ATCA_GENDIG_ZEROS_SIZE);       // (7) 25 zeros
        p_temp += ATCA_GENDIG_ZEROS_SIZE;

    }

    if (param->zone == GENDIG_ZONE_SHARED_NONCE && (0x8000u == (param->key_id & 0x8000u)))
    {
        (void)memcpy(p_temp, param->other_data, ATCA_KEY_SIZE);           // (8) 32 bytes OtherData
        p_temp += ATCA_KEY_SIZE;

    }
    else
    {
        (void)memcpy(p_temp, param->temp_key->value, ATCA_KEY_SIZE);      // (8) 32 bytes TempKey
        p_temp += ATCA_KEY_SIZE;

    }

    // Calculate SHA256 to get the new TempKey
    (void)atcac_sw_sha2_256(temporary, atcab_pointer_delta(p_temp, temporary), param->temp_key->value);

    // Update TempKey fields
    param->temp_key->valid = 1;

    if ((param->zone == GENDIG_ZONE_DATA) && (param->key_id <= 15u))
    {
        param->temp_key->gen_dig_data = 1;
        param->temp_key->key_id = (uint8_t)(param->key_id & 0xFu);   // mask lower 4-bit only
        if (param->is_key_nomac)
        {
            param->temp_key->no_mac_flag = 1;
        }
    }
    else
    {
        param->temp_key->gen_dig_data = 0;
        param->temp_key->key_id = 0;
    }

    return ATCA_SUCCESS;
}
#endif /* ATCAH_GENDIG */

/** \brief This function calculates the diversified key for the SHA105 device
 *
 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_GENDIVKEY
ATCA_STATUS atcah_gendivkey(struct atca_diversified_key_in_out *param)
{
    uint8_t diversified_key_input[ATCA_MSG_SIZE_DIVERSIFIED_KEY];
    uint8_t *p_temp;

    if ((NULL == param->parent_key) || (NULL == param->other_data) || (NULL == param->input_data))
    {
        return ATCA_BAD_PARAM;
    }

    p_temp = diversified_key_input;

    // (1) 32 bytes of parent key
    (void)memcpy(p_temp, param->parent_key, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    // (1) 4 bytes of other data
    (void)memcpy(p_temp, param->other_data, ATCA_WORD_SIZE);
    p_temp += ATCA_WORD_SIZE;

    // (5) 1 byte SN[8]
    *p_temp++ = param->sn[8];

    // (6) 2 bytes SN[0:1]
    *p_temp++ = param->sn[0];
    *p_temp++ = param->sn[1];

    // (7) 25 zeros
    (void)memset(p_temp, 0, ATCA_GENDIVKEY_ZEROS_SIZE);
    p_temp += ATCA_GENDIVKEY_ZEROS_SIZE;

    // (8) 32 bytes fixed input data
    (void)memcpy(p_temp, param->input_data, 32);

    // Calculate SHA256 to get diversified key
    (void)atcac_sw_sha2_256(diversified_key_input, sizeof(diversified_key_input), param->temp_key->value);

    return ATCA_SUCCESS;
}
#endif /* ATCAH_GENDIVKEY */

/** \brief This function generates mac with session key with a plain text.
 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_GEN_MAC
ATCA_STATUS atcah_gen_mac(struct atca_gen_dig_in_out *param)
{
    uint8_t temporary[ATCA_MSG_SIZE_GEN_DIG];
    uint8_t *p_temp;

    // Check parameters
    if ((NULL == param->stored_value) || (NULL == param->temp_key))
    {
        return ATCA_BAD_PARAM;
    }

    // Check TempKey fields validity (TempKey is always used)
    if ( // TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
        (param->temp_key->no_mac_flag != 0u) || (param->temp_key->valid != 1u)
        )
    {
        // Invalidate TempKey, then return
        param->temp_key->valid = 0;
        return ATCA_EXECUTION_ERROR;
    }

    // Start calculation
    p_temp = temporary;

    // (1) 32 bytes SessionKey
    //     (Config[KeyID] or OTP[KeyID] or Data.slot[KeyID] or TransportKey[KeyID])
    (void)memcpy(p_temp, param->temp_key->value, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    // (2) 1 byte Opcode
    *p_temp++ = ATCA_WRITE;

    // (3) 1 byte Param1 (zone)
    *p_temp++ = param->zone;

    // (4) 2 bytes Param2 (keyID)
    *p_temp++ = (uint8_t)(param->key_id & 0xFFu);
    *p_temp++ = (uint8_t)((param->key_id >> 8) & 0xFFu);

    // (5) 1 byte SN[8]
    *p_temp++ = param->sn[8];

    // (6) 2 bytes SN[0:1]
    *p_temp++ = param->sn[0];
    *p_temp++ = param->sn[1];

    // (7) 25 zeros
    (void)memset(p_temp, 0, ATCA_GENDIG_ZEROS_SIZE);
    p_temp += ATCA_GENDIG_ZEROS_SIZE;

    // (8) 32 bytes PlainText
    (void)memcpy(p_temp, param->stored_value, ATCA_KEY_SIZE);

    // Calculate SHA256 to get the new TempKey
    (void)atcac_sw_sha2_256(temporary, ATCA_MSG_SIZE_GEN_DIG, param->temp_key->value);

    // Update TempKey fields
    param->temp_key->valid = 1;

    if ((param->zone == GENDIG_ZONE_DATA) && (param->key_id <= 15u))
    {
        param->temp_key->gen_dig_data = 1;
        param->temp_key->key_id = (uint8_t)(param->key_id & 0xFu);   // mask lower 4-bit only
    }
    else
    {
        param->temp_key->gen_dig_data = 0;
        param->temp_key->key_id = 0;
    }

    return ATCA_SUCCESS;
}
#endif /* ATCAH_GEN_MAC */

/** \brief This function calculates the input MAC for the Write command.

   The Write command will need an input MAC if SlotConfig.WriteConfig.Encrypt is set.

 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_WRITE_AUTH_MAC
ATCA_STATUS atcah_write_auth_mac(struct atca_write_mac_in_out *param)
{
    uint8_t mac_input[ATCA_MSG_SIZE_ENCRYPT_MAC];
    uint8_t i;
    uint8_t *p_temp;

    // Check parameters
    if ((NULL == param->input_data) || (NULL == param->temp_key))
    {
        return ATCA_BAD_PARAM;
    }

    // Check TempKey fields validity (TempKey is always used)
    if ( // TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
        (0u != param->temp_key->no_mac_flag) || (param->temp_key->valid != 1u)
        )
    {
        // Invalidate TempKey, then return
        param->temp_key->valid = 0;
        return ATCA_EXECUTION_ERROR;
    }
    // Encrypt by XOR-ing Data with the TempKey
    for (i = 0u; i < 32u; i++)
    {
        param->encrypted_data[i] = param->input_data[i] ^ param->temp_key->value[i];
    }

    // If the pointer *mac is provided by the caller then calculate input MAC
    if (NULL != param->auth_mac)
    {
        // Start calculation
        p_temp = mac_input;

        // (1) 32 bytes TempKey
        (void)memcpy(p_temp, param->temp_key->value, ATCA_KEY_SIZE);
        p_temp += ATCA_KEY_SIZE;

        // (2) 1 byte Opcode
        *p_temp++ = ATCA_WRITE;

        // (3) 1 byte Param1 (zone)
        *p_temp++ = param->zone;

        // (4) 2 bytes Param2 (keyID)
        *p_temp++ = (uint8_t)(param->key_id & 0xFFu);
        *p_temp++ = (uint8_t)((param->key_id >> 8u) & 0xFFu);

        // (5) 1 byte SN[8]
        *p_temp++ = param->sn[8];

        // (6) 2 bytes SN[0:1]
        *p_temp++ = param->sn[0];
        *p_temp++ = param->sn[1];

        // (7) 25 zeros
        (void)memset(p_temp, 0, ATCA_WRITE_MAC_ZEROS_SIZE);
        p_temp += ATCA_WRITE_MAC_ZEROS_SIZE;

        // (8) 32 bytes PlainText
        (void)memcpy(p_temp, param->input_data, ATCA_KEY_SIZE);

        // Calculate SHA256 to get MAC
        (void)atcac_sw_sha2_256(mac_input, sizeof(mac_input), param->auth_mac);
    }

    return ATCA_SUCCESS;
}
#endif /* ATCAH_WRITE_AUTH_MAC */

/** \brief This function calculates the input MAC for the PrivWrite command.

   The PrivWrite command will need an input MAC if SlotConfig.WriteConfig.Encrypt is set.

 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_PRIVWRITE_AUTH_MAC
ATCA_STATUS atcah_privwrite_auth_mac(struct atca_write_mac_in_out *param)
{
    uint8_t mac_input[ATCA_MSG_SIZE_PRIVWRITE_MAC];
    uint8_t i = 0;
    uint8_t *p_temp = NULL;
    uint8_t session_key2[32] = { 0 };

    // Check parameters
    if ((NULL == param->input_data) || (NULL == param->temp_key))
    {
        return ATCA_BAD_PARAM;
    }

    // Check TempKey fields validity (TempKey is always used)
    if ( // TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
        (0u != param->temp_key->no_mac_flag) || (param->temp_key->valid != 1u)
        )
    {
        // Invalidate TempKey, then return
        param->temp_key->valid = 0;
        return ATCA_EXECUTION_ERROR;
    }


    /* Encrypt by XOR-ing Data with the TempKey
     */

    // Encrypt the next 28 bytes of the cipher text, which is the first part of the private key.
    for (i = 0u; i < 32u; i++)
    {
        param->encrypted_data[i] = param->input_data[i] ^ param->temp_key->value[i];
    }

    // Calculate the new key for the last 4 bytes of the cipher text
    (void)atcac_sw_sha2_256(param->temp_key->value, 32, session_key2);

    // Encrypt the last 4 bytes of the cipher text, which is the remaining part of the private key
    for (i = 32u; i < 36u; i++)
    {
        param->encrypted_data[i] = param->input_data[i] ^ session_key2[i - 32u];
    }

    // If the pointer *mac is provided by the caller then calculate input MAC
    if (NULL != param->auth_mac)
    {
        // Start calculation
        p_temp = mac_input;

        // (1) 32 bytes TempKey
        (void)memcpy(p_temp, param->temp_key->value, ATCA_KEY_SIZE);
        p_temp += ATCA_KEY_SIZE;

        // (2) 1 byte Opcode
        *p_temp++ = ATCA_PRIVWRITE;

        // (3) 1 byte Param1 (zone)
        *p_temp++ = param->zone;

        // (4) 2 bytes Param2 (keyID)
        *p_temp++ = (uint8_t)(param->key_id & 0xFFu);
        *p_temp++ = (uint8_t)((param->key_id >> 8u) & 0xFFu);

        // (5) 1 byte SN[8]
        *p_temp++ = param->sn[8];

        // (6) 2 bytes SN[0:1]
        *p_temp++ = param->sn[0];
        *p_temp++ = param->sn[1];

        // (7) 21 zeros
        (void)memset(p_temp, 0, ATCA_PRIVWRITE_MAC_ZEROS_SIZE);
        p_temp += ATCA_PRIVWRITE_MAC_ZEROS_SIZE;

        // (8) 36 bytes PlainText (Private Key)
        (void)memcpy(p_temp, param->input_data, ATCA_PRIVWRITE_PLAIN_TEXT_SIZE);

        // Calculate SHA256 to get the new TempKey
        (void)atcac_sw_sha2_256(mac_input, sizeof(mac_input), param->auth_mac);
    }

    return ATCA_SUCCESS;
}
#endif /* ATCAH_PRIVWRITE_AUTH_MAC */

/** \brief This function derives a key with a key and TempKey.

   Used in conjunction with DeriveKey command, the key derived by this function will match the key in the device.
   Two kinds of operation are supported:
   <ul>
   <li>Roll Key operation: target_key and parent_key parameters should be set to point to the same location (TargetKey).</li>
   <li>Create Key operation: target_key should be set to point to TargetKey, parent_key should be set to point to ParentKey.</li>
   </ul>
   After executing this function, the initial value of target_key will be overwritten with the derived key.
   The TempKey should be valid (temp_key.valid = 1) before executing this function.

 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_DERIVE_KEY
ATCA_STATUS atcah_derive_key(struct atca_derive_key_in_out *param)
{
    uint8_t temporary[ATCA_MSG_SIZE_DERIVE_KEY];
    uint8_t *p_temp;

    // Check parameters
    if ((NULL == param->parent_key) || (NULL == param->target_key) || (NULL == param->temp_key)
        || ((param->mode & ~DERIVE_KEY_RANDOM_FLAG) > 0u) || (param->target_key_id > ATCA_KEY_ID_MAX))
    {
        return ATCA_BAD_PARAM;
    }


    // Check TempKey fields validity (TempKey is always used)
    if ( // TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
        (0u != param->temp_key->no_mac_flag) || (param->temp_key->valid != 1u)
        // The random parameter bit 2 must match temp_key.source_flag
        // LHS and RHS expression to be evaluated to TRUE / FALSE first before comparison (!=).
        || ((DERIVE_KEY_RANDOM_FLAG != (param->mode & DERIVE_KEY_RANDOM_FLAG)) != (1u != (param->temp_key->source_flag)))
        )
    {
        // Invalidate TempKey, then return
        param->temp_key->valid = 0;
        return ATCA_EXECUTION_ERROR;
    }

    // Start calculation
    p_temp = temporary;

    // (1) 32 bytes parent key
    (void)memcpy(p_temp, param->parent_key, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    // (2) 1 byte Opcode
    *p_temp++ = ATCA_DERIVE_KEY;

    // (3) 1 byte Param1 (random)
    *p_temp++ = param->mode;

    // (4) 2 bytes Param2 (keyID)
    *p_temp++ = (uint8_t)(param->target_key_id & 0xFFu);
    *p_temp++ = (uint8_t)((param->target_key_id >> 8) & 0xFFu);

    // (5) 1 byte SN[8]
    *p_temp++ = param->sn[8];

    // (6) 2 bytes SN[0:1]
    *p_temp++ = param->sn[0];
    *p_temp++ = param->sn[1];

    // (7) 25 zeros
    (void)memset(p_temp, 0, ATCA_DERIVE_KEY_ZEROS_SIZE);
    p_temp += ATCA_DERIVE_KEY_ZEROS_SIZE;

    // (8) 32 bytes TempKey
    (void)memcpy(p_temp, param->temp_key->value, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    // Calculate SHA256 to get the derived key.
    (void)atcac_sw_sha2_256(temporary, ATCA_MSG_SIZE_DERIVE_KEY, param->target_key);

    // Update TempKey fields
    param->temp_key->valid = 0;

    return ATCA_SUCCESS;
}
#endif /* ATCAH_DERIVE_KEY */

/** \brief This function calculates the input MAC for a DeriveKey command.

   The DeriveKey command will need an input MAC if SlotConfig[TargetKey].Bit15 is set.

 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_DERIVE_KEY_MAC
ATCA_STATUS atcah_derive_key_mac(struct atca_derive_key_mac_in_out *param)
{
    uint8_t temporary[ATCA_MSG_SIZE_DERIVE_KEY_MAC];
    uint8_t *p_temp;

    // Check parameters
    if ((NULL == param->parent_key) || (NULL == param->mac) || ((param->mode & ~DERIVE_KEY_RANDOM_FLAG) > 0u)
        || (param->target_key_id > ATCA_KEY_ID_MAX))
    {
        return ATCA_BAD_PARAM;
    }

    // Start calculation
    p_temp = temporary;

    // (1) 32 bytes parent key
    (void)memcpy(p_temp, param->parent_key, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    // (2) 1 byte Opcode
    *p_temp++ = ATCA_DERIVE_KEY;

    // (3) 1 byte Param1 (random)
    *p_temp++ = param->mode;

    // (4) 2 bytes Param2 (keyID)
    *p_temp++ = (uint8_t)(param->target_key_id & 0xFFu);
    *p_temp++ = (uint8_t)((param->target_key_id >> 8) & 0xFFu);

    // (5) 1 byte SN[8]
    *p_temp++ = param->sn[8];

    // (6) 2 bytes SN[0:1]
    *p_temp++ = param->sn[0];
    *p_temp++ = param->sn[1];

    // Calculate SHA256 to get the input MAC for DeriveKey command
    (void)atcac_sw_sha2_256(temporary, ATCA_MSG_SIZE_DERIVE_KEY_MAC, param->mac);

    return ATCA_SUCCESS;
}
#endif /* ATCAH_DERIVE_KEY_MAC */

/** \brief This function decrypts 32-byte encrypted data received with the Read command.

   To use this function, first the nonce must be valid and synchronized between device and application.
   The application sends a GenDig command to the Device, using a key specified by SlotConfig.ReadKey.
   The device updates its TempKey.
   The application then updates its own TempKey using the GenDig calculation function, using the same key.
   The application sends a Read command to the device for a user zone configured with EncryptRead.
   The device encrypts 32-byte zone content, and outputs it to the host.
   The application passes these encrypted data to this decryption function. The function decrypts the data and returns them.
   TempKey must be updated by GenDig using a ParentKey as specified by SlotConfig.ReadKey before executing this function.
   The decryption function does not check whether the TempKey has been generated by a correct ParentKey for the corresponding zone.
   Therefore to get a correct result, the application has to make sure that prior GenDig calculation was done using correct ParentKey.

 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_DECRYPT
ATCA_STATUS atcah_decrypt(struct atca_decrypt_in_out *param)
{
    uint8_t i;

    // Check parameters
    if ((NULL == param->crypto_data) || (NULL == param->temp_key))
    {
        return ATCA_BAD_PARAM;
    }

    // Check TempKey fields validity
    // Note that if temp_key.key_id is not checked,
    // we cannot make sure if the key used in previous GenDig IS equal to
    // the key pointed by SlotConfig.ReadKey in the device.
    if ( // TempKey.CheckFlag must be 0
        (param->temp_key->no_mac_flag != 0u)
        // TempKey.Valid must be 1
        || (param->temp_key->valid != 1u)
        // TempKey.GenData must be 1
        || (param->temp_key->gen_dig_data != 1u)
        // TempKey.SourceFlag must be 0 (random)
        || (param->temp_key->source_flag != 0u)
        )
    {
        // Invalidate TempKey, then return
        param->temp_key->valid = 0;
        return ATCA_EXECUTION_ERROR;
    }

    // Decrypt by XOR-ing Data with the TempKey
    for (i = 0; i < ATCA_KEY_SIZE; i++)
    {
        param->crypto_data[i] ^= param->temp_key->value[i];
    }

    // Update TempKey fields
    param->temp_key->valid = 0;

    return ATCA_SUCCESS;
}
#endif /* ATCAH_DECRYPT */

/** \brief This function creates a SHA256 digest on a little-endian system.
 *
 * \param[in] len byte length of message
 * \param[in] message pointer to message
 * \param[out] digest SHA256 of message
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_SHA256
ATCA_STATUS atcah_sha256(uint32_t len, const uint8_t *message, uint8_t *digest)
{
    return (ATCA_STATUS)atcac_sw_sha2_256(message, (size_t)len, digest);
}
#endif /* ATCAH_SHA256 */

/** \brief Calculate the PubKey digest created by GenKey and saved to TempKey.
 *
 * \param[in,out] param  GenKey parameters required to calculate the PubKey
 *                        digest. Digest is return in the temp_key parameter.
 *
   \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_GEN_KEY_MSG
ATCA_STATUS atcah_gen_key_msg(struct atca_gen_key_in_out *param)
{
    uint8_t msg[128];

    if (param == NULL || param->public_key == NULL || param->sn == NULL || param->temp_key == NULL)
    {
        return ATCA_BAD_PARAM;
    }
    if (param->public_key_size == 0u || param->public_key_size > 88u)
    {
        return ATCA_BAD_PARAM;
    }

    (void)memset(msg, 0, sizeof(msg));
    (void)memcpy(&msg[0], param->temp_key->value, 32);
    msg[32] = ATCA_GENKEY;

    if (GENKEY_MODE_PUBKEY_DIGEST == (param->mode & GENKEY_MODE_PUBKEY_DIGEST))
    {
        // Calculate PubKey digest of stored public key, takes priority over other bits
        if (param->other_data == NULL)
        {
            return ATCA_BAD_PARAM;
        }
        (void)memcpy(&msg[33], param->other_data, 3); // OtherData replaces mode and key_id in message
    }
    else if (GENKEY_MODE_DIGEST == (param->mode & GENKEY_MODE_DIGEST))
    {
        msg[33] = param->mode;
        msg[34] = (uint8_t)((param->key_id >> 0u) & 0xFFu);
        msg[35] = (uint8_t)((param->key_id >> 8u) & 0xFFu);
    }
    else
    {
        // Mode indicates no PubKey digest was requested.
        // No change to TempKey.
        return ATCA_SUCCESS;
    }

    msg[36] = param->sn[8];
    (void)memcpy(&msg[37], &param->sn[0], 2);

    // Copy public key into end of message
    (void)memcpy(&msg[sizeof(msg) - param->public_key_size], param->public_key, param->public_key_size);

    (void)atcac_sw_sha2_256(msg, sizeof(msg), param->temp_key->value);
    param->temp_key->gen_dig_data = 0;
    param->temp_key->gen_key_data = 1;
    param->temp_key->key_id = (uint8_t)(param->key_id & 0x0Fu);

    return ATCA_SUCCESS;
}
#endif /* ATCAH_GEN_KEY_MSG */

/** \brief Populate the slot_config, key_config, and is_slot_locked fields in
 *         the atca_sign_internal_in_out structure from the provided config
 *         zone.
 *
 * The atca_sign_internal_in_out structure has a number of fields
 * (slot_config, key_config, is_slot_locked) that can be determined
 * automatically from the current state of TempKey and the full config
 * zone.
 *
 * \param[in,out] param          Sign(Internal) parameters to be filled out. Only
 *                              slot_config, key_config, and is_slot_locked will be
 *                              set.
 * \param[in]    device_type    The type of the device.
 * \param[in]    config         Full 128 byte config zone for the device.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_CONFIG_TO_SIGN_INTERNAL
ATCA_STATUS atcah_config_to_sign_internal(ATCADeviceType device_type, struct atca_sign_internal_in_out *param, const uint8_t* config)
{
    const uint8_t* value = NULL;
    uint16_t slot_locked = 0;
    uint8_t temp_key_id = 0;

    if (param == NULL || config == NULL || param->temp_key == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    // SlotConfig[TempKeyFlags.keyId]
    value = &config[20u + param->temp_key->key_id * 2u];
    param->slot_config = (uint16_t)value[0];
    param->slot_config |= ((uint16_t)value[1] << 8);

    // KeyConfig[TempKeyFlags.keyId]
    value = &config[96u + param->temp_key->key_id * 2u];
    param->key_config = (uint16_t)value[0];
    param->key_config |= ((uint16_t)value[1] << 8);

    if (device_type == ATECC108A && param->temp_key->key_id < 8u)
    {
        value = &config[52u + param->temp_key->key_id * 2u];
        param->use_flag = value[0];
        param->update_count = value[1];
    }
    else
    {
        param->use_flag = 0x00;
        param->update_count = 0x00;
    }

    //SlotLocked:TempKeyFlags.keyId
    slot_locked = (uint16_t)config[88];
    slot_locked |= ((uint16_t)config[89] << 8);
    temp_key_id = (param->temp_key->key_id & 0xFu);
    /* coverity[misra_c_2012_rule_10_7_violation] : 1u << temp_key_id could result in 16 bits */
    param->is_slot_locked = ((slot_locked & (1u << temp_key_id)) >= 1u) ? false : true;

    return ATCA_SUCCESS;
}
#endif /* ATCAH_CONFIG_TO_SIGN_INTERNAL */

/** \brief Builds the full message that would be signed by the Sign(Internal)
 *         command.
 *
 * Additionally, the function will optionally output the OtherData data
 * required by the Verify(In/Validate) command as well as the SHA256 digest of
 * the full message.
 *
 * \param[out] device_type  Device type to perform the calculation for.
 * \param[out] param        Input data and output buffers required.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_SIGN_INTERNAL_MSG
ATCA_STATUS atcah_sign_internal_msg(ATCADeviceType device_type, struct atca_sign_internal_in_out *param)
{
    uint8_t msg[55];

    if (param == NULL || param->temp_key == NULL || param->sn == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    (void)memset(msg, 0, sizeof(msg));
    (void)memcpy(&msg[0], param->temp_key->value, 32);
    msg[32] = ATCA_SIGN;                                     // Sign OpCode
    msg[33] = param->mode;                                   // Sign Mode

    msg[34] = (uint8_t)((param->key_id >> 0u) & 0xFFu);      // Sign KeyID
    msg[35] = (uint8_t)((param->key_id >> 8u) & 0xFFu);
    msg[36] = (uint8_t)((param->slot_config >> 0u) & 0xFFu); // SlotConfig[TempKeyFlags.keyId]
    msg[37] = (uint8_t)((param->slot_config >> 8u) & 0xFFu);
    msg[38] = (uint8_t)((param->key_config >> 0u) & 0xFFu);  // KeyConfig[TempKeyFlags.keyId]
    msg[39] = (uint8_t)((param->key_config >> 8u) & 0xFFu);

    //TempKeyFlags (b0-3: keyId, b4: sourceFlag, b5: GenDigData, b6: GenKeyData, b7: NoMacFlag)
    msg[40] |= (uint8_t)((param->temp_key->key_id & 0x0Fu) << 0u);
    msg[40] |= (uint8_t)((param->temp_key->source_flag & 0x01u) << 4u);
    msg[40] |= (uint8_t)((param->temp_key->gen_dig_data & 0x01u) << 5u);
    msg[40] |= (uint8_t)((param->temp_key->gen_key_data & 0x01u) << 6u);
    msg[40] |= (uint8_t)((param->temp_key->no_mac_flag & 0x01u) << 7u);

    if (device_type == ATECC108A && param->temp_key->key_id < 8u)
    {
        msg[41] = param->use_flag;     // UseFlag[TempKeyFlags.keyId]
        msg[42] = param->update_count; // UpdateCount[TempKeyFlags.keyId]
    }
    else
    {
        msg[41] = 0x00;
        msg[42] = 0x00;
    }

    // Serial Number
    msg[43] = param->sn[8];
    (void)memcpy(&msg[48], &param->sn[0], 2);
    if (SIGN_MODE_INCLUDE_SN == (param->mode & SIGN_MODE_INCLUDE_SN))
    {
        (void)memcpy(&msg[44], &param->sn[4], 4);
        (void)memcpy(&msg[50], &param->sn[2], 2);
    }

    // The bit within the SlotLocked field corresponding to the last key used in the TempKey computation is in the LSB
    msg[52] = param->is_slot_locked ? 0x00u : 0x01u;

    // If the slot contains a public key corresponding to a supported curve, and if PubInfo indicates this key must be
    // validated before being used by Verify, and if the validity bits have a value of 0x05, then the PubKey Valid byte
    // will be 0x01. In all other cases, it will be 0.
    msg[53] = param->for_invalidate ? 0x01u : 0x00u;

    msg[54] = 0x00;

    if (NULL != param->message)
    {
        (void)memcpy(param->message, msg, sizeof(msg));
    }
    if (NULL != param->verify_other_data)
    {
        (void)memcpy(&param->verify_other_data[0],  &msg[33], 10);
        (void)memcpy(&param->verify_other_data[10], &msg[44], 4);
        (void)memcpy(&param->verify_other_data[14], &msg[50], 5);
    }
    if (NULL != param->digest)
    {
        return (ATCA_STATUS)atcac_sw_sha2_256(msg, sizeof(msg), param->digest);
    }
    else
    {
        return ATCA_SUCCESS;
    }
}
#endif /* ATCAH_SIGN_INTERNAL_MSG */

/** \brief Builds the counter match value that needs to be stored in a slot.
 *
 * \param[in]  counter_value        Counter value to be used for the counter
 *                                  match. This must be a multiple of 32.
 * \param[out] counter_match_value  Data to be stored in the beginning of a
 *                                  counter match slot will be returned here
 *                                  (8 bytes).
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_ENCODE_COUNTER_MATCH
ATCA_STATUS atcah_encode_counter_match(uint32_t counter_value, uint8_t * counter_match_value)
{
    if ((counter_value > COUNTER_MAX_VALUE) || (counter_value % 32u != 0u) || (counter_match_value == NULL))
    {
        return ATCA_BAD_PARAM;
    }

    // Counter match value is stored in little-endian unsigned format
    counter_match_value[0] = (uint8_t)((counter_value >> 0u) & 0xFFu);
    counter_match_value[1] = (uint8_t)((counter_value >> 8u) & 0xFFu);
    counter_match_value[2] = (uint8_t)((counter_value >> 16u) & 0xFFu);
    counter_match_value[3] = (uint8_t)((counter_value >> 24u) & 0xFFu);

    // Counter match value should be repeated in the next 4 bytes
    (void)memcpy(counter_match_value + 4, counter_match_value, 4);

    return ATCA_SUCCESS;
}
#endif /* ATCAH_ENCODE_COUNTER_MATCAH */

/** \brief This function calculates the input MAC for the ECC204 Write command.

   The Write command will need an input MAC if SlotConfig3.bit0 is set.

 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_WRITE_AUTH_MAC
ATCA_STATUS atcah_ecc204_write_auth_mac(struct atca_write_mac_in_out *param)
{
    uint8_t mac_input[ATCA_MSG_SIZE_ENCRYPT_MAC];
    uint8_t i;
    uint8_t *p_temp;

    // Check parameters
    if ((NULL == param->input_data) || (NULL == param->temp_key))
    {
        return ATCA_BAD_PARAM;
    }

    // Encrypt by XOR-ing Data with the session key
    for (i = 0u; i < 32u; i++)
    {
        param->encrypted_data[i] = param->input_data[i] ^ param->temp_key->value[i];
    }

    // If the pointer *mac is provided by the caller then calculate input MAC
    if (NULL != param->auth_mac)
    {
        // Start calculation
        p_temp = mac_input;

        // (1) 32 bytes TempKey
        (void)memcpy(p_temp, param->temp_key->value, ATCA_KEY_SIZE);
        p_temp += ATCA_KEY_SIZE;

        // (2) 1 byte Opcode
        *p_temp++ = ATCA_WRITE;

        // (3) 1 byte Param1 (zone)
        *p_temp++ = param->zone;

        // (4) 2 bytes Param2 (keyID)
        *p_temp++ = (uint8_t)((param->key_id >> 8u) & 0xFFu);
        *p_temp++ = (uint8_t)(param->key_id & 0xFFu);

        // (5) 1 byte SN[8]
        *p_temp++ = param->sn[8];

        // (6) 2 bytes SN[0:1]
        *p_temp++ = param->sn[0];
        *p_temp++ = param->sn[1];

        // (7) 25 zeros
        (void)memset(p_temp, 0, ATCA_WRITE_MAC_ZEROS_SIZE);
        p_temp += ATCA_WRITE_MAC_ZEROS_SIZE;

        // (8) 32 bytes PlainText
        (void)memcpy(p_temp, param->input_data, ATCA_KEY_SIZE);

        // Calculate SHA256 to get MAC
        (void)atcac_sw_sha2_256(mac_input, sizeof(mac_input), param->auth_mac);
    }

    return ATCA_SUCCESS;
}
#endif /* ATCAH_WRITE_AUTH_MAC */

/** \brief This function calculates the session key for the ECC204.
 *
 * \param[in,out] param pointer to parameter structure
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_GEN_SESSION_KEY
ATCA_STATUS atcah_gen_session_key(atca_session_key_in_out_t *param)
{
    uint8_t session_key_input[ATCA_MSG_SIZE_SESSION_KEY];
    uint8_t *p_temp;

    if ((NULL == param->transport_key) || (NULL == param->nonce) || (NULL == param->session_key))
    {
        return ATCA_BAD_PARAM;
    }

    p_temp = session_key_input;

    // (1) 32 bytes of transport key
    (void)memcpy(p_temp, param->transport_key, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    // (2) 0x15
    *p_temp++ = 0x15;

    // (3) 0x00
    *p_temp++ = 0x00;

    // (4) 2bytes of transport key id
    *p_temp++ = (uint8_t)(param->transport_key_id & 0xFFu);
    *p_temp++ = (uint8_t)((param->transport_key_id >> 8) & 0xFFu);

    // (5) 1 byte SN[8]
    *p_temp++ = param->sn[8];

    // (6) 2 bytes SN[0:1]
    *p_temp++ = param->sn[0];
    *p_temp++ = param->sn[1];

    // (7) 25 zeros
    (void)memset(p_temp, 0, ATCA_WRITE_MAC_ZEROS_SIZE);
    p_temp += ATCA_WRITE_MAC_ZEROS_SIZE;

    // (8) 32 bytes nonce
    (void)memcpy(p_temp, param->nonce, 32);

    // Calculate SHA256 to get MAC
    (void)atcac_sw_sha2_256(session_key_input, sizeof(session_key_input), param->session_key);

    return ATCA_SUCCESS;
}
#endif /* ATCAH_GEN_SESSION_KEY */

/** \brief This function calculates host side mac with the parameters passed.
 *    \param[in,out] param pointer to parameter structure
 *   \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if ATCAH_DELETE_MAC
ATCA_STATUS atcah_delete_mac(struct atca_delete_in_out *param)
{
    uint8_t temporary[ATCA_MSG_SIZE_DELETE_MAC];
    uint8_t *p_temp;

    if ((NULL == param->key) || (NULL == param->nonce) || (NULL == param->mac))
    {
        return ATCA_BAD_PARAM;
    }

    p_temp = temporary;

    // (1) 32 bytes of key
    (void)memcpy(p_temp, param->key, ATCA_KEY_SIZE);
    p_temp += ATCA_KEY_SIZE;

    // (2) 0x13
    *p_temp++ = ATCA_DELETE;

    // (3) 0x00
    *p_temp++ = 0x00;

    // (4) 0x0000
    *p_temp++ = (uint8_t)(param->key_id & 0xFFu);
    *p_temp++ = (uint8_t)((param->key_id >> 8) & 0xFFu);

    // (5) 1 byte SN[8]
    *p_temp++ = param->sn[8];

    // (6) 2 bytes SN[0:1]
    *p_temp++ = param->sn[0];
    *p_temp++ = param->sn[1];

    // (7) 25 zeros
    (void)memset(p_temp, 0, ATCA_DELETE_MAC_ZEROS_SIZE);
    p_temp += ATCA_DELETE_MAC_ZEROS_SIZE;

    // (8) 32 bytes nonce
    (void)memcpy(p_temp, param->nonce, 32);

    // Calculate SHA256 to get MAC
    (void)atcac_sw_sha2_256(temporary, ATCA_MSG_SIZE_DELETE_MAC, param->mac);

    return ATCA_SUCCESS;
}
#endif /* ATCAH_DELETE_MAC */

#endif
