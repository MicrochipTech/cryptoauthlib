/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Write command.
 *
 * The Write command writes either one 4-byte word or a 32-byte block to one of
 * the EEPROM zones on the device. Depending upon the value of the WriteConfig
 * byte for a slot, the data may be required to be encrypted by the system prior
 * to being sent to the device
 *
 * \note List of devices that support this command - ATSHA204A, ATECC108A,
 *       ATECC508A, and ATECC608A/B. There are differences in the modes that they
 *       support. Refer to device datasheets for full details.
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

#include "host/atca_host.h"

#if CALIB_WRITE_EN
/**
 * \brief Executes the Write command, which writes either one four byte word or
 *        a 32-byte block to one of the EEPROM zones on the device. Depending
 *        upon the value of the WriteConfig byte for this slot, the data may be
 *        required to be encrypted by the system prior to being sent to the
 *        device. This command cannot be used to write slots configured as ECC
 *        private keys.
 *
 * \param[in] device   Device context pointer
 * \param[in] zone     Zone/Param1 for the write command.
 * \param[in] address  Address/Param2 for the write command.
 * \param[in] value    Plain-text data to be written or cipher-text for
 *                     encrypted writes. 32 or 4 bytes depending on bit 7 in the
 *                     zone.
 * \param[in] mac      MAC required for encrypted writes (32 bytes). Set to NULL
 *                     if not required.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_write(ATCADevice device, uint8_t zone, uint16_t address, const uint8_t *value, const uint8_t *mac)
{
    ATCAPacket * packet = calib_packet_alloc();
    ATCA_STATUS status;
    bool require_mac = false;

    if(NULL == packet)
    {
        (void)ATCA_TRACE(ATCA_ALLOC_FAILURE, "calib_packet_alloc - failed");
        return ATCA_ALLOC_FAILURE;
    }

    if ((device == NULL) || (value == NULL))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    #if (CA_MAX_PACKET_SIZE < (ATCA_CMD_SIZE_MIN + 32u + MAC_SIZE))
    #if ATCA_PREPROCESSOR_WARNING
    #warning "CA_MAX_PACKET_SIZE will not support optional mac with the write command"
    #endif
    if (((zone & ATCA_ZONE_READWRITE_32) == ATCA_ZONE_READWRITE_32) && (NULL != mac))
    {
        status = ATCA_TRACE(ATCA_INVALID_SIZE, "Unsupported parameter");
    }
    #endif

    do
    {
        (void)memset(packet, 0x00, sizeof(ATCAPacket));

        // Build the write command
        packet->param1 = zone;
        packet->param2 = address;
        if ((zone & ATCA_ZONE_READWRITE_32) == ATCA_ZONE_READWRITE_32)
        {
            // 32-byte write
            (void)memcpy(packet->data, value, 32);
            // Only 32-byte writes can have a MAC
            if (NULL != mac)
            {
                (void)memcpy(&packet->data[32], mac, 32);
            }
        }
        else
        {
            // 4-byte write
            (void)memcpy(packet->data, value, 4);
        }

        if ((NULL != mac) && ((zone & ATCA_ZONE_READWRITE_32) == ATCA_ZONE_READWRITE_32))
        {
            require_mac = true;
        }

        if ((status = atWrite(atcab_get_device_type_ext(device), packet, require_mac)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atWrite - failed");
            break;
        }

        if ((status = atca_execute_command(packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_write - execution failed");
            break;
        }

    } while (false);

    calib_packet_free(packet);
    return status;
}

/** \brief Executes the Write command, which writes either 4 or 32 bytes of
 *          data into a device zone.
 *
 *  \param[in] device  Device context pointer
 *  \param[in] zone    Device zone to write to (0=config, 1=OTP, 2=data).
 *  \param[in] slot    If writing to the data zone, it is the slot to write to,
 *                     otherwise it should be 0.
 *  \param[in] block   32-byte block to write to.
 *  \param[in] offset  4-byte word within the specified block to write to. If
 *                     performing a 32-byte write, this should be 0.
 *  \param[in] data    Data to be written.
 *  \param[in] len     Number of bytes to be written. Must be either 4 or 32.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_write_zone(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, const uint8_t *data, uint8_t len)
{
    ATCA_STATUS status;
    uint16_t addr;

    // Check the input parameters
    if (data == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    if (len != 4u && len != 32u)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid length received");
    }

    do
    {
        // The get address function checks the remaining variables
        if ((status = calib_get_addr(zone, slot, block, offset, &addr)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_get_addr - failed");
            break;
        }

        // If there are 32 bytes to write, then xor the bit into the mode
        if (len == ATCA_BLOCK_SIZE)
        {
            zone = zone | ATCA_ZONE_READWRITE_32;
        }

        status = calib_write(device, zone, addr, data, NULL);

    } while (false);

    return status;
}
#endif /* CALIB_WRITE_EN */

#if CALIB_WRITE_ENC_EN
/** \brief Executes the Write command, which performs an encrypted write of
 *          a 32 byte block into given slot.
 *
 * The function takes clear text bytes and encrypts them for writing over the
 * wire. Data zone must be locked and the slot configuration must be set to
 * encrypted write for the block to be successfully written.
 *
 *  \param[in] device      Device context pointer
 *  \param[in] key_id      Slot ID to write to.
 *  \param[in] block       Index of the 32 byte block to write in the slot.
 *  \param[in] data        32 bytes of clear text data to be written to the slot
 *  \param[in] enc_key     WriteKey to encrypt with for writing
 *  \param[in] enc_key_id  The KeyID of the WriteKey
 *  \param[in]  num_in       20 byte host nonce to inject into Nonce calculation
 *
 *  returns ATCA_SUCCESS on success, otherwise an error code.
 */

#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS calib_write_enc(ATCADevice device, uint16_t key_id, uint8_t block, const uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id)
{
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

#else
ATCA_STATUS calib_write_enc(ATCADevice device, uint16_t key_id, uint8_t block, const uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id,
                            const uint8_t num_in[NONCE_NUMIN_SIZE])
{
#endif
    ATCA_STATUS status;
    uint8_t zone = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    atca_nonce_in_out_t nonce_params;
    atca_gen_dig_in_out_t gen_dig_param;
    atca_write_mac_in_out_t write_mac_param;
    atca_temp_key_t temp_key;
    uint8_t serial_num[32];
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    uint8_t cipher_text[ATCA_KEY_SIZE] = { 0 };
    uint8_t mac[WRITE_MAC_SIZE] = { 0 };
    uint8_t other_data[4] = { 0 };
    uint16_t addr;

    do
    {
        // Verify inputs parameters
        if (data == NULL || enc_key == NULL)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
            break;
        }

        // Read the device SN
        if ((status = calib_read_zone(device, ATCA_ZONE_CONFIG, 0, 0, 0, serial_num, 32)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_read_zone - failed");
            break;
        }
        // Make the SN continuous by moving SN[4:8] right after SN[0:3]
        (void)memmove(&serial_num[4], &serial_num[8], 5);


        // Random Nonce inputs
        (void)memset(&temp_key, 0, sizeof(temp_key));
        (void)memset(&nonce_params, 0, sizeof(nonce_params));
        nonce_params.mode = NONCE_MODE_SEED_UPDATE;
        nonce_params.zero = 0;
        nonce_params.num_in = &num_in[0];
        nonce_params.rand_out = rand_out;
        nonce_params.temp_key = &temp_key;

        // Send the random Nonce command
        if ((status = calib_nonce_rand(device, num_in, rand_out)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Nonce failed");
            break;
        }

        // Calculate Tempkey
        if ((status = atcah_nonce(&nonce_params)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Calc TempKey failed");
            break;
        }

        // Supply OtherData so GenDig behavior is the same for keys with SlotConfig.NoMac set
        other_data[0] = ATCA_GENDIG;
        other_data[1] = GENDIG_ZONE_DATA;
        other_data[2] = (uint8_t)(enc_key_id & 0xFFu);
        other_data[3] = (uint8_t)(enc_key_id >> 8u);

        // Send the GenDig command
        if ((status = calib_gendig(device, GENDIG_ZONE_DATA, enc_key_id, other_data, (uint8_t)sizeof(other_data))) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "GenDig failed");
            break;
        }

        // Calculate Tempkey
        // NoMac bit isn't being considered here on purpose to remove having to read SlotConfig.
        // OtherData is built to get the same result regardless of the NoMac bit.
        (void)memset(&gen_dig_param, 0, sizeof(gen_dig_param));
        gen_dig_param.key_id = enc_key_id;
        gen_dig_param.is_key_nomac = false;
        gen_dig_param.sn = serial_num;
        gen_dig_param.stored_value = enc_key;
        gen_dig_param.zone = GENDIG_ZONE_DATA;
        gen_dig_param.other_data = other_data;
        gen_dig_param.temp_key = &temp_key;
        if ((status = atcah_gen_dig(&gen_dig_param)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atcah_gen_dig() failed");
            break;
        }

        // The get address function checks the remaining variables
        if ((status = calib_get_addr(ATCA_ZONE_DATA, key_id, block, 0, &addr)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Get address failed");
            break;
        }

        // Setting bit 6 to indicate input data is encrypted
        write_mac_param.zone = zone | ATCA_ZONE_ENCRYPTED;
        write_mac_param.key_id = addr;
        write_mac_param.sn = serial_num;
        write_mac_param.input_data = data;
        write_mac_param.encrypted_data = cipher_text;
        write_mac_param.auth_mac = mac;
        write_mac_param.temp_key = &temp_key;

        if ((status = atcah_write_auth_mac(&write_mac_param)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Calculate Auth MAC failed");
            break;
        }

        status = calib_write(device, write_mac_param.zone, write_mac_param.key_id, write_mac_param.encrypted_data, write_mac_param.auth_mac);

    } while (false);

    return status;
}
#endif /* CALIB_WRITE_ENC_EN */

/** \brief Executes the Write command, which writes the configuration zone.
 *
 *  First 16 bytes are skipped as they are not writable. LockValue and
 *  LockConfig are also skipped and can only be changed via the Lock
 *  command.
 *
 *  This command may fail if UserExtra and/or Selector bytes have
 *  already been set to non-zero values.
 *
 *  \param[in]  device      Device context pointer
 *  \param[in] config_data  Data to the config zone data. This should be 88
 *                          bytes for SHA devices and 128 bytes for ECC
 *                          devices.
 *
 *  \returns ATCA_SUCCESS on success, otherwise an error code.
 */

#if CALIB_WRITE_EN
ATCA_STATUS calib_write_config_zone(ATCADevice device, const uint8_t* config_data)
{
    ATCA_STATUS status;
    size_t config_size = 0;

    if (config_data == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        // Get config zone size for the device
        if (ATCA_SUCCESS != (status = calib_get_zone_size(device, ATCA_ZONE_CONFIG, 0, &config_size)))
        {
            (void)ATCA_TRACE(status, "calib_get_zone_size - failed");
            break;
        }

        // Write config zone excluding UserExtra and Selector
        if (ATCA_SUCCESS != (status = calib_write_bytes_zone(device, ATCA_ZONE_CONFIG, 0, 16, &config_data[16], config_size - 16u)))
        {
            (void)ATCA_TRACE(status, "calib_write_bytes_zone - failed");
            break;
        }

        // Write the UserExtra and Selector. This may fail if either value is already non-zero.
        if (ATCA_SUCCESS != (status = calib_updateextra(device, UPDATE_MODE_USER_EXTRA, config_data[84])))
        {
            (void)ATCA_TRACE(status, "calib_updateextra - failed");
            break;
        }

        if (ATCA_SUCCESS != (status = calib_updateextra(device, UPDATE_MODE_SELECTOR, config_data[85])))
        {
            (void)ATCA_TRACE(status, "calib_updateextra - failed");
            break;
        }
    } while (false);

    return status;
}

/** \brief Executes the Write command, which writes data into the
 *          configuration, otp, or data zones with a given byte offset and
 *          length. Offset and length must be multiples of a word (4 bytes).
 *
 * Config zone must be unlocked for writes to that zone. If data zone is
 * unlocked, only 32-byte writes are allowed to slots and OTP and the offset
 * and length must be multiples of 32 or the write will fail.
 *
 *  \param[in] device        Device context pointer
 *  \param[in] zone          Zone to write data to: ATCA_ZONE_CONFIG(0),
 *                           ATCA_ZONE_OTP(1), or ATCA_ZONE_DATA(2).
 *  \param[in] slot          If zone is ATCA_ZONE_DATA(2), the slot number to
 *                           write to. Ignored for all other zones.
 *  \param[in] offset_bytes  Byte offset within the zone to write to. Must be
 *                           a multiple of a word (4 bytes).
 *  \param[in] data          Data to be written.
 *  \param[in] length        Number of bytes to be written. Must be a multiple
 *                           of a word (4 bytes).
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_write_bytes_zone(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t *data, size_t length)
{
    ATCA_STATUS status;
    size_t zone_size = 0;
    size_t data_idx = 0;
    size_t cur_block = 0;
    size_t cur_word = 0;

    if (zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_OTP && zone != ATCA_ZONE_DATA)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received");
    }
    if (zone == ATCA_ZONE_DATA && slot > 15u)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot received");
    }
    if (length == 0u)
    {
        return ATCA_SUCCESS;  // Always succeed writing 0 bytes
    }
    if (data == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }
    if (offset_bytes % ATCA_WORD_SIZE != 0u || length % ATCA_WORD_SIZE != 0u)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Either Invalid length or offset received");
    }

    do
    {
        if (ATCA_SUCCESS != (status = calib_get_zone_size(device, zone, slot, &zone_size)))
        {
            (void)ATCA_TRACE(status, "calib_get_zone_size - failed");
            break;
        }
        if (offset_bytes + length > zone_size)
        {
            return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid parameter received");
        }

        cur_block = offset_bytes / ATCA_BLOCK_SIZE;
        cur_word = (offset_bytes % ATCA_BLOCK_SIZE) / ATCA_WORD_SIZE;

        while (data_idx < length)
        {
            // The last item makes sure we handle the selector, user extra, and lock bytes in the config properly
            if (cur_word == 0u && length - data_idx >= ATCA_BLOCK_SIZE && !(zone == ATCA_ZONE_CONFIG && cur_block == 2u))
            {
                if (ATCA_SUCCESS != (status = calib_write_zone(device, zone, slot, (uint8_t)cur_block, 0, &data[data_idx], ATCA_BLOCK_SIZE)))
                {
                    (void)ATCA_TRACE(status, "calib_write_zone - failed");
                    break;
                }
                data_idx += ATCA_BLOCK_SIZE;
                cur_block += 1u;
            }
            else
            {
                // Skip trying to change UserExtra, Selector, LockValue, and LockConfig which require the UpdateExtra command to change
                if (!(zone == ATCA_ZONE_CONFIG && cur_block == 2u && cur_word == 5u))
                {
                    if (ATCA_SUCCESS != (status = calib_write_zone(device, zone, slot, (uint8_t)cur_block, (uint8_t)cur_word, &data[data_idx], ATCA_WORD_SIZE)))
                    {
                        (void)ATCA_TRACE(status, "calib_write_zone - failed");
                        break;
                    }
                }
                data_idx += ATCA_WORD_SIZE;
                cur_word += 1u;
                if (cur_word == ATCA_BLOCK_SIZE / ATCA_WORD_SIZE)
                {
                    cur_block += 1u;
                    cur_word = 0u;
                }
            }
        }
    } while (false);

    return status;
}

/** \brief Initialize one of the monotonic counters in device with a specific
 *          value.
 *
 * The monotonic counters are stored in the configuration zone using a special
 * format. This encodes a binary count value into the 8 byte encoded value
 * required. Can only be set while the configuration zone is unlocked.
 *
 * \param[in]  device         Device context pointer
 * \param[in]  counter_id     Counter to be written.
 * \param[in]  counter_value  Counter value to set.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_write_config_counter(ATCADevice device, uint16_t counter_id, uint32_t counter_value)
{
    uint16_t lin_a, lin_b, bin_a, bin_b;
    uint8_t bytes[8];
    uint8_t idx = 0;
    ATCA_STATUS status;

    if (counter_id > 1u || counter_value > COUNTER_MAX_VALUE)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Either invalid counter id or counter value received");
    }

    /* coverity[misra_c_2012_rule_12_2_violation] Shifting more than 15 bits doesnot harm the functonality */
    lin_a = (uint16_t)((0xFFFFu >> (counter_value % 32u)) & UINT16_MAX);
    lin_b = (uint16_t)((0xFFFFu >> ((counter_value >= 16u) ? (counter_value - 16u) % 32u : 0u)) & UINT16_MAX);
    bin_a = (uint16_t)(counter_value / 32u);
    bin_b = (counter_value >= 16u) ? ((uint16_t)((counter_value - 16u) / 32u)) : 0u;

    bytes[idx++] = (uint8_t)(lin_a >> 8u);
    bytes[idx++] = (uint8_t)(lin_a & 0xFFu);
    bytes[idx++] = (uint8_t)(lin_b >> 8u);
    bytes[idx++] = (uint8_t)(lin_b & 0xFFu);

    bytes[idx++] = (uint8_t)(bin_a >> 8u);
    bytes[idx++] = (uint8_t)(bin_a & 0xFFu);
    bytes[idx++] = (uint8_t)(bin_b >> 8u);
    bytes[idx]   = (uint8_t)(bin_b & 0xFFu);

    status = calib_write_bytes_zone(device, ATCA_ZONE_CONFIG, 0, 52u + ((size_t)counter_id * 8u), bytes, sizeof(bytes));

    return status;
}
#endif /* CALIB_WRITE_EN */

/** \brief Execute write command to write either 16 byte or 32 byte to one of the EEPROM zones
 *         on the ECC204, TA010, SHA10x devices.
 *
 *  \param[in] device   Device context pointer
 *  \param[in] zone     Zone/Param1 for the write command.
 *  \param[in] address  Address/Param2 for the write command.
 *  \param[in] value    Plain-text data to be written or cipher-text for
 *                      encrypted writes. 32 or 16 bytes depending on zone.
 *  \param[in] mac      MAC required for encrypted writes (32 bytes). Set to NULL
 *                      if not required.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if CALIB_WRITE_CA2_EN
ATCA_STATUS calib_ca2_write(ATCADevice device, uint8_t zone, uint16_t address, const uint8_t *value,
                            const uint8_t *mac)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    ATCAPacket * packet = NULL;
    uint8_t write_zone = (zone == ATCA_ZONE_CONFIG) ? ATCA_ZONE_CA2_CONFIG : ATCA_ZONE_CA2_DATA;
    bool require_mac = false;

    if ((NULL == device) || (NULL == value))
    {
        status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer encountered");
    }
    if ((zone != ATCA_ZONE_CONFIG) && (zone != ATCA_ZONE_DATA))
    {
        status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received");
    }

    #if (CA_MAX_PACKET_SIZE < (ATCA_CMD_SIZE_MIN + ATCA_BLOCK_SIZE + MAC_SIZE))
    #if ATCA_PREPROCESSOR_WARNING
    #warning "CA_MAX_PACKET_SIZE will not support optional mac with the write command"
    #endif
    if ((ATCA_ZONE_CA2_DATA == write_zone) && (NULL != mac))
    {
        status = ATCA_TRACE(ATCA_INVALID_SIZE, "Unsupported parameter");
    }
    #endif

    #if (CA_MAX_PACKET_SIZE < (ATCA_CMD_SIZE_MIN + 16u))
    #if ATCA_PREPROCESSOR_WARNING
    #warning "CA_MAX_PACKET_SIZE will not support write command in config zone"
    #endif
    if (ATCA_ZONE_CA2_CONFIG == write_zone)
    {
        status = ATCA_TRACE(ATCA_INVALID_SIZE, "Unsupported parameter");
    }
    #endif

    packet = calib_packet_alloc();
    if(NULL == packet)
    {
        (void)ATCA_TRACE(ATCA_ALLOC_FAILURE, "calib_packet_alloc - failed");
        return ATCA_ALLOC_FAILURE;
    }

    (void)memset(packet, 0x00, sizeof(ATCAPacket));

    if (ATCA_SUCCESS == status)
    {
        packet->param1 = write_zone;
        packet->param2 = address;

        if (ATCA_ZONE_CA2_CONFIG == write_zone)
        {
            (void)memcpy(packet->data, value, 16);
        }
        if (ATCA_ZONE_CA2_DATA == write_zone)
        {
            (void)memcpy(packet->data, value, ATCA_BLOCK_SIZE);
        }

        if ((NULL != mac) && (ATCA_ZONE_CA2_DATA == write_zone))
        {
            (void)memcpy(&packet->data[ATCA_BLOCK_SIZE], mac, MAC_SIZE);
        }

        if ((NULL != mac) && (ATCA_ZONE_CA2_DATA == write_zone))
        {
            require_mac = true;
        }

        (void)atWrite(atcab_get_device_type_ext(device), packet, require_mac);
    }

    if (ATCA_SUCCESS == status)
    {
        if (ATCA_SUCCESS != (status = atca_execute_command(packet, device)))
        {
            (void)ATCA_TRACE(status, "calib_ca2_write - execution failed");
        }
    }

    calib_packet_free(packet);
    return status;

}

/** \brief Execute write command to write data into configuration zone or data zone
 *         This function only support ECC204,TA010,SHA10x devices
 *
 *  \param[in]    device      Device context pointer
 *  \param[in]    zone        Device zone to write (config=1, data=0)
 *  \param[in]    slot        the slot number to be witten
 *  \param[in]    block       32-byte block to write
 *  \param[in]    offset      ignore for ECC204 device
 *  \param[in]    data        Data to be written into slot
 *  \param[in]    len         Number of bytes to be written. Must be either 16 or 32.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_write_zone(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block,
                                 uint8_t offset, const uint8_t *data, uint8_t len)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint16_t addr;

    ((void)offset);

    if ((NULL == device) && (NULL == data))
    {
        status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer encountered");
    }
    if (((ATCA_ZONE_CONFIG == zone) && (16u != len)) ||
        ((ATCA_ZONE_DATA == zone) && (ATCA_BLOCK_SIZE != len)))
    {
        status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid length received");
    }

    if (ATCA_SUCCESS == status)
    {
        if (ATCA_SUCCESS != (status = calib_ca2_get_addr(zone, slot, block, 0, &addr)))
        {
            (void)ATCA_TRACE(status, "calib_ca2_get_addr - failed");
        }

        if (ATCA_SUCCESS == status)
        {
            status = calib_ca2_write(device, zone, addr, data, NULL);
        }
    }

    return status;
}

/** \brief Use write command to write configuration data into ECC204,TA010,SHA10x config zone
 *
 *  \param[in]  device       Device context pointer
 *  \param[in]  config_data  configuration data
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_write_config_zone(ATCADevice device, const uint8_t* config_data)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t slot = 1;

    if ((NULL == device) || (NULL == config_data))
    {
        status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer encountered");
    }

    if (ATCA_SUCCESS == status)
    {
        while (slot <= 3u)
        {
            if (ATCA_SUCCESS != (status = calib_ca2_write_zone(device, ATCA_ZONE_CONFIG, slot,
                                                               0, 0, &config_data[16u * slot], 16)))
            {
                (void)ATCA_TRACE(status, "calib_ca2_write_zone - failed");
            }
            slot += 1u; // Increment slot
        }
    }

    return status;
}

/** \brief Initialize monotonic counters in device with a specific value.
 *
 * The monotonic counters are stored in the configuration zone using a special
 * format. This encodes a binary count value into the 16 byte encoded value
 * required. Can only be set while the configuration subzone 2 is unlocked.
 *
 * \param[in]  device         Device context pointer
 * \param[in]  counter_id     Counter_id should always be 0.
 * \param[in]  counter_value  Counter value to set.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_ca2_write_config_counter(ATCADevice device, uint8_t counter_id, uint16_t counter_value)
{
    uint16_t bin_a, bin_b;
    uint64_t lin_a, lin_b;
    uint8_t bytes[16];
    ATCA_STATUS status;

    if (counter_id != 0u || counter_value > COUNTER_MAX_VALUE_CA2)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid counter id or counter value received");
    }

    bin_a = (uint16_t)(counter_value / 96u);
    bin_b = (counter_value >= 48u) ? ((uint16_t)((counter_value - 48u) / 96u)) : 0u;
    /* coverity[misra_c_2012_rule_12_2_violation] Shifting more than 63 bits doesnot harm the functonality */
    lin_a = (uint64_t)(0xFFFFFFFFFFFFu >> (counter_value % 96u));
    lin_b = (uint64_t)(0xFFFFFFFFFFFFu >> ((counter_value >= 48u) ? (counter_value - 48u) % 96u : 0u));

    bin_a = ATCA_UINT16_HOST_TO_BE(bin_a);
    (void)memcpy(&bytes[0], (uint8_t*)&bin_a, 2);

    bin_b = ATCA_UINT16_HOST_TO_BE(bin_b);
    (void)memcpy(&bytes[2], (uint8_t*)&bin_b, 2);

    lin_a = ATCA_UINT64_HOST_TO_BE(lin_a) >> 16;
    (void)memcpy(&bytes[4], (uint8_t*)&lin_a, 6);

    lin_b = ATCA_UINT64_HOST_TO_BE(lin_b) >> 16;
    (void)memcpy(&bytes[10], (uint8_t*)&lin_b, 6);

    status = calib_ca2_write_zone(device, ATCA_ZONE_CONFIG, 2, 0, counter_id, bytes, (uint8_t)sizeof(bytes));

    return status;
}
#endif /* CALIB_WRITE_CA2_EN */

#if CALIB_WRITE_ENC_EN && ATCA_CA2_SUPPORT
/** \brief Executes write command, performs an encrypted write of a 32 byte block into given slot.
 *
 *  \param[in]  device          Device context pointer
 *  \param[in]  slot            key slot to be written
 *  \param[in]  data            32 bytes of clear text data
 *  \param[in]  transport_key   Transport key
 *  \param[in]  key_id          Transport key id
 *  \param[in]  num_in          20 byte host nonce to inject into Nonce calculation
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_write_enc(ATCADevice device, uint16_t slot, uint8_t* data, uint8_t* transport_key,
                                uint16_t transport_key_id, uint8_t num_in[NONCE_NUMIN_SIZE])
{
    ATCA_STATUS status = ATCA_SUCCESS;
    atca_nonce_in_out_t nonce_params;
    atca_write_mac_in_out_t write_mac_param;
    atca_temp_key_t temp_key;
    atca_session_key_in_out_t session_key_params;
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE] = { 0 };
    uint8_t session_key[ATCA_KEY_SIZE] = { 0 };
    uint8_t cipher_text[ATCA_KEY_SIZE] = { 0 };
    uint8_t mac[WRITE_MAC_SIZE] = { 0 };
    uint16_t addr;

    if ((NULL == data) || (NULL == transport_key))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer encounteed");
    }

    do
    {
        // Read device serial number
        if (ATCA_SUCCESS != (status = calib_ca2_read_serial_number(device, serial_number)))
        {
            (void)ATCA_TRACE(status, "Read serial number failed");
            break;
        }

        // Generate session key on device
        if (ATCA_SUCCESS != (status = calib_nonce_gen_session_key(device, transport_key_id, num_in, rand_out)))
        {
            (void)ATCA_TRACE(status, "Session key generation failed");
            break;
        }

        // Random Nonce inputs
        (void)memset(&temp_key, 0, sizeof(temp_key));
        (void)memset(&nonce_params, 0, sizeof(nonce_params));
        nonce_params.mode = NONCE_MODE_GEN_SESSION_KEY;
        nonce_params.zero = transport_key_id;
        nonce_params.num_in = &num_in[0];
        nonce_params.rand_out = rand_out;
        nonce_params.temp_key = &temp_key;

        // Calculate Nonce
        if ((status = atcah_nonce(&nonce_params)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Calculate nonce failed");
            break;
        }

        // Session key inputs
        (void)memset(&session_key_params, 0, sizeof(session_key_params));
        session_key_params.transport_key = transport_key;
        session_key_params.transport_key_id = transport_key_id;
        session_key_params.sn = serial_number;
        session_key_params.nonce = temp_key.value;
        session_key_params.session_key = session_key;

        // calculate session key on host
        if (ATCA_SUCCESS != (status = atcah_gen_session_key(&session_key_params)))
        {
            (void)ATCA_TRACE(status, "Host session key generation failed");
            break;
        }

        if (ATCA_SUCCESS != (status = calib_ca2_get_addr(ATCA_ZONE_DATA, slot, 0, 0, &addr)))
        {
            (void)ATCA_TRACE(status, "Calculate slot address failed");
            break;
        }

        // copy session key into temp variable
        (void)memcpy(temp_key.value, session_key, ATCA_KEY_SIZE);

        // Write mac inputs
        write_mac_param.zone = ATCA_ZONE_CA2_DATA;
        write_mac_param.key_id = addr;
        write_mac_param.sn = serial_number;
        write_mac_param.input_data = data;
        write_mac_param.encrypted_data = cipher_text;
        write_mac_param.auth_mac = mac;
        write_mac_param.temp_key = &temp_key;

        // calculate MAC on host
        if (ATCA_SUCCESS != (status = atcah_ecc204_write_auth_mac(&write_mac_param)))
        {
            (void)ATCA_TRACE(status, "Data encryption failed");
            break;
        }

        status = calib_ca2_write(device, ATCA_ZONE_DATA, write_mac_param.key_id, write_mac_param.encrypted_data, write_mac_param.auth_mac);
    } while (false);

    return status;
}
#endif  /* CALIB_WRITE_ENC_EN */

/** \brief Use Write command to write bytes
 *
 * This function will issue the write command as many times as is required to
 * read the requested data.
 *
 *  \param[in]   device        Device context pointer
 *  \param[in]   zone          It accepts only ATCA_ZONE_DATA for ECC204,TA010,SHA10x devices
 *  \param[in]   slot          slot number to write to.
 *  \param[in]   block         offset bytes ignored
 *  \param[in]   data          data to be written
 *  \param[in]   length        number of bytes to e written
 *
 *  \return ATCA_SUCCESS on success, otheriwse an error code
 */
#if CALIB_WRITE_CA2_EN
ATCA_STATUS calib_ca2_write_bytes_zone(ATCADevice device, uint8_t zone, uint16_t slot, size_t block,
                                       const uint8_t *data, size_t length)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t data_idx = 0;
    uint8_t data_set_size;
    int8_t no_of_sets;

    if ((NULL == device) || (NULL == data))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Encountered NULL pointer");
    }
    if ((ATCA_ZONE_DATA != zone) && (ATCA_ZONE_CONFIG != zone))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone parameter received");
    }
    if ((ATCA_ZONE_DATA == zone) && (
            // Only Slot 1-3 are valid for data zone write
            ((SHA105 != device->mIface.mIfaceCFG->devtype) && (slot == 0u)) || (slot > 3u) ||
            // Slot1 is of 10 blocks with each block_size is 32... Cannot exceed 10 block boundary
            ((slot == 1u) && ((block > 9u) || (length > (ATCA_BLOCK_SIZE * (10u - block))) || ((length % ATCA_BLOCK_SIZE) != 0u))) ||
            // Slot2 is of 2 blocks with each block_size is 32... Cannot exceed 2 block boundary
            ((slot == 2u) && ((block > 1u) || (length > (ATCA_BLOCK_SIZE * (2u - block))) || ((length % ATCA_BLOCK_SIZE) != 0u))) ||
            // Slot3 is of 1 block with block_size is 32... Cannot exceed block boundary
            ((slot == 3u) && ((block > 0u) || (length > (ATCA_BLOCK_SIZE * (1u - block))) || ((length % ATCA_BLOCK_SIZE) != 0u)))))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot/block/length received");
    }
    if ((ATCA_ZONE_CONFIG == zone) && (
            (slot > 3u) ||
            (block != 0u) || ((length > (16u * (4u - (size_t)slot))) || ((length % 16u) != 0u))))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid block/length received");
    }

    if (0u == length)
    {
        return ATCA_SUCCESS;
    }

    data_set_size = (ATCA_ZONE_DATA == zone) ? ATCA_BLOCK_SIZE : 16u;
    /* coverity[misra_c_2012_rule_10_8_violation] limits are already checked so changing signedness will not cause overflow */
    no_of_sets = (int8_t)(length / data_set_size);

    while (--no_of_sets >= 0)
    {
        if (ATCA_SUCCESS != (status = calib_ca2_write_zone(device, zone, slot, (uint8_t)block, 0,
                                                           &data[data_set_size * data_idx], data_set_size)))
        {
            (void)ATCA_TRACE(status, "calib_ca2_write_zone failed");
            break;
        }

        data_idx++;                                              // increment data index
        block = (ATCA_ZONE_DATA == zone) ? (block + 1u) : block; // increment block number for DATA zone
        slot = (ATCA_ZONE_CONFIG == zone) ? (slot + 1u) : slot;  // increment slot number for CONFIG zone
    }

    return status;
}
#endif  /* CALIB_WRITE_CA2_EN */

#if CALIB_WRITE_EN || CALIB_WRITE_CA2_EN
ATCA_STATUS calib_write_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, const uint8_t *data, uint8_t len)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);
    if (atcab_is_ca2_device(device_type))
    {
        status = calib_ca2_write_zone(device, zone, slot, block, offset, data, len);
    }
    else
#endif
    {
#if CALIB_WRITE_EN
        status = calib_write_zone(device, zone, slot, block, offset, data, len);
#endif
    }

    return status;
}

ATCA_STATUS calib_write_ext(ATCADevice device, uint8_t zone, uint16_t address, const uint8_t *value, const uint8_t *mac)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);
    if (atcab_is_ca2_device(device_type))
    {
        status = calib_ca2_write(device, zone, address, value, mac);
    }
    else
#endif
    {
#if CALIB_WRITE_EN
        status = calib_write(device, zone, address, value, mac);
#endif
    }

    return status;
}

ATCA_STATUS calib_write_config_zone_ext(ATCADevice device, const uint8_t* config_data)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);
    if (atcab_is_ca2_device(device_type))
    {
        status = calib_ca2_write_config_zone(device, config_data);
    }
    else
#endif
    {
#if CALIB_WRITE_EN
        status = calib_write_config_zone(device, config_data);
#endif
    }

    return status;
}

ATCA_STATUS calib_write_config_counter_ext(ATCADevice device, uint16_t counter_id, uint32_t counter_value)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);
    if (atcab_is_ca2_device(device_type))
    {
        status = calib_ca2_write_config_counter(device, (uint8_t)(counter_id & UINT8_MAX), (uint16_t)(counter_value & UINT16_MAX));
    }
    else
#endif
    {
#if CALIB_WRITE_EN
        status = calib_write_config_counter(device, counter_id, counter_value);
#endif
    }

    return status;
}

ATCA_STATUS calib_write_bytes_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t *data, size_t length)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);
    if (atcab_is_ca2_device(device_type))
    {
        status = calib_ca2_write_bytes_zone(device, zone, slot, offset_bytes, data, length);
    }
    else
#endif
    {
#if CALIB_WRITE_EN
        status = calib_write_bytes_zone(device, zone, slot, offset_bytes, data, length);
#endif
    }

    return status;
}

/** \brief Uses the write command to write a public key to a slot in the
 *         proper format.
 *
 *  \param[in] device     Device context pointer
 *  \param[in] slot        Slot number to write. Only slots 8 to 15 are large
 *                         enough to store a public key.
 *  \param[in] public_key  Public key to write into the slot specified. X and Y
 *                         integers in big-endian format. 64 bytes for P256
 *                         curve.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_write_pubkey(ATCADevice device, uint16_t slot, const uint8_t *public_key)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t public_key_formatted[ATCA_BLOCK_SIZE * 3];
    uint8_t block;

    // Check the pointers
    if (public_key == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    // The 64 byte P256 public key gets written to a 72 byte slot in the following pattern
    // | Block 1                     | Block 2                                      | Block 3       |
    // | Pad: 4 Bytes | PubKey[0:27] | PubKey[28:31] | Pad: 4 Bytes | PubKey[32:55] | PubKey[56:63] |

    (void)memset(public_key_formatted, 0, sizeof(public_key_formatted));
    (void)memcpy(&public_key_formatted[4], &public_key[0], 32);   // Move X to padded position
    (void)memcpy(&public_key_formatted[40], &public_key[32], 32); // Move Y to padded position

    // Using this instead of calib_write_zone_bytes, as that function doesn't work when
    // the data zone is unlocked
    for (block = 0u; block < 3u; block++)
    {
        if (ATCA_SUCCESS != (status = calib_write_zone_ext(device, ATCA_ZONE_DATA, slot, block, 0, 
                                                           &public_key_formatted[ATCA_BLOCK_SIZE * block], ATCA_BLOCK_SIZE)))
        {
            (void)ATCA_TRACE(status, "calib_write_zone - failed");
            break;
        }
    }

    return status;
}
#endif
