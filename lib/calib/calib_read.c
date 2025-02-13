/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Read command.
 *
 * The Read command reads words either 4-byte words or 32-byte blocks from one
 * of the memory zones of the device. The data may optionally be encrypted
 * before being returned to the system.
 *
 * \note List of devices that support this command - ATSHA204A, ATECC108A,
 *       ATECC508A, ATECC608A/B. There are differences in the modes that they
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

#if CALIB_READ_ENC_EN
#include "host/atca_host.h"
#endif

#if CALIB_READ_EN
/** \brief Executes Read command, which reads either 4 or 32 bytes of data from
 *          a given slot, configuration zone, or the OTP zone.
 *
 *   When reading a slot or OTP, data zone must be locked and the slot
 *   configuration must not be secret for a slot to be successfully read.
 *
 *  \param[in]  device   Device context pointer
 *  \param[in]  zone     Zone to be read from device. Options are
 *                       ATCA_ZONE_CONFIG, ATCA_ZONE_OTP, or ATCA_ZONE_DATA.
 *  \param[in]  slot     Slot number for data zone and ignored for other zones.
 *  \param[in]  block    32 byte block index within the zone.
 *  \param[in]  offset   4 byte work index within the block. Ignored for 32 byte
 *                       reads.
 *  \param[out] data     Read data is returned here.
 *  \param[in]  len      Length of the data to be read. Must be either 4 or 32.
 *
 *  returns ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_read_zone(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint8_t *data, uint8_t len)
{
    ATCAPacket * packet = NULL;
    ATCA_STATUS status;
    uint16_t addr;

    do
    {
        // Check the input parameters
        ATCA_CHECK_INVALID_MSG(((NULL == device) || (NULL == data)), ATCA_BAD_PARAM, "NULL pointer received");
        ATCA_CHECK_INVALID_MSG((len != 4u && len != 32u), ATCA_BAD_PARAM, "NULL pointer received");
        ATCA_CHECK_INVALID_MSG((CA_MAX_PACKET_SIZE < (ATCA_PACKET_OVERHEAD + len)), ATCA_INVALID_SIZE, "Invalid size received");

        packet = calib_packet_alloc();
        if(NULL == packet)
        {
            (void)ATCA_TRACE(ATCA_ALLOC_FAILURE, "calib_packet_alloc - failed");
            status = ATCA_ALLOC_FAILURE;
            break;
        }

        // The get address function checks the remaining variables
        if ((status = calib_get_addr(zone, slot, block, offset, &addr)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_get_addr - failed");
            break;
        }

        // If there are 32 bytes to read, then OR the bit into the mode
        if (len == ATCA_BLOCK_SIZE)
        {
            zone = zone | ATCA_ZONE_READWRITE_32;
        }

        (void)memset(packet, 0x00, sizeof(ATCAPacket));

        // build a read command
        packet->param1 = zone;
        packet->param2 = addr;

        if ((status = atRead(atcab_get_device_type_ext(device), packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atRead - failed");
            break;
        }

        if ((status = atca_execute_command(packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_read_zone - execution failed");
            break;
        }

        (void)memcpy(data, &packet->data[1], len);
    } while (false); 
    calib_packet_free(packet);
    return status;
}

/** \brief Executes Read command, which reads the 9 byte serial number of the
 *          device from the config zone.
 *
 *  \param[in]  device         Device context pointer
 *  \param[out] serial_number  9 byte serial number is returned here.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_read_serial_number(ATCADevice device, uint8_t* serial_number)
{
    ATCA_STATUS status;
    uint8_t read_buf[ATCA_BLOCK_SIZE];

    if (NULL == serial_number)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    do
    {
        if ((status = calib_read_zone(device, ATCA_ZONE_CONFIG, 0, 0, 0, read_buf, ATCA_BLOCK_SIZE)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_read_zone - failed");
            break;
        }
        (void)memcpy(&serial_number[0], &read_buf[0], 4);
        (void)memcpy(&serial_number[4], &read_buf[8], 5);
    } while (false);

    return status;
}
#endif

#if CALIB_READ_ENC_EN
/** \brief Executes Read command on a slot configured for encrypted reads and
 *          decrypts the data to return it as plaintext.
 *
 * Data zone must be locked for this command to succeed. Can only read 32 byte
 * blocks.
 *
 *  \param[in]  device      Device context pointer
 *  \param[in]  key_id      The slot ID to read from.
 *  \param[in]  block       Index of the 32 byte block within the slot to read.
 *  \param[out] data        Decrypted (plaintext) data from the read is returned
 *                          here (32 bytes).
 *  \param[in]  enc_key     32 byte ReadKey for the slot being read.
 *  \param[in]  enc_key_id  KeyID of the ReadKey being used.
 *  \param[in]  num_in      20 byte host nonce to inject into Nonce calculation
 *
 *  returns ATCA_SUCCESS on success, otherwise an error code.
 */
#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS calib_read_enc(ATCADevice device, uint16_t key_id, uint8_t block, uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id)
{
    const uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

#else
ATCA_STATUS calib_read_enc(ATCADevice device, uint16_t key_id, uint8_t block, uint8_t *data, const uint8_t* enc_key, const uint16_t enc_key_id,
                           const uint8_t num_in[NONCE_NUMIN_SIZE])
{
#endif
    ATCA_STATUS status;
    uint8_t zone = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32;
    atca_nonce_in_out_t nonce_params;
    atca_gen_dig_in_out_t gen_dig_param;
    atca_temp_key_t temp_key;
    uint8_t serial_num[32];
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    uint8_t other_data[4] = { 0 };
    uint8_t i = 0;

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

        // Send the random Nonce command
        if ((status = calib_nonce_rand(device, num_in, rand_out)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Nonce failed"); break;
        }

        // Calculate Tempkey
        (void)memset(&temp_key, 0, sizeof(temp_key));
        (void)memset(&nonce_params, 0, sizeof(nonce_params));
        nonce_params.mode = NONCE_MODE_SEED_UPDATE;
        nonce_params.zero = 0;
        nonce_params.num_in = &num_in[0];
        nonce_params.rand_out = rand_out;
        nonce_params.temp_key = &temp_key;
        if ((status = atcah_nonce(&nonce_params)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Calc TempKey failed"); break;
        }

        // Supply OtherData so GenDig behavior is the same for keys with SlotConfig.NoMac set
        other_data[0] = ATCA_GENDIG;
        other_data[1] = GENDIG_ZONE_DATA;
        other_data[2] = (uint8_t)(enc_key_id & 0xFFu);
        other_data[3] = (uint8_t)(enc_key_id >> 8u);

        // Send the GenDig command
        if ((status = calib_gendig(device, GENDIG_ZONE_DATA, enc_key_id, other_data, (uint8_t)sizeof(other_data))) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "GenDig failed"); break;
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
            (void)ATCA_TRACE(status, ""); break;
        }

        // Read Encrypted
        if ((status = calib_read_zone(device, zone, key_id, block, 0, data, ATCA_BLOCK_SIZE)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Read encrypted failed"); break;
        }

        // Decrypt
        for (i = 0; i < ATCA_BLOCK_SIZE; i++)
        {
            data[i] = data[i] ^ temp_key.value[i];
        }

        status = ATCA_SUCCESS;

    } while (false);


    return status;
}
#endif   /* CALIB_READ_ENC_EN */

#if CALIB_READ_EN
/** \brief Used to read an arbitrary number of bytes from any zone configured
 *          for clear reads.
 *
 * This function will issue the Read command as many times as is required to
 * read the requested data.
 *
 *  \param[in]  device  Device context pointer
 *  \param[in]  zone    Zone to read data from. Option are ATCA_ZONE_CONFIG(0),
 *                      ATCA_ZONE_OTP(1), or ATCA_ZONE_DATA(2).
 *  \param[in]  slot    Slot number to read from if zone is ATCA_ZONE_DATA(2).
 *                      Ignored for all other zones.
 *  \param[in]  offset  Byte offset within the zone to read from.
 *  \param[out] data    Read data is returned here.
 *  \param[in]  length  Number of bytes to read starting from the offset.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_read_bytes_zone(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset, uint8_t *data, size_t length)
{
    ATCA_STATUS status;
    size_t zone_size = 0;
    uint8_t read_buf[32];
    size_t data_idx = 0;
    size_t cur_block = 0;
    size_t cur_offset = 0;
    uint8_t read_size = ATCA_BLOCK_SIZE;
    size_t read_buf_idx = 0;
    size_t copy_length = 0;
    size_t read_offset = 0;

    ATCA_CHECK_INVALID_MSG((zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_OTP && zone != ATCA_ZONE_DATA), ATCA_BAD_PARAM, "Invalid zone received");
    ATCA_CHECK_INVALID_MSG((zone == ATCA_ZONE_DATA && slot > 15u), ATCA_BAD_PARAM, "Invalid slot received");
    ATCA_CHECK_INVALID_MSG((length > 416u || offset > 416u), ATCA_BAD_PARAM, "Invalid length/offset received");

    if (length == 0u)
    {
        return ATCA_SUCCESS;  // Always succeed reading 0 bytes
    }

    ATCA_CHECK_INVALID_MSG(NULL == data, ATCA_BAD_PARAM, "NULL pointer received");

    do
    {
        if (ATCA_SUCCESS != (status = calib_get_zone_size(device, zone, slot, &zone_size)))
        {
            (void)ATCA_TRACE(status, "calib_get_zone_size - failed");
            break;
        }

        // Can't read past the end of a zone
        ATCA_CHECK_INVALID_MSG((offset + length > zone_size), ATCA_BAD_PARAM, "Invalid parameter received");

        cur_block = offset / ATCA_BLOCK_SIZE;

        while (data_idx < length)
        {
            /* coverity[cert_int30_c_violation:FALSE]  overflow will not happen as the limits are checked */
            if (read_size == ATCA_BLOCK_SIZE && zone_size - cur_block * ATCA_BLOCK_SIZE < ATCA_BLOCK_SIZE)
            {
                // We have less than a block to read and can't read past the end of the zone, switch to word reads
                read_size = ATCA_WORD_SIZE;
                cur_offset = ((data_idx + offset) / ATCA_WORD_SIZE) % (ATCA_BLOCK_SIZE / ATCA_WORD_SIZE);
            }

            // Read next chunk of data
            if (ATCA_SUCCESS != (status = calib_read_zone(device, zone, slot, (uint8_t)cur_block, (uint8_t)cur_offset, read_buf, read_size)))
            {
                (void)ATCA_TRACE(status, "calib_read_zone - failed");
                break;
            }

            // Calculate where in the read buffer we need data from
            read_offset = cur_block * ATCA_BLOCK_SIZE + cur_offset * ATCA_WORD_SIZE;
            if (read_offset < offset)
            {
                read_buf_idx = offset - read_offset;  // Read data starts before the requested chunk
            }
            else
            {
                read_buf_idx = 0;                     // Read data is within the requested chunk

            }
            // Calculate how much data from the read buffer we want to copy
            if (length - data_idx < read_size - read_buf_idx)
            {
                copy_length = length - data_idx;
            }
            else
            {
                copy_length = read_size - read_buf_idx;
            }

            (void)memcpy(&data[data_idx], &read_buf[read_buf_idx], copy_length);
            data_idx += copy_length;
            if (read_size == ATCA_BLOCK_SIZE)
            {
                cur_block += 1u;
            }
            else
            {
                cur_offset += 1u;
            }
        }
        if (status != ATCA_SUCCESS)
        {
            break;
        }
    } while (false);

    return status;
}

/** \brief Compares a specified configuration zone with the configuration zone
 *          currently on the SHA device.
 *
 * This only compares the static portions of the configuration zone and skips
 * those that are unique per device (first 16 bytes) and areas that can change
 * after the configuration zone has been locked (e.g. Counter).

 * \return TRUE if the zones pass the comparison test otherwise FALSE
 */
bool calib_sha_compare_config(
    uint8_t* expected,      /**< [in] Expected configuration zone */
    uint8_t* other          /**< [in] Read or Other buffer to compare */
    )
{
    bool same = false;

    if ((NULL != expected) && (NULL != other))
    {
        /* Compare only the user writeable and lockable bytes of the
           config zone - i.e. those that do not change with the device operation
           and are not configured by the factory
            Bytes [16 - 52] */
        if (0 == memcmp(&expected[16], &other[16], 52 - 16))
        {
            same = true;
        }
    }
    return same;
}

/** \brief Compares a specified configuration zone with the configuration zone
 *          currently on the ECC device.
 *
 * \return TRUE if the zones pass the comparison test otherwise FALSE
 */
bool calib_ecc_compare_config(
    uint8_t* expected,      /**< [in] Expected configuration zone */
    uint8_t* other          /**< [in] Read or Other buffer to compare */
    )
{
    bool same = false;

    if ((NULL != expected) && (NULL != other))
    {
        /* Compare only the user writeable and lockable bytes of the
           config zone - i.e. those that do not change with the device operation
           and are not configured by the factory
            Bytes [16 - 52] & [90 - 128]*/
        if ((0 == memcmp(&expected[16], &other[16], 52 - 16)) &&
            (0 == memcmp(&expected[90], &other[90], 128 - 90)))
        {
            same = true;
        }
    }
    return same;
}

/** \brief Compares a specified configuration zone with the configuration zone
 *          currently on the ECC608 device.
 *
 * \return TRUE if the zones pass the comparison test otherwise FALSE
 */
bool calib_ecc608_compare_config(
    uint8_t* expected,      /**< [in] Expected configuration zone */
    uint8_t* other          /**< [in] Read or Other buffer to compare */
    )
{
    bool same = false;

    if ((NULL != expected) && (NULL != other))
    {
        /* Compare only the user writeable and lockable bytes of the
           config zone - i.e. those that do not change with the device operation
           and are not configured by the factory:
            Bytes [16 - 52] & [68 - 84] & [90 - 128]*/
        if ((0 == memcmp(&expected[16], &other[16], 52 - 16)) &&
            (0 == memcmp(&expected[68], &other[68], 84 - 68)) &&
            (0 == memcmp(&expected[90], &other[90], 128 - 90)))
        {
            same = true;
        }
    }
    return same;
}

/** \brief Executes Read command to read a 64 byte ECDSA P256 signature from a
 *          slot configured for clear reads.
 *
 *  \param[in]  device  Device context pointer
 *  \param[in]  slot    Slot number to read from. Only slots 8 to 15 are large
 *                      enough for a signature.
 *  \param[out] sig     Signature will be returned here (64 bytes). Format will be
 *                      the 32 byte R and S big-endian integers concatenated.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_read_sig(ATCADevice device, uint16_t slot, uint8_t* sig)
{
    ATCA_STATUS status;

    do
    {
        // Check the value of the slot
        if (sig == NULL)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
            break;
        }

        if (slot < 8u || slot > 15u)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot received");
            break;
        }

        // Read the first block
        if ((status = calib_read_zone_ext(device, ATCA_ZONE_DATA, slot, 0, 0, &sig[0], ATCA_BLOCK_SIZE)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_read_zone - failed");
            break;
        }

        // Read the second block
        if ((status = calib_read_zone_ext(device, ATCA_ZONE_DATA, slot, 1, 0, &sig[ATCA_BLOCK_SIZE], ATCA_BLOCK_SIZE)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_read_zone - failed");
            break;
        }
    } while (false);

    return status;
}

#endif /* CALIB_READ_EN */

#if CALIB_READ_CA2_EN
/** \brief Use Read command to reads words 16 bytes from one of the slots in the EEPROM Configuration
 *         zone or 32 bytes in Data zone.
 *
 *  \param[in]  device    Device context pointer
 *  \param[in]  zone      Selects config or data zone
 *  \param[in]  slot      select slot in config or data zone
 *  \param[in]  block     select the lock in given slot
 *  \param[in]  offset    16 byte work index within the block. Ignored for 32 byte
 *                        reads.
 *  \param[out] data      Read data is returned here.
 *  \param[in]  len       Length of the data to be read. Must be either 16 or 32.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_read_zone(ATCADevice device, uint8_t zone, uint16_t slot, uint8_t block, size_t offset,
                                uint8_t* data, uint8_t len)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    ATCAPacket * packet = calib_packet_alloc();
    uint16_t addr;
    uint8_t read_zone;

    (void)offset;

    read_zone = (zone == ATCA_ZONE_CONFIG) ? ATCA_ZONE_CA2_CONFIG : ATCA_ZONE_CA2_DATA;


    if ((NULL == device) || (NULL == data))
    {
        status = ATCA_TRACE(ATCA_BAD_PARAM, "Encountered Null pointer");
    }
    if (ATCA_ZONE_CA2_DATA == read_zone)
    {
        if (32u != len)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid parameter received");
        }
        if ((0u == slot) || (3u == slot))
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot number received");
        }
    }
    if (ATCA_ZONE_CA2_CONFIG == read_zone)
    {
        if (16u != len)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid parameter received");
        }
    }
    if (CA_MAX_PACKET_SIZE < (ATCA_PACKET_OVERHEAD + len))
    {
        status = ATCA_TRACE(ATCA_INVALID_SIZE, "Invalid packet size received");
    }

    if(NULL == packet)
    {
        (void)ATCA_TRACE(ATCA_ALLOC_FAILURE, "calib_packet_alloc - failed");
        return ATCA_ALLOC_FAILURE;
    }

    if (ATCA_SUCCESS == status)
    {
        if (ATCA_SUCCESS != (status = calib_ca2_get_addr(read_zone, slot, block, 0, &addr)))
        {
            (void)ATCA_TRACE(status, "Address Encoding failed");
        }

        (void)memset(packet, 0x00, sizeof(ATCAPacket));

        if (ATCA_SUCCESS == status)
        {
            // Build packets
            packet->param1 = read_zone;
            packet->param2 = addr;

            (void)atRead(atcab_get_device_type_ext(device), packet);

            // Execute read command
            if (ATCA_SUCCESS != (status = atca_execute_command(packet, device)))
            {
                (void)ATCA_TRACE(status, "Read command failed");
            }
            else
            {
                (void)memcpy(data, &packet->data[ATCA_RSP_DATA_IDX], len);
            }

        }
    }

    calib_packet_free(packet);
    return status;
}

/** \brief Use Read command to read configuration zone of ECC204 device
 *
 *  \param[in]   device        Device context pointer
 *  \param[out]  config_data   returns config data of 64 bytes
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_read_config_zone(ATCADevice device, uint8_t* config_data)
{
    ATCA_STATUS status;
    uint8_t slot = 0;

    while (slot <= 3u)
    {
        if (ATCA_SUCCESS != (status = calib_ca2_read_zone(device, ATCA_ZONE_CONFIG,
                                                          slot, 0, 0,
                                                          &config_data[ATCA_CA2_CONFIG_SLOT_SIZE * slot],
                                                          ATCA_CA2_CONFIG_SLOT_SIZE)))
        {
            (void)ATCA_TRACE(status, "calib_ca2_read_zone - failed");
            break;
        }
        slot += 1u; // Increment slot to read next slot
    }

    return status;
}

/** \brief Use Read command to read serial number of device
 *
 *  \param[in]  device          Device context pointer
 *  \param[in]  serial_number   9 bytes ECC204 device serial number return here
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_read_serial_number(ATCADevice device, uint8_t* serial_number)
{
    ATCA_STATUS status;
    uint8_t read_buf[ATCA_CA2_CONFIG_SLOT_SIZE];


    status = calib_ca2_read_zone(device, ATCA_ZONE_CONFIG, 0, 0, 0, read_buf,
                                 ATCA_CA2_CONFIG_SLOT_SIZE);

    if (ATCA_SUCCESS == status)
    {
        (void)memcpy(serial_number, read_buf, ATCA_SERIAL_NUM_SIZE);
    }

    return status;
}

/** \brief Used to read an arbitrary number of bytes from any zone configured
 *          for clear reads. This function supports only for ECC204 device.
 *
 * This function will issue the Read command as many times as is required to
 * read the requested data.
 *
 *  \param[in]  device  Device context pointer
 *  \param[in]  zone    Zone to read data from. Option are ATCA_ZONE_CONFIG(1),
 *                      or ATCA_ZONE_DATA(0).
 *  \param[in]  slot    Slot number to read from
 *                      Ignored for all other zones.
 *  \param[in]  offset  Byte offset within the zone to read from.
 *  \param[out] data    Read data is returned here.
 *  \param[in]  length  Number of bytes to read starting from the offset.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_ca2_read_bytes_zone(ATCADevice device, uint8_t zone, uint16_t slot,
                                      size_t offset, uint8_t* data, size_t length)
{
    ATCA_STATUS status;
    uint8_t data_set_size = (ATCA_ZONE_DATA == zone) ? ATCA_BLOCK_SIZE : ATCA_CA2_CONFIG_SLOT_SIZE;
    size_t cur_block = 0;
    size_t data_idx = 0;
    uint8_t read_buf[ATCA_BLOCK_SIZE];
    size_t read_buf_idx = 0, copy_length = 0, read_offset = 0;

    if ((NULL == device) || (NULL == data))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Encountered NULL pointer");
    }
    if ((ATCA_ZONE_DATA != zone) && (ATCA_ZONE_CONFIG != zone))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone parameter received");
    }
    if ((length > 320u) || (offset > 320u))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid length/offset received");
    }
    if (ATCA_ZONE_DATA == zone)
    {
        if ((3u == slot) || (0u == slot) || (slot > 3u))
        {
            return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot received");
        }
        if (((slot == 1u) && ((length + offset) > 320u)) || ((slot == 2u) && ((length + offset) > 64u)))
        {
            return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid length received");
        }
    }
    if ((ATCA_ZONE_CONFIG == zone) && ((slot > 3u) || (offset > 15u) || ((length + offset) > 16u)))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot/length received");
    }

    if (0u == length)
    {
        return ATCA_SUCCESS;
    }

    cur_block = (ATCA_ZONE_DATA == zone) ? (offset / data_set_size) : 0u;
    while (data_idx < length)
    {
        if (ATCA_SUCCESS != (status = calib_ca2_read_zone(device, zone, slot, (uint8_t)(cur_block & UINT8_MAX), 0,
                                                          read_buf,
                                                          data_set_size)))
        {
            (void)ATCA_TRACE(status, "calib_ca2_read_zone failed");
            break;
        }

        // Calculate where in the read buffer we need data from
        read_offset = (ATCA_ZONE_DATA == zone) ? (cur_block * data_set_size) : 0U;

        // 0nly 0th block may contain offset
        read_buf_idx = (data_idx == 0u) ? (offset - read_offset) : 0u;

        // Calculate number of bytes to be copied
        copy_length = (size_t)(data_idx + data_set_size) <= length ? (data_set_size - read_buf_idx) : (length - data_idx);

        // Check whether the copy_length exceeds data_set_size
        copy_length = (read_buf_idx + copy_length) > data_set_size ? data_set_size - read_buf_idx : copy_length;

        (void)memcpy(&data[data_idx], &read_buf[read_buf_idx], copy_length);
        cur_block = (ATCA_ZONE_DATA == zone) ? (cur_block + 1u) : cur_block; // increment block number for DATA zone
        data_idx += copy_length;                                             // increment data index
    }

    return status;
}

/** \brief Compares a specified configuration zone with the configuration zone
 *          currently on the ECC204 device.
 *
 * This only compares the static portions of the configuration zone and skips
 * those that are unique per device (first 16 bytes) and areas that can change
 * after the configuration zone has been locked (e.g. Counter).

 * \return TRUE if the zones pass the comparison test otherwise FALSE
 */
bool calib_ca2_compare_config(
    uint8_t* expected,      /**< [in] Expected configuration zone */
    uint8_t* other          /**< [in] Read or Other buffer to compare */
    )
{
    bool same = false;

    if ((NULL != expected) && (NULL != other))
    {
        // compare slot 1 and slot 3 data && skip first 16 bytes and counter value
        if ((0 == memcmp(&expected[16], &other[16], ATCA_CA2_CONFIG_SLOT_SIZE)) ||
            (0 == memcmp(&expected[48], &other[48], ATCA_CA2_CONFIG_SLOT_SIZE)))
        {
            same = true;
        }
    }
    return same;
}
#endif  /* CALIB_READ_EN  */

#if CALIB_READ_EN || CALIB_READ_CA2_EN
/** \brief Checks the device type and maps to the correct read operation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_read_zone_ext(
    ATCADevice  device, /**< [in]  Device context pointer */
    uint8_t     zone,   /**< [in]  Zone to be read from device. Options are
                                   ATCA_ZONE_CONFIG, ATCA_ZONE_OTP, or ATCA_ZONE_DATA.*/
    uint16_t    slot,   /**< [in]  Slot number for data zone and ignored for other zones. */
    uint8_t     block,  /**< [in]  32 byte block index within the zone. */
    uint8_t     offset, /**< [in]  4 byte work index within the block. Ignored for 32 byte
                                   reads. */
    uint8_t *   data,   /**< [out] Read data is returned here. */
    uint8_t     len     /**< [in]  Length of the data to be read. Must be either 4 or 32. */
    )
{
#if ATCA_CA2_SUPPORT
    ATCADeviceType devtype = atcab_get_device_type_ext(device);
    ATCA_STATUS status;

    if (atcab_is_ca2_device(devtype))
    {
        status = calib_ca2_read_zone(device, zone, slot, block, offset, data, len);
    }
#if CALIB_READ_EN
    else if (atcab_is_ca_device(devtype))
    {
        status = calib_read_zone(device, zone, slot, block, offset, data, len);
    }
#endif /* CALIB_READ_EN */
    else
    {
        status = ATCA_UNIMPLEMENTED;
    }
    return status;
#else
    return calib_read_zone(device, zone, slot, block, offset, data, len);
#endif /* CALIB_ECC204_EN */
}

/** \brief Executes Read command to read the complete device configuration
 *          zone.
 *
 *  \param[in]  device       Device context pointer
 *  \param[out] config_data  Configuration zone data is returned here. 88 bytes
 *                           for ATSHA devices, 128 bytes for ATECC devices.
 *
 *  \returns ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_read_config_zone(ATCADevice device, uint8_t* config_data)
{
    ATCADeviceType devtype = atcab_get_device_type_ext(device);
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (NULL != config_data)
    {
        switch (devtype)
        {
#if CALIB_SHA204_EN || CALIB_SHA206_EN
        case ATSHA204A:
        /* fallthrough */
        case ATSHA206A:
            status = calib_read_bytes_zone(device, ATCA_ZONE_CONFIG, 0, 0x00, config_data, ATCA_SHA_CONFIG_SIZE);
            break;
#endif
#if ATCA_CA2_SUPPORT
        case ECC204:
        /* fallthrough */
        case TA010:
        /* fallthrough */
        case SHA104:
        /* fallthrough */
        case SHA105:
        /* fallthrough */
        case SHA106:
            status = calib_ca2_read_config_zone(device, config_data);
            break;
#endif
        default:
#if CALIB_ECC108_EN || CALIB_ECC508_EN || CALIB_ECC608_EN
            /* ECCx08 as the default */
            status = calib_read_bytes_zone(device, ATCA_ZONE_CONFIG, 0, 0x00, config_data, ATCA_ECC_CONFIG_SIZE);
#endif
            break;
        }
    }

    return status;
}

/** \brief Compares a specified configuration zone with the configuration zone
 *          currently on the device.
 *
 * This only compares the static portions of the configuration zone and skips
 * those that are unique per device (first 16 bytes) and areas that can change
 * after the configuration zone has been locked (e.g. LastKeyUse).
 *
 * \param[in]  device       Device context pointer
 * \param[in]  config_data  Full configuration data to compare the device
 *                          against.
 * \param[out] same_config  Result is returned here. True if the static portions
 *                          on the configuration zones are the same.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_cmp_config_zone(ATCADevice device, uint8_t* config_data, bool* same_config)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    ATCADeviceType devtype = atcab_get_device_type_ext(device);
    uint8_t device_config_data[ATCA_ECC_CONFIG_SIZE];   /** Max for all configs */

    do
    {
        // Check the inputs
        if (NULL == device || NULL == config_data || NULL == same_config)
        {
            break;
        }
        // Set the boolean to false
        *same_config = false;

        // Read all of the configuration bytes from the device
        if ((status = calib_read_config_zone(device, device_config_data)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "Read config zone failed");
            break;
        }

        switch (devtype)
        {
#if CALIB_SHA204_EN || CALIB_SHA206_EN
        case ATSHA204A:
        /* fallthrough */
        case ATSHA206A:
            *same_config = calib_sha_compare_config(config_data, device_config_data);
            break;
#endif
#if CALIB_ECC608_EN
        case ATECC608:
            *same_config = calib_ecc608_compare_config(config_data, device_config_data);
            break;
#endif
#if ATCA_CA2_SUPPORT
        case ECC204:
        /* fallthrough */
        case TA010:
        /* fallthrough */
        case SHA104:
        /* fallthrough */
        case SHA105:
        /* fallthrough */
        case SHA106:
            *same_config = calib_ca2_compare_config(config_data, device_config_data);
            break;
#endif
        default:
#if CALIB_ECC108_EN || CALIB_ECC508_EN
            *same_config = calib_ecc_compare_config(config_data, device_config_data);
#endif
            break;
        }
    } while (false);

    return status;
}

/** \brief Executes Read command to read an ECC P256 public key from a slot
 *          configured for clear reads.
 *
 * This function assumes the public key is stored using the ECC public key
 * format specified in the datasheet.
 *
 *  \param[in]  device      Device context pointer
 *  \param[in]  slot        Slot number to read from. Only slots 8 to 15 are
 *                          large enough for a public key.
 *  \param[out] public_key  Public key is returned here (64 bytes). Format will
 *                          be the 32 byte X and Y big-endian integers
 *                          concatenated.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_read_pubkey(ATCADevice device, uint16_t slot, uint8_t *public_key)
{
    ATCA_STATUS status;
    uint8_t read_buf[ATCA_BLOCK_SIZE];
    uint8_t block = 0;
    uint8_t offset = 0;
    uint8_t cpy_index = 0;
    uint8_t cpy_size = 0;
    uint8_t read_index = 0;

    // Check the pointers
    if (public_key == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }
    // Check the value of the slot
    if (slot < 8u || slot > 15u)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot received");
    }

    do
    {
        // The 64 byte P256 public key gets written to a 72 byte slot in the following pattern
        // | Block 1                     | Block 2                                      | Block 3       |
        // | Pad: 4 Bytes | PubKey[0:27] | PubKey[28:31] | Pad: 4 Bytes | PubKey[32:55] | PubKey[56:63] |

        // Read the block
        block = 0;
        if ((status = calib_read_zone_ext(device, ATCA_ZONE_DATA, slot, block, offset, read_buf, ATCA_BLOCK_SIZE)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_read_zone - failed");
            break;
        }

        // Copy.  Account for 4 byte pad
        cpy_size = ATCA_BLOCK_SIZE - ATCA_PUB_KEY_PAD;
        read_index = ATCA_PUB_KEY_PAD;
        (void)memcpy(&public_key[cpy_index], &read_buf[read_index], cpy_size);
        cpy_index += cpy_size;

        // Read the next block
        block = 1;
        if ((status = calib_read_zone_ext(device, ATCA_ZONE_DATA, slot, block, offset, read_buf, ATCA_BLOCK_SIZE)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_read_zone - failed");
            break;
        }

        // Copy.  First four bytes
        cpy_size = ATCA_PUB_KEY_PAD;
        read_index = 0;
        (void)memcpy(&public_key[cpy_index], &read_buf[read_index], cpy_size);
        cpy_index += cpy_size;
        // Copy.  Skip four bytes
        read_index = ATCA_PUB_KEY_PAD + ATCA_PUB_KEY_PAD;
        cpy_size = ATCA_BLOCK_SIZE - read_index;
        (void)memcpy(&public_key[cpy_index], &read_buf[read_index], cpy_size);
        cpy_index += cpy_size;

        // Read the next block
        block = 2;
        if ((status = calib_read_zone_ext(device, ATCA_ZONE_DATA, slot, block, offset, read_buf, ATCA_BLOCK_SIZE)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_read_zone - failed");
            break;
        }

        // Copy.  The remaining 8 bytes
        cpy_size = ATCA_PUB_KEY_PAD + ATCA_PUB_KEY_PAD;
        read_index = 0;
        (void)memcpy(&public_key[cpy_index], &read_buf[read_index], cpy_size);

    } while (false);

    return status;
}

/** \brief Executes Read command, which reads the 9 byte serial number of the
 *          device from the config zone.
 *
 *  \param[in]  device         Device context pointer
 *  \param[out] serial_number  9 byte serial number is returned here.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_read_serial_number_ext(ATCADevice device, uint8_t* serial_number)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);
    if (atcab_is_ca2_device(device_type))
    {
        status = calib_ca2_read_serial_number(device, serial_number);
    }
    else
#endif
    {
#if CALIB_READ_EN
        status = calib_read_serial_number(device, serial_number);
#endif
    }

    return status;
}

/** \brief Used to read an arbitrary number of bytes from any zone configured
 *          for clear reads.
 *
 * This function will issue the Read command as many times as is required to
 * read the requested data.
 *
 *  \param[in]  device  Device context pointer
 *  \param[in]  zone    Zone to read data from. Option are ATCA_ZONE_CONFIG(0),
 *                      ATCA_ZONE_OTP(1), or ATCA_ZONE_DATA(2).
 *  \param[in]  slot    Slot number to read from if zone is ATCA_ZONE_DATA(2).
 *                      Ignored for all other zones.
 *  \param[in]  offset  Byte offset within the zone to read from.
 *  \param[out] data    Read data is returned here.
 *  \param[in]  length  Number of bytes to read starting from the offset.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_read_bytes_zone_ext(ATCADevice device, uint8_t zone, uint16_t slot, size_t offset, uint8_t *data, size_t length)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);
    if (atcab_is_ca2_device(device_type))
    {
        status = calib_ca2_read_bytes_zone(device, zone, slot, offset, data, length);
    }
    else
#endif
    {
#if CALIB_READ_EN
        status = calib_read_bytes_zone(device, zone, slot, offset, data, length);
#endif
    }

    return status;
}

#endif
