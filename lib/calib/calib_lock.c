/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Lock command.
 *
 * The Lock command prevents future modifications of the Configuration zone,
 * enables configured policies for Data and OTP zones, and can render
 * individual slots read-only regardless of configuration.
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

#if CALIB_LOCK_EN || CALIB_LOCK_CA2_EN

#if (CA_MAX_PACKET_SIZE < ATCA_CMD_SIZE_MIN)
#error "Lock command packet cannot be accommodated inside the maximum packet size provided"
#endif

/** \brief The Lock command prevents future modifications of the Configuration
 *         and/or Data and OTP zones. If the device is so configured, then
 *         this command can be used to lock individual data slots. This
 *         command fails if the designated area is already locked.
 *
 * \param[in]  device         Device context pointer
 * \param[in]  mode           Zone, and/or slot, and summary check (bit 7).
 * \param[in]  summary_crc    CRC of the config or data zones. Ignored for
 *                            slot locks or when mode bit 7 is set.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_lock(ATCADevice device, uint8_t mode, uint16_t summary_crc)
{
    ATCAPacket * packet = NULL;
    ATCA_STATUS status;

    do
    {
        if (device == NULL)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
            break;
        }

        packet = calib_packet_alloc();
        if(NULL == packet)
        {
            (void)ATCA_TRACE(ATCA_ALLOC_FAILURE, "calib_packet_alloc - failed");
            status = ATCA_ALLOC_FAILURE;
            break;
        }

        // build command for lock zone and send
        (void)memset(packet, 0, sizeof(ATCAPacket));
        packet->param1 = mode;
        packet->param2 = summary_crc;

        if ((status = atLock(atcab_get_device_type_ext(device), packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atLock - failed");
            break;
        }

        if ((status = atca_execute_command(packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_lock - execution failed");
            break;
        }

    } while (false);

    calib_packet_free(packet);
    return status;
}

/** \brief Unconditionally (no CRC required) lock the config zone.
 *
 *  \param[in]  device      Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_lock_config_zone(ATCADevice device)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);
    if (atcab_is_ca2_device(device_type))
    {
        status = calib_ca2_lock_config_zone(device);
    }
    else
#endif
    {
#if CALIB_LOCK_EN
        status = calib_lock(device, LOCK_ZONE_NO_CRC | LOCK_ZONE_CONFIG, 0);
#endif
    }

    return status;
}

/** \brief Lock the config zone with summary CRC.
 *
 *  The CRC is calculated over the entire config zone contents. 88 bytes for
 *  ATSHA devices, 128 bytes for ATECC devices. Lock will fail if the provided
 *  CRC doesn't match the internally calculated one.
 *
 *  \param[in] device       Device context pointer
 *  \param[in] summary_crc  Expected CRC over the config zone.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_lock_config_zone_crc(ATCADevice device, uint16_t summary_crc)
{
#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);

    if (atcab_is_ca2_device(device_type))
    {
        return ATCA_UNIMPLEMENTED;
    }
    else
#endif
    {
        return calib_lock(device, LOCK_ZONE_CONFIG, summary_crc);
    }
}

/** \brief Unconditionally (no CRC required) lock the data zone (slots and OTP).
 *
 *	ConfigZone must be locked and DataZone must be unlocked for the zone to be successfully locked.
 *
 *  \param[in]  device      Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_lock_data_zone(ATCADevice device)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);
    if (atcab_is_ca2_device(device_type))
    {
        status = calib_ca2_lock_data_zone(device);
    }
    else
#endif
    {
#if CALIB_LOCK_EN
        status = calib_lock(device, LOCK_ZONE_NO_CRC | LOCK_ZONE_DATA, 0);
#endif
    }

    return status;
}

/** \brief Lock the data zone (slots and OTP) with summary CRC.
 *
 *  The CRC is calculated over the concatenated contents of all the slots and
 *  OTP at the end. Private keys (KeyConfig.Private=1) are skipped. Lock will
 *  fail if the provided CRC doesn't match the internally calculated one.
 *
 *  \param[in] device       Device context pointer
 *  \param[in] summary_crc  Expected CRC over the data zone.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_lock_data_zone_crc(ATCADevice device, uint16_t summary_crc)
{
#if ATCA_CA2_SUPPORT
    ATCADeviceType device_type = atcab_get_device_type_ext(device);

    if (atcab_is_ca2_device(device_type))
    {
        return ATCA_UNIMPLEMENTED;
    }
    else
#endif
    {
        return calib_lock(device, LOCK_ZONE_DATA, summary_crc);
    }
}

/** \brief Lock an individual slot in the data zone on an ATECC device. Not
 *         available for ATSHA devices. Slot must be configured to be slot
 *         lockable (KeyConfig.Lockable=1).
 *
 *  \param[in] device   Device context pointer
 *  \param[in] slot     Slot to be locked in data zone.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_lock_data_slot(ATCADevice device, uint16_t slot)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

#if ATCA_CA2_SUPPORT
    if (atcab_is_ca2_device(atcab_get_device_type_ext(device)))
    {
        status = calib_ca2_lock_data_slot(device, slot);
    }
    else
#endif
    {
#if CALIB_LOCK_EN
        status = calib_lock(device, (uint8_t)((LOCK_ZONE_DATA_SLOT | (slot << 2)) & UINT8_MAX), 0);
#endif
    }

    return status;
}
#endif

#if CALIB_LOCK_CA2_EN
/** \brief Use Lock command to lock individual configuration zone slots
 *
 *  \param[in]   device       Device context pointer
 *  \param[in]   slot         The slot number to be locked
 *  \param[in]   summary_crc  CRC calculated over all 16 bytes within the selected
 *                            slot of the configuration zone.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_lock_config_slot(ATCADevice device, uint16_t slot, uint16_t summary_crc)
{
    uint8_t mode = (uint8_t)((LOCK_ZONE_CA2_CONFIG | (slot << 1)) & UINT8_MAX);

    if (summary_crc == 0u)
    {
        mode |= LOCK_ZONE_NO_CRC;
    }

    return calib_lock(device, mode, summary_crc);
}

/** \brief Use lock command to lock complete configuration zone
 *
 *  \param[in]  device      Device context pointer
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_lock_config_zone(ATCADevice device)
{
    ATCA_STATUS status;
    uint8_t slot = 0;
    uint8_t mode;

    while (slot <= 3u)
    {
        mode = (uint8_t)(LOCK_ZONE_NO_CRC | LOCK_ZONE_CA2_CONFIG | (slot << 1));

        if (ATCA_SUCCESS != (status = calib_lock(device, mode, 0)))
        {
            // ECC204,TA010,SHA10x returns execution error if slot is already locked.
            // Consider already locked status as valid while locking the config zone.
            if (status == ATCA_EXECUTION_ERROR)
            {
                status = ATCA_SUCCESS;
            }
            else
            {
                (void)ATCA_TRACE(status, "calib_ca2_lock_config_zone - failed");
                break;
            }
        }

        slot += 1u; //Increment slot
    }

    return status;
}

/** \brief Use lock command to lock data zone slot
 *
 *  \param[in]   device   Device context pointer
 *  \param[in]   slot     The slot number to be locked
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_lock_data_slot(ATCADevice device, uint16_t slot)
{
    return calib_lock(device, (uint8_t)((LOCK_ZONE_CA2_DATA | (slot << 1)) & UINT8_MAX), 0);
}

/** \brief Use lock command to lock complete Data zone
 *
 *  \param[in]  device      Device context pointer
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code
 */
ATCA_STATUS calib_ca2_lock_data_zone(ATCADevice device)
{
    ATCA_STATUS status;
    uint8_t slot = 0;
    uint8_t mode;

    while (slot <= 3u)
    {
        mode = LOCK_ZONE_NO_CRC | LOCK_ZONE_CA2_DATA | (slot << 1);

        if (ATCA_SUCCESS != (status = calib_lock(device, mode, 0)))
        {
            // ECC204,TA010,SHA10x returns execution error if slot is already locked.
            // Consider already locked status as valid while locking the config zone.
            if (status == ATCA_EXECUTION_ERROR)
            {
                status = ATCA_SUCCESS;
            }
            else
            {
                (void)ATCA_TRACE(status, "calib_ca2_lock_data_zone - failed");
                break;
            }
        }

        slot += 1u; //Increment slot
    }

    return status;
}
#endif
