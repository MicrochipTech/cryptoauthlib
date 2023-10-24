/**
 * \file
 * \brief CryptoAuthLib Basic API methods for GenDig command.
 *
 * The GenDig command uses SHA-256 to combine a stored value with the contents
 * of TempKey, which must have been valid prior to the execution of this
 * command.
 *
 * \note List of devices that support this command - ATSHA204A, ATECC108A,
 *       ATECC508A, and ATECC608A/B. There are differences in  the modes that
 *       they support. Refer to device datasheets for full details.
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

#if CALIB_GENDIG_EN
/** \brief Issues a GenDig command, which performs a SHA256 hash on the source data indicated by zone with the
 *  contents of TempKey.  See the CryptoAuth datasheet for your chip to see what the values of zone
 *  correspond to.
 *  \param[in] device           Device context pointer
 *  \param[in] zone             Designates the source of the data to hash with TempKey.
 *  \param[in] key_id           Indicates the key, OTP block, or message order for shared nonce mode.
 *  \param[in] other_data       Four bytes of data for SHA calculation when using a NoMac key, 32 bytes for
 *                              "Shared Nonce" mode, otherwise ignored (can be NULL).
 *  \param[in] other_data_size  Size of other_data in bytes.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_gendig(ATCADevice device, uint8_t zone, uint16_t key_id, const uint8_t *other_data, uint8_t other_data_size)
{
    ATCAPacket packet;
    ATCA_STATUS status = ATCA_GEN_FAIL;
    bool is_no_mac_key = false;

    if ((device == NULL) || (other_data_size > 0u && other_data == NULL))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    if (CA_MAX_PACKET_SIZE < (ATCA_CMD_SIZE_MIN + other_data_size))
    {
        status = ATCA_TRACE(ATCA_INVALID_SIZE, "Invalid packet size received");
    }

    do
    {
        // build gendig command
        packet.param1 = zone;
        packet.param2 = key_id;

        if (packet.param1 == GENDIG_ZONE_SHARED_NONCE && other_data_size >= ATCA_BLOCK_SIZE)
        {
            (void)memcpy(&packet.data[0], &other_data[0], ATCA_BLOCK_SIZE);
        }

        if (packet.param1 == GENDIG_ZONE_DATA && other_data_size >= ATCA_WORD_SIZE)
        {
            (void)memcpy(&packet.data[0], &other_data[0], ATCA_WORD_SIZE);
            is_no_mac_key = true;
        }

        if ((status = atGenDig(atcab_get_device_type_ext(device), &packet, is_no_mac_key)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atGenDig - failed");
            break;
        }

        if ((status = atca_execute_command(&packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_gendig - execution failed");
            break;
        }

    }
    while (false);

    return status;
}
#endif /* CALIB_GENDIG_EN */

#if CALIB_GENDIVKEY_EN
/** \brief Issues a GenDivKey command to generate the equivalent diversified key as that programmed into the SHA104 or
 *         other client side device
 *  \param[in] device           Device context pointer
 *  \param[in] other_data       Must match data used when generating the diversified key in the client device
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_sha105_gendivkey(ATCADevice device, const uint8_t *other_data)
{
    return calib_gendig(device, GENDIVKEY_MODE, GENDIVKEY_DEFAULT_KEYID, other_data, GENDIVKEY_OTHER_DATA_SIZE);
}
#endif
