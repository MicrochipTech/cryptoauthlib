/**
 * \file
 * \brief CryptoAuthLib Basic API methods for AES command.
 *
 * The AES command supports 128-bit AES encryption or decryption of small
 * messages or data packets in ECB mode. Also can perform GFM (Galois Field
 * Multiply) calculation in support of AES-GCM.
 *
 * \note List of devices that support this command - ATECC608A/B. Refer to
 *       device edatasheet for full details.
 *
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

#if CALIB_AES_EN && (CA_MAX_PACKET_SIZE < (ATCA_CMD_SIZE_MIN + AES_DATA_SIZE))
#error "AES command packet cannot be accommodated inside the maximum packet size provided"
#endif

#if CALIB_AES_EN && CALIB_AES_GCM_EN && (CA_MAX_PACKET_SIZE < (ATCA_CMD_SIZE_MIN + AES_DATA_SIZE + AES_DATA_SIZE))
#error "AES GFM command packet cannot be accommodated inside the maximum packet size provided"
#endif

#if CALIB_AES_EN
/** \brief Compute the AES-128 encrypt, decrypt, or GFM calculation.
 *
 *  \param[in]  device   Device context pointer
 *  \param[in]  mode     The mode for the AES command.
 *  \param[in]  key_id   Key location. Can either be a slot number or
 *                       ATCA_TEMPKEY_KEYID for TempKey.
 *  \param[in]  aes_in   Input data to the AES command (16 bytes).
 *  \param[out] aes_out  Output data from the AES command is returned here (16
 *                       bytes).
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_aes(ATCADevice device, uint8_t mode, uint16_t key_id, const uint8_t* aes_in, uint8_t* aes_out)
{
    ATCAPacket * packet = NULL;
    ATCA_STATUS status;

    do
    {
        if ((device == NULL) || (aes_in == NULL))
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

        (void)memset(packet, 0x00, sizeof(ATCAPacket));

        // build a AES command
        packet->param1 = mode;
        packet->param2 = key_id;

        (void)memcpy(packet->data, aes_in, AES_DATA_SIZE);

        if ((status = atAES(atcab_get_device_type_ext(device), packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atAES - failed");
            break;
        }

        if ((status = atca_execute_command(packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_aes - execution failed");
            break;
        }

        if ((NULL != aes_out) && (packet->data[ATCA_COUNT_IDX] >= (3u + AES_DATA_SIZE)))
        {
            // The AES command return a 16 byte data.
            (void)memcpy(aes_out, &packet->data[ATCA_RSP_DATA_IDX], AES_DATA_SIZE);
        }

    } while (false);

    calib_packet_free(packet);
    return status;
}

/** \brief Perform an AES-128 encrypt operation with a key in the device.
 *
 * \param[in]  device      Device context pointer
 * \param[in]  key_id      Key location. Can either be a slot number or
 *                         ATCA_TEMPKEY_KEYID for TempKey.
 * \param[in]  key_block   Index of the 16-byte block to use within the key
 *                         location for the actual key.
 * \param[in]  plaintext   Input plaintext to be encrypted (16 bytes).
 * \param[out] ciphertext  Output ciphertext is returned here (16 bytes).
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_aes_encrypt(ATCADevice device, uint16_t key_id, uint8_t key_block, const uint8_t* plaintext, uint8_t* ciphertext)
{
    uint8_t mode;

    mode = AES_MODE_ENCRYPT | (AES_MODE_KEY_BLOCK_MASK & (uint8_t)(key_block << AES_MODE_KEY_BLOCK_POS));
    return calib_aes(device, mode, key_id, plaintext, ciphertext);
}

/** \brief Perform an AES-128 decrypt operation with a key in the device.
 *
 * \param[in]   device     Device context pointer
 * \param[in]   key_id     Key location. Can either be a slot number or
 *                         ATCA_TEMPKEY_KEYID for TempKey.
 * \param[in]   key_block  Index of the 16-byte block to use within the key
 *                         location for the actual key.
 * \param[in]  ciphertext  Input ciphertext to be decrypted (16 bytes).
 * \param[out] plaintext   Output plaintext is returned here (16 bytes).
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_aes_decrypt(ATCADevice device, uint16_t key_id, uint8_t key_block, const uint8_t* ciphertext, uint8_t* plaintext)
{
    uint8_t mode;

    mode = AES_MODE_DECRYPT | (AES_MODE_KEY_BLOCK_MASK & (uint8_t)(key_block << AES_MODE_KEY_BLOCK_POS));
    return calib_aes(device, mode, key_id, ciphertext, plaintext);
}
#endif

#if CALIB_AES_EN && CALIB_AES_GCM_EN
/** \brief Perform a Galois Field Multiply (GFM) operation.
 *
 * \param[in]   device  Device context pointer
 * \param[in]   h       First input value (16 bytes).
 * \param[in]   input   Second input value (16 bytes).
 * \param[out]  output  GFM result is returned here (16 bytes).
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_aes_gfm(ATCADevice device, const uint8_t* h, const uint8_t* input, uint8_t* output)
{
    ATCAPacket * packet = NULL;
    ATCA_STATUS status;

    do
    {
        if ((NULL == device) || (NULL == input) || (NULL == output))
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

        (void)memset(packet, 0x00, sizeof(ATCAPacket));

        // build a AES-GFM command
        packet->param1 = AES_MODE_GFM;

        // KeyID is ignored for GFM mode
        packet->param2 = 0x0000;

        (void)memcpy(&packet->data[0], h, AES_DATA_SIZE);
        (void)memcpy(&packet->data[0] + AES_DATA_SIZE, input, AES_DATA_SIZE);

        if (ATCA_SUCCESS != (status = ATCA_TRACE(atAES(atcab_get_device_type_ext(device), packet), "atAES - failed")))
        {
            break;
        }

        if (ATCA_SUCCESS != (status = ATCA_TRACE(atca_execute_command(packet, device), "execution failed")))
        {
            break;
        }

        if (packet->data[ATCA_COUNT_IDX] >= (3u + AES_DATA_SIZE))
        {
            // The AES command return a 16 byte data.
            (void)memcpy(output, &packet->data[ATCA_RSP_DATA_IDX], AES_DATA_SIZE);
        }

    } while (false);

    calib_packet_free(packet);
    return status;
}
#endif   /* CALIB_AES_MODE_ENCODING  */
