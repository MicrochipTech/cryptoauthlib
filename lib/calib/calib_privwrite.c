/**
 * \file
 * \brief CryptoAuthLib Basic API methods for PrivWrite command.
 *
 * The PrivWrite command is used to write externally generated ECC private keys
 * into the device.
 *
 * \note List of devices that support this command - ATECC108A, ATECC508A, and
 *       ATECC608A/B. There are differences in the modes that they support. Refer
 *       to device datasheets for full details.
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

#if CALIB_PRIVWRITE_EN

#include "host/atca_host.h"

#if (CA_MAX_PACKET_SIZE < PRIVWRITE_COUNT)
#error "PrivWrite command packet cannot be accommodated inside the maximum packet size provided"
#endif

/** \brief Executes PrivWrite command, to write externally generated ECC
 *          private keys into the device.
 *
 *  \param[in] device        Device context pointer
 *  \param[in] key_id        Slot to write the external private key into.
 *  \param[in] priv_key      External private key (36 bytes) to be written.
 *                           The first 4 bytes should be zero for P256 curve.
 *  \param[in] write_key_id  Write key slot. Ignored if write_key is NULL.
 *  \param[in] write_key     Write key (32 bytes). If NULL, perform an
 *                           unencrypted PrivWrite, which is only available when
 *                           the data zone is unlocked.
 *  \param[in]  num_in       20 byte host nonce to inject into Nonce calculation
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
#if defined(ATCA_USE_CONSTANT_HOST_NONCE)
ATCA_STATUS calib_priv_write(ATCADevice device, uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32])
{
    uint8_t num_in[NONCE_NUMIN_SIZE] = { 0 };

#else
ATCA_STATUS calib_priv_write(ATCADevice device, uint16_t key_id, const uint8_t priv_key[36], uint16_t write_key_id, const uint8_t write_key[32], const uint8_t num_in[NONCE_NUMIN_SIZE])
{
#endif
    ATCAPacket packet;
    ATCA_STATUS status = ATCA_GEN_FAIL;
    atca_nonce_in_out_t nonce_params;
    atca_gen_dig_in_out_t gen_dig_param;
    atca_write_mac_in_out_t host_mac_param;
    atca_temp_key_t temp_key;
    uint8_t serial_num[32]; // Buffer is larger than the 9 bytes required to make reads easier
    uint8_t rand_out[RANDOM_NUM_SIZE] = { 0 };
    uint8_t cipher_text[36] = { 0 };
    uint8_t host_mac[MAC_SIZE] = { 0 };
    uint8_t other_data[4] = { 0 };

    if ((device == NULL) || (priv_key == NULL) || (key_id > 15u))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Either NULL pointer or invalid slot received");
    }

    do
    {
        if (write_key == NULL)
        {
            // Caller requested an unencrypted PrivWrite, which is only allowed when the data zone is unlocked
            // build an PrivWrite command
            packet.param1 = 0x00;                           // Mode is unencrypted write
            packet.param2 = key_id;                         // Key ID
            (void)memcpy(&packet.data[0], priv_key, 36);    // Private key
            (void)memset(&packet.data[36], 0, 32);          // MAC (ignored for unencrypted write)
        }
        else
        {
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
                (void)ATCA_TRACE(status, "calib_nonce_rand - failed");
                break;
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
                (void)ATCA_TRACE(status, "atcah_nonce - failed");
                break;
            }

            // Supply OtherData so GenDig behavior is the same for keys with SlotConfig.NoMac set
            other_data[0] = ATCA_GENDIG;
            other_data[1] = GENDIG_ZONE_DATA;
            other_data[2] = (uint8_t)(write_key_id & 0xFFu);
            other_data[3] = (uint8_t)(write_key_id >> 8u);

            // Send the GenDig command
            if ((status = calib_gendig(device, GENDIG_ZONE_DATA, write_key_id, other_data, (uint8_t)sizeof(other_data))) != ATCA_SUCCESS)
            {
                (void)ATCA_TRACE(status, "calib_gendig - failed");
                break;
            }

            // Calculate Tempkey
            // NoMac bit isn't being considered here on purpose to remove having to read SlotConfig.
            // OtherData is built to get the same result regardless of the NoMac bit.
            (void)memset(&gen_dig_param, 0, sizeof(gen_dig_param));
            gen_dig_param.zone = GENDIG_ZONE_DATA;
            gen_dig_param.sn = serial_num;
            gen_dig_param.key_id = write_key_id;
            gen_dig_param.is_key_nomac = false;
            gen_dig_param.stored_value = write_key;
            gen_dig_param.other_data = other_data;
            gen_dig_param.temp_key = &temp_key;
            if ((status = atcah_gen_dig(&gen_dig_param)) != ATCA_SUCCESS)
            {
                (void)ATCA_TRACE(status, "atcah_gen_dig - failed");
                break;
            }

            // Calculate Auth MAC and cipher text
            (void)memset(&host_mac_param, 0, sizeof(host_mac_param));
            host_mac_param.zone = PRIVWRITE_MODE_ENCRYPT;
            host_mac_param.key_id = key_id;
            host_mac_param.sn = serial_num;
            host_mac_param.input_data = &priv_key[0];
            host_mac_param.encrypted_data = cipher_text;
            host_mac_param.auth_mac = host_mac;
            host_mac_param.temp_key = &temp_key;
            if ((status = atcah_privwrite_auth_mac(&host_mac_param)) != ATCA_SUCCESS)
            {
                (void)ATCA_TRACE(status, "atcah_privwrite_auth_mac - failed");
                break;
            }

            // build a write command for encrypted writes
            packet.param1 = PRIVWRITE_MODE_ENCRYPT;            // Mode is encrypted write
            packet.param2 = key_id;                            // Key ID
            (void)memcpy(&packet.data[0], cipher_text, sizeof(cipher_text));
            (void)memcpy(&packet.data[sizeof(cipher_text)], host_mac, sizeof(host_mac));
        }

        if ((status = atPrivWrite(atcab_get_device_type_ext(device), &packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atPrivWrite - failed");
            break;
        }

        if ((status = atca_execute_command(&packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_priv_write - execution failed");
            break;
        }

    }
    while (false);

    return status;
}
#endif  /* CALIB_PRIVWRITE_EN */
