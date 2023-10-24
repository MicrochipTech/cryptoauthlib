/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Random command.
 *
 * The Random command generates a random number for use by the system.
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

#if CALIB_RANDOM_EN

#if (CA_MAX_PACKET_SIZE < RANDOM_RSP_SIZE)
#error "Random command packet cannot be accommodated inside the maximum packet size provided"
#endif

/** \brief Executes Random command, which generates a 32 byte random number
 *          from the CryptoAuth device.
 *
 * \param[in]  device    Device context pointer
 * \param[out] rand_out  32 bytes of random data is returned here.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_random(ATCADevice device, uint8_t *rand_out)
{
    ATCAPacket packet;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    do
    {
        if (device == NULL)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
            break;
        }

        // build an random command
        packet.param1 = RANDOM_SEED_UPDATE;
        packet.param2 = 0x0000;

        if ((status = atRandom(atcab_get_device_type_ext(device), &packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atRandom - failed");
            break;
        }

        if ((status = atca_execute_command(&packet, device)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "calib_random - execution failed");
            break;
        }

        if (packet.data[ATCA_COUNT_IDX] != RANDOM_RSP_SIZE)
        {
            status = ATCA_TRACE(ATCA_RX_FAIL, "Unexpected response size");
            break;
        }

        if (NULL != rand_out)
        {
            (void)memcpy(rand_out, &packet.data[ATCA_RSP_DATA_IDX], RANDOM_NUM_SIZE);
        }
    }
    while (false);


    return status;
}
#endif  /* CALIB_RANDOM_EN */
