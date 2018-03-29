/**
 * \file
 * \brief CryptoAuthLib Basic API methods for Random command.
 *
 * The Random command generates a random number for use by the system.
 *
 * \note List of devices that support this command - ATSHA204A, ATECC108A,
 *       ATECC508A, ATECC608A. There are differences in the modes that they
 *       support. Refer to device datasheets for full details.
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
#include "atca_basic.h"
#include "atca_execution.h"

/** \brief Executes Random command, which generates a 32 byte random number
 *          from the CryptoAuth device.
 *
 * \param[out] rand_out  32 bytes of random data is returned here.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcab_random(uint8_t *rand_out)
{
    ATCAPacket packet;
    ATCACommand ca_cmd = _gDevice->mCommands;
    ATCA_STATUS status = ATCA_GEN_FAIL;

    do
    {
        // build an random command
        packet.param1 = RANDOM_SEED_UPDATE;
        packet.param2 = 0x0000;

        if ((status = atRandom(ca_cmd, &packet)) != ATCA_SUCCESS)
        {
            break;
        }

        if ((status = atca_execute_command(&packet, _gDevice)) != ATCA_SUCCESS)
        {
            break;
        }

        if (packet.rxsize < packet.data[ATCA_COUNT_IDX] || packet.data[ATCA_COUNT_IDX] != RANDOM_RSP_SIZE)
        {
            status = ATCA_RX_FAIL;
            break;
        }

        if (rand_out)
        {
            memcpy(rand_out, &packet.data[ATCA_RSP_DATA_IDX], RANDOM_NUM_SIZE);
        }
    }
    while (0);


    return status;
}
