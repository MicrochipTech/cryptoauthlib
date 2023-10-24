/**
 * \file
 * \brief CryptoAuthLib Basic API methods for SelfTest command.
 *
 * The SelfTest command performs a test of one or more of the cryptographic
 * engines within the device.
 *
 * \note List of devices that support this command - ATECC608A/B. Refer to
 *       device datasheet for full details.
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

#if CALIB_SELFTEST_EN

#if (CA_MAX_PACKET_SIZE < ATCA_CMD_SIZE_MIN)
#error "Selftest command packet cannot be accommodated inside the maximum packet size provided"
#endif

/** \brief Executes the SelfTest command, which performs a test of one or more
 *          of the cryptographic engines within the ATECC608 chip.
 *
 *  \param[in]  device  Device context pointer
 *  \param[in]  mode    Functions to test. Can be a bit field combining any
 *                      of the following: SELFTEST_MODE_RNG,
 *                      SELFTEST_MODE_ECDSA_VERIFY, SELFTEST_MODE_ECDSA_SIGN,
 *                      SELFTEST_MODE_ECDH, SELFTEST_MODE_AES,
 *                      SELFTEST_MODE_SHA, SELFTEST_MODE_ALL.
 *  \param[in]  param2  Currently unused, should be 0.
 *  \param[out] result  Results are returned here as a bit field.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_selftest(ATCADevice device, uint8_t mode, uint16_t param2, uint8_t* result)
{
    ATCAPacket packet;
    ATCA_STATUS status = ATCA_GEN_FAIL;
    uint8_t response = 0;

    do
    {
        if (device == NULL)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
            break;
        }

        // build a SelfTest command
        packet.param1 = mode;
        packet.param2 = param2;

        if ((status = atSelfTest(atcab_get_device_type_ext(device), &packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atSelfTest - failed");
            break;
        }

        status = atca_execute_command(&packet, device);

        // This command is a little awkward, because it returns its status as
        // a single byte, which can be hard to differentiate from an actual
        // error code.

        response = packet.data[ATCA_RSP_DATA_IDX];

        if ((response & (mode == 0u ? 1u : 0u)) != 0u)
        {
            // The response has bits set outside of the bit field requested by
            // the mode. This indicates an actual error rather than a self test
            // failure.
            return status; // Return the translated status.
        }
        else
        {
            // Here, we have the possibility of ambiguous results, where some
            // error codes can't be differentiated from self test failures.
            // We assume self-test failures.
            if (NULL != result)
            {
                *result = response;
            }

            // Self tests might have failed, but we returned success because
            // the results are returned in result.
            return ATCA_SUCCESS;
        }
    }
    while (false);

    return status;
}
#endif /* CALIB_SELFTEST_EN */
