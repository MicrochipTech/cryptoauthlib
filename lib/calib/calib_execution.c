/**
 * \file
 * \brief Implements an execution handler that executes a given command on a
 *        device and returns the results.
 *
 * This implementation wraps Polling and No polling (simple wait) schemes into
 * a single method and use it across the library. Polling is used by default,
 * however, by defining the ATCA_NO_POLL symbol the code will instead wait an
 * estimated max execution time before requesting the result.
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


#if defined(ATCA_NO_POLL) && defined(ATCA_ATECC608_SUPPORT) && !defined(ATCA_ATECC608A_SUPPORT)
#warning "ATECC608B supports only polling mode, if you are using an ATECC608A specify ATCA_ATECC608A_SUPPORT manually"
#endif


#ifdef ATCA_NO_POLL
// *INDENT-OFF* - Preserve time formatting from the code formatter
/*Execution times for ATSHA204A supported commands...*/
static const device_execution_time_t device_execution_time_204[] = {
    { ATCA_CHECKMAC,     38},
    { ATCA_DERIVE_KEY,   62},
    { ATCA_GENDIG,       43},
    { ATCA_HMAC,         69},
    { ATCA_INFO,         2},
    { ATCA_LOCK,         24},
    { ATCA_MAC,          35},
    { ATCA_NONCE,        60},
    { ATCA_PAUSE,        2},
    { ATCA_RANDOM,       50},
    { ATCA_READ,         5},
    { ATCA_SHA,          22},
    { ATCA_UPDATE_EXTRA, 12},
    { ATCA_WRITE,        42}
};

/*Execution times for ATSHA206A supported commands...*/
static const device_execution_time_t device_execution_time_206[] = {
    { ATCA_DERIVE_KEY,   62},
    { ATCA_INFO,         2},
    { ATCA_MAC,          35},
    { ATCA_READ,         5},
    { ATCA_WRITE,        42}
};

/*Execution times for ATECC108A supported commands...*/
static const device_execution_time_t device_execution_time_108[] = {
    { ATCA_CHECKMAC,     13},
    { ATCA_COUNTER,      20},
    { ATCA_DERIVE_KEY,   50},
    { ATCA_GENDIG,       11},
    { ATCA_GENKEY,       115},
    { ATCA_HMAC,         23},
    { ATCA_INFO,         2},
    { ATCA_LOCK,         32},
    { ATCA_MAC,          14},
    { ATCA_NONCE,        29},
    { ATCA_PAUSE,        3},
    { ATCA_PRIVWRITE,    48},
    { ATCA_RANDOM,       23},
    { ATCA_READ,         5},
    { ATCA_SHA,          9},
    { ATCA_SIGN,         60},
    { ATCA_UPDATE_EXTRA, 10},
    { ATCA_VERIFY,       72},
    { ATCA_WRITE,        26}
};

/*Execution times for ATECC508A supported commands...*/
static const device_execution_time_t device_execution_time_508[] = {
    { ATCA_CHECKMAC,     13},
    { ATCA_COUNTER,      20},
    { ATCA_DERIVE_KEY,   50},
    { ATCA_ECDH,         58},
    { ATCA_GENDIG,       11},
    { ATCA_GENKEY,       115},
    { ATCA_HMAC,         23},
    { ATCA_INFO,         2},
    { ATCA_LOCK,         32},
    { ATCA_MAC,          14},
    { ATCA_NONCE,        29},
    { ATCA_PAUSE,        3},
    { ATCA_PRIVWRITE,    48},
    { ATCA_RANDOM,       23},
    { ATCA_READ,         5},
    { ATCA_SHA,          9},
    { ATCA_SIGN,         60},
    { ATCA_UPDATE_EXTRA, 10},
    { ATCA_VERIFY,       72},
    { ATCA_WRITE,        26}
};

/*Execution times for ATECC608-M0 supported commands...*/
static const device_execution_time_t device_execution_time_608_m0[] = {
    { ATCA_AES,          27},
    { ATCA_CHECKMAC,     40},
    { ATCA_COUNTER,      25},
    { ATCA_DERIVE_KEY,   50},
    { ATCA_ECDH,         75},
    { ATCA_GENDIG,       25},
    { ATCA_GENKEY,       115},
    { ATCA_INFO,         5},
    { ATCA_KDF,          165},
    { ATCA_LOCK,         35},
    { ATCA_MAC,          55},
    { ATCA_NONCE,        20},
    { ATCA_PRIVWRITE,    50},
    { ATCA_RANDOM,       23},
    { ATCA_READ,         5},
    { ATCA_SECUREBOOT,   80},
    { ATCA_SELFTEST,     250},
    { ATCA_SHA,          36},
    { ATCA_SIGN,         115},
    { ATCA_UPDATE_EXTRA, 10},
    { ATCA_VERIFY,       105},
    { ATCA_WRITE,        45}
};

/*Execution times for ATECC608-M1 supported commands...*/
static const device_execution_time_t device_execution_time_608_m1[] = {
    { ATCA_AES,          27},
    { ATCA_CHECKMAC,     40},
    { ATCA_COUNTER,      25},
    { ATCA_DERIVE_KEY,   50},
    { ATCA_ECDH,         172},
    { ATCA_GENDIG,       35},
    { ATCA_GENKEY,       215},
    { ATCA_INFO,         5},
    { ATCA_KDF,          165},
    { ATCA_LOCK,         35},
    { ATCA_MAC,          55},
    { ATCA_NONCE,        20},
    { ATCA_PRIVWRITE,    50},
    { ATCA_RANDOM,       23},
    { ATCA_READ,         5},
    { ATCA_SECUREBOOT,   160},
    { ATCA_SELFTEST,     625},
    { ATCA_SHA,          42},
    { ATCA_SIGN,         220},
    { ATCA_UPDATE_EXTRA, 10},
    { ATCA_VERIFY,       295},
    { ATCA_WRITE,        45}
};

/*Execution times for ATECC608-M2 supported commands...*/
static const device_execution_time_t device_execution_time_608_m2[] = {
    { ATCA_AES,          27},
    { ATCA_CHECKMAC,     40},
    { ATCA_COUNTER,      25},
    { ATCA_DERIVE_KEY,   50},
    { ATCA_ECDH,         531},
    { ATCA_GENDIG,       35},
    { ATCA_GENKEY,       653},
    { ATCA_INFO,         5},
    { ATCA_KDF,          165},
    { ATCA_LOCK,         35},
    { ATCA_MAC,          55},
    { ATCA_NONCE,        20},
    { ATCA_PRIVWRITE,    50},
    { ATCA_RANDOM,       23},
    { ATCA_READ,         5},
    { ATCA_SECUREBOOT,   480},
    { ATCA_SELFTEST,     2324},
    { ATCA_SHA,          75},
    { ATCA_SIGN,         665},
    { ATCA_UPDATE_EXTRA, 10},
    { ATCA_VERIFY,       1085},
    { ATCA_WRITE,        45}
};
#endif

/*Execution times for ECC204 supported commands...*/
static const device_execution_time_t device_execution_time_ecc204[] = {
    { ATCA_COUNTER,      20},
    { ATCA_DELETE,       200},
    { ATCA_GENKEY,       500},
    { ATCA_INFO,         20},
    { ATCA_LOCK,         80},
    { ATCA_NONCE,        20},
    { ATCA_READ,         40},
    { ATCA_SELFTEST,     600},
    { ATCA_SHA,          80},
    { ATCA_SIGN,         500},
    { ATCA_WRITE,        80}
};

/*Execution times for SHA10x supported commands...*/
static const device_execution_time_t device_execution_time_sha10x[] = {
    { ATCA_CHECKMAC,     100},
    { ATCA_COUNTER,      20},
    { ATCA_DELETE,       200},
    { ATCA_GENDIG,       70},
    { ATCA_INFO,         20},
    { ATCA_LOCK,         80},
    { ATCA_MAC,          120},
    { ATCA_NONCE,        20},
    { ATCA_READ,         40},
    { ATCA_SELFTEST,     600},
    { ATCA_SHA,          80},
    { ATCA_WRITE,        80}
};
// *INDENT-ON*

/** \brief return the typical execution time for the given command
 *  \param[in] opcode  Opcode value of the command
 *  \param[in] ca_cmd  Command object for which the execution times are associated
 *  \return ATCA_SUCCESS
 */
ATCA_STATUS calib_get_execution_time(uint8_t opcode, ATCADevice device)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    const device_execution_time_t *execution_times;
    uint8_t i, no_of_commands;


    switch (device->mIface.mIfaceCFG->devtype)
    {
#ifdef ATCA_NO_POLL
    case ATSHA204A:
        execution_times = device_execution_time_204;
        no_of_commands = sizeof(device_execution_time_204) / sizeof(device_execution_time_t);
        break;

    case ATSHA206A:
        execution_times = device_execution_time_206;
        no_of_commands = sizeof(device_execution_time_206) / sizeof(device_execution_time_t);
        break;

    case ATECC108A:
        execution_times = device_execution_time_108;
        no_of_commands = sizeof(device_execution_time_108) / sizeof(device_execution_time_t);
        break;

    case ATECC508A:
        execution_times = device_execution_time_508;
        no_of_commands = sizeof(device_execution_time_508) / sizeof(device_execution_time_t);
        break;

    case ATECC608:
        if (device->clock_divider == ATCA_CHIPMODE_CLOCK_DIV_M1)
        {
            execution_times = device_execution_time_608_m1;
            no_of_commands = sizeof(device_execution_time_608_m1) / sizeof(device_execution_time_t);
        }
        else if (device->clock_divider == ATCA_CHIPMODE_CLOCK_DIV_M2)
        {
            execution_times = device_execution_time_608_m2;
            no_of_commands = sizeof(device_execution_time_608_m2) / sizeof(device_execution_time_t);
        }
        else
        {
            // Assume default M0 clock divider
            execution_times = device_execution_time_608_m0;
            no_of_commands = sizeof(device_execution_time_608_m0) / sizeof(device_execution_time_t);
        }
        break;
#endif

    case TA010:
    /* fallthrough */
    case ECC204:
        execution_times = device_execution_time_ecc204;
        no_of_commands = (uint8_t)(sizeof(device_execution_time_ecc204) / sizeof(device_execution_time_t));
        break;

    case SHA104:
    /* fallthrough */
    case SHA105:
        execution_times = device_execution_time_sha10x;
        no_of_commands = (uint8_t)(sizeof(device_execution_time_sha10x) / sizeof(device_execution_time_t));
        break;

    default:
        no_of_commands = 0;
        execution_times = NULL;
        break;
    }

    device->execution_time_msec = ATCA_UNSUPPORTED_CMD;

    for (i = 0; i < no_of_commands; i++)
    {
        if (execution_times[i].opcode == opcode)
        {
            device->execution_time_msec = execution_times[i].execution_time_msec;
            break;
        }
    }

    if (device->execution_time_msec == ATCA_UNSUPPORTED_CMD)
    {
        status = ATCA_BAD_OPCODE;
    }

    return status;
}

ATCA_STATUS calib_execute_send(ATCADevice device, uint8_t device_address, uint8_t* txdata, uint16_t txlength)
{
    ATCA_STATUS status = ATCA_COMM_FAIL;

    if ((NULL == txdata) || (0u == txlength))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer encountered");
    }

#ifdef ATCA_HAL_LEGACY_API
    ((void)device_address);
    status = atsend(&device->mIface, 0xFF, (uint8_t*)txdata, (int)txlength - 1);
#else
    if (atca_iface_is_kit(&device->mIface))
    {
        status = atsend(&device->mIface, 0xFF, (uint8_t*)&txdata[1], (int)txlength - 1);
    }
    else
    {
        status = atcontrol(&device->mIface, (uint8_t)ATCA_HAL_CONTROL_SELECT, NULL, 0);
        if (ATCA_UNIMPLEMENTED == status || ATCA_SUCCESS == status)
        {
            /* Send the command packet to the device */
            status = atsend(&device->mIface, device_address, (uint8_t*)txdata, (int)txlength);
        }
        (void)atcontrol(&device->mIface, (uint8_t)ATCA_HAL_CONTROL_DESELECT, NULL, 0);
    }
#endif

    return status;
}


ATCA_STATUS calib_execute_receive(ATCADevice device, uint8_t device_address, uint8_t* rxdata, uint16_t* rxlength)
{
    ATCA_STATUS status = ATCA_COMM_FAIL;

    if ((NULL == rxlength) || (NULL == rxdata))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer encountered");
    }

#ifdef ATCA_HAL_LEGACY_API
    ((void)device_address);
    status = atreceive(&device->mIface, 0, rxdata, rxlength);
#else
    uint16_t read_length = 1;
    uint8_t word_address;

    if (atca_iface_is_kit(&device->mIface))
    {
        status = atreceive(&device->mIface, 0, rxdata, rxlength);
    }
    else
    {
        do
        {
            status = atcontrol(&device->mIface, (uint8_t)ATCA_HAL_CONTROL_SELECT, NULL, 0);
            if (ATCA_UNIMPLEMENTED != status && ATCA_SUCCESS != status)
            {
                break;
            }

            /*Send Word address to device...*/
            if (ATCA_SWI_IFACE == device->mIface.mIfaceCFG->iface_type)
            {
                word_address = CALIB_SWI_FLAG_TX;
            }
            else
            {
                word_address = 0;
            }

            // Skip word address send for ECC204 device
            if (!atcab_is_ca2_device(device->mIface.mIfaceCFG->devtype))
            {
                if (ATCA_SUCCESS != (status = atsend(&device->mIface, device_address, &word_address, (int)sizeof(word_address))))
                {
                    break;
                }
            }

            /* Read length bytes to know number of bytes to read */
            status = atreceive(&device->mIface, device_address, rxdata, &read_length);
            if (ATCA_SUCCESS != status)
            {
                (void)ATCA_TRACE(status, "atreceive - failed");
                break;
            }

            /*Calculate bytes to read based on device response*/
            read_length = rxdata[0];

            if (read_length > *rxlength)
            {
                status = ATCA_TRACE(ATCA_SMALL_BUFFER, "rxdata is small buffer");
                break;
            }

            if (read_length < 4u)
            {
                status = ATCA_TRACE(ATCA_RX_FAIL, "packet size is invalid");
                break;
            }

            /* Read given length bytes from device */
            read_length -= 1u;

            status = atreceive(&device->mIface, device_address, &rxdata[1], &read_length);

            if (ATCA_SUCCESS != status)
            {
                status = ATCA_TRACE(status, "atreceive - failed");
                break;
            }

            read_length += 1u;

            *rxlength = read_length;
        }
        while (false);

        (void)atcontrol(&device->mIface, (uint8_t)ATCA_HAL_CONTROL_DESELECT, NULL, 0);
    }
#endif

    return status;
}

/** \brief Wakes up device, sends the packet, waits for command completion,
 *         receives response, and puts the device into the idle state.
 *
 * \param[in,out] packet  As input, the packet to be sent. As output, the
 *                       data buffer in the packet structure will contain the
 *                       response.
 * \param[in]    device  CryptoAuthentication device to send the command to.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_execute_command(ATCAPacket* packet, ATCADevice device)
{
    ATCA_STATUS status;
    uint32_t execution_or_wait_time;
    uint32_t max_delay_count;
    uint16_t rxsize;
    uint8_t device_address = atcab_get_device_address(device);
    int32_t retries = 1;

    do
    {
#ifdef ATCA_NO_POLL
        if ((status = calib_get_execution_time(packet->opcode, device)) != ATCA_SUCCESS)
        {
            return status;
        }
        execution_or_wait_time = device->execution_time_msec;
        max_delay_count = 0;
#else
        execution_or_wait_time = ATCA_POLLING_INIT_TIME_MSEC;
        max_delay_count = ATCA_POLLING_MAX_TIME_MSEC / ATCA_POLLING_FREQUENCY_TIME_MSEC;

    #if ATCA_CA2_SUPPORT
        if ((ATCA_SWI_GPIO_IFACE == device->mIface.mIfaceCFG->iface_type) && (atcab_is_ca2_device(device->mIface.mIfaceCFG->devtype)))
        {
            if ((status = calib_get_execution_time(packet->opcode, device)) != ATCA_SUCCESS)
            {
                return status;
            }
            execution_or_wait_time = device->execution_time_msec;
            max_delay_count = 0;
        }
    #endif
#endif
        retries = atca_iface_get_retries(&device->mIface);
        do
        {
            if ((uint8_t)ATCA_DEVICE_STATE_ACTIVE != device->device_state)
            {
                if (ATCA_SUCCESS == (status = calib_wakeup(device)))
                {
                    device->device_state = (uint8_t)ATCA_DEVICE_STATE_ACTIVE;
                }
            }

            /* Send the command packet to the device */
            if ((ATCA_I2C_IFACE == device->mIface.mIfaceCFG->iface_type) || (ATCA_CUSTOM_IFACE == device->mIface.mIfaceCFG->iface_type))
            {
                packet->reserved = 0x03;
            }
            if (ATCA_SWI_IFACE == device->mIface.mIfaceCFG->iface_type)
            {
                packet->reserved = CALIB_SWI_FLAG_CMD;
            }
    #if ATCA_CA2_SUPPORT
            if ((ATCA_SWI_GPIO_IFACE == device->mIface.mIfaceCFG->iface_type) && (atcab_is_ca2_device(device->mIface.mIfaceCFG->devtype)))
            {
                packet->reserved = 0x03;
            }
    #endif
            if (ATCA_RX_NO_RESPONSE == (status = calib_execute_send(device, device_address, (uint8_t*)packet, (uint16_t)packet->txsize + 1u)))
            {
                device->device_state = (uint8_t)ATCA_DEVICE_STATE_UNKNOWN;
            }
            else
            {
                if ((uint8_t)ATCA_DEVICE_STATE_ACTIVE != device->device_state)
                {
                    device->device_state = (uint8_t)ATCA_DEVICE_STATE_ACTIVE;
                }
                retries = 0;
            }

        }
        /* coverity[cert_int32_c_violation:FALSE]  No overflow possible */
        while (0 < retries--);

        if (ATCA_SUCCESS != status)
        {
            break;
        }

        // Delay for execution time or initial wait before polling
        atca_delay_ms(execution_or_wait_time);

        do
        {
            (void)memset(packet->data, 0, sizeof(packet->data));
            // receive the response
            rxsize = (uint16_t)sizeof(packet->data);

            if (ATCA_SUCCESS == (status = calib_execute_receive(device, device_address, packet->data, &rxsize)))
            {
                break;
            }

#ifndef ATCA_NO_POLL
            // delay for polling frequency time
            atca_delay_ms(ATCA_POLLING_FREQUENCY_TIME_MSEC);
#endif
        }
        /* coverity[cert_int30_c_violation:FALSE]  No overflow possible */
        while (max_delay_count-- > 0u);

        if (status != ATCA_SUCCESS)
        {
            break;
        }

        // Check response size
        if (rxsize < 4u)
        {
            if (rxsize > 0u)
            {
                status = ATCA_RX_FAIL;
            }
            else
            {
                status = ATCA_RX_NO_RESPONSE;
            }
            break;
        }

        /* coverity[misra_c_2012_directive_4_14_violation:FALSE] Packet data is handled properly */
        if ((status = atCheckCrc(packet->data)) != ATCA_SUCCESS)
        {
            break;
        }

        if ((status = isATCAError(packet->data)) != ATCA_SUCCESS)
        {
            break;
        }
    }
    while (false);

    // Skip Idle for ECC204 device
    if (!atcab_is_ca2_device(device->mIface.mIfaceCFG->devtype))
    {
        (void)calib_idle(device);
        device->device_state = (uint8_t)ATCA_DEVICE_STATE_IDLE;
    }

    return status;
}
