/**
 * \file
 * \brief ATCA Hardware abstraction layer for Windows using UART.
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
#include "atca_hal.h"

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <math.h>
#include <string.h>

typedef struct atca_uart_host_s
{
    char   uart_file[20];
    HANDLE hSerial;
    int    ref_ct;
} atca_uart_host_t;

/** \brief Open and configure serial COM Uart
 *  \param[in,out] hal_data  As Input, structure contain uart config info
 *                           As Output, com port HANDLE value
 *
 * \return ATCA_SUCCESS on success, else an error code
 */
static ATCA_STATUS hal_uart_open_file(ATCAIface iface)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    ATCAIfaceCfg* cfg = atgetifacecfg(iface);
    atca_uart_host_t* hal_data = atgetifacehaldat(iface);

    if ((NULL != hal_data) && (NULL != cfg))
    {
        DCB dcbSerialParams = { 0 };
        COMMTIMEOUTS timeouts = { 0 };

        /* coverity[misra_c_2012_rule_10_1_violation:SUPPRESS] Win32 API */
        /* coverity[misra_c_2012_rule_10_4_violation:SUPPRESS] Win32 API */
        /* coverity[misra_c_2012_rule_11_6_violation:SUPPRESS] Win32 API */
        hal_data->hSerial = CreateFileA(TEXT(hal_data->uart_file),
                                        GENERIC_READ | GENERIC_WRITE,
                                        0,
                                        NULL,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        NULL);

        /* coverity[misra_c_2012_rule_11_6_violation:SUPPRESS] Win32 API */
        /* coverity[cert_int36_c_violation:SUPPRESS] Win32 API */
        if (hal_data->hSerial == INVALID_HANDLE_VALUE)
        {
            return ATCA_COMM_FAIL;
        }

        (void)FlushFileBuffers(hal_data->hSerial);

        (void)SecureZeroMemory(&dcbSerialParams, sizeof(DCB));
        dcbSerialParams.DCBlength = (DWORD)sizeof(DCB);

        if (!GetCommState(hal_data->hSerial, &dcbSerialParams))
        {
            (void)CloseHandle(hal_data->hSerial);
            return ATCA_COMM_FAIL;
        }


        // Set com settings
        switch (ATCA_IFACECFG_VALUE(cfg, atcauart.parity))
        {
        case 0:
            dcbSerialParams.Parity = EVENPARITY;
            break;
        case 1:
            dcbSerialParams.Parity = ODDPARITY;
            break;
        default:
            dcbSerialParams.Parity = NOPARITY;
            break;
        }

        dcbSerialParams.BaudRate = ATCA_IFACECFG_VALUE(cfg, atcauart.baud);     //  baud rate
        dcbSerialParams.ByteSize = ATCA_IFACECFG_VALUE(cfg, atcauart.wordsize); //  data size, xmit and rcv
        dcbSerialParams.StopBits = ATCA_IFACECFG_VALUE(cfg, atcauart.stopbits); //  stop bit
        dcbSerialParams.fDtrControl = DTR_CONTROL_ENABLE;

        if (!SetCommState(hal_data->hSerial, &dcbSerialParams))
        {
            (void)CloseHandle(hal_data->hSerial);
            return ATCA_COMM_FAIL;
        }

        timeouts.ReadIntervalTimeout = 50;
        timeouts.ReadTotalTimeoutConstant = 50;
        timeouts.ReadTotalTimeoutMultiplier = 10;
        timeouts.WriteTotalTimeoutConstant = 50;
        timeouts.WriteTotalTimeoutMultiplier = 10;

        if (!SetCommTimeouts(hal_data->hSerial, &timeouts))
        {
            (void)CloseHandle(hal_data->hSerial);
            return ATCA_COMM_FAIL;
        }

        status = ATCA_SUCCESS;
    }

    return status;
}

/** \brief HAL implementation of UART init
 *
 * this implementation assumes UART SERIAL PORT peripheral has been enabled by user . It only initialize an
 * UART interface using given config.
 *
 *  \param[in] hal pointer to HAL specific data that is maintained by this HAL
 *  \param[in] cfg pointer to HAL specific configuration data that is used to initialize this HAL
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_uart_init(ATCAIface iface, ATCAIfaceCfg *cfg)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != iface) && (NULL != cfg))
    {
        if (NULL == iface->hal_data)
        {
            /* coverity[misra_c_2012_rule_21_3_violation] Appropriate usage in windows */
            atca_uart_host_t * hal_data = malloc(sizeof(atca_uart_host_t));

            if (NULL != hal_data)
            {
                (void)memset(hal_data, 0, sizeof(atca_uart_host_t));

                // Set COM port
                /* coverity[misra_c_2012_rule_21_6_violation] snprintf is approved for formatted string writes to buffers */
                (void)snprintf(hal_data->uart_file, sizeof(hal_data->uart_file) - 1U,
                               "\\\\.\\COM%d", (uint8_t)ATCA_IFACECFG_VALUE(cfg, atcauart.port));


                iface->hal_data = hal_data;

                // open com port file
                if (ATCA_SUCCESS == (status = hal_uart_open_file(iface)))
                {
                    hal_data->ref_ct = 1;
                }
            }
            else
            {
                status = ATCA_ALLOC_FAILURE;
            }
        }
        else
        {
            atca_uart_host_t * hal_data = (atca_uart_host_t*)atgetifacehaldat(iface);

            if (NULL != hal_data)
            {
                hal_data->ref_ct++;
                status = ATCA_SUCCESS;
            }
        }

    }
    return status;
}

/** \brief HAL implementation of UART post init
 * \param[in] iface  instance
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_uart_post_init(ATCAIface iface)
{
    ((void)iface);
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of UART send
 * \param[in] iface           instance
 * \param[in] word_address    transaction type
 * \param[in] txdata          data to be send to device
 * \param[in] txdata          pointer to space to bytes to send
 * \param[in] len  number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_uart_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    (void)word_address;
    ATCA_STATUS status = ATCA_BAD_PARAM;
    DWORD bytes_written = 0;

    if ((NULL != iface) && (NULL != txdata) && (0 < txlength))
    {
        atca_uart_host_t * hal_data = (atca_uart_host_t*)atgetifacehaldat(iface);

        /* coverity[misra_c_2012_rule_11_6_violation:SUPPRESS] Win32 API */
        /* coverity[cert_int36_c_violation:SUPPRESS] Win32 API*/
        if ((NULL != hal_data) && (INVALID_HANDLE_VALUE != hal_data->hSerial))
        {
            if (!WriteFile(hal_data->hSerial, txdata, (DWORD)txlength, &bytes_written, NULL))
            {
                status = ATCA_COMM_FAIL;
            }
            else
            {
                status = ATCA_SUCCESS;
            }
        }

        if (status == ATCA_SUCCESS)
        {
            if ((DWORD)txlength != bytes_written)
            {
                status = ATCA_COMM_FAIL;
            }
        }

        if ((ATCA_SUCCESS != status) && (NULL != hal_data))
        {
            (void)CloseHandle(hal_data->hSerial);
            /* coverity[misra_c_2012_rule_11_6_violation:SUPPRESS] Win32 API */
            /* coverity[cert_int36_c_violation:SUPPRESS] Win32 API */
            hal_data->hSerial = INVALID_HANDLE_VALUE;
        }

    }

    return status;
}

/** \brief HAL implementation of UART receive function
 * \param[in]      iface          Device to interact with.
 * \param[in]      word_address   device transaction type
 * \param[out]     rxdata         Data received will be returned here.
 * \param[in,out]  rxlength       As input, the size of the rxdata buffer.
 *                                As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_uart_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength)
{
    (void)word_address;
    DWORD bytes_read = 0;
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != iface) && (NULL != rxdata) && (NULL != rxlength) && (0U < *rxlength))
    {
        atca_uart_host_t * hal_data = (atca_uart_host_t*)atgetifacehaldat(iface);

        /* coverity[misra_c_2012_rule_11_6_violation:SUPPRESS] Win32 API*/
        /* coverity[cert_int36_c_violation:SUPPRESS] Win32 API */
        if ((NULL != hal_data) && (INVALID_HANDLE_VALUE != hal_data->hSerial))
        {
            if (*rxlength > 1U)
            {
                *rxlength = 1U; // packetsize to read
            }

            if (!ReadFile(hal_data->hSerial, rxdata, *rxlength, &bytes_read, NULL))
            {
                status = ATCA_COMM_FAIL;
            }
            else
            {
                status = ATCA_SUCCESS;
            }
        }

        if (status == ATCA_SUCCESS)
        {
            if (bytes_read > 0U)
            {
                *rxlength = (uint16_t)bytes_read;
            }
            else
            {
                status = ATCA_COMM_FAIL;
            }
        }

        if ((ATCA_SUCCESS != status) && (NULL != hal_data))
        {
            (void)CloseHandle(hal_data->hSerial);
            /* coverity[misra_c_2012_rule_11_6_violation:SUPPRESS] Win32 API */
            /* coverity[cert_int36_c_violation:SUPPRESS] Win32 API*/
            hal_data->hSerial = INVALID_HANDLE_VALUE;
        }

    }

    return status;
}

/** \brief Perform control operations for the UART
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_uart_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)option;
    (void)param;
    (void)paramlen;

    if ((NULL != iface) && (NULL != iface->mIfaceCFG))
    {
        /* This HAL does not support any of the control functions */
        return ATCA_UNIMPLEMENTED;
    }
    return ATCA_BAD_PARAM;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 *
 *  \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_uart_release(void *hal_data)
{
    atca_uart_host_t *hal = (atca_uart_host_t*)hal_data;

    if (NULL != hal)
    {
        (void)CloseHandle(hal->hSerial);
        hal_free(hal);
    }

    return ATCA_SUCCESS;
}
