/**
 * \file
 * \brief ATCA Hardware abstraction layer for Linux using UART.
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

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>

typedef struct atca_uart_host_s
{
    char    uart_file[20];
    int     fd_uart;
    int     uart_baud;
    int     uart_wordsize;
    uint8_t uart_parity;
    uint8_t uart_stopbit;
    int     ref_ct;
} atca_uart_host_t;

/** \brief Open and configure serial COM Uart
 * \param[out] fd  resulting file descriptor
 *
 * \return ATCA_SUCCESS on success, else an error code
 */
ATCA_STATUS hal_uart_open_file(atca_uart_host_t * hal_data)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (hal_data)
    {
        struct termios tty;

        hal_data->fd_uart = open(hal_data->uart_file, O_RDWR | O_NOCTTY);

        if (0 < hal_data->fd_uart)
        {
            /* Get existing device attributes */
            tcgetattr(hal_data->fd_uart, &tty);

            /* Raw Mode */
            tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

            /* No flow control */
            tty.c_iflag &= ~(IXON | IXOFF | IXANY);

            /* No output translation */
            tty.c_oflag &= ~OPOST;

            //Enable read timeout
            tty.c_cc[VTIME] = 5;

            cfsetispeed(&tty, hal_data->uart_baud);
            cfsetospeed(&tty, hal_data->uart_baud);

            // set number of stopbits
            if (1 < hal_data->uart_stopbit)
            {
                tty.c_cflag |= CSTOPB;
            }

            // set parity bits
            if (0 == hal_data->uart_parity) // even parity
            {
                tty.c_cflag |= PARENB;
            }
            else if (1 == hal_data->uart_parity) // odd parity
            {
                tty.c_cflag |= PARENB;
                tty.c_cflag |= PARODD;
            }

            if (tcsetattr(hal_data->fd_uart, TCSANOW, &tty))
            {
                close(hal_data->fd_uart);
                return ATCA_COMM_FAIL;
            }

            status = ATCA_SUCCESS;
        }
        else
        {
            status = ATCA_COMM_FAIL;
        }
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

    if (iface && cfg)
    {
        if (!iface->hal_data)
        {
            atca_uart_host_t * hal_data = malloc(sizeof(atca_uart_host_t));
            memset(hal_data, 0, sizeof(atca_uart_host_t));

            if (hal_data)
            {
                if (cfg->cfg_data)
                {
                    (void)snprintf(hal_data->uart_file, sizeof(hal_data->uart_file) - 1,
                                   "%s", (char*)cfg->cfg_data);
                }
                else
                {
                    (void)snprintf(hal_data->uart_file, sizeof(hal_data->uart_file) - 1,
                                   "/dev/ttyS%d", (uint8_t)cfg->atcauart.port);
                }

                // Set linux uart baudrate mask
                switch (cfg->atcauart.baud)
                {
                case 0:      hal_data->uart_baud = B0; break;
                case 4800:   hal_data->uart_baud = B4800; break;
                case 9600:   hal_data->uart_baud = B9600; break;
                case 115200: hal_data->uart_baud = B115200; break;
                default: hal_data->uart_baud = B115200; break;
                }
                // set linux uart character size
                switch (cfg->atcauart.wordsize)
                {
                case 5: hal_data->uart_wordsize = CS5; break;
                case 6: hal_data->uart_wordsize = CS6; break;
                case 7: hal_data->uart_wordsize = CS7; break;
                case 8: hal_data->uart_wordsize = CS8; break;
                default: hal_data->uart_wordsize = CS8; break;
                }

                hal_data->uart_parity = iface->mIfaceCFG->atcauart.parity;
                hal_data->uart_stopbit = iface->mIfaceCFG->atcauart.stopbits;
                iface->hal_data = hal_data;

                if (ATCA_SUCCESS == (status = hal_uart_open_file(hal_data)))
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

            if (hal_data)
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
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_uart_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    (void)word_address;
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (iface && txdata && txlength)
    {
        atca_uart_host_t * hal_data = (atca_uart_host_t*)atgetifacehaldat(iface);

        if (hal_data && (hal_data->fd_uart > 0))
        {
            if (write(hal_data->fd_uart, txdata, txlength) != txlength)
            {
                status = ATCA_COMM_FAIL;
            }
            else
            {
                status = ATCA_SUCCESS;
            }
        }

        if (ATCA_SUCCESS != status)
        {
            close(hal_data->fd_uart);
            hal_data->fd_uart = -1;
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
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (iface && rxdata && rxlength && *rxlength)
    {
        atca_uart_host_t * hal_data = (atca_uart_host_t*)atgetifacehaldat(iface);

        if (hal_data && (hal_data->fd_uart > 0))
        {
            if (*rxlength > 1)
            {
                *rxlength = 1; // packetsize to read
            }

            if (read(hal_data->fd_uart, rxdata, *rxlength) !=  *rxlength)
            {
                status = ATCA_COMM_FAIL;
            }
            else
            {
                status = ATCA_SUCCESS;
            }
        }

        if (ATCA_SUCCESS != status)
        {
            close(hal_data->fd_uart);
            hal_data->fd_uart = -1;
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

    if (iface && iface->mIfaceCFG)
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

    if (hal)
    {
        close(hal->fd_uart);
        free(hal);
    }

    return ATCA_SUCCESS;
}
