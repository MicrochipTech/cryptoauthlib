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
    char uart_file[20];
    int  fd_uart;
    int  ref_ct;
} atca_uart_host_t;

/**
 * \brief Convert an numerical value for baud rate into the posix/linux values
 * \return baudrate macro value
 */
static speed_t hal_uart_convert_baudrate(uint32_t baudrate)
{
    switch (baudrate)
    {
    case 0:
        return B0;
    case 4800:
        return B4800;
    case 9600:
        return B9600;
    case 115200:
        return B115200;
    case 230400:
        return B230400;
    default:
        return B115200;
    }
}

/**
 * \brief Convert integer wordsize into posix/linux flags
 * \return flag value
 */
static inline tcflag_t hal_uart_convert_wordsize(uint8_t wordsize)
{
    switch (wordsize)
    {
    case 5:
        return CS5;
    case 6:
        return CS6;
    case 7:
        return CS7;
    default:
        return CS8;
    }
}

/**
 * \brief Set baudrate default is 115200.
 *
 * \param[in] baudrate  contain new baudrate
 *
 * \return true on success, otherwise false.
 */
static ATCA_STATUS hal_uart_set_baudrate(ATCAIface iface, uint32_t baudrate)
{
    atca_uart_host_t * hal_data = (atca_uart_host_t*)atgetifacehaldat(iface);

    if (hal_data && hal_data->fd_uart)
    {
        struct termios tty;
        speed_t rate;

        /* Get existing device attributes */
        tcgetattr(hal_data->fd_uart, &tty);

        rate = hal_uart_convert_baudrate(baudrate);

        cfsetispeed(&tty, rate);
        cfsetospeed(&tty, rate);

        /* Update settings */
        tcsetattr(hal_data->fd_uart, TCSANOW, &tty);
    }
    return ATCA_SUCCESS;
}

/** \brief Open and configure serial COM Uart
 * \param[out] fd  resulting file descriptor
 *
 * \return ATCA_SUCCESS on success, else an error code
 */
static ATCA_STATUS hal_uart_open_file(atca_uart_host_t * hal_data, ATCAIfaceCfg *cfg)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (hal_data)
    {
        hal_data->fd_uart = open(hal_data->uart_file, O_RDWR | O_NOCTTY);

        if (0 < hal_data->fd_uart)
        {
            struct termios tty;
            speed_t rate;

            /* Get existing device attributes */
            tcgetattr(hal_data->fd_uart, &tty);

            /* Raw Mode (non-canonical, no echo, etc) */
            tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

            /* No flow control */
            tty.c_iflag &= ~(IXON | IXOFF | IXANY);

            /* No output translation */
            tty.c_oflag &= ~OPOST;

            /* Enable read timeout */
            tty.c_cc[VTIME] = 5;

            /* Convert baudrate to posix/linux format */
            rate = hal_uart_convert_baudrate(cfg->atcauart.baud);
            cfsetispeed(&tty, rate);
            cfsetospeed(&tty, rate);

            /* set number of stopbits */
            if (1 < cfg->atcauart.stopbits)
            {
                /* Two stop bits */
                tty.c_cflag |= CSTOPB;
            }
            else
            {
                /* One Stop Bit */
                tty.c_cflag &= ~CSTOPB;
            }

            /* Set the transmission word size */
            tty.c_cflag &= ~CSIZE;
            tty.c_cflag |= hal_uart_convert_wordsize(cfg->atcauart.wordsize);

            if (0 == cfg->atcauart.parity)
            {
                /* Set Even Parity */
                tty.c_cflag |= PARENB;
                tty.c_cflag &= ~PARODD;
            }
            else if (1 == cfg->atcauart.parity)
            {
                /* Set Odd Parity */
                tty.c_cflag |= (PARENB | PARODD);
            }
            else
            {
                /* Disable Parity */
                tty.c_cflag &= ~PARENB;
            }

            /* Configure the port with the configured settings immediately */
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

                iface->hal_data = hal_data;

                if (ATCA_SUCCESS == (status = hal_uart_open_file(hal_data, cfg)))
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
        switch (option)
        {
        case ATCA_HAL_CHANGE_BAUD:
            return hal_uart_set_baudrate(iface, *(uint32_t*)param);
        case ATCA_HAL_FLUSH_BUFFER:
            /* Using non-canonical mode so there should be no buffering */
            return ATCA_SUCCESS;
        case ATCA_HAL_CONTROL_SELECT:
        /* fallthrough */
        case ATCA_HAL_CONTROL_DESELECT:
            return ATCA_SUCCESS;
        default:
            return ATCA_UNIMPLEMENTED;
        }
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
