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

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "MISRA C-2012 Rule 21.6" "Standard library functions are required for file system access in linux & windows")
#endif

/**
 * \brief Convert an numerical value for baud rate into the posix/linux values
 * \return baudrate macro value
 */
static speed_t hal_uart_convert_baudrate(uint32_t baudrate)
{
    speed_t rv;

    switch (baudrate)
    {
    case 0:
        rv = B0;
        break;
    case 4800:
        rv = B4800;
        break;
    case 9600:
        rv = B9600;
        break;
    case 115200:
        rv = B115200;
        break;
    case 230400:
        rv = B230400;
        break;
    default:
        rv = B115200;
        break;
    }
    return rv;
}

/**
 * \brief Convert integer wordsize into posix/linux flags
 * \return flag value
 */
static tcflag_t hal_uart_convert_wordsize(uint8_t wordsize)
{
    tcflag_t flags;

    switch (wordsize)
    {
    case 5:
        flags = CS5;
        break;
    case 6:
        flags = CS6;
        break;
    case 7:
        flags = CS7;
        break;
    default:
        flags = CS8;
        break;
    }
    return flags;
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

    if ((NULL != hal_data) && (0 < hal_data->fd_uart))
    {
        struct termios tty;
        speed_t rate;

        /* Get existing device attributes */
        (void)tcgetattr(hal_data->fd_uart, &tty);

        rate = hal_uart_convert_baudrate(baudrate);

        (void)cfsetispeed(&tty, rate);
        (void)cfsetospeed(&tty, rate);

        /* Update settings */
        (void)tcsetattr(hal_data->fd_uart, TCSANOW, &tty);
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

    if (NULL != hal_data)
    {
#ifdef __COVERITY__
#pragma coverity compliance block \
        (fp:7 "CERT INT31-C" "Macro usage is correct per POSIX specification") \
        (fp:13 "MISRA C-2012 Rule 10.1" "Macro usage is correct per POSIX specification" ) \
        (fp:13 "MISRA C-2012 Rule 10.4" "Macro usage is correct per POSIX specification" ) \
        (deviate:1 "CERT FIO32-C" "It is the system owner's responsibility ensure configuration provides a valid uart compatible device")
#endif
        hal_data->fd_uart = open(hal_data->uart_file, O_RDWR | O_NOCTTY);

        if (0 < hal_data->fd_uart)
        {
            struct termios tty;
            speed_t rate;
            int flags;

            /* Get existing device attributes */
            (void)tcgetattr(hal_data->fd_uart, &tty);

            /* Raw Mode (non-canonical, no echo, etc) */
            tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

            /* No flow control */
            tty.c_iflag &= ~(IXON | IXOFF | IXANY);

            /* No output translation */
            tty.c_oflag &= ~OPOST;

            /* Enable read timeout */
            tty.c_cc[VTIME] = 5;

            /* Convert baudrate to posix/linux format */
            rate = hal_uart_convert_baudrate(ATCA_IFACECFG_VALUE(cfg, atcauart.baud));
            (void)cfsetispeed(&tty, rate);
            (void)cfsetospeed(&tty, rate);

            /* set number of stopbits */
            if (1 < ATCA_IFACECFG_VALUE(cfg, atcauart.stopbits))
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
            tty.c_cflag |= hal_uart_convert_wordsize(ATCA_IFACECFG_VALUE(cfg, atcauart.wordsize));

            if (0 == ATCA_IFACECFG_VALUE(cfg, atcauart.parity))
            {
                /* Set Even Parity */
                tty.c_cflag |= PARENB;
                tty.c_cflag &= ~PARODD;
            }
            else if (1 == ATCA_IFACECFG_VALUE(cfg, atcauart.parity))
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
            if (0 != tcsetattr(hal_data->fd_uart, TCSANOW, &tty))
            {
                (void)close(hal_data->fd_uart);
                return ATCA_COMM_FAIL;
            }

            flags = TIOCM_DTR;
            if (-1 == ioctl(hal_data->fd_uart, TIOCMBIS, &flags))
            {
                (void)close(hal_data->fd_uart);
                return ATCA_COMM_FAIL;
            }

#ifdef __COVERITY__
#pragma coverity compliance end_block \
            "CERT INT31-C" \
            "MISRA C-2012 Rule 10.1" \
            "MISRA C-2012 Rule 10.4" \
            "CERT FIO32-C"
#endif

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

    if ((NULL != iface) && (NULL != cfg))
    {
        if (NULL == iface->hal_data)
        {
            /* First Access so initialize the hal data structure */

#ifdef __COVERITY__
#pragma coverity compliance block \
            (fp:1 "CERT FIO42-C" "Context is maintained through iface->hal_data so the handle is not leaked") \
            (fp:1 "MISRA C-2012 Rule 22.1" "Context is maintained through iface->hal_data so the handle is not leaked" ) \
            (deviate:1 "MISRA C-2012 Directive 4.12" "Required for the linux environment" ) \
            (deviate:2 "MISRA C-2012 Rule 21.3" "Required for the linux environment" ) \
            (deviate:2 "MISRA C-2012 Rule 21.6" "snprintf is approved for formatted string writes to buffers" )
#endif
            if (NULL != (iface->hal_data = malloc(sizeof(atca_uart_host_t))))
            {
                atca_uart_host_t * hal_data = (atca_uart_host_t*)iface->hal_data;
                (void)memset(iface->hal_data, 0, sizeof(atca_uart_host_t));

                if (NULL != cfg->cfg_data)
                {
                    (void)snprintf(hal_data->uart_file, sizeof(hal_data->uart_file) - 1U,
                                   "%s", (char*)cfg->cfg_data);
                }
                else
                {
                    (void)snprintf(hal_data->uart_file, sizeof(hal_data->uart_file) - 1U,
                                   "/dev/ttyS%d", (uint8_t)ATCA_IFACECFG_VALUE(cfg, atcauart.port));
                }

                if (ATCA_SUCCESS == (status = hal_uart_open_file(hal_data, cfg)))
                {
                    /* Driver is configured - increment the ref count for usage */
                    hal_data->ref_ct = 1;
                }
                else
                {
                    free(iface->hal_data);
                    iface->hal_data = NULL;
                }
            }
            else
            {
                status = ATCA_ALLOC_FAILURE;
            }

#ifdef __COVERITY__
#pragma coverity compliance end_block \
            "CERT FIO42-C" \
            "MISRA C-2012 Rule 22.1" \
            "MISRA C-2012 Directive 4.12" \
            "MISRA C-2012 Rule 21.3" \
            "MISRA C-2012 Rule 21.6"
#endif

        }
        else
        {
            /* Repeated access so increment the access count */
            atca_uart_host_t * hal_data = (atca_uart_host_t*)iface->hal_data;
            hal_data->ref_ct++;
            status = ATCA_SUCCESS;
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

    if ((NULL != iface) && (NULL != txdata) && (0 < txlength))
    {
        atca_uart_host_t * hal_data = (atca_uart_host_t*)atgetifacehaldat(iface);

        if ((NULL != hal_data) && (0 < hal_data->fd_uart))
        {
            if (write(hal_data->fd_uart, txdata, (size_t)txlength) != txlength)
            {
                status = ATCA_COMM_FAIL;
            }
            else
            {
                status = ATCA_SUCCESS;
            }

            if (ATCA_SUCCESS != status)
            {
                (void)close(hal_data->fd_uart);
                hal_data->fd_uart = -1;
            }
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

    if ((NULL != iface) && (NULL != rxdata) && (NULL != rxlength) && (0U < *rxlength))
    {
        atca_uart_host_t * hal_data = (atca_uart_host_t*)atgetifacehaldat(iface);

        if ((NULL != hal_data) && (0 < hal_data->fd_uart))
        {
            if (1U < *rxlength)
            {
                *rxlength = 1U; // packetsize to read
            }

            if (read(hal_data->fd_uart, rxdata, (size_t)*rxlength) !=  (int)*rxlength)
            {
                status = ATCA_COMM_FAIL;
            }
            else
            {
                status = ATCA_SUCCESS;
            }

            if (ATCA_SUCCESS != status)
            {
                (void)close(hal_data->fd_uart);
                hal_data->fd_uart = -1;
            }
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
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != iface) && (NULL != iface->mIfaceCFG))
    {
        switch (option)
        {
        case ATCA_HAL_CHANGE_BAUD:
            status = hal_uart_set_baudrate(iface, *(uint32_t*)param);
            break;
        case ATCA_HAL_FLUSH_BUFFER:
            /* Using non-canonical mode so there should be no buffering */
            status = ATCA_SUCCESS;
            break;
        case ATCA_HAL_CONTROL_SELECT:
        /* fallthrough */
        case ATCA_HAL_CONTROL_DESELECT:
            status = ATCA_SUCCESS;
            break;
        default:
            status = ATCA_UNIMPLEMENTED;
            break;
        }
    }
    return status;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 *
 *  \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_uart_release(void *hal_data)
{
    if (NULL != hal_data)
    {
        atca_uart_host_t *hal = (atca_uart_host_t*)hal_data;
        (void)close(hal->fd_uart);
        /* coverity[misra_c_2012_rule_21_3_violation] Intentional as it is required for the linux environment */
        free(hal);
    }

    return ATCA_SUCCESS;
}

#ifdef __COVERITY__
#pragma coverity compliance end_block "MISRA C-2012 Rule 21.6"
#endif
