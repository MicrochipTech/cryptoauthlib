/**/
#include "cryptoauthlib.h"
#include "atca_hal.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

typedef struct atca_spi_host_s
{
    char    spi_file[20];
    int     f_spi;
} atca_spi_host_t;

/** \brief Open and configure the SPI device
 * \param[in]  dev_name  File name in the form /dev/spidevX.Y
 * \param[in]  speed     Clock speed in Hz
 * \param[out] fd        resulting file descriptor
 */
static ATCA_STATUS hal_spi_open_file(const char * dev_name, uint32_t speed, int * fd)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != dev_name) && (NULL != fd))
    {
        status = ATCA_COMM_FAIL;
        do
        {
#ifdef __COVERITY__
#pragma coverity compliance block \
            (fp:12 "MISRA C-2012 Rule 10.1" "Macro usage is correct per POSIX specification" ) \
            (fp:1 "MISRA C-2012 Rule 10.3" "Macro usage is correct per POSIX specification" ) \
            (fp:6 "MISRA C-2012 Rule 10.4" "Macro usage is correct per POSIX specification" ) \
            (fp:3 "MISRA C-2012 Rule 12.2" "Macro usage is correct per POSIX specification" ) \
            (deviate:1 "CERT FIO32-C" "It is the system owner's responsibility ensure configuration provides a valid SPI device")
#endif
            uint8_t mode = SPI_MODE_3;
            uint8_t bits = 8U;

            if (0 >= (*fd = open(dev_name, O_RDWR)))
            {
                break;
            }

            /* Perform Device Configuration */
            if (0 > ioctl(*fd, SPI_IOC_WR_MODE, &mode))
            {
                break;
            }

            if (0 > ioctl(*fd, SPI_IOC_WR_BITS_PER_WORD, &bits))
            {
                break;
            }
            if (0 > ioctl(*fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed))
            {
                break;
            }

#ifdef __COVERITY__
#pragma coverity compliance end_block \
            "MISRA C-2012 Rule 10.1" \
            "MISRA C-2012 Rule 10.3" \
            "MISRA C-2012 Rule 10.4" \
            "MISRA C-2012 Rule 12.2" \
            "CERT FIO32-C"
#endif

            /* Configuration was fully successful */
            status = ATCA_SUCCESS;
        } while (false);
    }

    return status;
}


/** \brief HAL implementation of SPI init
 *
 * this implementation assumes SPI peripheral has been enabled by user . It only initialize an
 * SPI interface using given config.
 *
 *  \param[in] hal pointer to HAL specific data that is maintained by this HAL
 *  \param[in] cfg pointer to HAL specific configuration data that is used to initialize this HAL
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_spi_init(ATCAIface iface, ATCAIfaceCfg *cfg)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != iface) && (NULL != cfg))
    {
        if (NULL == iface->hal_data)
        {
            /* coverity[misra_c_2012_directive_4_12_violation] Intentional as it is required for the linux environment */
            /* coverity[misra_c_2012_rule_21_3_violation] Intentional as it is required for the linux environment */
            if (NULL != (iface->hal_data = malloc(sizeof(atca_spi_host_t))))
            {
                atca_spi_host_t * hal_data = (atca_spi_host_t*)iface->hal_data;

                /* coverity[misra_c_2012_rule_21_6_violation] snprintf is approved for formatted string writes to buffers */
                (void)snprintf(hal_data->spi_file, sizeof(hal_data->spi_file) - 1U,
                               "/dev/spidev%d.%d", (uint8_t)ATCA_IFACECFG_VALUE(cfg, atcaspi.bus),
                               (uint8_t)ATCA_IFACECFG_VALUE(cfg, atcaspi.select_pin));

                status = ATCA_SUCCESS;
            }
            else
            {
                status = ATCA_ALLOC_FAILURE;
            }
        }
        else
        {
            status = ATCA_SUCCESS;
        }

    }
    return status;
}

ATCA_STATUS hal_spi_post_init(ATCAIface iface)
{
    ((void)iface);
    return ATCA_SUCCESS;
}


/** \brief HAL implementation to assert the device chip select
 * \param[in]    iface          Device to interact with.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS hal_spi_select(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    atca_spi_host_t * hal_data = (atca_spi_host_t*)atgetifacehaldat(iface);

    if ((NULL != hal_data) && (NULL != cfg))
    {
        return hal_spi_open_file(hal_data->spi_file,
                                 ATCA_IFACECFG_VALUE(cfg, atcaspi.baud), &hal_data->f_spi);
    }
    else
    {
        return ATCA_BAD_PARAM;
    }
}


/** \brief HAL implementation to deassert the device chip select
 * \param[in]    iface          Device to interact with.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS hal_spi_deselect(ATCAIface iface)
{
    atca_spi_host_t * hal_data = (atca_spi_host_t*)atgetifacehaldat(iface);

    if (NULL != hal_data)
    {
        struct spi_ioc_transfer spi_xfer = { 0 };

        /* coverity[misra_c_2012_rule_10_1_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
        /* coverity[misra_c_2012_rule_10_4_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
        /* coverity[misra_c_2012_rule_12_2_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
        (void)ioctl(hal_data->f_spi, SPI_IOC_MESSAGE(1), &spi_xfer);

        return close(hal_data->f_spi);
    }
    else
    {
        return ATCA_BAD_PARAM;
    }
}


/** \brief HAL implementation of SPI receive function
 * \param[in]    iface          Device to interact with.
 * \param[in]    word_address   device transaction type
 * \param[out]   rxdata         Data received will be returned here.
 * \param[in,out] len           As input, the size of the rxdata buffer.
 *                              As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_spi_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    atca_spi_host_t * hal_data = (atca_spi_host_t*)atgetifacehaldat(iface);

    ((void)word_address);

    if ((NULL != hal_data) && (NULL != rxdata) && (NULL != rxlength))
    {
        struct spi_ioc_transfer spi_xfer = { 0 };
        spi_xfer.rx_buf = (unsigned long)rxdata;
        spi_xfer.len = (unsigned int)*rxlength;
        spi_xfer.cs_change = 1U;

        /* coverity[misra_c_2012_rule_10_1_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
        /* coverity[misra_c_2012_rule_10_4_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
        /* coverity[misra_c_2012_rule_12_2_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
        if (*rxlength == ioctl(hal_data->f_spi, SPI_IOC_MESSAGE(1), &spi_xfer))
        {
            status = ATCA_SUCCESS;
        }
        else
        {
            status = ATCA_COMM_FAIL;
        }
    }
    return status;
}

/** \brief HAL implementation of SPI send
 * \param[in] iface           instance
 * \param[in] word_address    transaction type
 * \param[in] txdata          data to be send to device
 * \param[in] txdata          pointer to space to bytes to send
 * \param[in] len  number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_spi_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    atca_spi_host_t * hal_data = (atca_spi_host_t*)atgetifacehaldat(iface);

    if ((NULL != hal_data))
    {
        struct spi_ioc_transfer spi_xfer = { 0 };
        spi_xfer.tx_buf = (unsigned long)&word_address;
        spi_xfer.len = (unsigned int)sizeof(word_address);
        spi_xfer.cs_change = 1U;

        /* coverity[misra_c_2012_rule_10_1_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
        /* coverity[misra_c_2012_rule_10_4_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
        /* coverity[misra_c_2012_rule_12_2_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
        if (1 == ioctl(hal_data->f_spi, SPI_IOC_MESSAGE(1), &spi_xfer))
        {
            status = ATCA_SUCCESS;
        }
        else
        {
            status = ATCA_COMM_FAIL;
        }

        if ((ATCA_SUCCESS == status) && (NULL != txdata) && (0 < txlength))
        {
            struct spi_ioc_transfer spi_xfer_1 = { 0 };
            spi_xfer_1.tx_buf = (unsigned long)txdata;
            spi_xfer_1.len = (unsigned int)txlength;
            spi_xfer_1.cs_change = 1U;

            /* coverity[misra_c_2012_rule_10_1_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
            /* coverity[misra_c_2012_rule_10_4_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
            /* coverity[misra_c_2012_rule_12_2_violation] SPI_IOC_MESSAGE is defined by the Linux Specification and is used correctly here */
            if (txlength == ioctl(hal_data->f_spi, SPI_IOC_MESSAGE(1), &spi_xfer_1))
            {
                status = ATCA_SUCCESS;
            }
            else
            {
                status = ATCA_COMM_FAIL;
            }
        }
    }

    return status;
}

/** \brief Perform control operations for the kit protocol
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_spi_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if ((NULL != iface) && (NULL != iface->mIfaceCFG))
    {
        switch (option)
        {
        case ATCA_HAL_CONTROL_SELECT:
            status = hal_spi_select(iface);
            break;
        case ATCA_HAL_CONTROL_DESELECT:
            status = hal_spi_deselect(iface);
            break;
        default:
            status = ATCA_UNIMPLEMENTED;
            break;
        }
    }
    return status;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_spi_release(void *hal_data)
{
    if (NULL != hal_data)
    {
        atca_spi_host_t *hal = (atca_spi_host_t*)hal_data;

        (void)close(hal->f_spi);

        /* coverity[misra_c_2012_rule_21_3_violation] Intentional as it is required for the linux environment */
        free(hal);
    }

    return ATCA_SUCCESS;
}
