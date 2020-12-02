/**/
#include "cryptoauthlib.h"
#include "atca_hal.h"
#include "hal_linux_spi_userspace.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>


ATCA_STATUS hal_spi_discover_buses(int spi_buses[], int max_buses)
{
    return ATCA_UNIMPLEMENTED;
}

/** \brief discover any TA100 devices on a given logical bus number
 * \param[in]  bus_num  logical bus number on which to look for TA100 devices
 * \param[out] cfg     pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] found   number of devices found on this bus
 * \return ATCA_SUCCESS
 */

ATCA_STATUS hal_spi_discover_devices(int bus_num, ATCAIfaceCfg cfg[], int *found)
{
    return ATCA_UNIMPLEMENTED;
}

/** \brief Open and configure the SPI device
 * \param[in]  dev_name  File name in the form /dev/spidevX.Y
 * \param[in]  speed     Clock speed in Hz
 * \param[out] fd        resulting file descriptor
 */
ATCA_STATUS hal_spi_open_file(const char * dev_name, uint32_t speed, int * fd)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    int ret;

    if (dev_name && fd)
    {
        uint8_t mode = SPI_MODE_3;
        uint8_t bits = 8;

        ret = open(dev_name, O_RDWR);

        if (0 < ret)
        {
            *fd = ret;
            ret = ioctl(*fd, SPI_IOC_WR_MODE, &mode);
        }

        if (0 <= ret)
        {
            ret = ioctl(*fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
        }

        if (0 <= ret)
        {
            ret = ioctl(*fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
        }

        if (*fd && (0 <= ret))
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


/** \brief HAL implementation of SPI init
 *
 * this implementation assumes SPI peripheral has been enabled by user . It only initialize an
 * SPI interface using given config.
 *
 *  \param[in] hal pointer to HAL specific data that is maintained by this HAL
 *  \param[in] cfg pointer to HAL specific configuration data that is used to initialize this HAL
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_spi_init(void *hal, ATCAIfaceCfg *cfg)
{

    int f_spi;
    ATCAHAL_t *pHal = (ATCAHAL_t*)hal;
    ATCA_STATUS status = ATCA_SUCCESS;

    if (!pHal || !cfg)
    {
        status =  ATCA_BAD_PARAM;
    }
    else
    {
        if (pHal->hal_data)
        {
            ATCASPIMaster_t * hal_data = (ATCASPIMaster_t*)pHal->hal_data;

            // Assume the bus had already been initialized
            hal_data->ref_ct++;
        }
        else
        {
            ATCASPIMaster_t * hal_data = malloc(sizeof(ATCASPIMaster_t));
            if (hal_data)
            {
                hal_data->ref_ct = 1;   // buses are shared, this is the first instance

                (void)snprintf(hal_data->spi_file, sizeof(hal_data->spi_file) - 1,
                               "/dev/spidev%d.%d", (uint8_t)cfg->atcaspi.bus, (uint8_t)cfg->atcaspi.select_pin);

                pHal->hal_data = hal_data;
            }
            else
            {
                status = ATCA_ALLOC_FAILURE;
            }
        }
    }
    return status;
}

ATCA_STATUS hal_spi_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of SPI receive function
 * \param[in]    iface          Device to interact with.
 * \param[in]    word_address   device transaction type
 * \param[out]   rxdata         Data received will be returned here.
 * \param[in,out] len           As input, the size of the rxdata buffer.
 *                              As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_spi_receive(ATCAIface iface, uint8_t word_address, uint8_t *rxdata, uint16_t *len)
{
    int f_spi;
    uint8_t response_len[3] = { 0 };
    uint16_t read_length = 2u; //to read length bytes
    uint16_t rx_max_data = *len;
    ATCA_STATUS status = ATCA_BAD_PARAM;
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCASPIMaster_t * hal_data = (ATCASPIMaster_t*)atgetifacehaldat(iface);

    struct spi_ioc_transfer spi_xfer = { 0 };

    *len = 0;
    rxdata[0] = word_address;

    if (hal_data && cfg)
    {
        status = hal_spi_open_file(hal_data->spi_file, cfg->atcaspi.baud, &f_spi);
    }

    if (status == ATCA_SUCCESS)
    {
        /*check for READ_CSR or RD_FSR transaction*/
        if ((0x30 == word_address) || (0xB0 == word_address ))
        {
            read_length = 1;
        }

        spi_xfer.tx_buf = (unsigned long)rxdata;
        spi_xfer.rx_buf = (unsigned long)response_len;
        spi_xfer.len = read_length + 1;

        if (ioctl(f_spi, SPI_IOC_MESSAGE(1), &spi_xfer) == 1)
        {
            status = ATCA_COMM_FAIL;
        }

        if (status == ATCA_SUCCESS)
        {
            *rxdata = response_len[1];
            if (read_length == 2u) //if length bytes are read
            {
                read_length = response_len[1] << 8;
                read_length |= response_len[2];

                if (read_length >= ATCA_RSP_SIZE_MIN)
                {
                    if (read_length <= rx_max_data)
                    {
                        rxdata[0] = word_address;
                        spi_xfer.tx_buf = (unsigned long)rxdata;
                        spi_xfer.rx_buf = (unsigned long)(rxdata + 1);
                        spi_xfer.len = read_length - 1;

                        if (ioctl(f_spi, SPI_IOC_MESSAGE(1), &spi_xfer) == 1)
                        {
                            status = ATCA_COMM_FAIL;
                        }

                        *rxdata = response_len[1];
                        *(rxdata + 1) = response_len[2];
                    }
                    else
                    {
                        status = ATCA_SMALL_BUFFER;
                    }
                }
                else
                {
                    status = ATCA_INVALID_SIZE;
                }
            }
            *len = read_length;
        }
        close(f_spi);
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

ATCA_STATUS hal_spi_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int len)
{
    int f_spi;
    ATCA_STATUS status = ATCA_SUCCESS;
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCASPIMaster_t * hal_data = (ATCASPIMaster_t*)atgetifacehaldat(iface);

    if (hal_data && cfg)
    {
        status = hal_spi_open_file(hal_data->spi_file, cfg->atcaspi.baud, &f_spi);
    }

    if (status == ATCA_SUCCESS)
    {
        txdata[0] = word_address;

        status = (write(f_spi, txdata, len + 1) != (len + 1)) ? ATCA_COMM_FAIL : ATCA_SUCCESS;

        close(f_spi);
    }
    return status;
}

/** \brief wake up CryptoAuth device using SPI bus
 * \param[in] iface  interface to logical device to wakeup
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_spi_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    ATCA_STATUS status = ATCA_SUCCESS;
    uint16_t len = 1u;            // sleep command  packet length
    uint8_t word_address = 0x30u; // word address indicating RD_CSR
    uint8_t csr_reg;
    int delay_timeout = (int)cfg->wake_delay;


    do
    {
        status = hal_spi_receive(iface, word_address, &csr_reg, &len);

        if (status == ATCA_SUCCESS)
        {
#ifdef ATCA_TA100_SUPPORT
            /*status bit check in CSR register*/
            if ((len == 1) && (((csr_reg >> 1) & 0x03 ) != 0x03))
            {
                status = ATCA_SUCCESS;
                /*self test bit check*/
                if (csr_reg & 0x01)
                {
                    status = TA_SELF_TEST_FAILURE;
                }

                break;
            }
#else
            break;
#endif

        }
        /*poll csr register for every 100us*/
        atca_delay_us(100);
        delay_timeout = delay_timeout - 100;

    }
    while (delay_timeout > 0);

    if (delay_timeout < 0)
    {
        status =  ATCA_TIMEOUT;
    }

    return status;
}

/** \brief idle TA100 device using SPI bus
 * \param[in] iface  interface to logical device to idle
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_spi_idle(ATCAIface iface)
{
    return ATCA_UNIMPLEMENTED;
}

/** \brief sleep TA100 device using SPI bus
 * \param[in] iface  interface to logical device to sleep
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_spi_sleep(ATCAIface iface)
{

    uint16_t len = 10u;           // sleep command  packet length
    uint8_t word_address = 0x00u; // word address indicating WR_command
    /*2byte -length , opcode,mode,param2,crc*/
    uint8_t sleep_cmd[10] = { 0x00, 0x0a, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa6, 0xc1 };

    return hal_spi_send(iface, word_address, sleep_cmd, len);

}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */


ATCA_STATUS hal_spi_release(void *hal_data)
{
    ATCASPIMaster_t *hal = (ATCASPIMaster_t*)hal_data;

    // if the use count for this bus has gone to 0 references, disable it.  protect against an unbracketed release
    if (hal && --(hal->ref_ct) <= 0)
    {
        free(hal);
    }

    return ATCA_SUCCESS;
}
