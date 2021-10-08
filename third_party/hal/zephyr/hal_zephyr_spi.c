/*
 * Copyright (c) 2020 Microchip Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <kernel.h>
#include <drivers/spi.h>


#include "hal/atca_hal.h"
#include "hal_zephyr_spi.h"

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

typedef struct atca_spi_host_s
{
    struct device *     dev;
    struct spi_cs_control cs;
    struct spi_config   cfg;
} atca_spi_host_t;

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

    if (iface && cfg && cfg->cfg_data)
    {
        if (!iface->hal_data)
        {
            atca_spi_host_t * hal_data = malloc(sizeof(atca_spi_host_t));
            atca_spi_host_config_t * cfg_data = (atca_spi_host_config_t*)cfg->cfg_data;

            if (hal_data)
            {
                memset(hal_data, 0, sizeof(hal_data));

                hal_data->cfg.operation = SPI_OP_MODE_MASTER | SPI_MODE_CPOL | SPI_MODE_CPHA | SPI_TRANSFER_MSB |
                                          SPI_WORD_SET(8);
                hal_data->cfg.frequency = cfg->atcaspi.baud;

                hal_data->dev = device_get_binding(cfg_data->device_name);

                hal_data->cs.gpio_dev = device_get_binding(cfg_data->gpio_name);
                hal_data->cs.gpio_pin = cfg->atcaspi.select_pin;
                hal_data->cs.gpio_dt_flags = GPIO_ACTIVE_LOW;

                hal_data->cfg.cs = &hal_data->cs;

                iface->hal_data = hal_data;
                status = ATCA_SUCCESS;
            }
            else
            {
                status = ATCA_ALLOC_FAILURE;
            }
        }
    }
    printf("hal_spi_init: %d\n", status);
    return status;
}

ATCA_STATUS hal_spi_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}


/** \brief HAL implementation to assert the device chip select
 * \param[in]    iface          Device to interact with.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_spi_select(ATCAIface iface)
{
    atca_spi_host_t * hal_data = (atca_spi_host_t *)atgetifacehaldat(iface);

    if (hal_data)
    {
        hal_data->cfg.operation |= SPI_HOLD_ON_CS | SPI_LOCK_ON;
        return ATCA_SUCCESS;
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
ATCA_STATUS hal_spi_deselect(ATCAIface iface)
{
    atca_spi_host_t * hal_data = (atca_spi_host_t *)atgetifacehaldat(iface);

    if (hal_data)
    {
        hal_data->cfg.operation &= ~(SPI_HOLD_ON_CS | SPI_LOCK_ON);
        spi_release(hal_data->dev, &hal_data->cfg);
        return ATCA_SUCCESS;
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
ATCA_STATUS hal_spi_receive(ATCAIface iface, uint8_t flags, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;
    atca_spi_host_t * hal_data = (atca_spi_host_t *)atgetifacehaldat(iface);

    if (hal_data)
    {
        struct spi_buf rxbuf = { rxdata, *rxlength };
        struct spi_buf_set rxbufs = { &rxbuf, 1 };

        if (!spi_read(hal_data->dev, &hal_data->cfg, &rxbufs))
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

ATCA_STATUS hal_spi_send(ATCAIface iface, uint8_t flags, uint8_t *txdata, int txlen)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    atca_spi_host_t * hal_data = (atca_spi_host_t *)atgetifacehaldat(iface);

    if (hal_data)
    {
        struct spi_buf txbuf = { txdata, txlen };
        struct spi_buf_set txbufs = { &txbuf, 1 };

        if(!spi_write(hal_data->dev, &hal_data->cfg, &txbufs))
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

    if (iface && iface->mIfaceCFG)
    {
        switch (option)
        {
        case ATCA_HAL_CONTROL_SELECT:
            return hal_spi_select(iface);
        case ATCA_HAL_CONTROL_DESELECT:
            return hal_spi_deselect(iface);
        default:
            printf("hal_spi_control: %d, %lu\n", option, paramlen);
            return ATCA_UNIMPLEMENTED;
        }
    }
    return ATCA_BAD_PARAM;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_spi_release(void *hal_data)
{
    return ATCA_SUCCESS;
}

/** @} */
