/*
 * Copyright (c) 2020 Microchip Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <drivers/i2c.h>

#include "hal/atca_hal.h"

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */


/** \brief The function return pre defined macro value for corrsponding i2c speed
 * 
 *  \param[in] speed   As input, i2c clock speed in HZ
 * 
 *  \return Zephyr I2C speed constant
 */
static uint32_t hal_zephyr_i2c_convert_speed(const uint32_t speed)
{
    if (400000 < speed)
    {
        return I2C_SPEED_FAST_PLUS;
    }
    else if (100000 < speed)
    {
        return I2C_SPEED_FAST;
    }
    else
    {
        return I2C_SPEED_STANDARD;
    }
}

/** \brief Configure the zephyr i2c peripheral
 *  \return ATCA_SUCCESS otherwise an error
 */
static ATCA_STATUS hal_zephyr_i2c_configure(
    const struct device *   zdev,            /**< Zephyr device to configure */
    const uint32_t          speed            /**< baud rate (typically 100000 or 400000) */
)
{
    uint32_t i2c_cfg = I2C_MODE_MASTER | I2C_SPEED_SET(hal_zephyr_i2c_convert_speed(speed));

    if (i2c_configure(zdev, i2c_cfg)) 
    {
        return ATCA_GEN_FAIL;
    }
    else
    {
        return ATCA_SUCCESS;
    }
}


/** \brief HAL implementation of I2C init
 *
 * this implementation assumes I2C peripheral has been enabled by user. It only initialize an
 * I2C interface using given config.
 *
 *  \param[in] hal pointer to HAL specific data that is maintained by this HAL
 *  \param[in] cfg pointer to HAL specific configuration data that is used to initialize this HAL
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg* cfg)
{
    ATCA_STATUS status = ATCA_BAD_PARAM;

    if (iface && cfg && cfg->cfg_data)
    {
        if (!iface->hal_data)
        {
            const struct device * zdev = device_get_binding(cfg->cfg_data);

            if (ATCA_SUCCESS == (status = hal_zephyr_i2c_configure(zdev, cfg->atcai2c.baud)))
            {
                iface->hal_data = (void*)zdev;
            }
        }
        else
        {
            status = ATCA_SUCCESS;
        }
    }

    return status;
}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    ((void)iface);
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C send
 * \param[in] iface         instance
 * \param[in] word_address  device transaction type
 * \param[in] txdata        pointer to space to bytes to send
 * \param[in] txlength      number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t address, uint8_t *txdata, int txlength)
{
    struct device * zdev = (struct device *)atgetifacehaldat(iface);

    if (!zdev || (0 == txlength) || (NULL == txdata))
    {
        return ATCA_BAD_PARAM;
    }
    if (i2c_write(zdev, txdata, txlength, (address >> 0x1)))
    {
        return ATCA_TX_FAIL;
    }
     
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C receive function
 * \param[in]    iface          Device to interact with.
 * \param[in]    address        device address
 * \param[out]   rxdata         Data received will be returned here.
 * \param[in,out] rxlength      As input, the size of the rxdata buffer.
 *                              As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t address, uint8_t *rxdata, uint16_t *rxlength)
{
    struct device * zdev = (struct device *)atgetifacehaldat(iface);

    if (!zdev || (NULL == rxlength) || (NULL == rxdata))
    {
        return ATCA_BAD_PARAM;
    }

    if (i2c_read(zdev, rxdata, *rxlength, (address >> 0x1)))
    {
        return ATCA_RX_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief Perform control operations for the kit protocol
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    struct device * zdev = (struct device *)atgetifacehaldat(iface);

    if (zdev)
    {
        if (ATCA_HAL_CHANGE_BAUD == option && sizeof(uint32_t) == paramlen)
        {
            return hal_zephyr_i2c_configure(zdev, *(uint32_t*)param);
        }
        else
        {
            return ATCA_UNIMPLEMENTED;
        }
    }
    return ATCA_BAD_PARAM;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_release(void *hal_data)
{
    return ATCA_SUCCESS;
}

/** @} */
