/**
 * \file
 * \brief ATCA Hardware abstraction layer for SAMD21 I2C over Harmony PLIB.
 *
 * This code is structured in two parts.  Part 1 is the connection of the ATCA HAL API to the physical I2C
 * implementation. Part 2 is the Harmony I2C primitives to set up the interface.
 *
 * Prerequisite: add SERCOM I2C Master Polled support to application in Atmel Studio
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
#include <string.h>
#include <stdio.h>

#include "atca_config.h"
#include "atca_hal.h"
#include "atca_device.h"
#include "atca_execution.h"
#include "definitions.h"

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */



/* Notes:
    - this HAL implementation assumes you've included the Atmel START SERCOM I2C libraries in your project, otherwise,
    the HAL layer will not compile because the START I2C drivers are a dependency *
 */

/** \brief discover i2c buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the application
 * of the a-priori knowledge
 * \param[in] i2c_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt to discover
 * \return ATCA_SUCCESS
 */

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{
    i2c_buses[0] = 0;
    return ATCA_SUCCESS;
}

/** \brief discover any CryptoAuth devices on a given logical bus number
 * \param[in]  bus_num  logical bus number on which to look for CryptoAuth devices
 * \param[out] cfg     pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] found   number of devices found on this bus
 * \return ATCA_SUCCESS
 */

ATCA_STATUS hal_i2c_discover_devices(int bus_num, ATCAIfaceCfg cfg[], int *found)
{
    return ATCA_UNIMPLEMENTED;
}



/** \brief
    - this HAL implementation assumes you've included the START Twi libraries in your project, otherwise,
    the HAL layer will not compile because the START TWI drivers are a dependency *
 */

/** \brief hal_i2c_init manages requests to initialize a physical interface.  it manages use counts so when an interface
 * has released the physical layer, it will disable the interface for some other use.
 * You can have multiple ATCAIFace instances using the same bus, and you can have multiple ATCAIFace instances on
 * multiple i2c buses, so hal_i2c_init manages these things and ATCAIFace is abstracted from the physical details.
 */

/** \brief initialize an I2C interface using given config
 * \param[in] hal - opaque ptr to HAL data
 * \param[in] cfg - interface configuration
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C send over START
 * \param[in] iface     instance
 * \param[in] txdata    pointer to space to bytes to send
 * \param[in] txlength  number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg* cfg = atgetifacecfg(iface);
    atca_plib_api_t * plib;

    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }

    plib = (atca_plib_api_t*)cfg->cfg_data;
    if (!plib)
    {
        return ATCA_BAD_PARAM;
    }

    // for this implementation of I2C with CryptoAuth chips, txdata is assumed to have ATCAPacket format

    // other device types that don't require i/o tokens on the front end of a command need a different hal_i2c_send and wire it up instead of this one
    // this covers devices such as ATSHA204A and ATECCx08A that require a word address value pre-pended to the packet
    // txdata[0] is using _reserved byte of the ATCAPacket

    txdata[0] = 0x03;   // insert the Word Address Value, Command token
    txlength++;         // account for word address value byte.

    /* Wait for the I2C bus to be ready */
    while (plib->is_busy() == true)
    {
        ;
    }

    if (plib->write(cfg->atcai2c.slave_address >> 1, txdata, txlength) == true)
    {
        /* Wait for the I2C transfer to complete */
        while (plib->is_busy() == true)
        {
            ;
        }

        /* Transfer complete. Check if the transfer was successful */
        if (plib->error_get() != PLIB_I2C_ERROR_NONE)
        {
            return ATCA_COMM_FAIL;
        }
    }
    else
    {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C receive function for START I2C
 * \param[in]    iface     Device to interact with.
 * \param[out]   rxdata    Data received will be returned here.
 * \param[inout] rxlength  As input, the size of the rxdata buffer.
 *                         As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg* cfg = atgetifacecfg(iface);
    int retries;
    uint16_t count;
    uint16_t rxdata_max_size = *rxlength;
    bool isSuccess = false;

    atca_plib_api_t * plib;

    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }

    plib = (atca_plib_api_t*)cfg->cfg_data;
    if (!plib)
    {
        return ATCA_BAD_PARAM;
    }

    retries = cfg->rx_retries;
    *rxlength = 0;
    if (rxdata_max_size < 1)
    {
        return ATCA_SMALL_BUFFER;
    }

    /* Wait for the I2C bus to be ready */
    while (plib->is_busy() == true)
    {
        ;
    }

    while (retries-- > 0 && isSuccess == false)
    {
        if (plib->read(cfg->atcai2c.slave_address >> 1, rxdata, 1) == true)
        {
            /* Wait for the I2C transfer to complete */
            while (plib->is_busy() == true)
            {
                ;
            }

            /* Transfer complete. Check if the transfer was successful */
            if (plib->error_get() == PLIB_I2C_ERROR_NONE)
            {
                isSuccess = true;
            }
        }
    }
    if (isSuccess == false)
    {
        return ATCA_COMM_FAIL;
    }

    if (rxdata[0] < ATCA_RSP_SIZE_MIN)
    {
        return ATCA_INVALID_SIZE;
    }
    if (rxdata[0] > rxdata_max_size)
    {
        return ATCA_SMALL_BUFFER;
    }

    count = rxdata[0] - 1;

    if (plib->read(cfg->atcai2c.slave_address >> 1, &rxdata[1], count) == true)
    {
        /* Wait for the I2C transfer to complete */
        while (plib->is_busy() == true)
        {
            ;
        }

        /* Transfer complete. Check if the transfer was successful */
        if (plib->error_get() != PLIB_I2C_ERROR_NONE)
        {
            return ATCA_COMM_FAIL;
        }
    }
    else
    {
        return ATCA_COMM_FAIL;
    }

    *rxlength = rxdata[0];

    return ATCA_SUCCESS;
}

/** \brief method to change the bus speec of I2C
 * \param[in] iface  interface on which to change bus speed
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */

void change_i2c_speed(ATCAIface iface, uint32_t speed)
{
    ATCAIfaceCfg* cfg = atgetifacecfg(iface);
    atca_plib_api_t * plib;

    if (!cfg)
    {
        return;
    }

    plib = (atca_plib_api_t*)cfg->cfg_data;
    if (!plib)
    {
        return;
    }

    PLIB_I2C_TRANSFER_SETUP setup;
    setup.clkSpeed = speed;

    /* Make sure I2C is not busy before changing the I2C clock speed */
    while (plib->is_busy() == true)
    {
        ;
    }

    (void)plib->transfer_setup(&setup, 0);
}

/** \brief wake up CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to wakeup
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg* cfg = atgetifacecfg(iface);
    atca_plib_api_t * plib;
    int retries;
    uint32_t bdrt;
    uint8_t data[4] = { 0 };
    bool isSuccess = false;

    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }

    plib = (atca_plib_api_t*)cfg->cfg_data;
    if (!plib)
    {
        return ATCA_BAD_PARAM;
    }

    retries = cfg->rx_retries;

    bdrt = cfg->atcai2c.baud;
    if (bdrt != 100000)   // if not already at 100KHz, change it
    {
        change_i2c_speed(iface, 100000);
    }

    while (plib->is_busy() == true)
    {
        ;
    }

    // Send the 00 address as the wake pulse; part will NACK, so don't check for status
    (void)plib->write(0x00, (uint8_t*)&data[0], 1);

    /* Wait for the I2C transfer to complete */
    while (plib->is_busy() == true)
    {
        ;
    }

    // wait tWHI + tWLO which is configured based on device type and configuration structure
    atca_delay_us(cfg->wake_delay);

    while (retries-- > 0 && isSuccess == false)
    {
        if (plib->read(cfg->atcai2c.slave_address >> 1, (uint8_t*)&data[0], 4) == true)
        {
            /* Wait for the I2C transfer to complete */
            while (plib->is_busy() == true)
            {
                ;
            }

            /* Transfer complete. Check if the transfer was successful */
            if (plib->error_get() == PLIB_I2C_ERROR_NONE)
            {
                isSuccess = true;
            }
        }
    }

    if (isSuccess == true)
    {
        // if necessary, revert baud rate to what came in.
        if (bdrt != 100000)
        {
            change_i2c_speed(iface, bdrt);
        }
    }
    else
    {
        return ATCA_COMM_FAIL;
    }

    return hal_check_wake(data, 4);
}

/** \brief idle CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to idle
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    ATCAIfaceCfg* cfg = atgetifacecfg(iface);
    atca_plib_api_t * plib;
    uint8_t data[1];

    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }

    plib = (atca_plib_api_t*)cfg->cfg_data;
    if (!plib)
    {
        return ATCA_BAD_PARAM;
    }

    data[0] = 0x02;  // idle word address value

    /* Wait for the I2C bus to be ready */
    while (plib->is_busy() == true)
    {
        ;
    }

    if (plib->write(cfg->atcai2c.slave_address >> 1, (uint8_t*)&data[0], 1) == true)
    {
        /* Wait for the I2C transfer to complete */
        while (plib->is_busy() == true)
        {
            ;
        }

        /* Transfer complete. Check if the transfer was successful */
        if (plib->error_get() != PLIB_I2C_ERROR_NONE)
        {
            return ATCA_COMM_FAIL;
        }
    }
    else
    {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief sleep CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to sleep
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    ATCAIfaceCfg* cfg = atgetifacecfg(iface);
    atca_plib_api_t * plib;
    uint8_t data[4];

    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }

    plib = (atca_plib_api_t*)cfg->cfg_data;
    if (!plib)
    {
        return ATCA_BAD_PARAM;
    }

    data[0] = 0x01;  // sleep word address value

    /* Wait for the I2C bus to be ready */
    while (plib->is_busy() == true)
    {
        ;
    }

    if (plib->write(cfg->atcai2c.slave_address >> 1, (uint8_t*)&data[0], 1) == true)
    {
        /* Wait for the I2C transfer to complete */
        while (plib->is_busy() == true)
        {
            ;
        }

        /* Transfer complete. Check if the transfer was successful */
        if (plib->error_get() != PLIB_I2C_ERROR_NONE)
        {
            return ATCA_COMM_FAIL;
        }
    }
    else
    {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
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
