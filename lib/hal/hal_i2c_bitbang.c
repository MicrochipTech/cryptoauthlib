/**
 * \file
 * \brief ATCA Hardware abstraction layer for I2C bit banging.
 *
 * \copyright (c) 2017 Microchip Technology Inc. and its subsidiaries.
 *            You may use this software and any derivatives exclusively with
 *            Microchip products.
 *
 * \page License
 *
 * (c) 2017 Microchip Technology Inc. and its subsidiaries. You may use this
 * software and any derivatives exclusively with Microchip products.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE, OR ITS INTERACTION WITH MICROCHIP PRODUCTS, COMBINATION
 * WITH ANY OTHER PRODUCTS, OR USE IN ANY APPLICATION.
 *
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
 * INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
 * WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
 * BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
 * FULLEST EXTENT ALLOWED BY LAW, MICROCHIPS TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
 * THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
 *
 * MICROCHIP PROVIDES THIS SOFTWARE CONDITIONALLY UPON YOUR ACCEPTANCE OF THESE
 * TERMS.
 */

#include <asf.h>
#include <string.h>
#include <stdio.h>
#include "atca_hal.h"
#include "atca_device.h"
#include "hal_i2c_bitbang.h"
#include "atca_execution.h"


/**
 * \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief These methods define the hardware abstraction layer for
 *        communicating with a CryptoAuth device using I2C bit banging.
   @{ */

/**
 * \brief Logical to physical bus mapping structure.
 */
ATCAI2CMaster_t *i2c_hal_data[MAX_I2C_BUSES];   //!< map logical, 0-based bus number to index
int i2c_bus_ref_ct = 0;                         //!< total in-use count across buses


/** \brief discover i2c buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the application
 * of the prior knowledge
 * \param[in] i2c_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt to discover
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{

    i2c_discover_buses(i2c_buses, max_buses);

    return ATCA_SUCCESS;

}


/** \brief discover any CryptoAuth devices on a given logical bus number
 * \param[in] busNum - logical bus number on which to look for CryptoAuth devices
 * \param[out] cfg[] - pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] *found - number of devices found on this bus
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_discover_devices(int busNum, ATCAIfaceCfg cfg[], int *found)
{
    ATCAIfaceCfg *head = cfg;
    uint8_t slaveAddress = 0x01;
    ATCADevice device;
    ATCAPacket packet;
    ATCA_STATUS status;
    uint8_t revs608[][4] = { { 0x00, 0x00, 0x60, 0x01 }, { 0x00, 0x00, 0x60, 0x02 } };
    uint8_t revs508[][4] = { { 0x00, 0x00, 0x50, 0x00 } };
    uint8_t revs108[][4] = { { 0x80, 0x00, 0x10, 0x01 } };
    uint8_t revs204[][4] = { { 0x00, 0x02, 0x00, 0x08 }, { 0x00, 0x02, 0x00, 0x09 }, { 0x00, 0x04, 0x05, 0x00 } };
    int i;

    // default configuration, to be reused during discovery process
    ATCAIfaceCfg discoverCfg = {
        .iface_type             = ATCA_I2C_IFACE,
        .devtype                = ATECC508A,
        .atcai2c.slave_address  = 0x07,
        .atcai2c.bus            = busNum,
        .atcai2c.baud           = 400000,
        //.atcai2c.baud = 100000,
        .wake_delay             = 800,
        .rx_retries             = 3
    };

    ATCAHAL_t hal;

    if (busNum < 0)
    {
        return ATCA_COMM_FAIL;
    }

    hal_i2c_init(&hal, &discoverCfg);
    device = newATCADevice(&discoverCfg);

    // iterate through all addresses on given i2c bus
    // all valid 7-bit addresses go from 0x07 to 0x78
    for (slaveAddress = 0x07; slaveAddress <= 0x78; slaveAddress++)
    {
        discoverCfg.atcai2c.slave_address = slaveAddress << 1;  // turn it into an 8-bit address which is what the rest of the i2c HAL is expecting when a packet is sent

        memset(packet.data, 0x00, sizeof(packet.data));
        // build an info command
        packet.param1 = INFO_MODE_REVISION;
        packet.param2 = 0;
        // get devrev info and set device type accordingly
        atInfo(device->mCommands, &packet);
        if ((status = atca_execute_command(&packet, device)) != ATCA_SUCCESS)
        {
            continue;
        }

        // determine device type from common info and dev rev response byte strings... start with unknown
        discoverCfg.devtype = ATCA_DEV_UNKNOWN;
        for (i = 0; i < (int)sizeof(revs608) / 4; i++)
        {
            if (memcmp(&packet.data[1], &revs608[i], 4) == 0)
            {
                discoverCfg.devtype = ATECC608A;
                break;
            }
        }

        for (i = 0; i < (int)sizeof(revs508) / 4; i++)
        {
            if (memcmp(&packet.data[1], &revs508[i], 4) == 0)
            {
                discoverCfg.devtype = ATECC508A;
                break;
            }
        }

        for (i = 0; i < (int)sizeof(revs204) / 4; i++)
        {
            if (memcmp(&packet.data[1], &revs204[i], 4) == 0)
            {
                discoverCfg.devtype = ATSHA204A;
                break;
            }
        }

        for (i = 0; i < (int)sizeof(revs108) / 4; i++)
        {
            if (memcmp(&packet.data[1], &revs108[i], 4) == 0)
            {
                discoverCfg.devtype = ATECC108A;
                break;
            }
        }

        if (discoverCfg.devtype != ATCA_DEV_UNKNOWN)
        {
            // now the device type is known, so update the caller's cfg array element with it
            (*found)++;
            memcpy( (uint8_t*)head, (uint8_t*)&discoverCfg, sizeof(ATCAIfaceCfg));
            head->devtype = discoverCfg.devtype;
            head++;
        }

        atca_delay_ms(15);
    }

    deleteATCADevice(&device);

    return ATCA_SUCCESS;
}

/**
 * \brief This function creates a Start condition and sends the I2C
 *        address.
 *
 * \param[in] iface  interface of the logical device to send data to
 * \param[in] RorW   I2C_READ for reading, I2C_WRITE for writing.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
static ATCA_STATUS hal_i2c_send_slave_address(ATCAIface iface, uint8_t RorW)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    ATCA_STATUS status = ATCA_TX_TIMEOUT;

    uint8_t sla = cfg->atcai2c.slave_address | RorW;

    i2c_send_start();

    status = i2c_send_byte(sla);
    if (status != ATCA_SUCCESS)
    {
        i2c_send_stop();
    }

    return status;
}

/**
 * \brief hal_i2c_init manages requests to initialize a physical
 *        interface. It manages use counts so when an interface has
 *        released the physical layer, it will disable the interface for
 *        some other use. You can have multiple ATCAIFace instances using
 *        the same bus, and you can have multiple ATCAIFace instances on
 *        multiple i2c buses, so hal_i2c_init manages these things and
 *        ATCAIFace is abstracted from the physical details.
 */

/**
 * \brief Initialize an I2C interface using given config.
 *
 * \param[in] hal  opaque pointer to HAL data
 * \param[in] cfg  interface configuration
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    ATCAHAL_t *phal = (ATCAHAL_t*)hal;

    int bus = cfg->atcai2c.bus; // 0-based logical bus number

    if (i2c_bus_ref_ct == 0)    // power up state, no i2c buses will have been used

    {
        for (int i = 0; i < MAX_I2C_BUSES; i++)
        {
            i2c_hal_data[i] = NULL;
        }
    }

    i2c_bus_ref_ct++;   //!< total across buses

    if (bus >= 0 && bus < MAX_I2C_BUSES)
    {
        // if this is the first time this bus and interface has been created, do the physical work of enabling it
        if (i2c_hal_data[bus] == NULL)
        {
            i2c_hal_data[bus] = malloc(sizeof(ATCAI2CMaster_t));
            i2c_hal_data[bus]->ref_ct = 1;  //!< buses are shared, this is the first instance

            // assign GPIO pins
            i2c_hal_data[bus]->pin_sda = i2c_buses_default.pin_sda[bus];
            i2c_hal_data[bus]->pin_scl = i2c_buses_default.pin_scl[bus];

            i2c_set_pin(i2c_hal_data[bus]->pin_sda, i2c_hal_data[bus]->pin_scl);
            i2c_enable();

            // store this for use during the release phase
            i2c_hal_data[bus]->bus_index = bus;
        }
        else
        {
            // otherwise, another interface already initialized the bus, so this interface will share it and any different
            // cfg parameters will be ignored...first one to initialize this sets the configuration
            i2c_hal_data[bus]->ref_ct++;
        }

        phal->hal_data = i2c_hal_data[bus];

        return ATCA_SUCCESS;
    }

    return ATCA_COMM_FAIL;
}



/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/**
 * \brief HAL implementation of Send byte(s) via I2C.
 *
 * \param[in] iface     interface of the logical device to send data to
 * \param[in] txdata    pointer to bytes to send
 * \param[in] txlength  number of bytes to send
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    ATCA_STATUS status = ATCA_TX_TIMEOUT;

    int bus     = cfg->atcai2c.bus;

    txdata[0] = 0x03;   //!< Word Address Value = Command
    txlength++;         //!< count Word Address byte towards txlength

    //! Set I2C pins
    i2c_set_pin(i2c_hal_data[bus]->pin_sda, i2c_hal_data[bus]->pin_scl);

    do
    {
        //! Address the device and indicate that bytes are to be written
        status = hal_i2c_send_slave_address(iface, I2C_WRITE);
        if (status != ATCA_SUCCESS)
        {
            break;
        }

        //! Send the remaining bytes
        status = i2c_send_bytes(txlength, txdata);
    }
    while (0);

    //! Send STOP regardless of i2c_status
    i2c_send_stop();

    return status;
}

/**
 * \brief HAL implementation of Receive byte(s) via I2C.
 *
 * \param[in] iface     interface of the logical device to receive data
 *                      from
 * \param[in] rxdata    pointer to where bytes will be received
 * \param[in] rxlength  pointer to expected number of receive bytes to
 *                      request
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    ATCA_STATUS status = ATCA_RX_TIMEOUT;

    int bus     = cfg->atcai2c.bus;
    int retries = cfg->rx_retries;
    uint8_t count;

    // Set I2C pins
    i2c_set_pin(i2c_hal_data[bus]->pin_sda, i2c_hal_data[bus]->pin_scl);

    while (retries-- > 0 && status != ATCA_SUCCESS)
    {
        // Address the device and indicate that bytes are to be read
        status = hal_i2c_send_slave_address(iface, I2C_READ);
        if (status == ATCA_SUCCESS)
        {
            // Receive count byte
            i2c_receive_byte(rxdata);
            count = rxdata[0];
            if ((count < ATCA_RSP_SIZE_MIN) || (count > *rxlength))
            {
                i2c_send_stop();
                status = ATCA_INVALID_SIZE;
                break;
            }

            // Receive the remaining bytes
            i2c_receive_bytes(count - 1, &rxdata[1]);
        }
    }
    if (status == ATCA_TX_TIMEOUT)
    {
        status = ATCA_RX_NO_RESPONSE;
    }

    return status;
}


/** \brief wake up CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to wakeup
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    ATCA_STATUS status = ATCA_WAKE_FAILED;

    int bus     = cfg->atcai2c.bus;
    uint8_t response[4] = { 0x00, 0x00, 0x00, 0x00 };
    uint8_t expected_response[4] = { 0x04, 0x11, 0x33, 0x43 };
    uint16_t response_size = sizeof(response);

    // Set I2C pins
    i2c_set_pin(i2c_hal_data[bus]->pin_sda, i2c_hal_data[bus]->pin_scl);

    // Generate Wake Token
    i2c_send_wake_token();

    // Wait tWHI + tWLO
    atca_delay_us(cfg->wake_delay);

    // Receive Wake Response
    status = hal_i2c_receive(iface, response, &response_size);
    if (status == ATCA_SUCCESS)
    {
        // Compare response with expected_response
        if (memcmp(response, expected_response, 4) != 0)
        {
            status = ATCA_WAKE_FAILED;
        }
    }

    return status;
}

/** \brief idle CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to idle
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    ATCA_STATUS status = ATCA_TX_TIMEOUT;

    int bus     = cfg->atcai2c.bus;

    // Set I2C pins
    i2c_set_pin(i2c_hal_data[bus]->pin_sda, i2c_hal_data[bus]->pin_scl);

    // Address the device and indicate that bytes are to be written
    status = hal_i2c_send_slave_address(iface, I2C_WRITE);
    if (status == ATCA_SUCCESS)
    {
        status = i2c_send_byte(0x02);   //!< Word Address Value = Idle
        i2c_send_stop();
    }

    return status;
}

/** \brief sleep CryptoAuth device using I2C bus
 * \param[in] iface  interface to logical device to sleep
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    ATCA_STATUS status = ATCA_TX_TIMEOUT;

    int bus     = cfg->atcai2c.bus;

    // Set I2C pins
    i2c_set_pin(i2c_hal_data[bus]->pin_sda, i2c_hal_data[bus]->pin_scl);

    // Address the device and indicate that bytes are to be written
    status = hal_i2c_send_slave_address(iface, I2C_WRITE);
    if (status == ATCA_SUCCESS)
    {
        status = i2c_send_byte(0x01);   //!< Word Address Value = Sleep
        i2c_send_stop();
    }

    return status;
}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data  opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_release(void *hal_data)
{
    ATCAI2CMaster_t *hal = (ATCAI2CMaster_t*)hal_data;

    i2c_bus_ref_ct--;   // track total i2c bus interface instances for consistency checking and debugging

    // if the use count for this bus has gone to 0 references, disable it.  protect against an unbracketed release
    if (hal && --(hal->ref_ct) <= 0 && i2c_hal_data[hal->bus_index] != NULL)
    {
        i2c_set_pin(i2c_hal_data[hal->bus_index]->pin_sda, i2c_hal_data[hal->bus_index]->pin_scl);
        i2c_disable();
        free(i2c_hal_data[hal->bus_index]);
        i2c_hal_data[hal->bus_index] = NULL;
    }

    return ATCA_SUCCESS;
}

/** @} */