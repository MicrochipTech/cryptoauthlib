/**
 * \file
 * \brief ATCA Hardware abstraction layer for SAMG55 I2C over ASF drivers.
 *
 * This code is structured in two parts.  Part 1 is the connection of the ATCA HAL API to the physical I2C
 * implementation. Part 2 is the ASF I2C primitives to set up the interface.
 *
 * Prerequisite: add "TWI - Two-Wire Interface (Common API) (service)" module to application in Atmel Studio
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
#include "hal_samg55_i2c_asf.h"
#include "atca_execution.h"


//!< Uncomment when debugging
/*#define DEBUG_HAL*/

/**
 * \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 * using I2C driver of ASF.
 *
   @{ */

/**
 * \brief
 * Logical to physical bus mapping structure
 */
ATCAI2CMaster_t *i2c_hal_data[MAX_I2C_BUSES];   // map logical, 0-based bus number to index
int i2c_bus_ref_ct = 0;                         // total in-use count across buses
twi_options_t opt_twi_master;


#ifdef DEBUG_HAL
static void print_array(uint8_t *data, uint32_t data_size)
{
    uint32_t n;

    for (n = 0; n < data_size; n++)
    {
        printf("%.2x ", data[n]);
        if (((n + 1) % 16) == 0)
        {
            printf("\r\n");
            if ((n + 1) != data_size)
            {
                printf("         ");
            }
        }
    }
    if (data_size % 16 != 0)
    {
        printf("\r\n");
    }
}
#endif

/**
 * \brief
 * This HAL implementation assumes you've included the ASF TWI libraries in your project, otherwise,
 * the HAL layer will not compile because the ASF TWI drivers are a dependency
 */

/** \brief discover i2c buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the application
 * of the a-priori knowledge
 * \param[in] i2c_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt to discover
 * return ATCA_SUCCESS
 */

ATCA_STATUS hal_i2c_discover_buses(int i2c_buses[], int max_buses)
{
    /* logical bus numbers 0-2 map to the samG55 i2c buses:
     */
    i2c_buses[0] = 0;

    return ATCA_SUCCESS;
}

/** \brief discover any CryptoAuth devices on a given logical bus number
 * \param[in] busNum - logical bus number on which to look for CryptoAuth devices
 * \param[out] cfg[] - pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] *found - number of devices found on this bus
 * \return ATCA_SUCCESS
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

    /** \brief default configuration, to be reused during discovery process */
    ATCAIfaceCfg discoverCfg = {
        .iface_type               = ATCA_I2C_IFACE,
        .devtype                  = ATECC508A,
        .atcai2c.slave_address    = 0x07,
        .atcai2c.bus              = busNum,
        .atcai2c.baud             = 400000,
        .wake_delay               = 800,
        .rx_retries               = 3
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
        discoverCfg.atcai2c.slave_address = slaveAddress << 1; // turn it into an 8-bit address which is what the rest of the i2c HAL is expecting when a packet is sent

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
 * \brief
 * hal_i2c_init manages requests to initialize a physical interface. It manages use counts so when an interface
 * has released the physical layer, it will disable the interface for some other use.
 * You can have multiple ATCAIFace instances using the same bus, and you can have multiple ATCAIFace instances on
 * multiple i2c buses, so hal_i2c_init manages these things and ATCAIFace is abstracted from the physical details.
 */

/**
 * \brief initialize an I2C interface using given config
 *
 * \param[in] hal - opaque ptr to HAL data
 * \param[in] cfg - interface configuration
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    // set to default i2c bus
    if (cfg->atcai2c.bus > MAX_I2C_BUSES - 1)
    {
        cfg->atcai2c.bus = 0;
    }
    int bus = cfg->atcai2c.bus; // 0-based logical bus number
    ATCAHAL_t *phal = (ATCAHAL_t*)hal;

    if (i2c_bus_ref_ct == 0)    // power up state, no i2c buses will have been used
    {
        for (int i = 0; i < MAX_I2C_BUSES; i++)
        {
            i2c_hal_data[i] = NULL;
        }
    }

    i2c_bus_ref_ct++;   // total across buses

    if (bus >= 0 && bus < MAX_I2C_BUSES)
    {
        //// if this is the first time this bus and interface has been created, do the physical work of enabling it
        if (i2c_hal_data[bus] == NULL)
        {
            i2c_hal_data[bus] = malloc(sizeof(ATCAI2CMaster_t));
            i2c_hal_data[bus]->ref_ct = 1;  // buses are shared, this is the first instance

            switch (bus)
            {
            case 0:
                i2c_hal_data[bus]->twi_id = ID_FLEXCOM4;
                i2c_hal_data[bus]->twi_master_instance = TWI4;
                break;
            case 1:
                i2c_hal_data[bus]->twi_id = FLEXCOM6;
                i2c_hal_data[bus]->twi_master_instance = TWI6;
                break;
            }

            flexcom_enable((Flexcom*)i2c_hal_data[bus]->twi_id);
            flexcom_set_opmode((Flexcom*)i2c_hal_data[bus]->twi_id, FLEXCOM_TWI);

            opt_twi_master.master_clk = sysclk_get_cpu_hz();
            opt_twi_master.speed = cfg->atcai2c.baud;
            opt_twi_master.smbus = 0;

            twi_master_init(i2c_hal_data[bus]->twi_master_instance, &opt_twi_master);

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

/**
 * \brief HAL implementation of I2C post init
 *
 * \param[in] iface  instance
 *
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/**
 * \brief HAL implementation of I2C send over ASF
 *
 * \param[in] iface     instance
 * \param[in] txdata    pointer to space to bytes to send
 * \param[in] txlength  number of bytes to send
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
#ifdef DEBUG_HAL
    printf("hal_i2c_send()\r\n");

    printf("\r\nCommand Packet (size:0x%.8x)\r\n", (uint32_t)txlength);
    printf("Count  : %.2x\r\n", txdata[1]);
    printf("Opcode : %.2x\r\n", txdata[2]);
    printf("Param1 : %.2x\r\n", txdata[3]);
    printf("Param2 : "); print_array(&txdata[4], 2);
    if (txdata[1] > 7)
    {
        printf("Data   : "); print_array(&txdata[6], txdata[1] - 7);
    }
    printf("CRC    : "); print_array(&txdata[txdata[1] - 1], 2);
    printf("\r\n");
#endif

    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    // set to default i2c bus
    if (cfg->atcai2c.bus > MAX_I2C_BUSES - 1)
    {
        cfg->atcai2c.bus = 0;
    }
    int bus = cfg->atcai2c.bus;

    txdata[0] = 0x03;   // insert the Word Address Value, Command token
    txlength++;         // account for word address value byte.

    twi_packet_t packet = {
        .chip        = cfg->atcai2c.slave_address >> 1,
        .addr        = { 0 },
        .addr_length = 0,
        .buffer      = txdata,
        .length      = (uint32_t)txlength //(uint32_t)txdata[1]
    };

    // for this implementation of I2C with CryptoAuth chips, txdata is assumed to have ATCAPacket format

    // other device types that don't require i/o tokens on the front end of a command need a different hal_i2c_send and wire it up instead of this one
    // this covers devices such as ATSHA204A and ATECCx08A that require a word address value pre-pended to the packet

    if (twi_master_write(i2c_hal_data[bus]->twi_master_instance, &packet) != TWI_SUCCESS)
    {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/**
 * \brief HAL implementation of I2C receive function for ASF I2C
 *
 * \param[in] iface     instance
 * \param[out] rxdata    pointer to space to receive the data
 * \param[in] rxlength  ptr to expected number of receive bytes to request
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
#ifdef DEBUG_HAL
    printf("hal_i2c_receive()\r\n");
#endif

    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    // set to default i2c bus
    if (cfg->atcai2c.bus > MAX_I2C_BUSES - 1)
    {
        cfg->atcai2c.bus = 0;
    }
    int bus = cfg->atcai2c.bus;
    int retries = cfg->rx_retries;
    uint32_t status = !TWI_SUCCESS;

    twi_packet_t packet = {
        .chip        = cfg->atcai2c.slave_address >> 1,
        .addr        = { 0 },
        .addr_length = 0,
        .buffer      = rxdata,
        .length      = (uint32_t)*rxlength
    };

    while (retries-- > 0 && status != TWI_SUCCESS)
    {
        status = twi_master_read(i2c_hal_data[bus]->twi_master_instance, &packet);
    }
    if (status != TWI_SUCCESS)
    {
        if (retries <= 0)
        {
            return ATCA_TOO_MANY_COMM_RETRIES;
        }

        return ATCA_COMM_FAIL;
    }

#ifdef DEBUG_HAL
    printf("\r\nResponse Packet (size:0x%.4x)\r\n", rxlength);
    printf("Count  : %.2x\r\n", rxdata[0]);
    if (rxdata[0] > 3)
    {
        printf("Data   : "); print_array(&rxdata[1], rxdata[0] - 3);
        printf("CRC    : "); print_array(&rxdata[rxdata[0] - 2], 2);
    }
    printf("\r\n");
#endif

    return ATCA_SUCCESS;
}

/**
 * \brief method to change the bus speed of I2C
 *
 * \param[in] iface  interface on which to change bus speed
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */
void change_i2c_speed(ATCAIface iface, uint32_t speed)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    // set to default i2c bus
    if (cfg->atcai2c.bus > MAX_I2C_BUSES - 1)
    {
        cfg->atcai2c.bus = 0;
    }
    int bus = cfg->atcai2c.bus;

    pmc_enable_periph_clk(i2c_hal_data[bus]->twi_id);

    opt_twi_master.master_clk = sysclk_get_cpu_hz();
    opt_twi_master.speed      = speed;
    opt_twi_master.smbus      = 0;

    twi_master_init(i2c_hal_data[bus]->twi_master_instance, &opt_twi_master);
}

/**
 * \brief wake up CryptoAuth device using I2C bus
 *
 * \param[in] iface  interface to logical device to wakeup
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    //set to default i2c bus
    if (cfg->atcai2c.bus > MAX_I2C_BUSES - 1)
    {
        cfg->atcai2c.bus = 0;
    }
    int bus = cfg->atcai2c.bus;
    int retries = cfg->rx_retries;
    uint32_t bdrt = cfg->atcai2c.baud;
    int status = !TWI_SUCCESS;
    uint8_t data[4], expected[4] = { 0x04, 0x11, 0x33, 0x43 };

    // if not already at 100kHz, change it
    if (bdrt != 100000)
    {
        change_i2c_speed(iface, 100000);
    }

    // Send 0x00 as wake pulse
    twi_write_byte(i2c_hal_data[bus]->twi_master_instance, 0x00);

    // rounded up to the nearest ms
    atca_delay_ms(((uint32_t)cfg->wake_delay + (1000 - 1)) / 1000);   // wait tWHI + tWLO which is configured based on device type and configuration structure

    twi_packet_t packet = {
        .chip        = cfg->atcai2c.slave_address >> 1,
        .addr        = { 0 },
        .addr_length = 0,
        .buffer      = data,
        .length      = 4
    };

    // if necessary, revert baud rate to what came in.
    if (bdrt != 100000)
    {
        change_i2c_speed(iface, bdrt);
    }

    while (retries-- > 0 && status != TWI_SUCCESS)
    {
        status = twi_master_read(i2c_hal_data[bus]->twi_master_instance, &packet);
    }
    if (status != TWI_SUCCESS)
    {
        if (retries <= 0)
        {
            return ATCA_TOO_MANY_COMM_RETRIES;
        }

        return ATCA_COMM_FAIL;
    }

    if (memcmp(data, expected, 4) == 0)
    {
        return ATCA_SUCCESS;
    }

    return ATCA_COMM_FAIL;
}

/**
 * \brief idle CryptoAuth device using I2C bus
 *
 * \param[in] iface  interface to logical device to idle
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    // set to default i2c bus
    if (cfg->atcai2c.bus > MAX_I2C_BUSES - 1)
    {
        cfg->atcai2c.bus = 0;
    }
    int bus = cfg->atcai2c.bus;
    uint8_t data[4];

    data[0] = 0x02; // idle word address value

    twi_packet_t packet = {
        .chip        = cfg->atcai2c.slave_address >> 1,
        .addr        = { 0 },
        .addr_length = 0,
        .buffer      = data,
        .length      = 1
    };

    if (twi_master_write(i2c_hal_data[bus]->twi_master_instance, &packet) != TWI_SUCCESS)
    {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/**
 * \brief sleep CryptoAuth device using I2C bus
 *
 * \param[in] iface  interface to logical device to sleep
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    //// set to default i2c bus
    if (cfg->atcai2c.bus > MAX_I2C_BUSES - 1)
    {
        cfg->atcai2c.bus = 0;
    }
    int bus = cfg->atcai2c.bus;
    uint8_t data[4];

    data[0] = 0x01; // sleep word address value

    twi_packet_t packet = {
        .chip        = cfg->atcai2c.slave_address >> 1,
        .addr        = { 0 },
        .addr_length = 0,
        .buffer      = data,
        .length      = 1
    };

    if (twi_master_write(i2c_hal_data[bus]->twi_master_instance, &packet) != TWI_SUCCESS)
    {
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

/**
 * \brief manages reference count on given bus and releases resource if no more refences exist
 *
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_release(void *hal_data)
{
    ATCAI2CMaster_t *hal = (ATCAI2CMaster_t*)hal_data;

    // set to default i2c bus
    if (hal->bus_index > MAX_I2C_BUSES - 1)
    {
        hal->bus_index = 0;
    }

    i2c_bus_ref_ct--;  // track total i2c bus interface instances for consistency checking and debugging

    // if the use count for this bus has gone to 0 references, disable it.  protect against an unbracketed release
    if (hal && --(hal->ref_ct) <= 0 && i2c_hal_data[hal->bus_index] != NULL)
    {
        twi_reset(hal->twi_master_instance);
        free(i2c_hal_data[hal->bus_index]);
        i2c_hal_data[hal->bus_index] = NULL;
    }

    return ATCA_SUCCESS;
}

/** @} */
