/**
 * \file
 * \brief ATCA Hardware abstraction layer for SWI bit banging.
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
#include "hal_swi_bitbang.h"
#include "atca_device.h"


/**
 * \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief These methods define the hardware abstraction layer for
 *        communicating with a CryptoAuth device using SWI bit banging.
   @{ */

/**
 * \brief Logical to physical bus mapping structure.
 */
ATCASWIMaster_t *swi_hal_data[MAX_SWI_BUSES];   //!< map logical, 0-based bus number to index
int swi_bus_ref_ct = 0;                         //!< total in-use count across buses

/** \brief discover swi buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the application.This function is currently not supported.
 * of the a-priori knowledge
 * \param[in] swi_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt to discover
 * \return ATCA_UNIMPLEMENTED
 */
ATCA_STATUS hal_swi_discover_buses(int swi_buses[], int max_buses)
{

    return ATCA_UNIMPLEMENTED;

}

/** \brief discover any CryptoAuth devices on a given logical bus number.This function is curently not supported.
 * \param[in] busNum - logical bus number on which to look for CryptoAuth devices
 * \param[out] cfg[] - pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] *found - number of devices found on this bus
 * \return ATCA_UNIMPLEMENTED
 */

ATCA_STATUS hal_swi_discover_devices(int busNum, ATCAIfaceCfg cfg[], int *found)
{
    return ATCA_UNIMPLEMENTED;

}



/**
 * \brief hal_swi_init manages requests to initialize a physical
 *        interface. It manages use counts so when an interface has
 *        released the physical layer, it will disable the interface for
 *        some other use. You can have multiple ATCAIFace instances using
 *        the same bus, and you can have multiple ATCAIFace instances on
 *        multiple swi buses, so hal_swi_init manages these things and
 *        ATCAIFace is abstracted from the physical details.
 */

/**
 * \brief Initialize an SWI interface using given config.
 *
 * \param[in] hal  opaque pointer to HAL data
 * \param[in] cfg  interface configuration
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_swi_init(void *hal, ATCAIfaceCfg *cfg)
{
    ATCAHAL_t *phal = (ATCAHAL_t*)hal;

    int bus = cfg->atcaswi.bus; //!< 0-based logical bus number

    if (swi_bus_ref_ct == 0)    //!< power up state, no swi buses will have been used

    {
        for (int i = 0; i < MAX_SWI_BUSES; i++)
        {
            swi_hal_data[i] = NULL;
        }
    }
    swi_bus_ref_ct++; //!< total across buses

    if (bus >= 0 && bus < MAX_SWI_BUSES)
    {
        //! if this is the first time this bus and interface has been created, do the physical work of enabling it
        if (swi_hal_data[bus] == NULL)
        {
            swi_hal_data[bus] = malloc(sizeof(ATCASWIMaster_t));

            //! assign GPIO pin
            swi_hal_data[bus]->pin_sda = swi_buses_default.pin_sda[bus];

            swi_set_pin(swi_hal_data[bus]->pin_sda);
            swi_enable();

            //! store this for use during the release phase
            swi_hal_data[bus]->bus_index = bus;
        }
        else
        {
            //! otherwise, another interface already initialized the bus, any different
            //! cfg parameters will be ignored...first one to initialize this sets the configuration
        }

        phal->hal_data = swi_hal_data[bus];

        return ATCA_SUCCESS;
    }

    return ATCA_COMM_FAIL;
}

/**
 * \brief HAL implementation of SWI post init.
 *
 * \param[in] iface  ATCAIface instance
 *
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_swi_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/**
 * \brief Send byte(s) via SWI.
 *
 * \param[in] iface     interface of the logical device to send data to
 * \param[in] txdata    pointer to bytes to send
 * \param[in] txlength  number of bytes to send
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_swi_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    int bus     = cfg->atcaswi.bus;

    //! Skip the Word Address data as SWI doesn't use it
    txdata++;

    //! Set SWI pin
    swi_set_pin(swi_hal_data[bus]->pin_sda);

    //! Send Command Flag
    swi_send_byte(SWI_FLAG_CMD);

    //! Send the remaining bytes
    swi_send_bytes(txlength, txdata);

    return ATCA_SUCCESS;
}

/**
 * \brief Receive byte(s) via SWI.
 *
 * \param[in]  iface     interface of the logical device to receive data
 *                      from
 * \param[out] rxdata    pointer to where bytes will be received
 * \param[in]  rxlength  pointer to expected number of receive bytes to
 *                      request
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_swi_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    ATCA_STATUS status = ATCA_RX_TIMEOUT;

    int bus     = cfg->atcaswi.bus;
    int retries = cfg->rx_retries;
    uint16_t count;

    //! Set SWI pin
    swi_set_pin(swi_hal_data[bus]->pin_sda);

    while (retries-- > 0 && status != ATCA_SUCCESS)
    {
        swi_send_byte(SWI_FLAG_TX);

        status = swi_receive_bytes(*rxlength, rxdata);
        if (status == ATCA_RX_FAIL)
        {
            count = rxdata[0];
            if ((count < ATCA_RSP_SIZE_MIN) || (count > *rxlength))
            {
                status = ATCA_INVALID_SIZE;
                break;
            }
            else
            {
                status = ATCA_SUCCESS;
            }
        }
        else if (status == ATCA_RX_TIMEOUT)
        {
            status = ATCA_RX_NO_RESPONSE;
        }
    }

    return status;
}

/**
 * \brief Send Wake flag via SWI.
 *
 * \param[in] iface  interface of the logical device to wake up
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_swi_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    ATCA_STATUS status = ATCA_WAKE_FAILED;

    int bus     = cfg->atcaswi.bus;
    uint8_t response[4] = { 0x00, 0x00, 0x00, 0x00 };
    uint8_t expected_response[4] = { 0x04, 0x11, 0x33, 0x43 };
    uint16_t rxlength  = sizeof(response);

    //! Set SWI pin
    swi_set_pin(swi_hal_data[bus]->pin_sda);

    //! Generate Wake Token
    swi_send_wake_token();

    //! Wait tWHI + tWLO
    atca_delay_us(cfg->wake_delay);

    status = hal_swi_receive(iface, response, &rxlength);
    if (status == ATCA_SUCCESS)
    {
        //! Compare response with expected_response
        if (memcmp(response, expected_response, 4) != 0)
        {
            status = ATCA_WAKE_FAILED;
        }
    }

    return status;
}

/**
 * \brief Send Idle flag via SWI.
 *
 * \param[in] iface  interface of the logical device to idle
 *
 * \return ATCA_SUCCES
 */
ATCA_STATUS hal_swi_idle(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    int bus     = cfg->atcaswi.bus;

    //! Set SWI pin
    swi_set_pin(swi_hal_data[bus]->pin_sda);

    swi_send_byte(SWI_FLAG_IDLE);

    return ATCA_SUCCESS;
}

/**
 * \brief Send Sleep flag via SWI.
 *
 * \param[in] iface  interface of the logical device to sleep
 *
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_swi_sleep(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);

    int bus     = cfg->atcaswi.bus;

    //! Set SWI pin
    swi_set_pin(swi_hal_data[bus]->pin_sda);

    swi_send_byte(SWI_FLAG_SLEEP);

    return ATCA_SUCCESS;
}

/**
 * \brief Manages reference count on given bus and releases resource if
 *        no more reference(s) exist.
 *
 * \param[in] hal_data  opaque pointer to hal data structure - known only
 *                      to the HAL implementation
 *
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_swi_release(void *hal_data)
{
    ATCASWIMaster_t *hal = (ATCASWIMaster_t*)hal_data;

    swi_bus_ref_ct--; //!< track total SWI instances

    //! if the use count for this bus has gone to 0 references, disable it.  protect against an unbracketed release
    if (hal && swi_hal_data[hal->bus_index] != NULL)
    {
        swi_set_pin(swi_hal_data[hal->bus_index]->pin_sda);
        swi_disable();
        free(swi_hal_data[hal->bus_index]);
        swi_hal_data[hal->bus_index] = NULL;
    }

    return ATCA_SUCCESS;
}

/** @} */