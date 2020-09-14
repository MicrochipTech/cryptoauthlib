/**
 * \file
 * \brief HAL for kit protocol over HID for any platform.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hidapi.h"

#include "atca_hal.h"
#include "hal/kit_protocol.h"

/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 *
   @{ */

#define HID_PACKET_MAX      512     //! Maximum number of bytes for a HID send/receive packet (typically 64)

/** \brief discover cdc buses available for this hardware
 * this maintains a list of logical to physical bus mappings freeing the application
 * of the a-priori knowledge
 * \param[in] hid_buses - an array of logical bus numbers
 * \param[in] max_buses - maximum number of buses the app wants to attempt to discover
 */

ATCA_STATUS hal_kit_hid_discover_buses(int hid_buses[], int max_buses)
{
    return ATCA_UNIMPLEMENTED;
}

/** \brief discover any CryptoAuth devices on a given logical bus number
 * \param[in] bus_num - logical bus number on which to look for CryptoAuth devices
 * \param[out] cfg[] - pointer to head of an array of interface config structures which get filled in by this method
 * \param[out] *found - number of devices found on this bus
 */
ATCA_STATUS hal_kit_hid_discover_devices(int bus_num, ATCAIfaceCfg cfg[], int *found)
{
    return ATCA_UNIMPLEMENTED;
}

/** \brief HAL implementation of Kit USB HID init
 *  \param[in] hal pointer to HAL specific data that is maintained by this HAL
 *  \param[in] cfg pointer to HAL specific configuration data that is used to initialize this HAL
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_init(void* hal, ATCAIfaceCfg* cfg)
{
    ATCAHAL_t *phal = (ATCAHAL_t*)hal;

    int i = 0;
    int index = 0;

    // Check the input variables
    if ((cfg == NULL) || (phal == NULL))
    {
        return ATCA_BAD_PARAM;
    }

    // Create the enumerate object
#ifdef KIT_DEBUG
    printf("Enumerate HID device(s)\n");
#endif
    hid_init();

    phal->hal_data = hid_open(cfg->atcahid.vid, cfg->atcahid.pid, NULL);

    return (phal->hal_data) ? ATCA_SUCCESS : ATCA_COMM_FAIL;
}

/** \brief HAL implementation of Kit HID post init
 *  \param[in] iface  instance
 *  \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_post_init(ATCAIface iface)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    hid_device* pHid = (hid_device*)atgetifacehaldat(iface);
    ATCAIfaceCfg *pCfg = atgetifacecfg(iface);
    int i = 0;

    if ((pHid == NULL) || (pCfg == NULL))
    {
        return ATCA_BAD_PARAM;
    }

    status = kit_init(iface);
    if (status != ATCA_SUCCESS)
#ifdef KIT_DEBUG
    { printf("kit_init() Failed"); }
#endif
    {
        ATCA_TRACE(status, "kit_init() failed");
    }

    return status;
}

/** \brief HAL implementation of send over USB HID
 *  \param[in] iface     instance
 *  \param[in] txdata    pointer to bytes to send
 *  \param[in] txlength  number of bytes to send
 *  \return ATCA_STATUS
 */
ATCA_STATUS kit_phy_send(ATCAIface iface, uint8_t* txdata, int txlength)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    hid_device* pHid = (hid_device*)atgetifacehaldat(iface);
    int bytes_written = 0;
    int bytes_left;
    int bytes_to_send;
    uint8_t buffer[HID_PACKET_MAX];

    if ((txdata == NULL) || (cfg == NULL) || (pHid == NULL))
    {
        return ATCA_BAD_PARAM;
    }

#ifdef KIT_DEBUG
    printf("HID layer: Write: %s", txdata);
#endif

    //To avoid ERROR_INVALID_USER_BUFFER on Windows
    bytes_left = txlength;
    while (bytes_left > 0)
    {
        memset(buffer, 0, (HID_PACKET_MAX));

        if (bytes_left >= (int)cfg->atcahid.packetsize)
        {
            bytes_to_send = cfg->atcahid.packetsize;
        }
        else
        {
            bytes_to_send = bytes_left;
        }

        memcpy(&buffer[1], &txdata[(txlength - bytes_left)], bytes_to_send);

        bytes_written = hid_write(pHid, buffer, (size_t)cfg->atcahid.packetsize + 1);
        if (bytes_written != cfg->atcahid.packetsize + 1)
        {
            return ATCA_TX_FAIL;
        }

        bytes_left -= bytes_to_send;
    }

    return ATCA_SUCCESS;
}

/** \brief HAL implementation of kit protocol send over USB HID
 * \param[in]    iface   instance
 * \param[out]   rxdata  pointer to space to receive the data
 * \param[in,out] rxsize  ptr to expected number of receive bytes to request
 * \return ATCA_STATUS
 */
ATCA_STATUS kit_phy_receive(ATCAIface iface, uint8_t* rxdata, int* rxsize)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    hid_device* pHid = (hid_device*)atgetifacehaldat(iface);
    size_t bytes_read = 0;
    size_t total_bytes_read = 0;
    size_t bytes_to_read = *rxsize;
    char *location;

    if ((rxdata == NULL) || (rxsize == NULL) || (cfg == NULL) || (pHid == NULL))
    {
        return ATCA_BAD_PARAM;
    }

    bytes_to_read--;

    // Receive the data from the kit USB device
    do
    {
        bytes_read = hid_read(pHid, &rxdata[total_bytes_read], bytes_to_read);
        if (bytes_read == -1)
        {
            return ATCA_RX_FAIL;
        }

        location = memchr(&rxdata[total_bytes_read], '\n', bytes_read);

        total_bytes_read += bytes_read;
        bytes_to_read -= bytes_read;
    }
    while (!location && 0 < bytes_to_read);

    // Save the total bytes read
    if (location != NULL)
    {
        *rxsize = (int)(location - (char*)rxdata);
    }
    else
    {
        *rxsize = (int)total_bytes_read;
    }

#ifdef KIT_DEBUG
    printf("HID layer: Read: %s", rxdata);
#endif // KIT_DEBUG

    return ATCA_SUCCESS;
}

/** \brief Number of USB HID devices found
 *  \param[out] num_found   return number of USB HID devices found
 *  \return ATCA_STATUS
 */
ATCA_STATUS kit_phy_num_found(int8_t* num_found)
{
    return ATCA_UNIMPLEMENTED;
}

/** \brief HAL implementation of kit protocol send over USB HID
 *  \param[in] iface          instance
 *  \param[in] word_address   determine device transaction type
 *  \param[in] txdata         pointer to bytes to send
 *  \param[in] txlength       number of bytes to send
 *  \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_send(ATCAIface iface, uint8_t word_address, uint8_t* txdata, int txlength)
{
    // Call the kit_send() function that will call phy_send() implemented below
    return kit_send(iface, word_address, txdata, txlength);
}

/** \brief HAL implementation of send over USB HID
 * \param[in]    iface          instance
 * \param[in]    word_address   determine device transaction type
 * \param[in]    rxdata         pointer to space to receive the data
 * \param[in,out] rxsize        ptr to expected number of receive bytes to request
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_receive(ATCAIface iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxsize)
{
    // Call the kit_receive() function that will call phy_receive() implemented below
    return kit_receive(iface, word_address, rxdata, rxsize);
}

/** \brief Call the wake for kit protocol
 * \param[in] iface  ATCAIface instance that is the interface object to send the bytes over
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_wake(ATCAIface iface)
{
    // Call the kit_wake() function that will call phy_send() and phy_receive()
    return kit_wake(iface);
}

/** \brief Call the idle for kit protocol
 * \param[in] iface  ATCAIface instance that is the interface object to send the bytes over
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_idle(ATCAIface iface)
{
    // Call the kit_idle() function that will call phy_send() and phy_receive()
    return kit_idle(iface);
}

/** \brief Call the sleep for kit protocol
 * \param[in] iface  ATCAIface instance that is the interface object to send the bytes over
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_sleep(ATCAIface iface)
{
    // Call the kit_sleep() function that will call phy_send() and phy_receive()
    return kit_sleep(iface);
}

/** \brief Close the physical port for HID
 * \param[in] hal_data  The hardware abstraction data specific to this HAL
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_release(void* hal_data)
{
    hid_device* pHid = (hid_device*)hal_data;
    int i = 0;

    if (pHid == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    hid_close(pHid);

    return ATCA_SUCCESS;
}

/** @} */
