/**
 * \file
 * \brief CryptoAuthLib Basic API methods. These methods provide a simpler way
 *        to access the core crypto methods.
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

/** \brief basic API methods are all prefixed with atcab_  (CryptoAuthLib Basic)
 *  the fundamental premise of the basic API is it is based on a single interface
 *  instance and that instance is global, so all basic API commands assume that
 *  one global device is the one to operate on.
 */

/** \brief wakeup the CryptoAuth device
 *  \param[in] device     Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_wakeup(ATCADevice device)
{
    if (device == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    return atwake(device->mIface);
}

/** \brief idle the CryptoAuth device
 *  \param[in] device     Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_idle(ATCADevice device)
{
    if (device == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    return atidle(device->mIface);
}

/** \brief invoke sleep on the CryptoAuth device
 *  \param[in] device     Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_sleep(ATCADevice device)
{
    if (device == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    return atsleep(device->mIface);
}

/** \brief auto discovery of crypto auth devices
 *
 * Calls interface discovery functions and fills in cfg_array up to the maximum
 * number of configurations either found or the size of the array. The cfg_array
 * can have a mixture of interface types (ie: some I2C, some SWI or UART) depending upon
 * which interfaces you've enabled
 *
 * \param[out] cfg_array ptr to an array of interface configs
 * \param[in] max_ifaces maximum size of cfg_array
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_cfg_discover(ATCAIfaceCfg cfg_array[], int max_ifaces)
{
    int iface_num = 0;
    int found = 0;
    int i = 0;

// this cumulatively gathers all the interfaces enabled by #defines
#define MAX_BUSES   4

#ifdef ATCA_HAL_I2C
    int i2c_buses[MAX_BUSES];
    memset(i2c_buses, -1, sizeof(i2c_buses));
    hal_i2c_discover_buses(i2c_buses, MAX_BUSES);

    for (i = 0; i < MAX_BUSES && iface_num < max_ifaces; i++)
    {
        if (i2c_buses[i] != -1)
        {
            hal_i2c_discover_devices(i2c_buses[i], &cfg_array[iface_num], &found);
            iface_num += found;
        }
    }
#endif

#ifdef ATCA_HAL_SWI
    int swi_buses[MAX_BUSES];
    memset(swi_buses, -1, sizeof(swi_buses));
    hal_swi_discover_buses(swi_buses, MAX_BUSES);
    for (i = 0; i < MAX_BUSES && iface_num < max_ifaces; i++)
    {
        if (swi_buses[i] != -1)
        {
            hal_swi_discover_devices(swi_buses[i], &cfg_array[iface_num], &found);
            iface_num += found;
        }
    }

#endif

#ifdef ATCA_HAL_UART
    int uart_buses[MAX_BUSES];
    memset(uart_buses, -1, sizeof(uart_buses));
    hal_uart_discover_buses(uart_buses, MAX_BUSES);
    for (i = 0; i < MAX_BUSES && iface_num < max_ifaces; i++)
    {
        if (uart_buses[i] != -1)
        {
            hal_uart_discover_devices(uart_buses[i], &cfg_array[iface_num], &found);
            iface_num += found;
        }
    }
#endif

#ifdef ATCA_HAL_KIT_CDC
    int cdc_buses[MAX_BUSES];
    memset(cdc_buses, -1, sizeof(cdc_buses));
    hal_kit_cdc_discover_buses(cdc_buses, MAX_BUSES);
    for (i = 0; i < MAX_BUSES && iface_num < max_ifaces; i++)
    {
        if (cdc_buses[i] != -1)
        {
            hal_kit_cdc_discover_devices(cdc_buses[i], &cfg_array[iface_num++], &found);
            iface_num += found;
        }
    }
#endif

#ifdef ATCA_HAL_KIT_HID
    int hid_buses[MAX_BUSES];
    memset(hid_buses, -1, sizeof(hid_buses));
    hal_kit_hid_discover_buses(hid_buses, MAX_BUSES);
    for (i = 0; i < MAX_BUSES && iface_num < max_ifaces; i++)
    {
        if (hid_buses[i] != -1)
        {
            hal_kit_hid_discover_devices(hid_buses[i], &cfg_array[iface_num++], &found);
            iface_num += found;
        }
    }
#endif
    return ATCA_SUCCESS;
}

/** \brief common cleanup code which idles the device after any operation
 *  \param[in] device     Device context pointer
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS _calib_exit(ATCADevice device)
{
    return calib_idle(device);
}


/** \brief Compute the address given the zone, slot, block, and offset
 *  \param[in] zone   Zone to get address from. Config(0), OTP(1), or
 *                    Data(2) which requires a slot.
 *  \param[in] slot   Slot Id number for data zone and zero for other zones.
 *  \param[in] block  Block number within the data or configuration or OTP zone .
 *  \param[in] offset Offset Number within the block of data or configuration or OTP zone.
 *  \param[out] addr  Pointer to the address of data or configuration or OTP zone.
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t* addr)
{
    ATCA_STATUS status = ATCA_SUCCESS;
    uint8_t mem_zone = zone & 0x03;

    if (addr == NULL)
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }
    if ((mem_zone != ATCA_ZONE_CONFIG) && (mem_zone != ATCA_ZONE_DATA) && (mem_zone != ATCA_ZONE_OTP))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received");
    }
    do
    {
        // Initialize the addr to 00
        *addr = 0;
        // Mask the offset
        offset = offset & (uint8_t)0x07;
        if ((mem_zone == ATCA_ZONE_CONFIG) || (mem_zone == ATCA_ZONE_OTP))
        {
            *addr = block << 3;
            *addr |= offset;
        }
        else     // ATCA_ZONE_DATA
        {
            *addr = slot << 3;
            *addr  |= offset;
            *addr |= block << 8;
        }
    }
    while (0);

    return status;
}

/** \brief Gets the size of the specified zone in bytes.
 *
 * \param[in]  device  Device context pointer
 * \param[in]  zone    Zone to get size information from. Config(0), OTP(1), or
 *                     Data(2) which requires a slot.
 * \param[in]  slot    If zone is Data(2), the slot to query for size.
 * \param[out] size    Zone size is returned here.
 *
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_get_zone_size(ATCADevice device, uint8_t zone, uint16_t slot, size_t* size)
{
    ATCA_STATUS status = ATCA_SUCCESS;

    if ((device == NULL) || (size == NULL))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
    }

    if (device->mIface->mIfaceCFG->devtype == ATSHA204A)
    {
        switch (zone)
        {
        case ATCA_ZONE_CONFIG: *size = 88; break;
        case ATCA_ZONE_OTP:    *size = 64; break;
        case ATCA_ZONE_DATA:   *size = 32; break;
        default: status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received"); break;
        }
    }
    else if (device->mIface->mIfaceCFG->devtype == ATSHA206A)
    {
        switch (zone)
        {
        case ATCA_ZONE_CONFIG: *size = 88; break;
        case ATCA_ZONE_OTP:    *size = 0; break;
        case ATCA_ZONE_DATA:   *size = 32; break;
        default: status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received"); break;
        }
    }
    else
    {
        switch (zone)
        {
        case ATCA_ZONE_CONFIG: *size = 128; break;
        case ATCA_ZONE_OTP:    *size = 64; break;
        case ATCA_ZONE_DATA:
            if (slot < 8)
            {
                *size = 36;
            }
            else if (slot == 8)
            {
                *size = 416;
            }
            else if (slot < 16)
            {
                *size = 72;
            }
            else
            {
                status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid slot received");
            }
            break;
        default: status = ATCA_TRACE(ATCA_BAD_PARAM, "Invalid zone received"); break;
        }
    }

    return status;
}
