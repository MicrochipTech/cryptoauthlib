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

/** \brief HAL implementation of Kit USB HID init
 *  \param[in] hal pointer to HAL specific data that is maintained by this HAL
 *  \param[in] cfg pointer to HAL specific configuration data that is used to initialize this HAL
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_init(ATCAIface iface, ATCAIfaceCfg* cfg)
{
    // Check the input variables
    if ((cfg == NULL) || (iface == NULL))
    {
        return ATCA_BAD_PARAM;
    }

    // Create the enumerate object
#ifdef KIT_DEBUG
    printf("Enumerate HID device(s)\n");
#endif
    (void)hid_init();

    iface->hal_data = hid_open((uint16_t)(ATCA_IFACECFG_VALUE(cfg, atcahid.vid) & UINT16_MAX), (uint16_t)(ATCA_IFACECFG_VALUE(cfg, atcahid.pid) & UINT16_MAX), NULL);

    return (NULL != iface->hal_data) ? ATCA_SUCCESS : ATCA_COMM_FAIL;
}

/** \brief HAL implementation of Kit HID post init
 *  \param[in] iface  instance
 *  \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_post_init(ATCAIface iface)
{
    ((void)iface);
    return ATCA_SUCCESS;
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
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    hid_device* pHid = (hid_device*)atgetifacehaldat(iface);
    int bytes_written;

    ((void)word_address);
    ((void)txlength);

    if ((txdata == NULL) || (cfg == NULL) || (pHid == NULL))
    {
        return ATCA_BAD_PARAM;
    }

#ifdef KIT_DEBUG
    printf("HID layer: Write: %s", txdata);
#endif

    if (0 > (bytes_written = hid_write(pHid, txdata, (size_t)ATCA_IFACECFG_VALUE(cfg, atcahid.packetsize) + 1u)))
    {
        return ATCA_TX_FAIL;
    }

    if ((uint32_t)bytes_written != ATCA_IFACECFG_VALUE(cfg, atcahid.packetsize) + 1u)
    {
        return ATCA_TX_FAIL;
    }

    return ATCA_SUCCESS;
}

/** \brief HAL implementation of send over USB HID
 * \param[in]    iface          instance
 * \param[in]    word_address   determine device transaction type
 * \param[in]    rxdata         pointer to space to receive the data
 * \param[in,out] rxsize        ptr to expected number of receive bytes to request
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_receive(ATCAIface iface, uint8_t word_address, uint8_t* rxdata, uint16_t* rxlength)
{
    hid_device* pHid = (hid_device*)atgetifacehaldat(iface);
    int ret;

    ((void)word_address);

    if ((rxdata == NULL) || (rxlength == NULL) || (pHid == NULL))
    {
        return ATCA_BAD_PARAM;
    }

    ret = hid_read(pHid, rxdata, (size_t)*rxlength);
    if (ret < 0)
    {
        return ATCA_RX_FAIL;
    }
    else
    {
        *rxlength = (uint16_t)ret;
    }

#ifdef KIT_DEBUG
    printf("HID layer: Read: %s", rxdata);
#endif // KIT_DEBUG

    return ATCA_SUCCESS;
}

/** \brief Perform control operations for the kit protocol
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_kit_hid_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    ((void)option);
    ((void)param);
    ((void)paramlen);

    if ((NULL != iface) && (NULL != iface->mIfaceCFG))
    {
        return ATCA_UNIMPLEMENTED;
    }
    return ATCA_BAD_PARAM;
}


/** \brief Close the physical port for HID
 * \param[in] hal_data  The hardware abstraction data specific to this HAL
 * \return ATCA_STATUS
 */
ATCA_STATUS hal_kit_hid_release(void* hal_data)
{
    hid_device* pHid = (hid_device*)hal_data;

    if (pHid == NULL)
    {
        return ATCA_BAD_PARAM;
    }

    hid_close(pHid);

    return ATCA_SUCCESS;
}

/** @} */
