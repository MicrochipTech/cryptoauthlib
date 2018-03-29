/**
 * \file
 *
 * \brief  Microchip CryptoAuthLib hardware interface object
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

#include <stdlib.h>
#include "atca_iface.h"
#include "hal/atca_hal.h"

/** \defgroup interface ATCAIface (atca_)
 *  \brief Abstract interface to all CryptoAuth device types.  This interface
 *  connects to the HAL implementation and abstracts the physical details of the
 *  device communication from all the upper layers of CryptoAuthLib
   @{ */

ATCA_STATUS _atinit(ATCAIface ca_iface, ATCAHAL_t *hal);

/** \brief constructor for ATCAIface objects
 * \param[in] cfg  points to the logical configuration for the interface
 * \return ATCAIface
 */

ATCAIface newATCAIface(ATCAIfaceCfg *cfg)  // constructor
{
    ATCAIface ca_iface;

    ca_iface = (ATCAIface)malloc(sizeof(struct atca_iface));
    ca_iface->mType = cfg->iface_type;
    ca_iface->mIfaceCFG = cfg;

    if (atinit(ca_iface) != ATCA_SUCCESS)
    {
        free(ca_iface);
        ca_iface = NULL;
    }

    return ca_iface;
}

// public ATCAIface methods

/** \brief This function performs the HAL initialisation by calling intermediate HAL wrapper function.
 *  User should not call this function directly,instead use atcab_init() function
 * \param[in] ca_iface  points to the logical configuration for the interface
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */

ATCA_STATUS atinit(ATCAIface ca_iface)
{
    ATCA_STATUS status = ATCA_COMM_FAIL;
    ATCAHAL_t hal;

    _atinit(ca_iface, &hal);

    status = ca_iface->atinit(&hal, ca_iface->mIfaceCFG);
    if (status == ATCA_SUCCESS)
    {
        ca_iface->hal_data = hal.hal_data;

        // Perform the post init
        status = ca_iface->atpostinit(ca_iface);
    }

    return status;
}

/** \brief This function sends the data to device by calling intermediate HAL wrapper function.
 * \param[in] ca_iface   points to the logical configuration for the interface
 * \param[in] txdata    pointer to the data to be transmitted to the device
 * \param[in] txlength  The total number of bytes to be transmitted to the device
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atsend(ATCAIface ca_iface, uint8_t *txdata, int txlength)
{
    return ca_iface->atsend(ca_iface, txdata, txlength);
}

/**\brief This function receives  data from device by calling intermediate HAL wrapper function.
 * \param[in] ca_iface  points to the logical configuration for the interface
 * \param[in] rxdata   pointer to the data to be stored from device
 * \param[in] rxlength  pointer to holds the number of bytes to be received from device.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atreceive(ATCAIface ca_iface, uint8_t *rxdata, uint16_t *rxlength)
{
    return ca_iface->atreceive(ca_iface, rxdata, rxlength);
}

/** \brief This function performs waking up of device by calling intermediate HAL wrapper function.
 *  User should not call this function directly,instead  use atcab_wakeup() function
 * \param[in] ca_iface  points to the logical configuration for the interface
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atwake(ATCAIface ca_iface)
{
    return ca_iface->atwake(ca_iface);
}


/** \brief This function makes the device to go to idle state by calling intermediate HAL wrapper function.
 *  User should not call this function directly,instead  use atcab_idle() function
 * \param[in] ca_iface  points to the logical configuration for the interface
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atidle(ATCAIface ca_iface)
{
    ATCA_STATUS status;

    status = ca_iface->atidle(ca_iface);
    atca_delay_ms(1);
    return status;
}

/** \brief This function makes the device to go to sleep by calling intermediate HAL wrapper function.
 *  User should not call this function directly,instead  use atcab_sleep() function
 * \param[in] ca_iface  points to the logical configuration for the interface
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atsleep(ATCAIface ca_iface)
{
    ATCA_STATUS status;

    status = ca_iface->atsleep(ca_iface);
    atca_delay_ms(1);
    return status;
}


/** \brief This function returns the pointer to Interface configuration of the Crypto Auth device.
 * \param[in] ca_iface  points to the logical configuration for the interface
 * \return returns the pointer to ATCAIfaceCfg.
 */
ATCAIfaceCfg * atgetifacecfg(ATCAIface ca_iface)
{
    return ca_iface->mIfaceCFG;
}


/** \brief This function returns the pointer of HAL data of the Crypto Auth device.
 * \param[in] ca_iface  points to the logical configuration for the interface
 * \return returns the pointer to HAL data.
 */
void* atgetifacehaldat(ATCAIface ca_iface)
{
    return ca_iface->hal_data;
}


/** \brief destructor for ATCAIface objects
 * \param[in] ca_iface  points to the logical configuration for the interface
 */
void deleteATCAIface(ATCAIface *ca_iface) // destructor
{
    if (*ca_iface)
    {
        hal_iface_release( (*ca_iface)->mType, (*ca_iface)->hal_data);  // let HAL clean up and disable physical level interface if ref count is 0
        free((void*)*ca_iface);
    }

    *ca_iface = NULL;
}

ATCA_STATUS _atinit(ATCAIface ca_iface, ATCAHAL_t *hal)
{
    // get method mapping to HAL methods for this interface
    hal_iface_init(ca_iface->mIfaceCFG, hal);
    ca_iface->atinit     = hal->halinit;
    ca_iface->atpostinit = hal->halpostinit;
    ca_iface->atsend     = hal->halsend;
    ca_iface->atreceive  = hal->halreceive;
    ca_iface->atwake     = hal->halwake;
    ca_iface->atsleep    = hal->halsleep;
    ca_iface->atidle     = hal->halidle;
    ca_iface->hal_data   = hal->hal_data;

    return ATCA_SUCCESS;
}
/** @} */
