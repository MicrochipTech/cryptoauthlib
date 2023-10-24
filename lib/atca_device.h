/**
 * \file
 *
 * \brief  Microchip Crypto Auth device object
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

#ifndef ATCA_DEVICE_H
#define ATCA_DEVICE_H
/*lint +flb */

#include "atca_iface.h"
/** \defgroup device ATCADevice (atca_)
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

/** \brief ATCADeviceState says about device state
 */
typedef enum
{
    ATCA_DEVICE_STATE_UNKNOWN = 0,
    ATCA_DEVICE_STATE_SLEEP,
    ATCA_DEVICE_STATE_IDLE,
    ATCA_DEVICE_STATE_ACTIVE
} ATCADeviceState;

/** \brief Callback function to clean up the session context
 */
typedef void (*ctx_cb)(void* ctx);

/** \brief atca_device is the C object backing ATCADevice.  See the atca_device.h file for
 * details on the ATCADevice methods
 */
struct atca_device
{
    atca_iface_t mIface;                /**< Physical interface */
    uint8_t      device_state;          /**< Device Power State */

    uint8_t  clock_divider;
    uint16_t execution_time_msec;

    /* Session Management */
    void * session_ctx;
    ctx_cb session_cb;
};

typedef struct atca_device * ATCADevice;

ATCA_STATUS initATCADevice(ATCAIfaceCfg* cfg, ATCADevice ca_dev);
ATCADevice newATCADevice(ATCAIfaceCfg *cfg);
ATCA_STATUS releaseATCADevice(ATCADevice ca_dev);
void deleteATCADevice(ATCADevice *ca_dev);

ATCAIface atGetIFace(ATCADevice dev);

#ifdef __cplusplus
}
#endif

/** @} */
/*lint -flb*/
#endif
