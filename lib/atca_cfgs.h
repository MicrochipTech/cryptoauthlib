/**
 * \file
 * \brief a set of default configurations for various ATCA devices and interfaces
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


#ifndef ATCA_CFGS_H_
#define ATCA_CFGS_H_

#include "atca_iface.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(ATCA_ECC_SUPPORT) && defined(ATCA_HAL_I2C)
/** \brief default configuration for an ECCx08A device on the first logical I2C bus */
extern ATCAIfaceCfg cfg_ateccx08a_i2c_default;
#endif

#if defined(ATCA_ECC_SUPPORT) && defined(ATCA_HAL_SWI)
/** \brief default configuration for an ECCx08A device on the logical SWI bus over UART*/
extern ATCAIfaceCfg cfg_ateccx08a_swi_default;
#endif

#if defined(ATCA_ECC_SUPPORT) && defined(ATCA_HAL_KIT_UART)
/** \brief default configuration for Kit protocol over a CDC interface */
extern ATCAIfaceCfg cfg_ateccx08_kituart_default;
#endif

#if defined(ATCA_ECC_SUPPORT) && defined(ATCA_HAL_KIT_HID)
/** \brief default configuration for Kit protocol over a HID interface */
extern ATCAIfaceCfg cfg_ateccx08a_kithid_default;
#endif

#if defined(ATCA_SHA_SUPPORT) && defined(ATCA_HAL_I2C)
/** \brief default configuration for a SHA204A device on the first logical I2C bus */
extern ATCAIfaceCfg cfg_atsha20xa_i2c_default;
#endif

#if defined(ATCA_SHA_SUPPORT) && defined(ATCA_HAL_SWI)
/** \brief default configuration for an SHA20xA device on the logical SWI bus over UART*/
extern ATCAIfaceCfg cfg_atsha20xa_swi_default;
#endif

#if defined(ATCA_SHA_SUPPORT) && defined(ATCA_HAL_KIT_UART)
/** \brief default configuration for Kit protocol over a CDC interface */
extern ATCAIfaceCfg cfg_atsha20xa_kituart_default;
#endif

#if defined(ATCA_SHA_SUPPORT) && defined(ATCA_HAL_KIT_HID)
/** \brief default configuration for Kit protocol over a HID interface for SHA204 */
extern ATCAIfaceCfg cfg_atsha20xa_kithid_default;
#endif

#ifdef __cplusplus
}
#endif
#endif /* ATCA_CFGS_H_ */
