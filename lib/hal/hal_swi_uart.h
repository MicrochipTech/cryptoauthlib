/**
 * \file
 * \brief ATCA Hardware abstraction layer for SWI over UART drivers.
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

#ifndef HAL_SWI_UART_H_
#define HAL_SWI_UART_H_

#ifdef SAMD21_START
    #include "swi_uart_samd21_start.h"
#elif defined (SAMD21_ASF)
    #include "swi_uart_samd21_asf.h"
#elif defined (XMEGA_ASF)
    #include "swi_uart_xmega_a3bu_asf.h"
#elif defined (AT90USB_ASF)
    #include "swi_uart_at90usb1287_asf.h"
#endif


/** \defgroup hal_ Hardware abstraction layer (hal_)
 *
 * \brief
 * These methods define the hardware abstraction layer for communicating with a CryptoAuth device
 * using SWI interface.
 *
   @{ */
#define SWI_WAKE_TOKEN   ((uint8_t)0x00)    //!< flag preceding a command
#define SWI_FLAG_CMD     ((uint8_t)0x77)    //!< flag preceding a command
#define SWI_FLAG_TX      ((uint8_t)0x88)    //!< flag requesting a response
#define SWI_FLAG_IDLE    ((uint8_t)0xBB)    //!< flag requesting to go into Idle mode
#define SWI_FLAG_SLEEP   ((uint8_t)0xCC)    //!< flag requesting to go into Sleep mode

ATCA_STATUS hal_swi_send_flag(ATCAIface iface, uint8_t flag);

/** @} */
#endif /* HAL_SWI_UART_H_ */