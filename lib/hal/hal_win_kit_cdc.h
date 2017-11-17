/**
 * \file
 * \brief ATCA Hardware abstraction layer for Windows using kit protocol over a USB CDC device.
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

#ifndef HAL_WIN_KIT_CDC_H_
#define HAL_WIN_KIT_CDC_H_

#include <Windows.h>

// Kit USB defines
#define CDC_DEVICES_MAX     10      //! Maximum number of supported Kit USB devices
#define CDC_BUFFER_MAX      1024    //! Maximum number of bytes read per port read


// Each device that is found will have a read handle and a write handle
typedef struct cdc_device
{
    HANDLE read_handle;         //! The kit USB read file handle
    HANDLE write_handle;        //! The kit USB write file handle
} cdc_device_t;


// A structure to hold CDC information
typedef struct atcacdc
{
    cdc_device_t kits[CDC_DEVICES_MAX];
    int8_t       num_kits_found;
} atcacdc_t;

#endif /* HAL_WIN_KIT_CDC_H_ */

