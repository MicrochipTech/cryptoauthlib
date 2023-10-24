/**
 * \file
 * \brief TNG LORA device certificate definition
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

#ifndef TNGLORA_CERT_DEF_4_DEVICE_H
#define TNGLORA_CERT_DEF_4_DEVICE_H

#include "atcacert/atcacert_def.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup tng_
 * @{
 */
#define TNGLORA_CERT_TEMPLATE_4_DEVICE_SIZE 552
ATCA_DLL const atcacert_def_t g_tnglora_cert_def_4_device;

extern SHARED_LIB_EXPORT const uint8_t g_tnglora_cert_template_4_device[];
extern SHARED_LIB_EXPORT const atcacert_cert_element_t g_tnglora_cert_elements_4_device[];

/** @} */

#ifdef __cplusplus
}
#endif

#endif
