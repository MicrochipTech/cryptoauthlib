/**
 * \file
 *
 * \brief Provides required interface between boot loader and secure boot.
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

#ifndef CRYPTO_DEVICE_CONFIG_H
#define CRYPTO_DEVICE_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "atca_status.h"
#include "atca_command.h"
#include "host/atca_host.h"

#define CRYPTO_DEVICE_ENABLE_SECURE_BOOT    true
#define CRYPTO_DEVICE_LOAD_CONFIG_ENABLED   false
#define IO_PROTECTION_KEY_SLOT              4
#define SECURE_BOOT_PUBLIC_KEY_SLOT         11
#define SECURE_BOOT_SIGN_DIGEST_SLOT        12

ATCA_STATUS crypto_device_verify_app(void);
ATCA_STATUS crypto_device_load_configuration(void);

#ifdef __cplusplus
}
#endif

#endif



