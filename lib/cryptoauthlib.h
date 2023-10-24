/**
 * \file
 * \brief Single aggregation point for all CryptoAuthLib header files
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

#ifndef CRYPTOAUTHLIB_H
#define CRYPTOAUTHLIB_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/** Library Configuration File - All build attributes should be included in
    atca_config.h */
#include "atca_config_check.h"
#include "atca_compiler.h"
#include "atca_version.h"
#include "atca_platform.h"
#include "atca_status.h"
#include "atca_debug.h"
#include "cal_buffer.h"
#include "atca_iface.h"
#include "atca_device.h"
#include "atca_helpers.h"
#include "hal/atca_hal.h"

/* Common Cryptographic Definitions */
#define ATCA_SHA256_BLOCK_SIZE              (64u)
#define ATCA_SHA256_DIGEST_SIZE             (32u)

#define ATCA_SHA384_BLOCK_SIZE              (128u)
#define ATCA_SHA384_DIGEST_SIZE             (48u)

#define ATCA_SHA512_BLOCK_SIZE              (128u)
#define ATCA_SHA512_DIGEST_SIZE             (64u)

#define ATCA_AES128_BLOCK_SIZE              (16u)
#define ATCA_AES128_KEY_SIZE                (16)

#define ATCA_AES256_BLOCK_SIZE              (16u)
#define ATCA_AES256_KEY_SIZE                (32u)

#define ATCA_ECCP256_KEY_SIZE               (32)
#define ATCA_ECCP256_PUBKEY_SIZE            (64)
#define ATCA_ECCP256_SIG_SIZE               (64u)

#define ATCA_ZONE_CONFIG                    ((uint8_t)0x00)
#define ATCA_ZONE_OTP                       ((uint8_t)0x01)
#define ATCA_ZONE_DATA                      ((uint8_t)0x02)

#if ATCA_CA2_SUPPORT
#define ATCA_ZONE_CA2_DATA                  ((uint8_t)0x00)
#define ATCA_ZONE_CA2_CONFIG                ((uint8_t)0x01)
#define ATCA_ECC204_DEVICE_ID               ((uint8_t)0x5A)
#define ATCA_TA010_DEVICE_ID                ((uint8_t)0x6A)
#define ATCA_SHA104_DEVICE_ID               ((uint8_t)0x35)
#define ATCA_SHA105_DEVICE_ID               ((uint8_t)0x3B)
#endif

/** Place resulting digest both in Output buffer and TempKey */
#define SHA_MODE_TARGET_TEMPKEY             ((uint8_t)0x00)
/** Place resulting digest both in Output buffer and Message Digest Buffer */
#define SHA_MODE_TARGET_MSGDIGBUF           ((uint8_t)0x40)
/** Place resulting digest both in Output buffer ONLY */
#define SHA_MODE_TARGET_OUT_ONLY            ((uint8_t)0xC0)

#if ATCA_CA_SUPPORT || defined(ATCA_USE_ATCAB_FUNCTIONS)
#include "atca_cfgs.h"
#include "calib/calib_basic.h"
#include "calib/calib_command.h"
#include "calib/calib_aes_gcm.h"
#endif

#if ATCA_TA_SUPPORT
#include "talib/talib_status.h"
#include "talib/talib_basic.h"
#endif

/* Common Library Functions */
#include "atca_basic.h"

#define ATCA_STRINGIFY(x) #x
#define ATCA_TOSTRING(x) ATCA_STRINGIFY(x)

#ifdef ATCA_PRINTF
    #define ATCA_TRACE(s, m)         atca_trace_msg(s, __FILE__ ":" ATCA_TOSTRING(__LINE__) ":%x:" m "\n")
#else
    #define ATCA_TRACE(s, m)         atca_trace(s)
#endif

#endif /* CRYPTOAUTHLIB_H */
