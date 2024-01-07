/**
 * \file
 * \brief  Microchip Crypto Auth
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

#ifndef ATCA_DEVTYPES_H_
#define ATCA_DEVTYPES_H_

#include <stdint.h>

/** \defgroup device ATCADevice (atca_)
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __COVERITY__
#pragma coverity compliance block deviate "CERT DCL37-C" "ECC part defines will not conflict with errno.h codes"
#endif

typedef uint8_t ATCADeviceType;

/** \brief The supported Device type in Cryptoauthlib library */

#define ATSHA204A           (0U)
#define ATECC108A           (1U)
#define ATECC508A           (2U)
#define ATECC608A           (3U)
#define ATECC608B           (3U)
#define ATECC608            (3U)
#define ATSHA206A           (4U)
#define TA100               (0x10U)
#define TA101               (0x11U)
#define ECC204              (0x20U)
#define TA010               (0x21U)
#define ECC206              (0x22U)
#define RNG90               (0x23U)
#define SHA104              (0x24U)
#define SHA105              (0x25U)
#define SHA106              (0x26U)

#define ATCA_DEV_UNKNOWN    (0x7EU)
#define ATCA_DEV_INVALID    (0x7FU)

#ifdef __COVERITY__
#pragma coverity compliance end_block "CERT DCL37-C"
#endif

#ifdef __cplusplus
}
#endif

/** @} */
#endif /* ATCA_DEVTYPES_H_ */
