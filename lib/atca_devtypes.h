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

/** \defgroup device ATCADevice (atca_)
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

/** \brief The supported Device type in Cryptoauthlib library */
typedef enum
{
    ATSHA204A   = 0,
    ATECC108A   = 1,
    ATECC508A   = 2,
    ATECC608A   = 3,
    ATECC608B   = 3,
    ATECC608    = 3,
    ATSHA206A   = 4,
    TA100       = 0x10,
    ECC204      = 0x20,
    TA010       = 0x21,
    ECC206      = 0x22,
    RNG90       = 0x23,
    SHA104      = 0x24,
    SHA105      = 0x25,
    SHA106      = 0x26,
    ATCA_DEV_UNKNOWN = 0x7E,
    ATCA_DEV_INVALID = 0x7F,
} ATCADeviceType;

#ifdef __cplusplus
}
#endif
/** @} */
#endif /* ATCA_DEVTYPES_H_ */
