/**
 * \file
 * \brief Configuration check and defaults for the atcacert module
 *
 * \copyright (c) 2015-2022 Microchip Technology Inc. and its subsidiaries.
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
#ifndef ATCACERT_CHECK_CONFIG_H
#define ATCACERT_CHECK_CONFIG_H

#include "cryptoauthlib.h"
#include "crypto/atca_crypto_sw.h"

#ifndef HOSTLIB_CERT_EN
#define HOSTLIB_CERT_EN                     DEFAULT_DISABLED
#endif

#ifndef ATCACERT_INTEGRATION_EN
#define ATCACERT_INTEGRATION_EN             HOSTLIB_CERT_EN
#endif

#ifndef ATCACERT_FULLSTOREDCERT_EN
#define ATCACERT_FULLSTOREDCERT_EN          DEFAULT_ENABLED
#endif

#ifndef ATCACERT_COMPCERT_EN
#define ATCACERT_COMPCERT_EN                DEFAULT_ENABLED
#endif

#ifndef ATCACERT_EN
#define ATCACERT_EN                         (ATCACERT_FULLSTOREDCERT_EN || ATCACERT_COMPCERT_EN)
#endif

#ifndef ATCACERT_HW_CHALLENGE_EN
#define ATCACERT_HW_CHALLENGE_EN            (ATCAB_RANDOM_EN && (ATCA_ECC_SUPPORT || ATCA_TA_SUPPORT))
#endif

#ifndef ATCACERT_HW_VERIFY_EN
#define ATCACERT_HW_VERIFY_EN               (ATCAB_VERIFY_EXTERN_EN && (ATCA_ECC_SUPPORT || ATCA_TA_SUPPORT))
#endif

#ifndef ATCACERT_DATEFMT_ISO_EN
#define ATCACERT_DATEFMT_ISO_EN             DEFAULT_ENABLED
#endif

#ifndef ATCACERT_DATEFMT_UTC_EN
#define ATCACERT_DATEFMT_UTC_EN             DEFAULT_ENABLED
#endif

#ifndef ATCACERT_DATEFMT_POSIX_EN
#define ATCACERT_DATEFMT_POSIX_EN           DEFAULT_ENABLED
#endif

#ifndef ATCACERT_DATEFMT_GEN_EN
#define ATCACERT_DATEFMT_GEN_EN             DEFAULT_ENABLED
#endif

#endif /* ATCACERT_CHECK_CONFIG_H */
