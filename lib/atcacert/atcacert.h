/**
 * \file
 * \brief Declarations common to all atcacert code.
 *
 * These are common definitions used by all the atcacert code.
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

#ifndef ATCACERT_H
#define ATCACERT_H

#include <stddef.h>
#include <stdint.h>

#include "atcacert_check_config.h"
#include "atca_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Format version 0 supports ECCP256 curve
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * |                                                    Signature: 64 bytes                                                        |
 * |                                                       Bytes 0 to 63                                                           |
 * +-------------------------------------------------------------------------------------------------------------------------------+
 * | Byte 64       | Byte 65       | Byte 66       | Byte 67       | Byte 68       | Byte 69       | Byte 70       | Byte 71       |
 * +---------------+---------------+-----------------------------------------------------------------------------------------------+
 * | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |
 * | 5 bits  | 4 bits| 5 bits  | 5 bits  | 5 bits  |             16 bits           | 4 bits| 4 bits| 4 bits| 4 bits|     8 bits    |
 * |  Issue  | Issue |  Issue  | Issue   | Expire  |            Signer ID          |Templa | Chain |  SN   | Format|    Reserved   |
 * |  Year   | Month |  Day    | Hour    | Years   |                               | te ID |   ID  | Source|Version|               |
 * +---------+-------+---------+---------+---------+-------------------------------+-------+-------+-------+-------+---------------+
 *
 * Minutes and seconds are always zero.
 */
#define FORMAT_VERSION_0                        0u
/*
 * Format version 1 supports extended years (Issue years and Expire years from 2031 to 2127)
 * +-------------------------------------------------------------------------------------------------------------------------------------+
 * |                                                    Signature: 64 bytes                                                              |
 * |                                                       Bytes 0 to 63                                                                 |
 * +-------------------------------------------------------------------------------------------------------------------------------------+
 * | Byte 64       | Byte 65       | Byte 66       | Byte 67       | Byte 68       | Byte 69       | Byte 70       | Byte 71             |
 * +---------------+---------------+-----------------------------------------------------------------------------------------------------+
 * | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |  | | |  | |
 * | 5 bits  | 4 bits| 5 bits  | 5 bits  | 5 bits  |             16 bits           | 4 bits| 4 bits| 4 bits| 4 bits|  2  |  2   | 4 bits |
 * |  Issue  | Issue |  Issue  | Issue   | Expire  |            Signer ID          |Templa | Chain |  SN   | Format| bits| bits |Reserved|
 * |  Year   | Month |   Day   | Hour    | Years   |                               | te ID |   ID  | Source|Version|Issue|Expire|        |
 * |         |       |         |         |         |                               |       |       |       |       |Years|Years |        |
 * +---------+-------+---------+---------+---------+-------------------------------+-------+-------+-------+-------+-----+------+--------+
 *
 * Minutes and seconds are always zero.
 */
#define FORMAT_VERSION_1                        1u
/*
 * Format version 2 supports ECC higher curves (ECCP384/ECCP521)
 * +-------------------------------------------------------------------------------------------------------------------------------------+
 * |                                                    Signature: 64 bytes                                                              |
 * |                                                       Bytes 0 to 63                                                                 |
 * +-------------------------------------------------------------------------------------------------------------------------------------+
 * | Byte 64       | Byte 65       | Byte 66       | Byte 67       | Byte 68       | Byte 69       | Byte 70       | Byte 71             |
 * +---------------+---------------+-----------------------------------------------------------------------------------------------------+
 * | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |  | | |  | |
 * | 5 bits  | 4 bits| 5 bits  | 5 bits  | 5 bits  |             16 bits           | 4 bits| 4 bits| 4 bits| 4 bits|  2  |  2   | 4 bits |
 * |  Issue  | Issue |  Issue  | Issue   | Expire  |            Signer ID          |Templa | Chain |  SN   | Format| bits| bits |Reserved|
 * |  Year   | Month |   Day   | Hour    | Years   |                               | te ID |   ID  | Source|Version|Issue|Expire|        |
 * |         |       |         |         |         |                               |       |       |       |       |Years|Years |        |
 * +---------+-------+---------+---------+---------+-------------------------------+-------+-------+-------+-------+-----+------+--------+
 * |                                                       Signature:                                                                    |
 * |                                                 ECCP256 - Reserved                                                                  |
 * |                                                 ECCP384 - Bytes 72 to 103                                                           |
 * |                                                 ECCP521 - Bytes 72 to 139                                                           |
 * +-------------------------------------------------------------------------------------------------------------------------------------+
 *
 * Minutes and seconds are always zero.
 */
#define FORMAT_VERSION_2                        2u

/** \defgroup atcacert_ Certificate manipulation methods (atcacert_)
 *
 * \brief
 * These methods provide convenient ways to perform certification I/O with
 * CryptoAuth chips and perform certificate manipulation in memory
 *
   @{ */
#ifndef FALSE
#define FALSE (0)
#endif
#ifndef TRUE
#define TRUE (1)
#endif

/** Operation completed successfully. */
#define ATCACERT_E_SUCCESS              ATCA_SUCCESS

/** General error. */
#define ATCACERT_E_ERROR                ATCA_GEN_FAIL

/** Invalid/bad parameter passed to function. */
#define ATCACERT_E_BAD_PARAMS           ATCA_BAD_PARAM

/** Supplied buffer for output is too small to hold the result. */
#define ATCACERT_E_BUFFER_TOO_SMALL     ATCA_SMALL_BUFFER

/** Function is unimplemented for the current configuration. */
#define ATCACERT_E_UNIMPLEMENTED        ATCA_UNIMPLEMENTED


/** Data being decoded/parsed has an invalid format. */
#define ATCACERT_E_DECODING_ERROR       4

/** Date is invalid. */
#define ATCACERT_E_INVALID_DATE         5

/** A certificate element size was not what was expected. */
#define ATCACERT_E_UNEXPECTED_ELEM_SIZE 7

/** The certificate element isn't defined for the certificate definition. */
#define ATCACERT_E_ELEM_MISSING         8

/** Certificate element is out of bounds for the given certificate. */
#define ATCACERT_E_ELEM_OUT_OF_BOUNDS   9

/** Certificate structure is bad in some way. */
#define ATCACERT_E_BAD_CERT             10

/** */
#define ATCACERT_E_WRONG_CERT_DEF       11

/** Certificate or challenge/response verification failed. */
#define ATCACERT_E_VERIFY_FAILED        12

/** Invalid transform passed to function. */
#define ATCACERT_E_INVALID_TRANSFORM    13

#ifdef __cplusplus
}
#endif

/** @} */
#endif
