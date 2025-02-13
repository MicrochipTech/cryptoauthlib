/**
 * \file
 * \brief Declarations for date handling with regard to certificates.
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

#ifndef ATCACERT_DATE_H
#define ATCACERT_DATE_H

#include <stddef.h>
#include "atcacert.h"

#ifdef __COVERITY__
#pragma coverity compliance block fp "MISRA C-2012 Rule 5.4" "Rule for C99 is 63 characters"
#endif

// Inform function naming when compiling in C++
#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup atcacert_ Certificate manipulation methods (atcacert_)
 *
 * \brief
 * These methods provide convenient ways to perform certification I/O with
 * CryptoAuth chips and perform certificate manipulation in memory
 *
   @{ */

#ifdef __COVERITY__
#pragma coverity compliance block \
    (deviate "CERT DCL37-C" "The atcacert_tm_utc_t structure is designed to be compatible with time.h for systems without it") \
    (deviate "MISRA C-2012 Rule 21.2" "The atcacert_tm_utc_t structure is designed to be compatible with time.h for systems without it")
#endif
/**
 * Holds a broken-down date in UTC. Mimics atcacert_tm_utc_t from time.h.
 */
typedef struct atcacert_tm_utc_s
{
    int tm_sec;     // 0 to 59
    int tm_min;     // 0 to 59
    int tm_hour;    // 0 to 23
    int tm_mday;    // 1 to 31
    int tm_mon;     // 0 to 11
    int tm_year;    // years since 1900
} atcacert_tm_utc_t;
#ifdef __COVERITY__
#pragma coverity compliance end_block "CERT DCL37-C" "MISRA C-2012 Rule 21.2"
#endif

/**
 * Date formats.
 */
#define DATEFMT_ISO8601_SEP         (0U)    //!< ISO8601 full date YYYY-MM-DDThh:mm:ssZ
#define DATEFMT_RFC5280_UTC         (1U)    //!< RFC 5280 (X.509) 4.1.2.5.1 UTCTime format YYMMDDhhmmssZ
#define DATEFMT_POSIX_UINT32_BE     (2U)    //!< POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, big endian.
#define DATEFMT_POSIX_UINT32_LE     (3U)    //!< POSIX (aka UNIX) date format. Seconds since Jan 1, 1970. 32 bit unsigned integer, little endian.
#define DATEFMT_RFC5280_GEN         (4U)    //!< RFC 5280 (X.509) 4.1.2.5.2 GeneralizedTime format YYYYMMDDhhmmssZ
#define DATEFMT_INVALID             (0xFFU)

typedef uint8_t atcacert_date_format_t;

#define DATEFMT_ISO8601_SEP_SIZE     (20)
#define DATEFMT_RFC5280_UTC_SIZE     (13)
#define DATEFMT_POSIX_UINT32_BE_SIZE (4)
#define DATEFMT_POSIX_UINT32_LE_SIZE (4)
#define DATEFMT_RFC5280_GEN_SIZE     (15)
#define DATEFMT_MAX_SIZE             DATEFMT_ISO8601_SEP_SIZE
#define ATCACERT_DATE_FORMAT_SIZES_COUNT 5

extern const size_t ATCACERT_DATE_FORMAT_SIZES[ATCACERT_DATE_FORMAT_SIZES_COUNT];

/**
 * \brief Format a timestamp according to the format type.
 *
 * \param[in]    format               Format to use.
 * \param[in]    timestamp            Timestamp to format.
 * \param[out]   formatted_date       Formatted date will be returned in this buffer.
 * \param[in,out] formatted_date_size  As input, the size of the formatted_date buffer.
 *                                    As output, the size of the returned formatted_date.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_date_enc(atcacert_date_format_t   format,
                              const atcacert_tm_utc_t* timestamp,
                              uint8_t*                 formatted_date,
                              size_t*                  formatted_date_size);

/**
 * \brief Parse a formatted timestamp according to the specified format.
 *
 * \param[in]  format               Format to parse the formatted date as.
 * \param[in]  formatted_date       Formatted date to be parsed.
 * \param[in]  formatted_date_size  Size of the formatted date in bytes.
 * \param[out] timestamp            Parsed timestamp is returned here.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_date_dec(atcacert_date_format_t format,
                              const uint8_t*         formatted_date,
                              size_t                 formatted_date_size,
                              atcacert_tm_utc_t*     timestamp);

/**
 * \brief Encode the issue and expire dates in the format used by the compressed certificate.
 *
 * \param[in]  issue_date    Issue date to encode. Note that minutes and seconds will be ignored.
 * \param[in]  expire_years  Expire date is expressed as a number of years past the issue date.
 *                           0 should be used if there is no expire date.
 * \param[out] enc_dates     Encoded dates for use in the compressed certificate is returned here.
 *                           3 bytes.
 *
 * \return 0 on success
 */
ATCA_STATUS atcacert_date_enc_compcert(const atcacert_tm_utc_t * issue_date,
                                       uint8_t                   expire_years,
                                       uint8_t                   enc_dates[3]);

/**
 * \brief Encode the issue and expire dates in the format used by the compressed certificate.
 * 
 * Supports extended dates if the format version field is set appropriately (currently 1).
 *
 * \param[in]  issue_date    Issue date to encode. Note that minutes and seconds will be ignored.
 * \param[in]  expire_years  Expire date is expressed as a number of years past the issue date.
 *                           0 should be used if there is no expire date.
 * \param[in,out] comp_cert  Compressed certificate (72 bytes) where the encoded dates will be
 *                           set. Format version must be set appropriately.
 *
 * \return 0 on success
 */
ATCA_STATUS atcacert_date_enc_compcert_ext(const atcacert_tm_utc_t* issue_date,
                                           uint8_t                  expire_years,
                                           uint8_t                  comp_cert[ATCACERT_COMP_CERT_MAX_SIZE]);

/**
 * \brief Decode the issue and expire dates from the format used by the compressed certificate.
 *
 * \param[in]  enc_dates           Encoded date from the compressed certificate. 3 bytes.
 * \param[in]  expire_date_format  Expire date format. Only used to determine max date when no
 *                                 expiration date is specified by the encoded date.
 * \param[out] issue_date          Decoded issue date is returned here.
 * \param[out] expire_date         Decoded expire date is returned here. If there is no
 *                                 expiration date, the expire date will be set to a maximum
 *                                 value for the given expire_date_format.
 *
 * \return 0 on success
 */
ATCA_STATUS atcacert_date_dec_compcert(const uint8_t          enc_dates[3],
                                       atcacert_date_format_t expire_date_format,
                                       atcacert_tm_utc_t*     issue_date,
                                       atcacert_tm_utc_t*     expire_date);

/**
 * \brief Decode the issue and expire dates from the format used by the compressed certificate.
 *
 *  Supports extended dates if the format version field is 1
 * 
 * \param[in,out] comp_cert        Compressed certificate (72 bytes) where the encoded dates will be
 *                                 set. Format version (In comp_cert byte 70([3:0]) must be set to 1 to use extended dates.
 * \param[in]  expire_date_format  Expire date format. Only used to determine max date when no
 *                                 expiration date is specified by the encoded date.
 * \param[out] issue_date          Decoded issue date is returned here.
 * \param[out] expire_date         Decoded expire date is returned here. If there is no
 *                                 expiration date, the expire date will be set to a maximum
 *                                 value for the given expire_date_format.
 * \return 0 on success
 */
ATCA_STATUS atcacert_date_dec_compcert_ext(const uint8_t          comp_cert[ATCACERT_COMP_CERT_MAX_SIZE],
                                           atcacert_date_format_t expire_date_format,
                                           atcacert_tm_utc_t*     issue_date,
                                           atcacert_tm_utc_t*     expire_date);
/**
 * \brief Convert the asn1 tag for the supported time formats into the local time format
 *
 * \return DATEFMT_RFC5280_UTC, DATEFMT_RFC5280_GEN, or DATEFMT_INVALID
 */
atcacert_date_format_t atcacert_date_from_asn1_tag(const uint8_t tag);

/**
 * \brief Return the maximum date available for the given format.
 *
 * \param[in]  format     Format to get the max date for.
 * \param[out] timestamp  Max date is returned here.
 *
 * \return ATCACERT_E_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS atcacert_date_get_max_date(atcacert_date_format_t format, atcacert_tm_utc_t* timestamp);

ATCA_STATUS atcacert_date_enc_iso8601_sep(const atcacert_tm_utc_t * timestamp,
                                          uint8_t                   formatted_date[DATEFMT_ISO8601_SEP_SIZE]);

ATCA_STATUS atcacert_date_dec_iso8601_sep(const uint8_t      formatted_date[DATEFMT_ISO8601_SEP_SIZE],
                                          atcacert_tm_utc_t* timestamp);

ATCA_STATUS atcacert_date_enc_rfc5280_utc(const atcacert_tm_utc_t * timestamp,
                                          uint8_t                   formatted_date[DATEFMT_RFC5280_UTC_SIZE]);

ATCA_STATUS atcacert_date_dec_rfc5280_utc(const uint8_t      formatted_date[DATEFMT_RFC5280_UTC_SIZE],
                                          atcacert_tm_utc_t* timestamp);

ATCA_STATUS atcacert_date_enc_rfc5280_gen(const atcacert_tm_utc_t * timestamp,
                                          uint8_t                   formatted_date[DATEFMT_RFC5280_GEN_SIZE]);

ATCA_STATUS atcacert_date_dec_rfc5280_gen(const uint8_t      formatted_date[DATEFMT_RFC5280_GEN_SIZE],
                                          atcacert_tm_utc_t* timestamp);

ATCA_STATUS atcacert_date_enc_posix_be(const atcacert_tm_utc_t * timestamp,
                                       uint8_t                   formatted_date[DATEFMT_POSIX_UINT32_BE_SIZE]);
#define atcacert_date_enc_posix_uint32_be       atcacert_date_enc_posix_be

ATCA_STATUS atcacert_date_dec_posix_be(const uint8_t      formatted_date[DATEFMT_POSIX_UINT32_BE_SIZE],
                                       atcacert_tm_utc_t* timestamp);
#define atcacert_date_dec_posix_uint32_be       atcacert_date_dec_posix_be

ATCA_STATUS atcacert_date_enc_posix_le(const atcacert_tm_utc_t * timestamp,
                                       uint8_t                   formatted_date[DATEFMT_POSIX_UINT32_LE_SIZE]);
#define atcacert_date_enc_posix_uint32_le       atcacert_date_enc_posix_le

ATCA_STATUS atcacert_date_dec_posix_le(const uint8_t      formatted_date[DATEFMT_POSIX_UINT32_LE_SIZE],
                                       atcacert_tm_utc_t* timestamp);
#define atcacert_date_dec_posix_uint32_le       atcacert_date_dec_posix_le

/** \brief Compare two dates.
 * 
 * Dates are not checked for validity before comparing.
 * 
 * \param[in] timestamp1  First date to compare.
 * \param[in] timestamp2  Second date to compare.
 * 
 * \return  -1 if timestamp1 is before timestamp2,
            0 if they are equal,
            1 if they are timestamp1 is after timestamp2.
 *          ATCACERT_E_BAD_PARAMS if either input is NULL.
 */
int atcacert_date_cmp(const atcacert_tm_utc_t* timestamp1, const atcacert_tm_utc_t* timestamp2);

/** @} */
#ifdef __cplusplus
}
#endif

#ifdef __COVERITY__
#pragma coverity compliance end_block "MISRA C-2012 Rule 5.4"
#endif

#endif
