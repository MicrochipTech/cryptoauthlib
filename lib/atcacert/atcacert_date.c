/**
 * \file
 * \brief Date handling with regard to certificates.
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

#include <string.h>
#include <limits.h>
#include "atcacert_date.h"
#include "atca_compiler.h"

#if ATCACERT_EN

const size_t ATCACERT_DATE_FORMAT_SIZES[ATCACERT_DATE_FORMAT_SIZES_COUNT] = {
    DATEFMT_ISO8601_SEP_SIZE,
    DATEFMT_RFC5280_UTC_SIZE,
    DATEFMT_POSIX_UINT32_BE_SIZE,
    DATEFMT_POSIX_UINT32_LE_SIZE,
    DATEFMT_RFC5280_GEN_SIZE
};

atcacert_date_format_t atcacert_date_from_asn1_tag(const uint8_t tag)
{
    atcacert_date_format_t fmt;

#ifdef ATCA_MBEDTLS
    fmt = DATEFMT_RFC5280_GEN;  //Mbedtls follows always "YYYY-MM-DD HH:MM:SS."
    UNUSED_VAR(tag);
#else
    switch (tag)
    {
#if ATCACERT_DATEFMT_UTC_EN
    case 0x17:
        fmt = DATEFMT_RFC5280_UTC;
        break;
#endif
#if ATCACERT_DATEFMT_GEN_EN
    case 0x18:
        fmt = DATEFMT_RFC5280_GEN;
        break;
#endif
    default:
        fmt = DATEFMT_INVALID;
        break;
    }
#endif

    return fmt;
}


ATCA_STATUS atcacert_date_enc(atcacert_date_format_t    format,
                              const atcacert_tm_utc_t*  timestamp,
                              uint8_t*                  formatted_date,
                              size_t*                   formatted_date_size)
{
    ATCA_STATUS rv;

    if (timestamp == NULL || formatted_date_size == NULL || format >= sizeof(ATCACERT_DATE_FORMAT_SIZES) / sizeof(ATCACERT_DATE_FORMAT_SIZES[0]))
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (formatted_date != NULL && *formatted_date_size < ATCACERT_DATE_FORMAT_SIZES[format])
    {
        *formatted_date_size = ATCACERT_DATE_FORMAT_SIZES[format];
        return ATCACERT_E_BUFFER_TOO_SMALL;
    }
    *formatted_date_size = ATCACERT_DATE_FORMAT_SIZES[format];
    if (formatted_date == NULL)
    {
        return ATCACERT_E_SUCCESS;  // Caller just wanted

    }
    switch (format)
    {
#if ATCACERT_DATEFMT_ISO_EN
    case DATEFMT_ISO8601_SEP:
        rv = atcacert_date_enc_iso8601_sep(timestamp, formatted_date);
        break;
#endif
#if ATCACERT_DATEFMT_UTC_EN
    case DATEFMT_RFC5280_UTC:
        rv = atcacert_date_enc_rfc5280_utc(timestamp, formatted_date);
        break;
#endif
#if ATCACERT_DATEFMT_POSIX_EN
    case DATEFMT_POSIX_UINT32_BE:
        rv = atcacert_date_enc_posix_be(timestamp, formatted_date);
        break;
    case DATEFMT_POSIX_UINT32_LE:
        rv = atcacert_date_enc_posix_le(timestamp, formatted_date);
        break;
#endif
#if ATCACERT_DATEFMT_GEN_EN
    case DATEFMT_RFC5280_GEN:
        rv = atcacert_date_enc_rfc5280_gen(timestamp, formatted_date);
        break;
#endif
    default:
        rv = ATCACERT_E_BAD_PARAMS;
        break;
    }

    return rv;
}

ATCA_STATUS atcacert_date_dec(atcacert_date_format_t    format,
                              const uint8_t*            formatted_date,
                              size_t                    formatted_date_size,
                              atcacert_tm_utc_t*        timestamp)
{
    ATCA_STATUS rv;

    if (formatted_date == NULL || timestamp == NULL || format >= sizeof(ATCACERT_DATE_FORMAT_SIZES) / sizeof(ATCACERT_DATE_FORMAT_SIZES[0]))
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    if (formatted_date_size < ATCACERT_DATE_FORMAT_SIZES[format])
    {
        return ATCACERT_E_DECODING_ERROR;   // Not enough data to parse this date format

    }
    switch (format)
    {
#if ATCACERT_DATEFMT_ISO_EN
    case DATEFMT_ISO8601_SEP:
        rv = atcacert_date_dec_iso8601_sep(formatted_date, timestamp);
        break;
#endif
#if ATCACERT_DATEFMT_UTC_EN
    case DATEFMT_RFC5280_UTC:
        rv = atcacert_date_dec_rfc5280_utc(formatted_date, timestamp);
        break;
#endif
#if ATCACERT_DATEFMT_POSIX_EN
    case DATEFMT_POSIX_UINT32_BE:
        rv = atcacert_date_dec_posix_be(formatted_date, timestamp);
        break;
    case DATEFMT_POSIX_UINT32_LE:
        rv = atcacert_date_dec_posix_le(formatted_date, timestamp);
        break;
#endif
#if ATCACERT_DATEFMT_GEN_EN
    case DATEFMT_RFC5280_GEN:
        rv = atcacert_date_dec_rfc5280_gen(formatted_date, timestamp);
        break;
#endif
    default:
        rv = ATCACERT_E_BAD_PARAMS;
        break;
    }

    return rv;
}

ATCA_STATUS atcacert_date_get_max_date(atcacert_date_format_t format, atcacert_tm_utc_t* timestamp)
{
    ATCA_STATUS rv = ATCACERT_E_SUCCESS;

    if (timestamp == NULL || format >= sizeof(ATCACERT_DATE_FORMAT_SIZES) / sizeof(ATCACERT_DATE_FORMAT_SIZES[0]))
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    switch (format)
    {
#if ATCACERT_DATEFMT_ISO_EN
    case DATEFMT_ISO8601_SEP:
        timestamp->tm_year = 9999 - 1900;
        timestamp->tm_mon = 12 - 1;
        timestamp->tm_mday = 31;
        timestamp->tm_hour = 23;
        timestamp->tm_min = 59;
        timestamp->tm_sec = 59;
        break;
#endif
#if ATCACERT_DATEFMT_UTC_EN
    case DATEFMT_RFC5280_UTC:
        timestamp->tm_year = 2049 - 1900;
        timestamp->tm_mon = 12 - 1;
        timestamp->tm_mday = 31;
        timestamp->tm_hour = 23;
        timestamp->tm_min = 59;
        timestamp->tm_sec = 59;
        break;
#endif
#if ATCACERT_DATEFMT_POSIX_EN
    case DATEFMT_POSIX_UINT32_BE:
        timestamp->tm_year = 2106 - 1900;
        timestamp->tm_mon = 2 - 1;
        timestamp->tm_mday = 7;
        timestamp->tm_hour = 6;
        timestamp->tm_min = 28;
        timestamp->tm_sec = 15;
        break;

    case DATEFMT_POSIX_UINT32_LE:
        timestamp->tm_year = 2106 - 1900;
        timestamp->tm_mon = 2 - 1;
        timestamp->tm_mday = 7;
        timestamp->tm_hour = 6;
        timestamp->tm_min = 28;
        timestamp->tm_sec = 15;
        break;
#endif
#if ATCACERT_DATEFMT_GEN_EN
    case DATEFMT_RFC5280_GEN:
        timestamp->tm_year = 9999 - 1900;
        timestamp->tm_mon = 12 - 1;
        timestamp->tm_mday = 31;
        timestamp->tm_hour = 23;
        timestamp->tm_min = 59;
        timestamp->tm_sec = 59;
        break;
#endif
    default:
        rv = ATCACERT_E_BAD_PARAMS;
        break;
    }

    return rv;
}

/**
 * \brief Convert an unsigned integer to a zero padded string with no terminating null.
 */
static uint8_t* uint_to_str(int num, int width, uint8_t* str)
{
    uint8_t* ret = str + width;
    int i;

    // Pre-fill the string width with zeros
    for (i = 0; i < width; i++)
    {
        *(str++) = (uint8_t)'0';
    }
    // Convert the number from right to left
    for (; num != 0; num /= 10)
    {
        /* coverity[cert_int31_c_violation] num is known to be a positive value */
        *(--str) = (uint8_t)'0' + (uint8_t)((unsigned int)num % 10u);
    }

    return ret;
}

/**
 * \brief Convert a number string as a zero padded unsigned integer back into a number
 */
static const uint8_t* str_to_uint(const uint8_t* str, int width, uint32_t* num)
{
    const uint8_t* error_ret = str;
    const uint8_t* good_ret = str + width;
    uint32_t prev_num = 0;
    uint32_t digit_value = 1;
    int digit;

    str += width - 1;
    *num = 0;
    for (digit = 0; digit < width; digit++)
    {
        if (*str < (uint8_t)'0' || *str > (uint8_t)'9')
        {
            return error_ret;   // Character is not a digit
        }
        if (digit >= 10)
        {
            if (*str != (uint8_t)'0')
            {
                return error_ret;   // Number is larger than the output can handle
            }
            continue;
        }
        if (digit == 9 && *str > (uint8_t)'4')
        {
            return error_ret;   // Number is larger than the output can handle

        }

        /* coverity[cert_int30_c_violation] Overflow is checked by the next statement */
        *num += digit_value * ((uint32_t)*str - (uint32_t)'0');
        if (*num < prev_num)
        {
            return error_ret;   // Number rolled over, it is larger than the output can handle

        }

        /* coverity[cert_int30_c_violation : FALSE] No overflow possible */
        digit_value *= 10u;
        prev_num = *num;
        str--;
    }

    return good_ret;
}

/**
 * \brief Convert a number string as a zero padded unsigned integer back into a number constrained
 *        to an integer's size.
 */
static const uint8_t* str_to_int(const uint8_t* str, int width, int* num)
{
    uint32_t unum = 0;
    const uint8_t* ret = str_to_uint(str, width, &unum);

    if (ret != str)
    {
        if (unum > (uint32_t)INT_MAX)
        {
            // Number exceeds int32's range
            ret = str;
        }
        else
        {
            *num = (int)unum;
        }
    }

    return ret;
}

#if ATCACERT_DATEFMT_ISO_EN
ATCA_STATUS atcacert_date_enc_iso8601_sep(const atcacert_tm_utc_t*  timestamp,
                                          uint8_t                   formatted_date[DATEFMT_ISO8601_SEP_SIZE])
{
    uint8_t* cur_pos = formatted_date;
    int year = 0;

    if (timestamp == NULL || formatted_date == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    year = timestamp->tm_year + 1900;

    if (year < 0 || year > 9999)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(year, 4, cur_pos);

    *(cur_pos++) = (uint8_t)'-';

    if (timestamp->tm_mon < 0 || timestamp->tm_mon > 11)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_mon + 1, 2, cur_pos);

    *(cur_pos++) = (uint8_t)'-';

    if (timestamp->tm_mday < 1 || timestamp->tm_mday > 31)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_mday, 2, cur_pos);

    *(cur_pos++) = (uint8_t)'T';

    if (timestamp->tm_hour < 0 || timestamp->tm_hour > 23)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_hour, 2, cur_pos);

    *(cur_pos++) = (uint8_t)':';

    if (timestamp->tm_min < 0 || timestamp->tm_min > 59)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_min, 2, cur_pos);

    *(cur_pos++) = (uint8_t)':';

    if (timestamp->tm_sec < 0 || timestamp->tm_sec > 59)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_sec, 2, cur_pos);

    *(cur_pos++) = (uint8_t)'Z';

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_date_dec_iso8601_sep(const uint8_t         formatted_date[DATEFMT_ISO8601_SEP_SIZE],
                                          atcacert_tm_utc_t*    timestamp)
{
    const uint8_t* cur_pos = formatted_date;
    const uint8_t* new_pos = NULL;

    if (formatted_date == NULL || timestamp == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    (void)memset(timestamp, 0, sizeof(*timestamp));

    new_pos = str_to_int(cur_pos, 4, &timestamp->tm_year);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;
    timestamp->tm_year -= 1900;

    if (*(cur_pos++) != (uint8_t)'-')
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected separator

    }
    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_mon);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;
    timestamp->tm_mon -= 1;

    if (*(cur_pos++) != (uint8_t)'-')
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected separator

    }
    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_mday);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    if (*(cur_pos++) != (uint8_t)'T')
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected separator
    }
    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_hour);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    if (*(cur_pos++) != (uint8_t)':')
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected separator
    }
    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_min);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    if (*(cur_pos++) != (uint8_t)':')
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected separator

    }
    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_sec);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    if (*(cur_pos++) != (uint8_t)'Z')
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected UTC marker

    }
    return ATCACERT_E_SUCCESS;
}
#endif

#if ATCACERT_DATEFMT_UTC_EN
ATCA_STATUS atcacert_date_enc_rfc5280_utc(const atcacert_tm_utc_t*  timestamp,
                                          uint8_t                   formatted_date[DATEFMT_RFC5280_UTC_SIZE])
{
    uint8_t* cur_pos = formatted_date;
    int year = 0;

    if (timestamp == NULL || formatted_date == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    year = timestamp->tm_year + 1900;

    if (year >= 1950 && year <= 1999)
    {
        year = year - 1900;
    }
    else if (year >= 2000 && year <= 2049)
    {
        year = year - 2000;
    }
    else
    {
        return ATCACERT_E_INVALID_DATE; // Year out of range for RFC2459 UTC format
    }
    cur_pos = uint_to_str(year, 2, cur_pos);

    if (timestamp->tm_mon < 0 || timestamp->tm_mon > 11)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_mon + 1, 2, cur_pos);

    if (timestamp->tm_mday < 1 || timestamp->tm_mday > 31)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_mday, 2, cur_pos);

    if (timestamp->tm_hour < 0 || timestamp->tm_hour > 23)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_hour, 2, cur_pos);

    if (timestamp->tm_min < 0 || timestamp->tm_min > 59)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_min, 2, cur_pos);

    if (timestamp->tm_sec < 0 || timestamp->tm_sec > 59)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_sec, 2, cur_pos);

    *(cur_pos++) = (uint8_t)'Z';

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_date_dec_rfc5280_utc(const uint8_t         formatted_date[DATEFMT_RFC5280_UTC_SIZE],
                                          atcacert_tm_utc_t*    timestamp)
{
    const uint8_t* cur_pos = formatted_date;
    const uint8_t* new_pos = NULL;

    if (formatted_date == NULL || timestamp == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    (void)memset(timestamp, 0, sizeof(*timestamp));

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_year);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;
    if (timestamp->tm_year < 50)
    {
        timestamp->tm_year += 2000;
    }
    else
    {
        timestamp->tm_year += 1900;
    }
    timestamp->tm_year -= 1900;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_mon);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;
    timestamp->tm_mon -= 1;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_mday);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_hour);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_min);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_sec);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    if (*(cur_pos++) != (uint8_t)'Z')
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected UTC marker

    }
    return ATCACERT_E_SUCCESS;
}
#endif

#if ATCACERT_DATEFMT_GEN_EN
ATCA_STATUS atcacert_date_enc_rfc5280_gen(const atcacert_tm_utc_t*  timestamp,
                                          uint8_t                   formatted_date[DATEFMT_RFC5280_GEN_SIZE])
{
    uint8_t* cur_pos = formatted_date;
    int year = 0;

    if (timestamp == NULL || formatted_date == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    year = timestamp->tm_year + 1900;

    if (year < 0 || year > 9999)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(year, 4, cur_pos);

    if (timestamp->tm_mon < 0 || timestamp->tm_mon > 11)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_mon + 1, 2, cur_pos);

    if (timestamp->tm_mday < 1 || timestamp->tm_mday > 31)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_mday, 2, cur_pos);

    if (timestamp->tm_hour < 0 || timestamp->tm_hour > 23)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_hour, 2, cur_pos);

    if (timestamp->tm_min < 0 || timestamp->tm_min > 59)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_min, 2, cur_pos);

    if (timestamp->tm_sec < 0 || timestamp->tm_sec > 59)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    cur_pos = uint_to_str(timestamp->tm_sec, 2, cur_pos);

    *(cur_pos++) = (uint8_t)'Z';

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_date_dec_rfc5280_gen(const uint8_t         formatted_date[DATEFMT_RFC5280_GEN_SIZE],
                                          atcacert_tm_utc_t*    timestamp)
{
    const uint8_t* cur_pos = formatted_date;
    const uint8_t* new_pos = NULL;

    if (formatted_date == NULL || timestamp == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    (void)memset(timestamp, 0, sizeof(*timestamp));

    new_pos = str_to_int(cur_pos, 4, &timestamp->tm_year);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;
    timestamp->tm_year -= 1900;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_mon);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;
    timestamp->tm_mon -= 1;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_mday);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_hour);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_min);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    new_pos = str_to_int(cur_pos, 2, &timestamp->tm_sec);
    if (new_pos == cur_pos)
    {
        return ATCACERT_E_DECODING_ERROR;   // There was a problem converting the string to a number
    }
    cur_pos = new_pos;

    if (*(cur_pos++) != (uint8_t)'Z')
    {
        return ATCACERT_E_DECODING_ERROR;   // Unexpected UTC marker

    }
    return ATCACERT_E_SUCCESS;
}
#endif

#if ATCACERT_DATEFMT_POSIX_EN
static bool is_leap_year(int year)
{
    return (year % 400 == 0) || ((year % 4 == 0) && (year % 100 != 0));
}

static int get_month_days(int year, int month)
{
    const uint8_t days[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    /* coverity[cert_str31_c_violation:FALSE] month is checked by caller */
    /* coverity[cert_arr30_c_violation:FALSE] month is checked by caller */
    /* coverity[misra_c_2012_rule_10_3_violation:FALSE] month is checked by caller */
    int limit = days[month];

    if (month == 1 && is_leap_year(year))
    {
        /* coverity[cert_int32_c_violation:FALSE] if month == 1 then limit = 28 which is significantly smaller than INT_MAX */
        limit++;
    }

    return limit;
}


static uint32_t get_year_secs(int year)
{
    if (is_leap_year(year))
    {
        return (31 + 29 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31) * 86400;
    }
    else
    {
        return (31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31) * 86400;
    }
}

static uint32_t get_month_secs(int year, int mon)
{
    static const uint32_t month_secs[] = { 2678400, 2419200, 2678400, 2592000, 2678400, 2592000, 2678400, 2678400, 2592000, 2678400, 2592000, 2678400 };

    if (mon == 1 && is_leap_year(year))
    {
        return 2505600;
    }
    else if ((mon >= 0) && (mon < 12))
    {
        return month_secs[mon];
    }
    else
    {
        return 0;
    }
}

static atcacert_tm_utc_t *atcacert_gmtime32(const uint32_t *posix_time, atcacert_tm_utc_t *result)
{
    uint32_t secs_remaining = *posix_time;
    uint32_t secs = 0;

    result->tm_year = 1970;
    result->tm_mon = 0;
    result->tm_mday = 1;
    result->tm_hour = 0;
    result->tm_min = 0;
    result->tm_sec = 0;

    secs = get_year_secs(result->tm_year);
    while (secs_remaining >= secs)
    {
        /* coverity[cert_int32_c_violation : FALSE] No overflow possible */
        result->tm_year++;
        secs_remaining -= secs;
        secs = get_year_secs(result->tm_year);
    }

    secs = get_month_secs(result->tm_year, result->tm_mon);
    while (secs_remaining >= secs)
    {
        /* coverity[cert_int32_c_violation : FALSE] No overflow possible */
        result->tm_mon++;
        secs_remaining -= secs;
        secs = get_month_secs(result->tm_year, result->tm_mon);
    }

    result->tm_year -= 1900;

    result->tm_mday += (int)secs_remaining / 86400;
    secs_remaining %= 86400u;

    result->tm_hour += (int)secs_remaining / 3600;
    secs_remaining %= 3600u;

    result->tm_min += (int)secs_remaining / 60;
    secs_remaining %= 60u;

    /* coverity[misra_c_2012_rule_10_8_violation : FALSE] No overflow possible */
    result->tm_sec += (int)secs_remaining;

    return result;
}

static ATCA_STATUS atcacert_posix_time_inc(uint32_t * posix_time, uint32_t secs)
{
    ATCA_STATUS rv = ATCACERT_E_INVALID_DATE;

    if ((UINT32_MAX - *posix_time) > secs)
    {
        *posix_time += secs;
        rv = ATCACERT_E_SUCCESS;
    }

    return rv;
}

static bool atcacert_posix_year_is_valid(int year)
{
    return (year >= 1970) && (year <= 2106);
}

static bool atcacert_posix_month_is_valid(int month)
{
    return (month >= 0) && (month < 12);
}

static bool atcacert_posix_day_is_valid(int year, int month, int day)
{
    bool rv = false;

    if (atcacert_posix_year_is_valid(year) && atcacert_posix_month_is_valid(month))
    {
        rv = ((day >= 0) && (day < get_month_days(year, month)));
    }
    return rv;
}

static ATCA_STATUS atcacert_posix_enc_year(uint32_t* posix_time, int year)
{
    ATCA_STATUS rv = ATCACERT_E_SUCCESS;

    if (atcacert_posix_year_is_valid(year))
    {
        year--;
        while (year >= 1970 && rv == ATCACERT_E_SUCCESS)
        {
            rv = atcacert_posix_time_inc(posix_time, get_year_secs(year));
            year--;
        }
    }
    else
    {
        rv = ATCACERT_E_INVALID_DATE;
    }

    return rv;
}

static ATCA_STATUS atcacert_posix_enc_month(uint32_t* posix_time, int year, int month)
{
    ATCA_STATUS rv = ATCACERT_E_SUCCESS;

    if (atcacert_posix_year_is_valid(year) && atcacert_posix_month_is_valid(month))
    {
        month--;
        while (month >= 0 && rv == ATCACERT_E_SUCCESS)
        {
            rv = atcacert_posix_time_inc(posix_time, get_month_secs(year, month));
            month--;
        }
    }
    else
    {
        rv = ATCACERT_E_INVALID_DATE;
    }

    return rv;
}

static ATCA_STATUS atcacert_posix_enc_day(uint32_t* posix_time, int year, int month, int day)
{
    ATCA_STATUS rv = ATCACERT_E_INVALID_DATE;

    if (atcacert_posix_day_is_valid(year, month, day))
    {
        rv = atcacert_posix_time_inc(posix_time, ((uint32_t)day - 1u) * 86400u);
    }

    return rv;
}

static ATCA_STATUS atcacert_posix_enc_hour(uint32_t* posix_time, int hour)
{
    ATCA_STATUS rv = ATCACERT_E_INVALID_DATE;

    if ((hour) >= 0 && (hour < 24))
    {
        rv = atcacert_posix_time_inc(posix_time, (uint32_t)hour * 3600u);
    }
    return rv;
}

static ATCA_STATUS atcacert_posix_enc_minute(uint32_t* posix_time, int minute)
{
    ATCA_STATUS rv = ATCACERT_E_INVALID_DATE;

    if ((minute >= 0) && (minute < 60))
    {
        rv = atcacert_posix_time_inc(posix_time, (uint32_t)minute * 60u);
    }
    return rv;
}

static ATCA_STATUS atcacert_posix_enc_second(uint32_t* posix_time, int second)
{
    ATCA_STATUS rv = ATCACERT_E_INVALID_DATE;

    if (second >= 0)
    {
        rv = atcacert_posix_time_inc(posix_time, (uint32_t)second);
    }

    return rv;
}

static ATCA_STATUS atcacert_date_enc_posix_uint32(const atcacert_tm_utc_t* timeptr, uint32_t* posix_uint32)
{
    ATCA_STATUS rv = ATCACERT_E_BAD_PARAMS;

    if ((NULL != timeptr) && (NULL != posix_uint32))
    {
        do
        {
            int year = timeptr->tm_year + 1900;

            if (ATCACERT_E_SUCCESS != (rv = atcacert_posix_enc_year(posix_uint32, year)))
            {
                break;
            }

            if (ATCACERT_E_SUCCESS != (rv = atcacert_posix_enc_month(posix_uint32, year, timeptr->tm_mon)))
            {
                break;
            }

            if (ATCACERT_E_SUCCESS != (rv = atcacert_posix_enc_day(posix_uint32, year, timeptr->tm_mon, timeptr->tm_mday)))
            {
                break;
            }

            if (ATCACERT_E_SUCCESS != (rv = atcacert_posix_enc_hour(posix_uint32, timeptr->tm_hour)))
            {
                break;
            }

            if (ATCACERT_E_SUCCESS != (rv = atcacert_posix_enc_minute(posix_uint32, timeptr->tm_min)))
            {
                break;
            }

            rv = atcacert_posix_enc_second(posix_uint32, timeptr->tm_sec);

        } while (false);
    }

    return rv;
}

ATCA_STATUS atcacert_date_enc_posix_be(const atcacert_tm_utc_t* timestamp,
                                       uint8_t                  formatted_date[DATEFMT_POSIX_UINT32_BE_SIZE])
{
    uint32_t posix_uint32 = 0;
    ATCA_STATUS ret = 0;

    if (timestamp == NULL || formatted_date == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    ret = atcacert_date_enc_posix_uint32(timestamp, &posix_uint32);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    formatted_date[0] = (uint8_t)((posix_uint32 >> 24) & 0xFFu);
    formatted_date[1] = (uint8_t)((posix_uint32 >> 16) & 0xFFu);
    formatted_date[2] = (uint8_t)((posix_uint32 >> 8) & 0xFFu);
    formatted_date[3] = (uint8_t)((posix_uint32 >> 0) & 0xFFu);

    return ATCACERT_E_SUCCESS;
}

static ATCA_STATUS atcacert_date_dec_posix_uint32(uint32_t              posix_uint32,
                                                  atcacert_tm_utc_t*    timestamp)
{
//#ifdef WIN32
//	time_t posix_time = (time_t)posix_uint32;
//	errno_t ret = 0;
//
//	if (timestamp == NULL)
//		return ATCACERT_E_BAD_PARAMS;
//
//	memset(timestamp, 0, sizeof(*timestamp));
//	ret = gmtime_s(timestamp, &posix_time);
//	if (ret != 0)
//		return ATCACERT_E_DECODING_ERROR; // Failed to convert to timestamp structure
//#else
//	time_t posix_time = (time_t)posix_uint32;
//	atcacert_tm_utc_t* ret = NULL;
//	if (timestamp == NULL)
//		return ATCACERT_E_BAD_PARAMS;
//
//	memset(timestamp, 0, sizeof(*timestamp));
//	ret = gmtime_r(&posix_time, timestamp);
//	if (ret == NULL)
//		return ATCACERT_E_DECODING_ERROR; // Failed to convert to timestamp structure
//#endif
    (void)atcacert_gmtime32(&posix_uint32, timestamp);

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_date_dec_posix_be(const uint8_t        formatted_date[DATEFMT_POSIX_UINT32_BE_SIZE],
                                       atcacert_tm_utc_t*   timestamp)
{
    uint32_t posix_uint32 = 0;

    if (formatted_date == NULL || timestamp == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    posix_uint32 =
        ((uint32_t)formatted_date[0] << 24) |
        ((uint32_t)formatted_date[1] << 16) |
        ((uint32_t)formatted_date[2] << 8) |
        ((uint32_t)formatted_date[3]);

    return atcacert_date_dec_posix_uint32(posix_uint32 & UINT32_MAX, timestamp);
}

ATCA_STATUS atcacert_date_enc_posix_le(const atcacert_tm_utc_t* timestamp,
                                       uint8_t                  formatted_date[DATEFMT_POSIX_UINT32_LE_SIZE])
{
    uint32_t posix_uint32 = 0;
    ATCA_STATUS ret = 0;

    if (timestamp == NULL || formatted_date == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    ret = atcacert_date_enc_posix_uint32(timestamp, &posix_uint32);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    formatted_date[0] = (uint8_t)((posix_uint32 >> 0u) & 0xFFu);
    formatted_date[1] = (uint8_t)((posix_uint32 >> 8u) & 0xFFu);
    formatted_date[2] = (uint8_t)((posix_uint32 >> 16u) & 0xFFu);
    formatted_date[3] = (uint8_t)((posix_uint32 >> 24u) & 0xFFu);

    return ATCACERT_E_SUCCESS;
}

ATCA_STATUS atcacert_date_dec_posix_le(const uint8_t        formatted_date[DATEFMT_POSIX_UINT32_LE_SIZE],
                                       atcacert_tm_utc_t*   timestamp)
{
    uint32_t posix_uint32 = 0;

    if (formatted_date == NULL || timestamp == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    posix_uint32 =
        ((uint32_t)formatted_date[3] << 24) |
        ((uint32_t)formatted_date[2] << 16) |
        ((uint32_t)formatted_date[1] << 8) |
        ((uint32_t)formatted_date[0]);

    return atcacert_date_dec_posix_uint32(posix_uint32 & UINT32_MAX, timestamp);
}
#endif

ATCA_STATUS atcacert_date_enc_compcert(const atcacert_tm_utc_t* issue_date,
                                       uint8_t                  expire_years,
                                       uint8_t                  enc_dates[3])
{
    ATCA_STATUS ret = ATCACERT_E_BAD_PARAMS;

    if (NULL == enc_dates)
    {
        return ret;
    }

    uint8_t comp_cert[ATCACERT_COMP_CERT_MAX_SIZE] = { 0 };

    ret = atcacert_date_enc_compcert_ext(issue_date, expire_years, comp_cert);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    (void)memcpy(enc_dates, &comp_cert[64], 3);

    return ret;
}

#ifdef __COVERITY__
#pragma coverity compliance block deviate "CERT INT31-C" "Custom integer encoding scheme with documented limitations"
#pragma coverity compliance block deviate "MISRA C-2012 Rule 10.8" "Custom integer encoding scheme with documented limitations"
#endif
ATCA_STATUS atcacert_date_enc_compcert_ext(const atcacert_tm_utc_t* issue_date,
                                           uint8_t                  expire_years,
                                           uint8_t                  comp_cert[ATCACERT_COMP_CERT_MAX_SIZE])
{
    /*
     * Issue and expire dates are compressed/encoded as below in the
     * compressed certificate.
     * +---------------+---------------+---------------+
     * | Byte 64       | Byte 65       | Byte 66       |
     * +---------------+---------------+---------------+
     * | | | | | | | | | | | | | | | | | | | | | | | | |
     * | 5 bits  | 4 bits| 5 bits  | 5 bits  | 5 bits  |
     * | Year    | Month | Day     | Hour    | Expire  |
     * |         |       |         |         | Years   |
     * +---------+-------+---------+---------+---------+
     *
     * Minutes and seconds are always zero.
     *
     * If extended dates are used then the format version must be 1
     * and the issue year and expire years get a couple extra bits
     * in the last byte of the compressed certificate.
     * +-------------------------------------------+
     * | Byte 71                                   |
     * +-------------------------------------------+
     * |       |       |       |       |  |  |  |  |
     * | 2 bits        | 2 bits        | 4 bits    |
     * | Year (MSbits) | Expire Years  | Reserved  |
     * |               | (MSbits)      |           |
     * +---------------+---------------+-----------+
     */
    uint8_t format_version = 0u;

    if (issue_date == NULL || comp_cert == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    // Compressed certificate format version is the lower 4 bits of byte 70
    format_version = comp_cert[70] & (uint8_t)0x0Fu;

    if (format_version == FORMAT_VERSION_0)
    {
        // This version handles years from 2000 to 2031
        if ((issue_date->tm_year + 1900) < 2000 || (issue_date->tm_year + 1900) > 2031)
        {
            return ATCACERT_E_INVALID_DATE;
        }
        // and expire years from 0 to 31
        if (expire_years > 31u)
        {
            return ATCACERT_E_INVALID_DATE;
        }
    }
    else if (format_version == FORMAT_VERSION_1 || format_version == FORMAT_VERSION_2)
    {
        // This version extends years from 2000 to 2127
        if ((issue_date->tm_year + 1900) < 2000 || (issue_date->tm_year + 1900) > 2127)
        {
            return ATCACERT_E_INVALID_DATE;
        }
        // and expire years from 0 to 127
        if (expire_years > 127u)
        {
            return ATCACERT_E_INVALID_DATE;
        }
    }
    else
    {
        // Unsupported format version
        return ATCACERT_E_BAD_CERT;
    }
    if (issue_date->tm_mon < 0 || issue_date->tm_mon > 11)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    if (issue_date->tm_mday < 1 || issue_date->tm_mday > 31)
    {
        return ATCACERT_E_INVALID_DATE;
    }
    if (issue_date->tm_hour < 0 || issue_date->tm_hour > 23)
    {
        return ATCACERT_E_INVALID_DATE;
    }

    (void)memset(&comp_cert[64], 0, 3);

    comp_cert[64] = (uint8_t)((((uint32_t)issue_date->tm_year + 1900u - 2000u) & 0x1Fu) << 3u);
    comp_cert[64] = (uint8_t)((comp_cert[64] & 0xF8u) | (((uint8_t)((uint32_t)issue_date->tm_mon + 1u) & 0x0Fu) >> 1u));
    comp_cert[65] = (uint8_t)(((((uint32_t)issue_date->tm_mon + 1u) & 0x0Fu) << 7u) & 0x80u);
    comp_cert[65] = (uint8_t)((comp_cert[65] & 0x83u) | (uint8_t)((((uint32_t)issue_date->tm_mday & 0x1Fu)) << 2u));
    comp_cert[65] = (uint8_t)((comp_cert[65] & 0xFCu) | (((uint8_t)((uint32_t)issue_date->tm_hour & 0x1Fu)) >> 3u));
    comp_cert[66] = (uint8_t)(((((uint32_t)issue_date->tm_hour & 0x1Fu)) << 5u) & 0xE0u);
    comp_cert[66] = (uint8_t)((comp_cert[66] & 0xE0u) | ((uint8_t)expire_years & 0x1Fu));

    comp_cert[71] = comp_cert[71] & 0x0Fu;                                                                                  // Clear the upper 4 bits for extended dates
    comp_cert[71] = (uint8_t)((comp_cert[71] | (uint8_t)((((uint32_t)issue_date->tm_year + 1900u - 2000u) & 0x60u) << 1u)) & 0xFFu);  // Set upper 2 bits of issue date
    comp_cert[71] = (uint8_t)((comp_cert[71] | ((uint8_t)((expire_years & 0x60u) >> 1u))) & 0xFFu);                           // Set upper 2 bits of expire years

    return ATCACERT_E_SUCCESS;
}


ATCA_STATUS atcacert_date_dec_compcert(const uint8_t            enc_dates[3],
                                       atcacert_date_format_t   expire_date_format,
                                       atcacert_tm_utc_t*       issue_date,
                                       atcacert_tm_utc_t*       expire_date)
{
    ATCA_STATUS ret = ATCACERT_E_BAD_PARAMS;

    uint8_t comp_cert[ATCACERT_COMP_CERT_MAX_SIZE] = { 0 };

    if (NULL == enc_dates)
    {
        return ret;
    }

    (void)memcpy(&comp_cert[64], enc_dates, 3);

    ret = atcacert_date_dec_compcert_ext(comp_cert, expire_date_format, issue_date, expire_date);
    if (ret != ATCACERT_E_SUCCESS)
    {
        return ret;
    }

    return ret;
}

ATCA_STATUS atcacert_date_dec_compcert_ext(const uint8_t            comp_cert[ATCACERT_COMP_CERT_MAX_SIZE],
                                           atcacert_date_format_t   expire_date_format,
                                           atcacert_tm_utc_t*       issue_date,
                                           atcacert_tm_utc_t*       expire_date
                                           )
{
    ATCA_STATUS ret = ATCACERT_E_SUCCESS;
    uint8_t expire_years = 0;

    /*
     * Issue and expire dates are compressed/encoded as below in the
     * compressed certificate.
     * +---------------+---------------+---------------+
     * | Byte 64       | Byte 65       | Byte 66       |
     * +---------------+---------------+---------------+
     * | | | | | | | | | | | | | | | | | | | | | | | | |
     * | 5 bits  | 4 bits| 5 bits  | 5 bits  | 5 bits  |
     * | Year    | Month | Day     | Hour    | Expire  |
     * |         |       |         |         | Years   |
     * +---------+-------+---------+---------+---------+
     *
     * Minutes and seconds are always zero.
     *
     * If extended dates are used then the format version must be 1
     * or 2 and the issue year and expire years get a couple extra bits
     * in the last byte of the compressed certificate.
     * +-------------------------------------------+
     * | Byte 71                                   |
     * +-------------------------------------------+
     * |       |       |       |       |  |  |  |  |
     * | 2 bits        | 2 bits        | 4 bits    |
     * | Year (MSbits) | Expire Years  | Reserved  |
     * |               | (MSbits)      |           |
     * +---------------+---------------+-----------+
     */
    if (comp_cert == NULL || issue_date == NULL || expire_date == NULL ||
        expire_date_format >= sizeof(ATCACERT_DATE_FORMAT_SIZES) / sizeof(ATCACERT_DATE_FORMAT_SIZES[0]))
    {
        return ATCACERT_E_BAD_PARAMS;
    }

    (void)memset(issue_date, 0, sizeof(*issue_date));
    (void)memset(expire_date, 0, sizeof(*expire_date));

    // Compressed certificate format version is the lower 4 bits of byte 70
    uint8_t format_version = comp_cert[70] & (uint8_t)0x0Fu;

    if (format_version == FORMAT_VERSION_1 || format_version == FORMAT_VERSION_2)
    {
        /*
           =================================================================
           Issue year byte obtained from 64[7:3] and byte 71[7:6], (note:100u = 2000 - 1900)
           =================================================================
         */
        issue_date->tm_year = (int)((uint8_t)((((uint8_t)(((((((comp_cert[71] & (uint8_t)0xc0) >> 1u) & 0x60u) | ((comp_cert[64] >> 3u) & 0x1Fu)) & 0xFFu) + 100u) & 0xFFu)) & 0xFFu)));
        /*
           =================================================================
           Extended expiry years from 71[5:4] is copied to expire_years [6:5]
           =================================================================
         */
        expire_years = (uint8_t)((comp_cert[66] & 0x1Fu) | ((comp_cert[71] & 0x30u) << 1u));
    }
    else
    {   
        issue_date->tm_year = (int)((uint8_t)((((comp_cert[64] & (uint8_t)0xF8u) >> 3u)) + 100u));
        expire_years = (comp_cert[66] & (uint8_t)0x1F);
    }
    issue_date->tm_mon = (int)((uint8_t)((uint8_t)((((comp_cert[64] & (uint8_t)0x07) << 1u) | ((comp_cert[65] & (uint8_t)0x80) >> 7u)) - 1u)) & 0x0Fu);
    issue_date->tm_mday = (int)((uint8_t)((comp_cert[65] & (uint8_t)0x7C) >> 2u));
    issue_date->tm_hour = (int)((uint8_t)(((comp_cert[65] & (uint8_t)0x03) << 3u) | ((comp_cert[66] & (uint8_t)0xE0) >> 5u)));

    if (expire_years != 0u)
    {
        expire_date->tm_year = issue_date->tm_year + (int)expire_years;
        expire_date->tm_mon = issue_date->tm_mon;
        expire_date->tm_mday = issue_date->tm_mday;
        expire_date->tm_hour = issue_date->tm_hour;
    }
    else
    {
        // Expire years of 0, means no expiration. Set to max date for the given expiration date format.
        ret = atcacert_date_get_max_date(expire_date_format, expire_date);
        if (ret != ATCACERT_E_SUCCESS)
        {
            return ret;
        }
    }

    return ret;
}
#ifdef __COVERITY__
#pragma coverity compliance end_block "CERT INT31-C"
#pragma coverity compliance end_block "MISRA C-2012 Rule 10.8"
#endif

int atcacert_date_cmp(const atcacert_tm_utc_t* timestamp1, const atcacert_tm_utc_t* timestamp2)
{
    if (timestamp1 == NULL || timestamp2 == NULL)
    {
        return ATCACERT_E_BAD_PARAMS;
    }
    if (timestamp1->tm_year < timestamp2->tm_year)
    {
        return -1;
    }
    if (timestamp1->tm_year > timestamp2->tm_year)
    {
        return 1;
    }
    if (timestamp1->tm_mon < timestamp2->tm_mon)
    {
        return -1;
    }
    if (timestamp1->tm_mon > timestamp2->tm_mon)
    {
        return 1;
    }
    if (timestamp1->tm_mday < timestamp2->tm_mday)
    {
        return -1;
    }
    if (timestamp1->tm_mday > timestamp2->tm_mday)
    {
        return 1;
    }
    if (timestamp1->tm_hour < timestamp2->tm_hour)
    {
        return -1;
    }
    if (timestamp1->tm_hour > timestamp2->tm_hour)
    {
        return 1;
    }
    if (timestamp1->tm_min < timestamp2->tm_min)
    {
        return -1;
    }
    if (timestamp1->tm_min > timestamp2->tm_min)
    {
        return 1;
    }
    if (timestamp1->tm_sec < timestamp2->tm_sec)
    {
        return -1;
    }
    if (timestamp1->tm_sec > timestamp2->tm_sec)
    {
        return 1;
    }
    return 0;
}

#endif /* ATCACERT_EN */